/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.athenz.mop.service;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.athenz.mop.config.DatabricksTokenExchangeConfig;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.UpstreamHttpCallLabels;
import jakarta.enterprise.context.Dependent;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Exchanges the MoP-held Okta {@code id_token} (JWT) for a Databricks workspace access token via
 * {@code POST https://&lt;workspace&gt;/oidc/v1/token} (token-exchange grant). No Databricks refresh token.
 * Shared by both {@code databricks-sql} and {@code databricks-vector-search} providers;
 * each instance receives its own {@link DatabricksTokenExchangeConfig} and provider label via setters.
 */
@Dependent
public class TokenExchangeServiceDatabricksImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
    private static final String TOKEN_PATH = "/oidc/v1/token";
    private static final long DEFAULT_EXPIRES_SECONDS = 3600L;

    private DatabricksTokenExchangeConfig config;
    private String providerLabel = OauthProviderLabel.DATABRICKS_SQL;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    @Inject
    DatabricksTokenClient databricksTokenClient;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public void setConfig(DatabricksTokenExchangeConfig config) {
        this.config = config;
    }

    public void setProviderLabel(String providerLabel) {
        this.providerLabel = providerLabel;
    }

    @Override
    public AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO) {
        throw new UnsupportedOperationException("Databricks exchange uses getAccessTokenFromResourceAuthorizationServer");
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO) {
        if (tokenExchangeDO == null || tokenExchangeDO.tokenWrapper() == null) {
            log.warn("Databricks {} exchange: missing token wrapper", providerLabel);
            return AuthorizationResultDO.unauthorized("Databricks " + providerLabel + " exchange: missing token wrapper");
        }
        String idToken = StringUtils.trimToNull(tokenExchangeDO.tokenWrapper().idToken());
        if (idToken == null) {
            log.warn("Databricks {} exchange: missing Okta id_token", providerLabel);
            return AuthorizationResultDO.unauthorized("Databricks " + providerLabel + " exchange: missing Okta id_token");
        }
        String resource = tokenExchangeDO.resource();
        Optional<DatabricksWorkspaceResolver.DatabricksWorkspace> resolved =
                DatabricksWorkspaceResolver.resolve(resource, config);
        if (resolved.isEmpty()) {
            log.warn("Databricks {} exchange: invalid or unsupported resource URI for workspace extraction", providerLabel);
            return AuthorizationResultDO.unauthorized(
                    "Databricks " + providerLabel + " exchange: invalid or unsupported resource URI");
        }
        DatabricksWorkspaceResolver.DatabricksWorkspace ws = resolved.get();
        String oauthScope = StringUtils.trimToNull(config.oauthScope());
        if (oauthScope == null) {
            log.warn("Databricks {} exchange: oauth-scope is blank", providerLabel);
            return AuthorizationResultDO.unauthorized("Databricks " + providerLabel + " exchange: oauth-scope is blank");
        }
        if (scopeContainsOfflineAccess(oauthScope)) {
            log.warn("Databricks {} exchange: offline_access is not allowed in configured oauth-scope", providerLabel);
            return AuthorizationResultDO.unauthorized(
                    "Databricks " + providerLabel + " exchange: offline_access is not allowed in configured oauth-scope");
        }

        String tokenUrl = ws.workspaceBaseUrl().replaceAll("/+$", "") + TOKEN_PATH;
        String body = buildFormBody(idToken, oauthScope);

        long startNanos = System.nanoTime();
        String region = metricsRegionProvider.primaryRegion();
        try (var ignored = UpstreamHttpCallLabels.withLabels(providerLabel, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN)) {
            DatabricksTokenClient.DatabricksTokenHttpResponse response =
                    databricksTokenClient.postForm(URI.create(tokenUrl), body);
            double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
            oauthProxyMetrics.recordUpstreamRequest(
                    providerLabel, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN, response.statusCode(), region, seconds);

            String requestId = response.requestId().orElse(null);
            if (response.statusCode() != 200) {
                String snippet = abbreviateBody(response.body());
                log.warn(
                        "Databricks {} token exchange failed: status={} workspaceHost={} scope={} requestId={} bodySnippet={}",
                        providerLabel,
                        response.statusCode(),
                        ws.hostname(),
                        oauthScope,
                        requestId,
                        snippet);
                return AuthorizationResultDO.unauthorized(
                        "Databricks " + providerLabel + " upstream HTTP " + response.statusCode()
                                + " (workspace=" + ws.hostname() + "): " + snippet);
            }

            DatabricksTokenJson parsed = objectMapper.readValue(response.body(), DatabricksTokenJson.class);
            if (parsed == null || StringUtils.isBlank(parsed.accessToken)) {
                log.warn("Databricks {} exchange: success status but missing access_token workspaceHost={} requestId={}",
                        providerLabel, ws.hostname(), requestId);
                return AuthorizationResultDO.unauthorized(
                        "Databricks " + providerLabel + " exchange: success status but missing access_token (workspace="
                                + ws.hostname() + ")");
            }
            long ttl = parsed.expiresIn != null && parsed.expiresIn > 0 ? parsed.expiresIn : DEFAULT_EXPIRES_SECONDS;
            String returnedScope = StringUtils.isNotBlank(parsed.scope) ? parsed.scope.trim() : oauthScope;
            TokenWrapper out = new TokenWrapper(null, null, null, parsed.accessToken, null, ttl);
            log.info(
                    "Databricks {} token exchange ok: workspaceHost={} scope={} expiresIn={} requestId={}",
                    providerLabel,
                    ws.hostname(),
                    returnedScope,
                    ttl,
                    requestId);
            return new AuthorizationResultDO(AuthResult.AUTHORIZED, out, returnedScope);
        } catch (Exception e) {
            double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
            oauthProxyMetrics.recordUpstreamRequest(
                    providerLabel, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN, 0, region, seconds);
            log.warn("Databricks {} token exchange error: workspaceHost={} message={}", providerLabel, ws.hostname(), e.getMessage());
            return AuthorizationResultDO.unauthorized(
                    "Databricks " + providerLabel + " transport error (workspace=" + ws.hostname() + "): " + e.getMessage());
        }
    }

    private static boolean scopeContainsOfflineAccess(String scope) {
        for (String part : scope.split("\\s+")) {
            if ("offline_access".equalsIgnoreCase(part.trim())) {
                return true;
            }
        }
        return false;
    }

    private static String buildFormBody(String idToken, String scope) {
        return "grant_type=" + enc(GRANT_TYPE)
                + "&subject_token_type=" + enc(SUBJECT_TOKEN_TYPE)
                + "&subject_token=" + enc(idToken)
                + "&scope=" + enc(scope);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String abbreviateBody(String body) {
        if (body == null) {
            return "";
        }
        String t = body.trim();
        return t.length() > 200 ? t.substring(0, 200) + "…" : t;
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(TokenExchangeDO tokenExchangeDO) {
        throw new UnsupportedOperationException("Databricks exchange does not support client credentials");
    }

    @Override
    public TokenWrapper refreshWithUpstreamToken(String upstreamRefreshToken) {
        return null;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static final class DatabricksTokenJson {
        @JsonProperty("access_token")
        String accessToken;
        @JsonProperty("expires_in")
        Long expiresIn;
        @JsonProperty("scope")
        String scope;
    }
}
