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

import io.athenz.mop.config.AthenzTokenExchangeConfig;
import io.athenz.mop.config.GoogleWorkforceTokenExchangeConfig;
import io.athenz.mop.config.GoogleWorkforceTokenExchangeConfig.ServiceConfig;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.GcpZmsPrincipalScope;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.RequestedZtsTokenType;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.telemetry.ExchangeStep;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import io.athenz.mop.util.JwtUtils;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Token exchange for GCP Workforce-backed MCPs (monitoring, logging, bigquery, ...): Okta id_token → ZMS scope →
 * Athenz id_token → Google STS access token. Same flow for every audience; per-service scopes and role name(s)
 * are resolved from {@code server.token-exchange.google-workforce.services.<audience>}. Each
 * {@code gcp-role-name} entry may list several comma-separated short role names; ZMS assertions matching
 * any of them are included in scope. Adding a new GCP MCP is a pure config change.
 */
@ApplicationScoped
public class TokenExchangeServiceGcpWorkforceImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final long DEFAULT_STS_TTL_SECONDS = 3600L;
    private static final String DEFAULT_GCP_ROLE_NAME = "gcp.fed.mcp.user";

    @Inject
    ZMSServiceImpl zmsServiceImpl;

    @Inject
    TokenExchangeServiceProducer tokenExchangeServiceProducer;

    @Inject
    AthenzTokenExchangeConfig athenzTokenExchangeConfig;

    @Inject
    GoogleWorkforceTokenExchange googleWorkforceTokenExchange;

    @Inject
    GoogleWorkforceTokenExchangeConfig googleWorkforceConfig;

    @Inject
    ConfigService configService;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    TelemetryRequestContext telemetryRequestContext;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    @Override
    public AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO) {
        throw new UnsupportedOperationException("Google GCP exchange uses getAccessTokenFromResourceAuthorizationServer");
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO) {
        TokenWrapper oktaToken = tokenExchangeDO != null ? tokenExchangeDO.tokenWrapper() : null;
        if (oktaToken == null) {
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }
        String oktaIdToken = oktaToken.idToken();
        if (oktaIdToken == null || oktaIdToken.isBlank()) {
            log.warn("Google GCP exchange: missing Okta id_token");
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }
        String resource = tokenExchangeDO.resource();
        io.athenz.mop.model.ResourceMeta resourceMeta = configService.getResourceMeta(resource);
        if (resourceMeta == null || resourceMeta.audience() == null) {
            log.warn("Google GCP exchange: no resource meta or audience for resource: {}", resource);
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }
        String audience = resourceMeta.audience();
        Map<String, ServiceConfig> services = googleWorkforceConfig.services();
        ServiceConfig serviceConfig = services != null ? services.get(audience) : null;
        if (serviceConfig == null) {
            log.warn("Google GCP exchange: unsupported audience: {}", audience);
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }
        String roleName = serviceConfig.gcpRoleName().orElse(DEFAULT_GCP_ROLE_NAME);

        Object shortIdObj = JwtUtils.getClaimFromToken(oktaIdToken, "short_id");
        String shortId = shortIdObj != null ? shortIdObj.toString().trim() : null;
        if (shortId == null || shortId.isBlank()) {
            log.warn("Google GCP exchange: missing short_id claim in Okta id_token");
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }
        String roleMember = "user." + shortId;
        GcpZmsPrincipalScope zmsScope = zmsServiceImpl.getScopeForPrincipal(roleMember, roleName);
        String scopeStr = zmsScope.scope();
        List<String> scopeList = (scopeStr != null && !scopeStr.isBlank())
                ? Arrays.asList(scopeStr.split("\\s+"))
                : List.of();
        TokenExchangeDO athenzRequest = new TokenExchangeDO(
                scopeList,
                resource,
                "",
                athenzTokenExchangeConfig.audience(),
                oktaToken,
                RequestedZtsTokenType.ID_TOKEN);
        TokenExchangeService athenzExchange = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("athenz");
        String oauthProviderLabel = OauthProviderLabel.normalize(audience);
        String oauthClient = telemetryRequestContext.oauthClient();
        String region = metricsRegionProvider.primaryRegion();

        long tAthenz = System.nanoTime();
        AuthorizationResultDO athenzResult = athenzExchange.getAccessTokenFromResourceAuthorizationServer(athenzRequest);
        boolean athenzOk = athenzResult != null && athenzResult.token() != null && athenzResult.authResult() == AuthResult.AUTHORIZED;
        recordGcpStep(ExchangeStep.GCP_ATHENZ_ID_TOKEN, oauthProviderLabel, oauthClient, region, tAthenz, athenzOk);

        if (!athenzOk) {
            log.warn("Google GCP exchange: Athenz ID token exchange failed");
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }
        String athenzIdToken = athenzResult.token().idToken();
        if (athenzIdToken == null || athenzIdToken.isBlank()) {
            log.warn("Google GCP exchange: Athenz ID token exchange returned no id_token");
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }

        long tSts = System.nanoTime();
        String stsAccessToken = googleWorkforceTokenExchange.exchange(
                athenzIdToken, audience, zmsScope.defaultBillingProject());
        boolean stsOk = stsAccessToken != null && !stsAccessToken.isBlank();
        recordGcpStep(ExchangeStep.GCP_GOOGLE_STS, oauthProviderLabel, oauthClient, region, tSts, stsOk);
        if (!stsOk) {
            log.warn("Google GCP exchange: Google STS exchange failed");
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }

        TokenWrapper result = new TokenWrapper(
                null,
                null,
                null,
                stsAccessToken,
                null,
                DEFAULT_STS_TTL_SECONDS
        );
        return new AuthorizationResultDO(AuthResult.AUTHORIZED, result);
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(TokenExchangeDO tokenExchangeDO) {
        throw new UnsupportedOperationException("Google GCP exchange does not support client credentials");
    }

    @Override
    public TokenWrapper refreshWithUpstreamToken(String upstreamRefreshToken) {
        // Upstream for GCP Workforce-backed MCPs is Okta; refresh is performed by the Okta exchange service.
        return null;
    }

    private void recordGcpStep(ExchangeStep step, String oauthProvider, String oauthClient, String region,
                               long startNanos, boolean success) {
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        oauthProxyMetrics.recordExchangeStep(step, oauthProvider, success,
                success ? null : "unauthorized", oauthClient, region, seconds);
    }
}
