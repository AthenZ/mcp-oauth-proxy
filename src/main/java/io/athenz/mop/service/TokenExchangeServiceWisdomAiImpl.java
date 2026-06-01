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

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.secret.K8SSecretsProvider;
import io.athenz.mop.telemetry.ExchangeStep;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryProviderResolver;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import io.athenz.mop.telemetry.UpstreamHttpCallLabels;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * WisdomAI OAuth integration. WisdomAI access tokens last 7 days
 * ({@code expires_in=604800}) and the {@code POST} body is
 * {@code application/x-www-form-urlencoded}. Although Descope DCR registers WisdomAI as a public
 * client, Descope's token endpoint requires a {@code client_secret} for refresh
 * ({@code errorCode=E011002 "missing secret"}); operators populate the secret in the K8s secret
 * store under {@link K8SSecretsProvider#SECRET_DATA_KEY_WISDOMAI_CLIENT_SECRET}.
 *
 * <p>Auth method: {@code client_secret_post} first, with a one-shot retry on
 * {@code invalid_client} using {@code client_secret_basic} (mirrors
 * {@link WisdomAiUpstreamRefreshClient}).
 *
 * <p>With WisdomAI promoted to the L2 model in
 * {@link UpstreamProviderClassifier#isUpstreamPromoted(String)}, the canonical refresh path is
 * {@code UpstreamRefreshService.refreshUpstream("wisdomai", ...)} -&gt;
 * {@link WisdomAiUpstreamRefreshClient}. {@link #refreshWithUpstreamToken(String)} below remains
 * for the legacy/native fallback path used by
 * {@code AuthorizerService.refreshUpstreamAndGetToken}.
 *
 * <p>We persist the response RT verbatim when WisdomAI rotates and defensively carry forward the
 * prior RT only when the response unexpectedly omits a new one (so an upstream hiccup does not
 * null out the L2 row's encrypted_upstream_refresh_token).
 */
@ApplicationScoped
public class TokenExchangeServiceWisdomAiImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final URI WISDOMAI_TOKEN_ENDPOINT = URI.create("https://api.descope.com/oauth2/v1/apps/token");
    /** WisdomAI's documented access-token lifetime ({@code expires_in=604800} ~7 days). Used only when the response omits {@code expires_in}. */
    static final long WISDOMAI_DEFAULT_TOKEN_TTL = 604_800L;

    @ConfigProperty(name = "server.token-exchange.wisdomai.client-id", defaultValue = "")
    String clientId;

    @ConfigProperty(name = "server.token-exchange.wisdomai.client-secret-key",
            defaultValue = "wisdomai-client-secret")
    String clientSecretKey;

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

    @Inject
    TokenClient tokenClient;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    TelemetryProviderResolver telemetryProviderResolver;

    @Inject
    TelemetryRequestContext telemetryRequestContext;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    @Override
    public AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO) {
        long t0 = System.nanoTime();
        String oauthProvider = telemetryProviderResolver.fromResourceUri(tokenExchangeDO.resource());
        double seconds = (System.nanoTime() - t0) / 1_000_000_000.0;
        oauthProxyMetrics.recordExchangeStep(ExchangeStep.PASS_THROUGH, oauthProvider, true, null,
                telemetryRequestContext.oauthClient(), metricsRegionProvider.primaryRegion(), seconds);
        return new AuthorizationResultDO(AuthResult.AUTHORIZED, tokenExchangeDO.tokenWrapper());
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(TokenExchangeDO tokenExchangeDO) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public TokenWrapper refreshWithUpstreamToken(String upstreamRefreshToken) {

        if (upstreamRefreshToken == null || upstreamRefreshToken.isBlank()) {
            return null;
        }

        if (clientId == null || clientId.isBlank()) {
            log.warn("WisdomAI refresh: client_id not configured");
            return null;
        }
        if (clientSecretKey == null || clientSecretKey.isBlank()) {
            log.warn("WisdomAI refresh: client_secret_key not configured");
            return null;
        }
        Map<String, String> credentials = k8SSecretsProvider.getCredentials(null);
        String clientSecret = credentials != null ? credentials.get(clientSecretKey) : null;
        if (clientSecret == null || clientSecret.isEmpty()) {
            log.warn("WisdomAI refresh: client_secret not found (key={})", clientSecretKey);
            return null;
        }

        long t0 = System.nanoTime();
        String oauthProvider = OauthProviderLabel.WISDOMAI;
        String oauthClient = telemetryRequestContext.oauthClient();
        String region = metricsRegionProvider.primaryRegion();
        String refreshTokenValue = upstreamRefreshToken.trim();
        ClientID cid = new ClientID(clientId.trim());
        Secret secret = new Secret(clientSecret.trim());

        // client_secret_post first; one-shot retry with client_secret_basic on invalid_client.
        TokenWrapper wrapper = attemptRefresh(refreshTokenValue, new ClientSecretPost(cid, secret),
                "client_secret_post");
        if (wrapper != null) {
            recordWisdomAiRefresh(t0, oauthProvider, oauthClient, region, true);
            return wrapper;
        }
        if (lastErrorWasInvalidClient) {
            log.warn("WisdomAI refresh: client_secret_post rejected with invalid_client; retrying with client_secret_basic");
            wrapper = attemptRefresh(refreshTokenValue, new ClientSecretBasic(cid, secret),
                    "client_secret_basic");
            if (wrapper != null) {
                recordWisdomAiRefresh(t0, oauthProvider, oauthClient, region, true);
                return wrapper;
            }
        }
        recordWisdomAiRefresh(t0, oauthProvider, oauthClient, region, false);
        return null;
    }

    /**
     * Per-call flag set by {@link #attemptRefresh} to communicate to
     * {@link #refreshWithUpstreamToken} whether the most recent attempt failed with
     * {@code invalid_client} (eligible for retry with the alternate client-auth method).
     * {@code @ApplicationScoped} beans are effectively single-threaded for a given refresh
     * (each upstream refresh is sequential per L2 row CAS lock), so this is safe.
     */
    private volatile boolean lastErrorWasInvalidClient;

    private TokenWrapper attemptRefresh(String refreshTokenValue,
                                        ClientAuthentication clientAuth,
                                        String authMethodLabel) {
        lastErrorWasInvalidClient = false;
        try {
            RefreshTokenGrant grant = new RefreshTokenGrant(new RefreshToken(refreshTokenValue));
            TokenRequest tokenRequest = new TokenRequest(WISDOMAI_TOKEN_ENDPOINT, clientAuth, grant);

            TokenResponse tokenResponse;
            try (var ignored = UpstreamHttpCallLabels.withLabels(
                    OauthProviderLabel.WISDOMAI, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN)) {
                tokenResponse = tokenClient.execute(tokenRequest);
            }

            if (tokenResponse.indicatesSuccess()) {
                AccessTokenResponse successResponse = tokenResponse.toSuccessResponse();
                AccessToken accessToken = successResponse.getTokens().getAccessToken();
                RefreshToken newRefreshToken = successResponse.getTokens().getRefreshToken();
                Long lifetime = accessToken.getLifetime();
                long ttl = (lifetime != null && lifetime > 0) ? lifetime : WISDOMAI_DEFAULT_TOKEN_TTL;
                return new TokenWrapper(
                        null,
                        null,
                        null,
                        accessToken.getValue(),
                        newRefreshToken != null ? newRefreshToken.getValue() : refreshTokenValue,
                        ttl
                );
            }
            TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            String code = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getCode() : "unknown";
            if ("invalid_client".equals(code)) {
                lastErrorWasInvalidClient = true;
            }
            log.error("WisdomAI refresh failed (auth={}); upstream response: {}",
                    authMethodLabel,
                    UpstreamTokenRefreshErrors.formatTokenError(errorResponse));
            return null;
        } catch (Exception e) {
            log.error("WisdomAI refresh failed (auth={}; could not complete token request or parse upstream response)",
                    authMethodLabel, e);
            return null;
        }
    }

    private void recordWisdomAiRefresh(long startNanos, String oauthProvider, String oauthClient,
                                       String region, boolean success) {
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        oauthProxyMetrics.recordExchangeStep(ExchangeStep.UPSTREAM_REFRESH, oauthProvider, success,
                success ? null : "unauthorized", oauthClient, region, seconds);
    }
}
