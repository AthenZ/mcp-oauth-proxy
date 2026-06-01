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
 * Oracle EPM (Oracle IDCS) OAuth integration. Access tokens last 1 hour
 * ({@code expires_in=3600}); the {@code POST} body is {@code application/x-www-form-urlencoded}
 * with {@code client_secret_post} authentication (matches the verified Oracle curl example).
 *
 * <p>Note: with Oracle promoted to the L2 model in
 * {@link UpstreamProviderClassifier#isUpstreamPromoted(String)}, the canonical refresh path is
 * {@code UpstreamRefreshService.refreshUpstream("oracle-epm", ...)} -&gt;
 * {@link OracleEpmUpstreamRefreshClient}. {@link #refreshWithUpstreamToken(String)} below
 * remains for the legacy/native fallback path used by
 * {@code AuthorizerService.refreshUpstreamAndGetToken}.
 *
 * <p>Oracle <strong>rotates</strong> the refresh token on each refresh; we always persist the
 * response RT verbatim. Defensive carry-forward of the prior RT is retained only for the
 * (anomalous) case where the response is HTTP 200 but contains no new refresh_token.
 */
@ApplicationScoped
public class TokenExchangeServiceOracleEpmImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final URI ORACLE_EPM_TOKEN_ENDPOINT = URI.create(
            "https://idcs-c0b7a2ce098d48a0a78b94a30f9e42a1.identity.oraclecloud.com/oauth2/v1/token");
    /** Oracle IDCS documents 3,600 s (1 h) for access tokens; used only when the response omits {@code expires_in}. */
    static final long ORACLE_EPM_DEFAULT_TOKEN_TTL = 3_600L;

    @ConfigProperty(name = "server.token-exchange.oracle-epm.client-id", defaultValue = "")
    String clientId;

    @ConfigProperty(name = "server.token-exchange.oracle-epm.client-secret-key",
            defaultValue = "oracle-epm-client-secret")
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
            log.warn("Oracle EPM refresh: client_id not configured");
            return null;
        }

        if (clientSecretKey == null || clientSecretKey.isBlank()) {
            log.warn("Oracle EPM refresh: client secret key not configured (server.token-exchange.oracle-epm.client-secret-key)");
            return null;
        }
        Map<String, String> credentials = k8SSecretsProvider.getCredentials(null);
        String clientSecret = credentials != null ? credentials.get(clientSecretKey) : null;
        if (clientSecret == null || clientSecret.isBlank()) {
            log.warn("Oracle EPM refresh: client secret missing (key={})", clientSecretKey);
            return null;
        }

        long t0 = System.nanoTime();
        String oauthProvider = OauthProviderLabel.ORACLE_EPM;
        String oauthClient = telemetryRequestContext.oauthClient();
        String region = metricsRegionProvider.primaryRegion();
        try {
            String refreshTokenValue = upstreamRefreshToken.trim();

            // Confidential client (client_secret_post): client_id and client_secret are placed
            // in the form body (Oracle's verified curl shape). Do NOT switch to ClientSecretBasic
            // — Oracle's documented examples and the working flow both use client_secret_post.
            RefreshTokenGrant grant = new RefreshTokenGrant(new RefreshToken(refreshTokenValue));
            TokenRequest tokenRequest = new TokenRequest(
                    ORACLE_EPM_TOKEN_ENDPOINT,
                    new ClientSecretPost(
                            new ClientID(clientId.trim()),
                            new Secret(clientSecret.trim())
                    ),
                    grant
            );

            TokenResponse tokenResponse;
            try (var ignored = UpstreamHttpCallLabels.withLabels(
                    OauthProviderLabel.ORACLE_EPM, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN)) {
                tokenResponse = tokenClient.execute(tokenRequest);
            }

            if (tokenResponse.indicatesSuccess()) {
                AccessTokenResponse successResponse = tokenResponse.toSuccessResponse();
                AccessToken accessToken = successResponse.getTokens().getAccessToken();
                RefreshToken newRefreshToken = successResponse.getTokens().getRefreshToken();
                Long lifetime = accessToken.getLifetime();
                long ttl = (lifetime != null && lifetime > 0) ? lifetime : ORACLE_EPM_DEFAULT_TOKEN_TTL;
                recordOracleEpmRefresh(t0, oauthProvider, oauthClient, region, true);
                return new TokenWrapper(
                        null,
                        null,
                        null,
                        accessToken.getValue(),
                        // Oracle rotates the RT each refresh — persist the response RT verbatim
                        // and only fall back to the prior RT when the response unexpectedly
                        // omits one (defensive; should not happen in steady state).
                        newRefreshToken != null ? newRefreshToken.getValue() : refreshTokenValue,
                        ttl
                );
            } else {
                TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                log.error("Oracle EPM refresh failed; upstream response: {}",
                        UpstreamTokenRefreshErrors.formatTokenError(errorResponse));
                recordOracleEpmRefresh(t0, oauthProvider, oauthClient, region, false);
                return null;
            }
        } catch (Exception e) {
            log.error("Oracle EPM refresh failed (could not complete token request or parse upstream response)", e);
            recordOracleEpmRefresh(t0, oauthProvider, oauthClient, region, false);
            return null;
        }
    }

    private void recordOracleEpmRefresh(long startNanos, String oauthProvider, String oauthClient,
                                        String region, boolean success) {
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        oauthProxyMetrics.recordExchangeStep(ExchangeStep.UPSTREAM_REFRESH, oauthProvider, success,
                success ? null : "unauthorized", oauthClient, region, seconds);
    }
}
