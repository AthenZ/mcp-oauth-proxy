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
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
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
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Datadog OAuth integration. Datadog access tokens last 1 hour and the {@code POST} body is
 * {@code application/x-www-form-urlencoded}. Datadog DCR returns no client_secret and registers
 * as a public PKCE client ({@code token_endpoint_auth_method=none}), so the refresh request
 * carries {@code client_id} in the body but has no {@code Authorization} header.
 *
 * <p>Note: with Datadog promoted to the L2 model in
 * {@link UpstreamProviderClassifier#isUpstreamPromoted(String)}, the canonical refresh path is
 * {@code UpstreamRefreshService.refreshUpstream("datadog", ...)} →
 * {@link DatadogUpstreamRefreshClient}. {@link #refreshWithUpstreamToken(String)} below remains
 * for the legacy/native fallback path used by {@code AuthorizerService.refreshUpstreamAndGetToken}.
 */
@ApplicationScoped
public class TokenExchangeServiceDatadogImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final URI DATADOG_TOKEN_ENDPOINT =
            URI.create("https://app.datadoghq.com/oauth2/v1/token");
    /** Datadog documents 3,600 s (1 h) for access tokens; used only when the response omits {@code expires_in}. */
    static final long DATADOG_DEFAULT_TOKEN_TTL = 3_600L;

    @ConfigProperty(name = "server.token-exchange.datadog.client-id", defaultValue = "")
    String clientId;

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
            log.warn("Datadog refresh: client_id not configured");
            return null;
        }

        long t0 = System.nanoTime();
        String oauthProvider = OauthProviderLabel.DATADOG;
        String oauthClient = telemetryRequestContext.oauthClient();
        String region = metricsRegionProvider.primaryRegion();
        try {
            String refreshTokenValue = upstreamRefreshToken.trim();

            // Public PKCE client: no ClientAuthentication. The TokenRequest(URI, ClientID,
            // AuthorizationGrant, Scope) overload puts client_id in the form body and sends no
            // Authorization header — exactly what Datadog's token_endpoint_auth_method=none flow
            // requires. Do NOT switch to ClientSecretBasic / ClientSecretPost here: Datadog DCR
            // does not return a client_secret, so any auth mechanism that requires one would
            // start sending bogus / blank credentials and break the upstream call.
            RefreshTokenGrant grant = new RefreshTokenGrant(new RefreshToken(refreshTokenValue));
            TokenRequest tokenRequest = new TokenRequest(
                    DATADOG_TOKEN_ENDPOINT,
                    new ClientID(clientId.trim()),
                    grant,
                    /* scope */ null
            );

            TokenResponse tokenResponse;
            try (var ignored = UpstreamHttpCallLabels.withLabels(
                    OauthProviderLabel.DATADOG, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN)) {
                tokenResponse = tokenClient.execute(tokenRequest);
            }

            if (tokenResponse.indicatesSuccess()) {
                AccessTokenResponse successResponse = tokenResponse.toSuccessResponse();
                AccessToken accessToken = successResponse.getTokens().getAccessToken();
                RefreshToken newRefreshToken = successResponse.getTokens().getRefreshToken();
                Long lifetime = accessToken.getLifetime();
                long ttl = (lifetime != null && lifetime > 0) ? lifetime : DATADOG_DEFAULT_TOKEN_TTL;
                recordDatadogRefresh(t0, oauthProvider, oauthClient, region, true);
                return new TokenWrapper(
                        null,
                        null,
                        null,
                        accessToken.getValue(),
                        // Datadog's RT does not rotate; defensively carry forward the old RT when
                        // the response omits a new one so the L2 row does not get nulled out.
                        newRefreshToken != null ? newRefreshToken.getValue() : refreshTokenValue,
                        ttl
                );
            } else {
                TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                log.error("Datadog refresh failed; upstream response: {}",
                        UpstreamTokenRefreshErrors.formatTokenError(errorResponse));
                recordDatadogRefresh(t0, oauthProvider, oauthClient, region, false);
                return null;
            }
        } catch (Exception e) {
            log.error("Datadog refresh failed (could not complete token request or parse upstream response)", e);
            recordDatadogRefresh(t0, oauthProvider, oauthClient, region, false);
            return null;
        }
    }

    private void recordDatadogRefresh(long startNanos, String oauthProvider, String oauthClient,
                                      String region, boolean success) {
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        oauthProxyMetrics.recordExchangeStep(ExchangeStep.UPSTREAM_REFRESH, oauthProvider, success,
                success ? null : "unauthorized", oauthClient, region, seconds);
    }
}
