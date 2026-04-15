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
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.secret.K8SSecretsProvider;
import io.athenz.mop.telemetry.ExchangeStep;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryProviderResolver;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import io.athenz.mop.telemetry.UpstreamHttpCallLabels;
import jakarta.inject.Inject;
import java.net.URI;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shared token exchange logic for all Google Workspace services (Drive, Docs, Sheets, etc.).
 * All Google Workspace services share the same Google OAuth app (client-id and secret) and use the
 * same token endpoint. The provider label is set by the producer at init time for telemetry.
 */
public abstract class TokenExchangeServiceGoogleWorkspaceBase implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(TokenExchangeServiceGoogleWorkspaceBase.class);
    private static final String GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token";

    @ConfigProperty(name = "server.token-exchange.google-workspace.client-id", defaultValue = "")
    String clientId;

    @ConfigProperty(name = "server.token-exchange.google-workspace.client-secret-key", defaultValue = "")
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

    private String providerLabel;

    public void setProviderLabel(String providerLabel) {
        this.providerLabel = providerLabel;
    }

    public String getProviderLabel() {
        return providerLabel;
    }

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
        String providerLabel = getProviderLabel();
        if (upstreamRefreshToken == null || upstreamRefreshToken.isEmpty()) {
            return null;
        }
        String refreshTokenValue = upstreamRefreshToken.trim();
        if (refreshTokenValue.isEmpty()) {
            return null;
        }
        if (clientId == null || clientId.isBlank()) {
            log.warn("{} refresh: client_id not configured (server.token-exchange.google-workspace.client-id)", providerLabel);
            return null;
        }
        if (clientSecretKey == null || clientSecretKey.isBlank()) {
            log.warn("{} refresh: client secret key not configured (server.token-exchange.google-workspace.client-secret-key)", providerLabel);
            return null;
        }
        Map<String, String> credentials = k8SSecretsProvider.getCredentials(null);
        String clientSecret = credentials != null ? credentials.get(clientSecretKey) : null;
        if (clientSecret == null || clientSecret.isEmpty()) {
            log.warn("{} refresh: client secret not found (key={})", providerLabel, clientSecretKey);
            return null;
        }
        long t0 = System.nanoTime();
        String oauthClient = telemetryRequestContext.oauthClient();
        String region = metricsRegionProvider.primaryRegion();
        try {
            URI tokenEndpoint = URI.create(GOOGLE_TOKEN_URI);
            ClientAuthentication clientAuth = new ClientSecretPost(
                    new ClientID(clientId.trim()),
                    new com.nimbusds.oauth2.sdk.auth.Secret(clientSecret.trim())
            );
            AuthorizationGrant refreshGrant = new RefreshTokenGrant(new RefreshToken(refreshTokenValue));
            TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, refreshGrant);
            TokenResponse tokenResponse;
            try (var ignored = UpstreamHttpCallLabels.withLabels(
                    providerLabel, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN)) {
                tokenResponse = tokenClient.execute(tokenRequest);
            }
            if (tokenResponse.indicatesSuccess()) {
                AccessTokenResponse successResponse = tokenResponse.toSuccessResponse();
                String newAccessToken = successResponse.getTokens().getAccessToken().getValue();
                com.nimbusds.oauth2.sdk.token.RefreshToken newRefreshToken = successResponse.getTokens().getRefreshToken();
                Long lifetime = successResponse.getTokens().getAccessToken().getLifetime();
                long ttl = (lifetime != null) ? lifetime : 3600L;
                recordRefresh(t0, providerLabel, oauthClient, region, true);
                return new TokenWrapper(
                        null,
                        null,
                        null,
                        newAccessToken,
                        newRefreshToken != null ? newRefreshToken.getValue() : refreshTokenValue,
                        ttl
                );
            } else {
                TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                log.error("{} refresh failed; upstream response: {}", providerLabel, UpstreamTokenRefreshErrors.formatTokenError(errorResponse));
                recordRefresh(t0, providerLabel, oauthClient, region, false);
                return null;
            }
        } catch (Exception e) {
            log.error("{} refresh failed (could not complete token request or parse upstream response)", providerLabel, e);
            recordRefresh(t0, providerLabel, oauthClient, region, false);
            return null;
        }
    }

    private void recordRefresh(long startNanos, String oauthProvider, String oauthClient, String region, boolean success) {
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        oauthProxyMetrics.recordExchangeStep(ExchangeStep.UPSTREAM_REFRESH, oauthProvider, success,
                success ? null : "unauthorized", oauthClient, region, seconds);
    }
}
