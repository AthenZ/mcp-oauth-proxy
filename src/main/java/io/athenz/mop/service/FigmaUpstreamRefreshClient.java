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
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import io.athenz.mop.secret.K8SSecretsProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
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
 * {@link UpstreamRefreshClient} for Figma (L2 promoted).
 *
 * <p>Calls {@code https://api.figma.com/v1/oauth/token} with {@code grant_type=refresh_token}
 * using the {@code figma} OIDC tenant's {@code client_id} / {@code client_secret} (form-post
 * auth, per the verified Figma curl example).
 *
 * <p>Figma access tokens last 90 days ({@code expires_in=7776000}); when the upstream omits
 * {@code expires_in} we fall back to that documented constant. Refresh tokens may rotate; the
 * client carries forward the prior RT when the response omits a new one (defensive — same
 * pattern Slack uses).
 *
 * <p>Error contract follows {@link UpstreamRefreshClient}: {@code invalid_grant} →
 * {@link OktaTokenRevokedException}; everything else → {@link OktaTokenRefreshException}. Reusing
 * the Okta exception types keeps {@link UpstreamRefreshService}'s revoke-on-invalid-grant logic
 * provider-agnostic.
 */
@ApplicationScoped
public class FigmaUpstreamRefreshClient implements UpstreamRefreshClient {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final String FIGMA_TOKEN_URI = "https://api.figma.com/v1/oauth/token";
    /** Documented Figma access-token lifetime (90 d); used only when the upstream omits {@code expires_in}. */
    static final long DEFAULT_EXPIRES_IN_SECONDS = 7_776_000L;

    @ConfigProperty(name = "server.figma.client-id", defaultValue = "")
    String clientId;

    @ConfigProperty(name = "server.figma.client-secret-key", defaultValue = "figma-client-secret")
    String clientSecretKey;

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

    @Inject
    TokenClient tokenClient;

    @Override
    public UpstreamRefreshResponse refresh(String providerUserId, String upstreamRefreshToken) {
        if (upstreamRefreshToken == null || upstreamRefreshToken.isBlank()) {
            throw new OktaTokenRefreshException("Figma upstream refresh token is empty");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new OktaTokenRefreshException(
                    "Figma client_id not configured (quarkus.oidc.figma.client-id)");
        }
        if (clientSecretKey == null || clientSecretKey.isBlank()) {
            throw new OktaTokenRefreshException(
                    "Figma client secret key not configured (quarkus.oidc.figma.credentials.client-secret.provider.key)");
        }
        Map<String, String> credentials = k8SSecretsProvider.getCredentials(null);
        String clientSecret = credentials != null ? credentials.get(clientSecretKey) : null;
        if (clientSecret == null || clientSecret.isEmpty()) {
            throw new OktaTokenRefreshException(
                    "Figma client secret not found (key=" + clientSecretKey + ")");
        }
        String trimmedRt = upstreamRefreshToken.trim();
        try {
            URI tokenEndpoint = URI.create(FIGMA_TOKEN_URI);
            ClientAuthentication clientAuth = new ClientSecretPost(
                    new ClientID(clientId.trim()),
                    new Secret(clientSecret.trim())
            );
            AuthorizationGrant refreshGrant = new RefreshTokenGrant(new RefreshToken(trimmedRt));
            TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, refreshGrant);
            TokenResponse tokenResponse;
            try (var ignored = UpstreamHttpCallLabels.withLabels(
                    OauthProviderLabel.FIGMA, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN)) {
                tokenResponse = tokenClient.execute(tokenRequest);
            }
            if (tokenResponse.indicatesSuccess()) {
                AccessTokenResponse success = tokenResponse.toSuccessResponse();
                String newAccessToken = success.getTokens().getAccessToken().getValue();
                RefreshToken newRefreshToken = success.getTokens().getRefreshToken();
                Long lifetime = success.getTokens().getAccessToken().getLifetime();
                long expiresIn = lifetime != null && lifetime > 0L ? lifetime : DEFAULT_EXPIRES_IN_SECONDS;
                String rotatedRt = newRefreshToken != null ? newRefreshToken.getValue() : trimmedRt;
                Object scopeObj = success.getCustomParameters() != null
                        ? success.getCustomParameters().get("scope") : null;
                String scope = scopeObj != null ? scopeObj.toString() : null;
                return new UpstreamRefreshResponse(newAccessToken, rotatedRt, /* idToken */ null,
                        expiresIn, scope);
            }
            TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            String body = UpstreamTokenRefreshErrors.formatTokenError(errorResponse);
            log.error("Figma refresh failed for provider_user_id={} upstream response: {}",
                    providerUserId, body);
            String code = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getCode() : "unknown";
            String desc = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getDescription() : "unknown";
            if ("invalid_grant".equals(code)) {
                throw new OktaTokenRevokedException("Figma refresh token invalid or revoked: " + desc);
            }
            throw new OktaTokenRefreshException("Figma token refresh failed: " + code + " - " + desc);
        } catch (OktaTokenRevokedException | OktaTokenRefreshException e) {
            throw e;
        } catch (Exception e) {
            log.error("Figma refresh failed for provider_user_id={} (could not complete token request or parse upstream response)",
                    providerUserId, e);
            throw new OktaTokenRefreshException("Figma token refresh failed: " + e.getMessage(), e);
        }
    }
}
