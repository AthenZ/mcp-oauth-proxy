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
 * {@link UpstreamRefreshClient} for Google Workspace providers.
 *
 * <p>Calls {@code https://oauth2.googleapis.com/token} with {@code grant_type=refresh_token}
 * using the shared MoP Google OAuth web-app client (one client_id, one secret) regardless of
 * which Google Workspace product the call is for. Provider name is part of {@code providerUserId}
 * and used only for telemetry labels — the protocol shape is identical across all 12 providers.
 *
 * <p>Mirrors the HTTP / parsing logic that previously lived in
 * {@code TokenExchangeServiceGoogleWorkspaceBase.refreshWithUpstreamToken}; that path is kept
 * for the rare non-promoted provider but for promoted providers the call is now routed through
 * {@link UpstreamRefreshService} (which holds the L2 lock and writes back to L2).
 *
 * <p>Error contract:
 * <ul>
 *   <li>{@code invalid_grant} → {@link OktaTokenRevokedException}. Reusing the Okta exception
 *       type keeps {@link UpstreamRefreshService}'s revoke-on-invalid-grant logic provider-
 *       agnostic with no further plumbing.</li>
 *   <li>Any other upstream error → {@link OktaTokenRefreshException}. The service maps these
 *       to a non-revoking 503-style failure to the MCP client.</li>
 *   <li>Network / parse / config failures → {@link OktaTokenRefreshException}.</li>
 * </ul>
 */
@ApplicationScoped
public class GoogleWorkspaceUpstreamRefreshClient implements UpstreamRefreshClient {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final String GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token";
    private static final long DEFAULT_EXPIRES_IN_SECONDS = 3600L;

    @ConfigProperty(name = "server.token-exchange.google-workspace.client-id", defaultValue = "")
    String clientId;

    @ConfigProperty(name = "server.token-exchange.google-workspace.client-secret-key", defaultValue = "")
    String clientSecretKey;

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

    @Inject
    TokenClient tokenClient;

    @Override
    public UpstreamRefreshResponse refresh(String providerUserId, String upstreamRefreshToken) {
        if (upstreamRefreshToken == null || upstreamRefreshToken.isBlank()) {
            throw new OktaTokenRefreshException("Google upstream refresh token is empty");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new OktaTokenRefreshException(
                    "Google client_id not configured (server.token-exchange.google-workspace.client-id)");
        }
        if (clientSecretKey == null || clientSecretKey.isBlank()) {
            throw new OktaTokenRefreshException(
                    "Google client secret key not configured (server.token-exchange.google-workspace.client-secret-key)");
        }
        Map<String, String> credentials = k8SSecretsProvider.getCredentials(null);
        String clientSecret = credentials != null ? credentials.get(clientSecretKey) : null;
        if (clientSecret == null || clientSecret.isEmpty()) {
            throw new OktaTokenRefreshException(
                    "Google client secret not found (key=" + clientSecretKey + ")");
        }
        String trimmedRt = upstreamRefreshToken.trim();
        String providerLabel = providerUserId != null ? providerLabelOf(providerUserId) : "google";
        try {
            URI tokenEndpoint = URI.create(GOOGLE_TOKEN_URI);
            ClientAuthentication clientAuth = new ClientSecretPost(
                    new ClientID(clientId.trim()),
                    new Secret(clientSecret.trim())
            );
            AuthorizationGrant refreshGrant = new RefreshTokenGrant(new RefreshToken(trimmedRt));
            TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, refreshGrant);
            TokenResponse tokenResponse;
            try (var ignored = UpstreamHttpCallLabels.withLabels(
                    providerLabel, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN)) {
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
            log.error("Google refresh failed for provider_user_id={} upstream response: {}",
                    providerUserId, body);
            String code = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getCode() : "unknown";
            String desc = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getDescription() : "unknown";
            if ("invalid_grant".equals(code)) {
                throw new OktaTokenRevokedException("Google refresh token invalid or revoked: " + desc);
            }
            throw new OktaTokenRefreshException("Google token refresh failed: " + code + " - " + desc);
        } catch (OktaTokenRevokedException | OktaTokenRefreshException e) {
            throw e;
        } catch (Exception e) {
            log.error("Google refresh failed for provider_user_id={} (could not complete token request or parse upstream response)",
                    providerUserId, e);
            throw new OktaTokenRefreshException("Google token refresh failed: " + e.getMessage(), e);
        }
    }

    /**
     * Extract the {@code <provider>} portion of a {@code provider#sub} key for telemetry labels.
     * Bad inputs fall back to {@code "google"} so we never throw out of a label resolution.
     */
    private static String providerLabelOf(String providerUserId) {
        if (providerUserId == null || providerUserId.isEmpty()) {
            return "google";
        }
        int idx = providerUserId.indexOf('#');
        if (idx <= 0) {
            return "google";
        }
        return providerUserId.substring(0, idx);
    }
}
