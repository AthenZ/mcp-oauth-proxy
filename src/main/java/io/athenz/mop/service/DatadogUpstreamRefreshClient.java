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
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.UpstreamHttpCallLabels;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link UpstreamRefreshClient} for Datadog (L2 promoted).
 *
 * <p>Calls {@code https://mcp.datadoghq.com/api/unstable/mcp-server/token} with
 * {@code grant_type=refresh_token} as a public PKCE client: the request body carries
 * {@code client_id} only and there is no {@code Authorization} header. Datadog DCR returns no
 * {@code client_secret} ({@code token_endpoint_auth_method=none}); injecting any client-secret
 * machinery here would break the upstream call.
 *
 * <p>Datadog access tokens last 1 hour ({@code expires_in=3600}); when the upstream omits
 * {@code expires_in} we fall back to that documented constant. Refresh tokens do <strong>not</strong>
 * rotate; the client carries forward the prior RT verbatim when the response omits a new one
 * (defensive — same pattern Figma / Slack use).
 *
 * <p>Error contract follows {@link UpstreamRefreshClient}: {@code invalid_grant} →
 * {@link OktaTokenRevokedException}; everything else → {@link OktaTokenRefreshException}. Reusing
 * the Okta exception types keeps {@link UpstreamRefreshService}'s revoke-on-invalid-grant logic
 * provider-agnostic.
 */
@ApplicationScoped
public class DatadogUpstreamRefreshClient implements UpstreamRefreshClient {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final String DATADOG_TOKEN_URI =
            "https://mcp.datadoghq.com/api/unstable/mcp-server/token";
    /** Documented Datadog access-token lifetime (1 h); used only when the upstream omits {@code expires_in}. */
    static final long DEFAULT_EXPIRES_IN_SECONDS = 3_600L;

    @ConfigProperty(name = "server.token-exchange.datadog.client-id", defaultValue = "")
    String clientId;

    @Inject
    TokenClient tokenClient;

    @Override
    public UpstreamRefreshResponse refresh(String providerUserId, String upstreamRefreshToken) {
        if (upstreamRefreshToken == null || upstreamRefreshToken.isBlank()) {
            throw new OktaTokenRefreshException("Datadog upstream refresh token is empty");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new OktaTokenRefreshException(
                    "Datadog client_id not configured (server.token-exchange.datadog.client-id)");
        }
        String trimmedRt = upstreamRefreshToken.trim();
        try {
            URI tokenEndpoint = URI.create(DATADOG_TOKEN_URI);
            AuthorizationGrant refreshGrant = new RefreshTokenGrant(new RefreshToken(trimmedRt));
            // Public PKCE client: TokenRequest(URI, ClientID, AuthorizationGrant, Scope) puts
            // client_id in the form body and sends NO Authorization header. Do NOT introduce
            // ClientSecretBasic / ClientSecretPost — Datadog DCR does not return a client_secret
            // and any auth mechanism that requires one would silently break refresh.
            TokenRequest tokenRequest = new TokenRequest(
                    tokenEndpoint,
                    new ClientID(clientId.trim()),
                    refreshGrant,
                    /* scope */ null);
            TokenResponse tokenResponse;
            try (var ignored = UpstreamHttpCallLabels.withLabels(
                    OauthProviderLabel.DATADOG, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN)) {
                tokenResponse = tokenClient.execute(tokenRequest);
            }
            if (tokenResponse.indicatesSuccess()) {
                AccessTokenResponse success = tokenResponse.toSuccessResponse();
                String newAccessToken = success.getTokens().getAccessToken().getValue();
                RefreshToken newRefreshToken = success.getTokens().getRefreshToken();
                Long lifetime = success.getTokens().getAccessToken().getLifetime();
                long expiresIn = lifetime != null && lifetime > 0L ? lifetime : DEFAULT_EXPIRES_IN_SECONDS;
                // Datadog does not rotate the RT — carry forward the prior RT when the response
                // omits a new one so the L2 row's encrypted_upstream_refresh_token is not nulled.
                String rotatedRt = newRefreshToken != null ? newRefreshToken.getValue() : trimmedRt;
                Object scopeObj = success.getCustomParameters() != null
                        ? success.getCustomParameters().get("scope") : null;
                String scope = scopeObj != null ? scopeObj.toString() : null;
                return new UpstreamRefreshResponse(newAccessToken, rotatedRt, /* idToken */ null,
                        expiresIn, scope);
            }
            TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            String body = UpstreamTokenRefreshErrors.formatTokenError(errorResponse);
            log.error("Datadog refresh failed for provider_user_id={} upstream response: {}",
                    providerUserId, body);
            String code = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getCode() : "unknown";
            String desc = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getDescription() : "unknown";
            if ("invalid_grant".equals(code)) {
                throw new OktaTokenRevokedException("Datadog refresh token invalid or revoked: " + desc);
            }
            throw new OktaTokenRefreshException("Datadog token refresh failed: " + code + " - " + desc);
        } catch (OktaTokenRevokedException | OktaTokenRefreshException e) {
            throw e;
        } catch (Exception e) {
            log.error("Datadog refresh failed for provider_user_id={} (could not complete token request or parse upstream response)",
                    providerUserId, e);
            throw new OktaTokenRefreshException("Datadog token refresh failed: " + e.getMessage(), e);
        }
    }
}
