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
 * {@link UpstreamRefreshClient} for Linear (L2 promoted).
 *
 * <p>Calls {@code https://api.linear.app/oauth/token} with {@code grant_type=refresh_token} as a
 * public PKCE client today: the request body carries {@code client_id} only and there is no
 * {@code Authorization} header. Linear DCR currently registers public clients
 * ({@code token_endpoint_auth_method=none}); injecting any client-secret machinery here would
 * break the upstream call.
 *
 * <p>Linear access tokens last ~24 hours ({@code expires_in=86399}). When the upstream omits
 * {@code expires_in} we fall back to that documented constant.
 *
 * <p>Linear <strong>rotates</strong> the refresh token on every successful refresh and offers a
 * documented 30-minute replay-grace window: if MoP loses the response (network failure between
 * Linear and MoP) and replays the original {@code refresh_token} request within 30 min, Linear
 * returns the same new RT so the client converges. The replay grace is server-side at Linear and
 * transparent to MoP — we always persist the response RT verbatim. Defensive carry-forward of
 * the prior RT is kept as a safety net only for the (anomalous) case where the response is HTTP
 * 200 but contains no new refresh_token.
 *
 * <p>Error contract follows {@link UpstreamRefreshClient}: {@code invalid_grant} -&gt;
 * {@link OktaTokenRevokedException}; everything else -&gt; {@link OktaTokenRefreshException}. Reusing
 * the Okta exception types keeps {@link UpstreamRefreshService}'s revoke-on-invalid-grant logic
 * provider-agnostic.
 *
 * <p>TODO(linear-confidential): if Linear later issues a {@code client_secret}, populate
 * {@code server.token-exchange.linear.client-secret-key} and switch to
 * {@code ClientSecretBasic} via {@link io.athenz.mop.secret.K8SSecretsProvider} (mirror Figma's
 * pattern). The branch is intentionally inert today so a future regression that wires up a
 * secret without test coverage breaks loudly (see the public-client header assertions in
 * {@code LinearUpstreamRefreshClientTest}).
 */
@ApplicationScoped
public class LinearUpstreamRefreshClient implements UpstreamRefreshClient {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final String LINEAR_TOKEN_URI = "https://api.linear.app/oauth/token";
    /** Documented Linear access-token lifetime ({@code expires_in=86399} ~24 h). */
    static final long DEFAULT_EXPIRES_IN_SECONDS = 86_399L;

    @ConfigProperty(name = "server.token-exchange.linear.client-id", defaultValue = "")
    String clientId;

    /**
     * Reserved for future confidential-client rollout. Empty today (public PKCE). When populated,
     * this client should switch to {@code ClientSecretBasic} via {@code K8SSecretsProvider}; the
     * actual wiring is gated behind {@code TODO(linear-confidential)} above.
     */
    @ConfigProperty(name = "server.token-exchange.linear.client-secret-key", defaultValue = "")
    String clientSecretKey;

    @Inject
    TokenClient tokenClient;

    @Override
    public UpstreamRefreshResponse refresh(String providerUserId, String upstreamRefreshToken) {
        if (upstreamRefreshToken == null || upstreamRefreshToken.isBlank()) {
            throw new OktaTokenRefreshException("Linear upstream refresh token is empty");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new OktaTokenRefreshException(
                    "Linear client_id not configured (server.token-exchange.linear.client-id)");
        }
        String trimmedRt = upstreamRefreshToken.trim();
        try {
            URI tokenEndpoint = URI.create(LINEAR_TOKEN_URI);
            AuthorizationGrant refreshGrant = new RefreshTokenGrant(new RefreshToken(trimmedRt));
            // Public PKCE client: TokenRequest(URI, ClientID, AuthorizationGrant, Scope) puts
            // client_id in the form body and sends NO Authorization header. Do NOT introduce
            // ClientSecretBasic / ClientSecretPost — Linear DCR does not return a client_secret
            // and any auth mechanism that requires one would silently break refresh.
            TokenRequest tokenRequest = new TokenRequest(
                    tokenEndpoint,
                    new ClientID(clientId.trim()),
                    refreshGrant,
                    /* scope */ null);
            TokenResponse tokenResponse;
            try (var ignored = UpstreamHttpCallLabels.withLabels(
                    OauthProviderLabel.LINEAR, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN)) {
                tokenResponse = tokenClient.execute(tokenRequest);
            }
            if (tokenResponse.indicatesSuccess()) {
                AccessTokenResponse success = tokenResponse.toSuccessResponse();
                String newAccessToken = success.getTokens().getAccessToken().getValue();
                RefreshToken newRefreshToken = success.getTokens().getRefreshToken();
                Long lifetime = success.getTokens().getAccessToken().getLifetime();
                long expiresIn = lifetime != null && lifetime > 0L ? lifetime : DEFAULT_EXPIRES_IN_SECONDS;
                // Linear rotates the RT each refresh; persist the response RT verbatim. Carry
                // forward the prior RT only if the response (anomalously) omits one so the L2
                // row's encrypted_upstream_refresh_token is not nulled out.
                String rotatedRt = newRefreshToken != null ? newRefreshToken.getValue() : trimmedRt;
                Object scopeObj = success.getCustomParameters() != null
                        ? success.getCustomParameters().get("scope") : null;
                String scope = scopeObj != null ? scopeObj.toString() : null;
                return new UpstreamRefreshResponse(newAccessToken, rotatedRt, /* idToken */ null,
                        expiresIn, scope);
            }
            TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            String body = UpstreamTokenRefreshErrors.formatTokenError(errorResponse);
            log.error("Linear refresh failed for provider_user_id={} upstream response: {}",
                    providerUserId, body);
            String code = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getCode() : "unknown";
            String desc = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getDescription() : "unknown";
            if ("invalid_grant".equals(code)) {
                throw new OktaTokenRevokedException("Linear refresh token invalid or revoked: " + desc);
            }
            throw new OktaTokenRefreshException("Linear token refresh failed: " + code + " - " + desc);
        } catch (OktaTokenRevokedException | OktaTokenRefreshException e) {
            throw e;
        } catch (Exception e) {
            log.error("Linear refresh failed for provider_user_id={} (could not complete token request or parse upstream response)",
                    providerUserId, e);
            throw new OktaTokenRefreshException("Linear token refresh failed: " + e.getMessage(), e);
        }
    }
}
