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
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
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
 * Performs the Figma OAuth 2.0 authorization-code-with-PKCE exchange against
 * {@code POST https://api.figma.com/v1/oauth/token}.
 *
 * <p>This client is the upstream-side of the custom Figma flow that lives entirely outside
 * Quarkus OIDC (see {@link io.athenz.mop.resource.FigmaResource} for why). The protocol shape
 * is identical to the verified curl example in the Figma integration plan:
 * <pre>
 *   POST https://api.figma.com/v1/oauth/token
 *   Content-Type: application/x-www-form-urlencoded
 *
 *   grant_type=authorization_code
 *   client_id=ya3TXRUOYz3n5mypao2BSz
 *   client_secret=&lt;figma-client-secret&gt;
 *   code=&lt;authz code&gt;
 *   redirect_uri=https://&lt;mop-host&gt;/figma/authorize/callback
 *   code_verifier=&lt;code_verifier&gt;
 * </pre>
 *
 * <p>Returns a {@link FigmaTokens} carrying the 90-day {@code access_token}, the
 * {@code refresh_token}, and the upstream {@code expires_in}. Failures throw
 * {@link FigmaCodeExchangeException}; the caller maps that to a 5xx callback response.
 */
@ApplicationScoped
public class FigmaCodeExchangeClient {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    static final URI FIGMA_TOKEN_ENDPOINT = URI.create("https://api.figma.com/v1/oauth/token");
    /** Figma documents 90-day access tokens; used only when the upstream omits {@code expires_in}. */
    static final long DEFAULT_EXPIRES_IN_SECONDS = 7_776_000L;

    @ConfigProperty(name = "server.figma.client-id", defaultValue = "")
    String clientId;

    @ConfigProperty(name = "server.figma.client-secret-key", defaultValue = "figma-client-secret")
    String clientSecretKey;

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

    @Inject
    TokenClient tokenClient;

    /**
     * Exchanges an authorization code (returned by Figma to {@code /figma/authorize/callback})
     * for the upstream token set.
     *
     * @param code         the authorization code value Figma returned in the callback URL.
     * @param redirectUri  the redirect URI we sent on the original authorize request — Figma
     *                     requires the same value on the token call (RFC 6749 § 4.1.3).
     * @param codeVerifier the PKCE {@code code_verifier} matching the {@code code_challenge} we
     *                     sent on authorize.
     * @throws FigmaCodeExchangeException on any config/transport/upstream-error failure.
     */
    public FigmaTokens exchange(String code, String redirectUri, String codeVerifier) {
        if (code == null || code.isBlank()) {
            throw new FigmaCodeExchangeException("authorization code is empty");
        }
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new FigmaCodeExchangeException("redirect_uri is empty");
        }
        if (codeVerifier == null || codeVerifier.isBlank()) {
            throw new FigmaCodeExchangeException("code_verifier is empty");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new FigmaCodeExchangeException(
                    "Figma client_id not configured (quarkus.oidc.figma.client-id)");
        }
        if (clientSecretKey == null || clientSecretKey.isBlank()) {
            throw new FigmaCodeExchangeException(
                    "Figma client secret key not configured (quarkus.oidc.figma.credentials.client-secret.provider.key)");
        }
        Map<String, String> credentials = k8SSecretsProvider.getCredentials(null);
        String clientSecret = credentials != null ? credentials.get(clientSecretKey) : null;
        if (clientSecret == null || clientSecret.isEmpty()) {
            throw new FigmaCodeExchangeException(
                    "Figma client secret not found (key=" + clientSecretKey + ")");
        }
        try {
            ClientAuthentication clientAuth = new ClientSecretPost(
                    new ClientID(clientId.trim()),
                    new Secret(clientSecret.trim())
            );
            AuthorizationGrant grant = new AuthorizationCodeGrant(
                    new AuthorizationCode(code),
                    URI.create(redirectUri),
                    new CodeVerifier(codeVerifier)
            );
            TokenRequest tokenRequest = new TokenRequest(FIGMA_TOKEN_ENDPOINT, clientAuth, grant);
            TokenResponse tokenResponse;
            try (var ignored = UpstreamHttpCallLabels.withLabels(
                    OauthProviderLabel.FIGMA, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN)) {
                tokenResponse = tokenClient.execute(tokenRequest);
            }
            if (tokenResponse.indicatesSuccess()) {
                AccessTokenResponse success = tokenResponse.toSuccessResponse();
                String accessToken = success.getTokens().getAccessToken().getValue();
                RefreshToken rt = success.getTokens().getRefreshToken();
                String refreshToken = rt != null ? rt.getValue() : null;
                Long lifetime = success.getTokens().getAccessToken().getLifetime();
                long expiresIn = lifetime != null && lifetime > 0L ? lifetime : DEFAULT_EXPIRES_IN_SECONDS;
                if (refreshToken == null || refreshToken.isEmpty()) {
                    // Figma's documented response always includes a refresh token; treat absence
                    // as an upstream protocol error rather than silently storing a half-record.
                    throw new FigmaCodeExchangeException(
                            "Figma /v1/oauth/token success response did not include a refresh_token");
                }
                return new FigmaTokens(accessToken, refreshToken, expiresIn);
            }
            TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            String body = UpstreamTokenRefreshErrors.formatTokenError(errorResponse);
            log.error("Figma authorization-code exchange failed; upstream response: {}", body);
            String errorCode = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getCode() : "unknown";
            String errorDesc = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getDescription() : "unknown";
            throw new FigmaCodeExchangeException(
                    "Figma authorization-code exchange failed: " + errorCode + " - " + errorDesc);
        } catch (FigmaCodeExchangeException e) {
            throw e;
        } catch (Exception e) {
            log.error("Figma authorization-code exchange failed (could not complete token request or parse upstream response)", e);
            throw new FigmaCodeExchangeException(
                    "Figma authorization-code exchange failed: " + e.getMessage(), e);
        }
    }

    /** The subset of the Figma token response we persist. */
    public record FigmaTokens(String accessToken, String refreshToken, long expiresInSeconds) {
    }

    /** Thrown for any failure during the Figma code exchange; callers map to a 5xx callback response. */
    public static class FigmaCodeExchangeException extends RuntimeException {
        public FigmaCodeExchangeException(String message) {
            super(message);
        }

        public FigmaCodeExchangeException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
