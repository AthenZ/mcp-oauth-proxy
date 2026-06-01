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
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
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
 * {@link UpstreamRefreshClient} for WisdomAI (Descope-backed, L2 promoted).
 *
 * <p>Calls {@code https://api.descope.com/oauth2/v1/apps/token} with
 * {@code grant_type=refresh_token} as a confidential client. Although Descope DCR registers the
 * app as public, Descope's token endpoint requires a client_secret on refresh
 * ({@code errorCode=E011002 "missing secret"}); operators populate the secret in the K8s secret
 * store under {@link K8SSecretsProvider#SECRET_DATA_KEY_WISDOMAI_CLIENT_SECRET}.
 *
 * <p>Auth method handling: we attempt {@code client_secret_post} (form body) first because
 * Descope's docs/examples lean toward it. If Descope responds with an
 * {@code invalid_client}-shaped error we retry once with {@code client_secret_basic} (HTTP Basic)
 * to cover deployments that prefer that mechanism. The retry is one-shot and only on
 * {@code invalid_client} so a real {@code invalid_grant}/server error is not masked.
 *
 * <p>WisdomAI access tokens last 7 days ({@code expires_in=604800}). When the upstream omits
 * {@code expires_in} we fall back to that documented constant. The Descope refresh token JWT
 * carries {@code rexp} ~10y; the L2 row TTL is capped at 6 months via
 * {@code server.upstream-token.expiry-seconds-by-provider.wisdomai} so row sprawl is bounded.
 *
 * <p>Refresh-token rotation is unknown for Descope refresh apps. We persist the response RT
 * verbatim when present and defensively carry forward the prior RT only if the response
 * (anomalously) omits one — same defensive pattern as Linear/Oracle EPM.
 *
 * <p>Error contract follows {@link UpstreamRefreshClient}: {@code invalid_grant} -&gt;
 * {@link OktaTokenRevokedException}; everything else -&gt; {@link OktaTokenRefreshException}.
 */
@ApplicationScoped
public class WisdomAiUpstreamRefreshClient implements UpstreamRefreshClient {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final String WISDOMAI_TOKEN_URI = "https://api.descope.com/oauth2/v1/apps/token";
    /** Documented WisdomAI access-token lifetime ({@code expires_in=604800} ~7 days). */
    static final long DEFAULT_EXPIRES_IN_SECONDS = 604_800L;

    @ConfigProperty(name = "server.token-exchange.wisdomai.client-id", defaultValue = "")
    String clientId;

    @ConfigProperty(name = "server.token-exchange.wisdomai.client-secret-key",
            defaultValue = "wisdomai-client-secret")
    String clientSecretKey;

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

    @Inject
    TokenClient tokenClient;

    @Override
    public UpstreamRefreshResponse refresh(String providerUserId, String upstreamRefreshToken) {
        if (upstreamRefreshToken == null || upstreamRefreshToken.isBlank()) {
            throw new OktaTokenRefreshException("WisdomAI upstream refresh token is empty");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new OktaTokenRefreshException(
                    "WisdomAI client_id not configured (server.token-exchange.wisdomai.client-id)");
        }
        if (clientSecretKey == null || clientSecretKey.isBlank()) {
            throw new OktaTokenRefreshException(
                    "WisdomAI client secret key not configured (server.token-exchange.wisdomai.client-secret-key)");
        }
        Map<String, String> credentials = k8SSecretsProvider.getCredentials(null);
        String clientSecret = credentials != null ? credentials.get(clientSecretKey) : null;
        if (clientSecret == null || clientSecret.isEmpty()) {
            throw new OktaTokenRefreshException(
                    "WisdomAI client secret not found (key=" + clientSecretKey + ")");
        }

        String trimmedRt = upstreamRefreshToken.trim();
        URI tokenEndpoint = URI.create(WISDOMAI_TOKEN_URI);
        ClientID cid = new ClientID(clientId.trim());
        Secret secret = new Secret(clientSecret.trim());

        // Attempt client_secret_post first. If Descope returns an invalid_client-shaped error,
        // retry once with client_secret_basic. Anything else (invalid_grant, server_error, IO
        // failures) bubbles up unchanged from the first attempt.
        try {
            return executeRefresh(providerUserId, tokenEndpoint, trimmedRt,
                    new ClientSecretPost(cid, secret), "client_secret_post");
        } catch (OktaTokenRefreshException e) {
            if (!isInvalidClientError(e)) {
                throw e;
            }
            log.warn("WisdomAI refresh: client_secret_post rejected with invalid_client; retrying with client_secret_basic");
            return executeRefresh(providerUserId, tokenEndpoint, trimmedRt,
                    new ClientSecretBasic(cid, secret), "client_secret_basic");
        }
    }

    private UpstreamRefreshResponse executeRefresh(String providerUserId,
                                                   URI tokenEndpoint,
                                                   String trimmedRt,
                                                   ClientAuthentication clientAuth,
                                                   String authMethodLabel) {
        try {
            AuthorizationGrant refreshGrant = new RefreshTokenGrant(new RefreshToken(trimmedRt));
            TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, refreshGrant);
            TokenResponse tokenResponse;
            try (var ignored = UpstreamHttpCallLabels.withLabels(
                    OauthProviderLabel.WISDOMAI, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN)) {
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
            log.error("WisdomAI refresh failed for provider_user_id={} auth={} upstream response: {}",
                    providerUserId, authMethodLabel, body);
            String code = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getCode() : "unknown";
            String desc = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getDescription() : "unknown";
            // Descope returns non-RFC6749 error bodies of the shape:
            //   {"errorCode":"E0XXXXX","errorMessage":"...","errorDescription":"..."}
            // Nimbus parses those as code/desc=null (since the JSON keys are non-standard). Map
            // the known refresh-token-binding errors to OktaTokenRevokedException so MoP marks
            // the L2 row revoked and forces a re-login. Without this branch the user gets a
            // generic refresh failure and the broken L2 row sticks around. Codes covered:
            //   E061004 - "azp in the refresh token is invalid"        (client_id mismatch)
            //   E011002 - "missing secret"                              (only seen when secret
            //             is dropped after rotation; safe to revoke and re-consent)
            String descopeErrorCode = extractDescopeErrorCode(body);
            if (isDescopeRevokeWorthy(descopeErrorCode)) {
                throw new OktaTokenRevokedException(
                        "WisdomAI refresh token rejected by Descope (errorCode=" + descopeErrorCode
                                + "): user must re-consent. body=" + body);
            }
            if ("invalid_grant".equals(code)) {
                throw new OktaTokenRevokedException("WisdomAI refresh token invalid or revoked: " + desc);
            }
            throw new OktaTokenRefreshException("WisdomAI token refresh failed: " + code + " - " + desc);
        } catch (OktaTokenRevokedException | OktaTokenRefreshException e) {
            throw e;
        } catch (Exception e) {
            log.error("WisdomAI refresh failed for provider_user_id={} auth={} (could not complete token request or parse upstream response)",
                    providerUserId, authMethodLabel, e);
            throw new OktaTokenRefreshException("WisdomAI token refresh failed: " + e.getMessage(), e);
        }
    }

    /**
     * Returns true when the exception message indicates {@code invalid_client} (the error code
     * Descope returns for an unaccepted client-auth method or a missing/wrong secret). The
     * message is built in {@link #executeRefresh} as {@code "WisdomAI token refresh failed: <code>
     * - <desc>"}, so a string-match on the code is stable.
     */
    private static boolean isInvalidClientError(OktaTokenRefreshException e) {
        String msg = e.getMessage();
        return msg != null && msg.contains("invalid_client");
    }

    /**
     * Pulls the Descope-style {@code "errorCode":"E0XXXXX"} from a raw JSON error body. Returns
     * {@code null} when the body does not match Descope's shape (e.g. when it is a normal
     * RFC 6749 error response). Intentionally lightweight — we only need the code; full body is
     * already in {@code body} for logging.
     */
    static String extractDescopeErrorCode(String body) {
        if (body == null) {
            return null;
        }
        int idx = body.indexOf("\"errorCode\"");
        if (idx < 0) {
            return null;
        }
        int colon = body.indexOf(':', idx);
        if (colon < 0) {
            return null;
        }
        int firstQuote = body.indexOf('"', colon + 1);
        if (firstQuote < 0) {
            return null;
        }
        int secondQuote = body.indexOf('"', firstQuote + 1);
        if (secondQuote < 0) {
            return null;
        }
        return body.substring(firstQuote + 1, secondQuote);
    }

    /**
     * Returns true for Descope error codes that indicate the stored refresh token is no longer
     * usable for this client and the user must re-consent (mapped to
     * {@link OktaTokenRevokedException} so {@link UpstreamRefreshService} clears the L2 row).
     * Conservative on purpose — only codes whose semantics map cleanly to "RT cannot be used by
     * this client anymore" are listed here. Transient errors (server_error, network) keep
     * {@link OktaTokenRefreshException}.
     */
    static boolean isDescopeRevokeWorthy(String descopeErrorCode) {
        if (descopeErrorCode == null) {
            return false;
        }
        switch (descopeErrorCode) {
            case "E061004": // "azp in the refresh token is invalid" -- RT bound to a different client
            case "E061003": // refresh token revoked / not found
            case "E061002": // refresh token expired
                return true;
            default:
                return false;
        }
    }
}
