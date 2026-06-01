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
 * {@link UpstreamRefreshClient} for Oracle EPM (Oracle IDCS, L2 promoted).
 *
 * <p>Calls {@code https://idcs-c0b7a2ce098d48a0a78b94a30f9e42a1.identity.oraclecloud.com/oauth2/v1/token}
 * with {@code grant_type=refresh_token} as a confidential client using {@code client_secret_post}
 * (form-body auth, matches Oracle's verified curl examples). The K8s secret store provides the
 * {@code client_secret} via the configured {@code clientSecretKey}.
 *
 * <p>Oracle access tokens last 1 hour ({@code expires_in=3600}); when the upstream omits
 * {@code expires_in} we fall back to that documented constant.
 *
 * <p>Oracle <strong>rotates</strong> the refresh token on every successful refresh. We always
 * persist the response RT verbatim. Defensive carry-forward of the prior RT is retained as a
 * safety net only for the (anomalous) case where the response is HTTP 200 but contains no new
 * refresh_token.
 *
 * <p>Error contract follows {@link UpstreamRefreshClient}: {@code invalid_grant} -&gt;
 * {@link OktaTokenRevokedException}; everything else -&gt; {@link OktaTokenRefreshException}. Reusing
 * the Okta exception types keeps {@link UpstreamRefreshService}'s revoke-on-invalid-grant logic
 * provider-agnostic.
 */
@ApplicationScoped
public class OracleEpmUpstreamRefreshClient implements UpstreamRefreshClient {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final String ORACLE_EPM_TOKEN_URI =
            "https://idcs-c0b7a2ce098d48a0a78b94a30f9e42a1.identity.oraclecloud.com/oauth2/v1/token";
    /** Documented Oracle IDCS access-token lifetime ({@code expires_in=3600} = 1 h). */
    static final long DEFAULT_EXPIRES_IN_SECONDS = 3_600L;

    @ConfigProperty(name = "server.token-exchange.oracle-epm.client-id", defaultValue = "")
    String clientId;

    @ConfigProperty(name = "server.token-exchange.oracle-epm.client-secret-key",
            defaultValue = "oracle-epm-client-secret")
    String clientSecretKey;

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

    @Inject
    TokenClient tokenClient;

    @Override
    public UpstreamRefreshResponse refresh(String providerUserId, String upstreamRefreshToken) {
        if (upstreamRefreshToken == null || upstreamRefreshToken.isBlank()) {
            throw new OktaTokenRefreshException("Oracle EPM upstream refresh token is empty");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new OktaTokenRefreshException(
                    "Oracle EPM client_id not configured (server.token-exchange.oracle-epm.client-id)");
        }
        if (clientSecretKey == null || clientSecretKey.isBlank()) {
            throw new OktaTokenRefreshException(
                    "Oracle EPM client secret key not configured (server.token-exchange.oracle-epm.client-secret-key)");
        }
        Map<String, String> credentials = k8SSecretsProvider.getCredentials(null);
        String clientSecret = credentials != null ? credentials.get(clientSecretKey) : null;
        if (clientSecret == null || clientSecret.isEmpty()) {
            throw new OktaTokenRefreshException(
                    "Oracle EPM client secret not found (key=" + clientSecretKey + ")");
        }
        String trimmedRt = upstreamRefreshToken.trim();
        try {
            URI tokenEndpoint = URI.create(ORACLE_EPM_TOKEN_URI);
            // Confidential client (client_secret_post): client_id + client_secret in the form
            // body. Do NOT switch to ClientSecretBasic — Oracle's documented curl uses the body
            // form, and matching it keeps the wire shape verifiable against Oracle's examples.
            ClientAuthentication clientAuth = new ClientSecretPost(
                    new ClientID(clientId.trim()),
                    new Secret(clientSecret.trim())
            );
            AuthorizationGrant refreshGrant = new RefreshTokenGrant(new RefreshToken(trimmedRt));
            TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, refreshGrant);
            TokenResponse tokenResponse;
            try (var ignored = UpstreamHttpCallLabels.withLabels(
                    OauthProviderLabel.ORACLE_EPM, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN)) {
                tokenResponse = tokenClient.execute(tokenRequest);
            }
            if (tokenResponse.indicatesSuccess()) {
                AccessTokenResponse success = tokenResponse.toSuccessResponse();
                String newAccessToken = success.getTokens().getAccessToken().getValue();
                RefreshToken newRefreshToken = success.getTokens().getRefreshToken();
                Long lifetime = success.getTokens().getAccessToken().getLifetime();
                long expiresIn = lifetime != null && lifetime > 0L ? lifetime : DEFAULT_EXPIRES_IN_SECONDS;
                // Oracle rotates the RT each refresh; persist the response RT verbatim. Carry
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
            log.error("Oracle EPM refresh failed for provider_user_id={} upstream response: {}",
                    providerUserId, body);
            String code = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getCode() : "unknown";
            String desc = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getDescription() : "unknown";
            if ("invalid_grant".equals(code)) {
                throw new OktaTokenRevokedException("Oracle EPM refresh token invalid or revoked: " + desc);
            }
            throw new OktaTokenRefreshException("Oracle EPM token refresh failed: " + code + " - " + desc);
        } catch (OktaTokenRevokedException | OktaTokenRefreshException e) {
            throw e;
        } catch (Exception e) {
            log.error("Oracle EPM refresh failed for provider_user_id={} (could not complete token request or parse upstream response)",
                    providerUserId, e);
            throw new OktaTokenRefreshException("Oracle EPM token refresh failed: " + e.getMessage(), e);
        }
    }
}
