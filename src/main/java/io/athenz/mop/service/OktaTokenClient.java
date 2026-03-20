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

import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import io.athenz.mop.config.OktaTokenExchangeConfig;
import io.athenz.mop.secret.K8SSecretsProvider;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Calls Okta's {@code /v1/token} with {@code grant_type=refresh_token} using the OIDC app credentials
 * (same as interactive login).
 */
@ApplicationScoped
public class OktaTokenClient {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    OktaTokenExchangeConfig oktaTokenExchangeConfig;

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

    @Inject
    TokenClient tokenClient;

    @ConfigProperty(name = "quarkus.oidc.client-id", defaultValue = "")
    String oidcClientId;

    @ConfigProperty(name = "quarkus.oidc.credentials.client-secret.provider.key", defaultValue = "")
    String oidcClientSecretKey;

    /**
     * @param refreshTokenValue plaintext Okta refresh token
     */
    public OktaTokens refreshToken(String refreshTokenValue) {
        if (refreshTokenValue == null || refreshTokenValue.isBlank()) {
            throw new OktaTokenRefreshException("empty refresh token");
        }
        String trimmed = refreshTokenValue.trim();
        if (oidcClientId == null || oidcClientId.isBlank()) {
            throw new OktaTokenRefreshException("OIDC client_id not configured (quarkus.oidc.client-id)");
        }
        if (oidcClientSecretKey == null || oidcClientSecretKey.isBlank()) {
            throw new OktaTokenRefreshException("OIDC client secret key not configured (quarkus.oidc.credentials.client-secret.provider.key)");
        }
        Map<String, String> credentials = k8SSecretsProvider.getCredentials(null);
        String clientSecret = credentials != null ? credentials.get(oidcClientSecretKey) : null;
        if (clientSecret == null || clientSecret.trim().isEmpty()) {
            throw new OktaTokenRefreshException("OIDC client secret not found (key=" + oidcClientSecretKey + ")");
        }
        try {
            String authServerUrl = oktaTokenExchangeConfig.authServerUrl();
            URI tokenEndpoint = URI.create(authServerUrl + "/v1/token");
            ClientSecretBasic clientAuth = new ClientSecretBasic(
                    new ClientID(oidcClientId.trim()),
                    new Secret(clientSecret.trim())
            );
            com.nimbusds.oauth2.sdk.RefreshTokenGrant grant =
                    new com.nimbusds.oauth2.sdk.RefreshTokenGrant(new RefreshToken(trimmed));
            TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, grant);
            TokenResponse tokenResponse = tokenClient.execute(tokenRequest);
            if (tokenResponse.indicatesSuccess()) {
                OIDCTokenResponse oidcResponse = OIDCTokenResponse.parse(tokenResponse.toHTTPResponse());
                var tokens = oidcResponse.getOIDCTokens();
                AccessToken accessToken = tokens.getAccessToken();
                RefreshToken newRefreshToken = tokens.getRefreshToken();
                String idTokenString = tokens.getIDToken() != null ? tokens.getIDToken().serialize() : null;
                Long lifetime = accessToken.getLifetime();
                int expiresIn = lifetime != null ? lifetime.intValue() : 3600;
                String rt = newRefreshToken != null ? newRefreshToken.getValue() : trimmed;
                return new OktaTokens(accessToken.getValue(), rt, idTokenString, expiresIn);
            }
            TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            String code = errorResponse.getErrorObject() != null ? errorResponse.getErrorObject().getCode() : "unknown";
            String desc = errorResponse.getErrorObject() != null ? errorResponse.getErrorObject().getDescription() : "unknown";
            log.warn("Okta refresh failed: {} - {}", code, desc);
            if ("invalid_grant".equals(code)) {
                throw new OktaTokenRevokedException("Okta refresh token invalid or revoked: " + desc);
            }
            throw new OktaTokenRefreshException("Okta token refresh failed: " + code + " - " + desc);
        } catch (OktaTokenRevokedException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Okta refresh failed: {}", e.getMessage());
            throw new OktaTokenRefreshException("Okta token refresh failed: " + e.getMessage(), e);
        }
    }
}
