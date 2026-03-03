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
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.secret.K8SSecretsProvider;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class TokenExchangeServiceGithubImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final URI GITHUB_TOKEN_ENDPOINT = URI.create("https://github.com/login/oauth/access_token");
    private static final long GITHUB_DEFAULT_TOKEN_TTL = 28800L; // 8 hours

    @ConfigProperty(name = "quarkus.oidc.github.client-id", defaultValue = "")
    String clientId;

    @ConfigProperty(name = "quarkus.oidc.github.credentials.client-secret.provider.key", defaultValue = "")
    String clientSecretKey;

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

    @Inject
    TokenClient tokenClient;

    @Override
    public AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO) {
        return new AuthorizationResultDO(AuthResult.AUTHORIZED, tokenExchangeDO.tokenWrapper());
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(TokenExchangeDO tokenExchangeDO) {
        throw new RuntimeException("Not implemented yet");
    }

    /**
     * Refresh with GitHub. Refresh tokens are only available for GitHub Apps using expiring
     * user tokens, not classic OAuth Apps. When a new refresh token is returned, persist it.
     * Uses Nimbus with Accept: application/json so GitHub returns JSON (required by GitHub).
     */
    @Override
    public TokenWrapper refreshWithUpstreamToken(String upstreamRefreshToken) {

        if (upstreamRefreshToken == null || upstreamRefreshToken.isBlank()) {
            return null;
        }

        if (clientId == null || clientId.isBlank()) {
            log.warn("GitHub refresh: client_id not configured");
            return null;
        }

        if (clientSecretKey == null || clientSecretKey.isBlank()) {
            log.warn("GitHub refresh: client secret key not configured (quarkus.oidc.github.credentials.client-secret.provider.key)");
            return null;
        }
        Map<String, String> credentials = k8SSecretsProvider.getCredentials(null);
        String clientSecret =
                credentials != null ? credentials.get(clientSecretKey) : null;

        if (clientSecret == null || clientSecret.isBlank()) {
            log.warn("GitHub refresh: client secret missing (key={})", clientSecretKey);
            return null;
        }

        try {
            String refreshTokenValue = upstreamRefreshToken.trim();

            RefreshTokenGrant grant = new RefreshTokenGrant(new RefreshToken(refreshTokenValue));
            TokenRequest tokenRequest = new TokenRequest(
                    GITHUB_TOKEN_ENDPOINT,
                    new ClientSecretBasic(
                            new ClientID(clientId.trim()),
                            new Secret(clientSecret.trim())
                    ),
                    grant
            );

            TokenResponse tokenResponse = tokenClient.execute(tokenRequest);

            if (tokenResponse.indicatesSuccess()) {
                AccessTokenResponse successResponse = tokenResponse.toSuccessResponse();
                AccessToken accessToken = successResponse.getTokens().getAccessToken();
                RefreshToken newRefreshToken = successResponse.getTokens().getRefreshToken();
                Long lifetime = accessToken.getLifetime();
                long ttl = (lifetime != null && lifetime > 0) ? lifetime : GITHUB_DEFAULT_TOKEN_TTL;
                return new TokenWrapper(
                        null,
                        null,
                        null,
                        accessToken.getValue(),
                        newRefreshToken != null ? newRefreshToken.getValue() : refreshTokenValue,
                        ttl
                );
            } else {
                TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                String code = errorResponse.getErrorObject() != null ? errorResponse.getErrorObject().getCode() : "unknown";
                String desc = errorResponse.getErrorObject() != null ? errorResponse.getErrorObject().getDescription() : "unknown";
                log.warn("GitHub refresh failed: {} - {}", code, desc);
                return null;
            }
        } catch (Exception e) {
            log.warn("GitHub refresh failed", e);
            return null;
        }
    }
}
