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
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class TokenExchangeServiceAtlassianImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final String ATLASSIAN_TOKEN_URI = "https://auth.atlassian.com/oauth/token";

    @ConfigProperty(name = "quarkus.oidc.atlassian.client-id", defaultValue = "")
    String clientId;

    @ConfigProperty(name = "quarkus.oidc.atlassian.credentials.client-secret.provider.key", defaultValue = "")
    String clientSecretKey;

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

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
     * Refresh with Atlassian. Atlassian rotates refresh tokens; a new one is returned every time.
     * Always persist the newly returned refresh token (caller does so when non-null).
     */
    @Override
    public TokenWrapper refreshWithUpstreamToken(String upstreamRefreshToken) {
        if (upstreamRefreshToken == null || upstreamRefreshToken.isEmpty()) {
            return null;
        }
        String refreshTokenValue = upstreamRefreshToken.trim();
        if (refreshTokenValue.isEmpty()) {
            return null;
        }
        if (clientId == null || clientId.isBlank()) {
            log.warn("Atlassian refresh: client_id not configured (quarkus.oidc.atlassian.client-id)");
            return null;
        }
        if (clientSecretKey == null || clientSecretKey.isBlank()) {
            log.warn("Atlassian refresh: client secret key not configured (quarkus.oidc.atlassian.credentials.client-secret.provider.key)");
            return null;
        }
        Map<String, String> credentials = k8SSecretsProvider.getCredentials(null);
        String clientSecret = credentials != null ? credentials.get(clientSecretKey) : null;
        if (clientSecret == null || clientSecret.isEmpty()) {
            log.warn("Atlassian refresh: client secret not found (key={})", clientSecretKey);
            return null;
        }
        try {
            URI tokenEndpoint = URI.create(ATLASSIAN_TOKEN_URI);
            ClientAuthentication clientAuth = new ClientSecretPost(
                    new ClientID(clientId.trim()),
                    new com.nimbusds.oauth2.sdk.auth.Secret(clientSecret.trim())
            );
            AuthorizationGrant refreshGrant = new RefreshTokenGrant(new RefreshToken(refreshTokenValue));
            TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, refreshGrant);
            TokenResponse tokenResponse = TokenResponse.parse(tokenRequest.toHTTPRequest().send());
            if (tokenResponse.indicatesSuccess()) {
                AccessTokenResponse successResponse = tokenResponse.toSuccessResponse();
                String newAccessToken = successResponse.getTokens().getAccessToken().getValue();
                com.nimbusds.oauth2.sdk.token.RefreshToken newRefreshToken = successResponse.getTokens().getRefreshToken();
                Long lifetime = successResponse.getTokens().getAccessToken().getLifetime();
                long ttl = (lifetime != null) ? lifetime : 3600L;
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
                String code = errorResponse.getErrorObject() != null ? errorResponse.getErrorObject().getCode() : "unknown";
                String desc = errorResponse.getErrorObject() != null ? errorResponse.getErrorObject().getDescription() : "unknown";
                log.warn("Atlassian refresh failed: {} - {}", code, desc);
                return null;
            }
        } catch (Exception e) {
            log.warn("Atlassian refresh failed: {}", e.getMessage());
            return null;
        }
    }
}
