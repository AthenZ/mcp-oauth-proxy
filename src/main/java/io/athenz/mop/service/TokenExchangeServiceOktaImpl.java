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

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.Map;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.tokenexchange.TokenExchangeGrant;

import io.athenz.mop.config.OktaTokenExchangeConfig;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.secret.K8SSecretsProvider;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.lang.invoke.MethodHandles;

@ApplicationScoped
public class TokenExchangeServiceOktaImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    OktaTokenExchangeConfig oktaTokenExchangeConfig;

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

    @Override
    public AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO) {
        try {

            String clientId = oktaTokenExchangeConfig.clientId();
            String clientSecretKey = oktaTokenExchangeConfig.clientSecretKey();

            Map<String, String> credentials = k8SSecretsProvider.getCredentials(null);
            String clientSecret = credentials.get(clientSecretKey);

            if (clientSecret == null) {
                log.error("Failed to retrieve client secret for key: {}", clientSecretKey);
                return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
            }

            String audience = oktaTokenExchangeConfig.audience();
            return exchangeToken(
                    tokenExchangeDO.tokenWrapper().accessToken(),
                    clientId,
                    clientSecret,
                    audience
            );
        } catch (Exception e) {
            log.error("Error exchanging token", e);
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(
            TokenExchangeDO tokenExchangeDO) {
        throw new RuntimeException("Not implemented yet");
    }

    private AuthorizationResultDO exchangeToken(
            String subjectToken,
            String clientId,
            String clientSecret,
            String audience) throws ParseException, IOException {

        // Build token endpoint URL from auth server URL
        String authServerUrl = oktaTokenExchangeConfig.authServerUrl();
        URI tokenEndpoint = URI.create(authServerUrl + "/v1/token");

        ClientSecretBasic clientAuth = new ClientSecretBasic(
                new ClientID(clientId),
                new Secret(clientSecret));

        BearerAccessToken subjectAccessToken = new BearerAccessToken(subjectToken);

        Audience audienceObj = new Audience(audience);

        TokenExchangeGrant grant = new TokenExchangeGrant(
                subjectAccessToken,
                TokenTypeURI.ACCESS_TOKEN,
                null,
                null,
                null,
                Collections.singletonList(audienceObj));

        TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, grant);
        TokenResponse tokenResponse = TokenResponse.parse(tokenRequest.toHTTPRequest().send());

        if (!tokenResponse.indicatesSuccess()) {
            TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            log.error("Error exchanging token: {} - {}", errorResponse.getErrorObject().getCode(), errorResponse.getErrorObject().getDescription());
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }

        AccessTokenResponse successResponse = tokenResponse.toSuccessResponse();
        AccessToken accessToken = successResponse.getTokens().getAccessToken();
        return new AuthorizationResultDO(AuthResult.AUTHORIZED,
                new TokenWrapper(null, null, null, accessToken.getValue(), null, accessToken.getLifetime()));
    }
}
