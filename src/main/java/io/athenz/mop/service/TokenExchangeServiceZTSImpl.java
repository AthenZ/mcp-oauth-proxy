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

import com.yahoo.athenz.zts.AccessTokenResponse;
import com.yahoo.athenz.zts.OAuthTokenRequestBuilder;
import com.yahoo.athenz.zts.ZTSClient;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class TokenExchangeServiceZTSImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    ZTSClient ztsClient;

    @Override
    public AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO) {
        log.info("getJWTAuthorizationGrantFromIdentityProvider: domain: {} scopes: {}",
                tokenExchangeDO.namespace(), tokenExchangeDO.scopes());
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder
                .newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_TOKEN_EXCHANGE)
                .requestedTokenType(OAuthTokenRequestBuilder.OAUTH_TOKEN_TYPE_JAG)
                .audience(tokenExchangeDO.remoteServer())
                .roleNames(tokenExchangeDO.scopes())
                .subjectTokenType(OAuthTokenRequestBuilder.OAUTH_TOKEN_TYPE_ID)
                .subjectToken(tokenExchangeDO.tokenWrapper().idToken())
                .openIdIssuer(true);

        AccessTokenResponse tokenResponse = ztsClient.getJAGToken(builder);
        TokenWrapper jagToken = new TokenWrapper(tokenExchangeDO.tokenWrapper().key(), tokenExchangeDO.remoteServer(), tokenResponse.getAccess_token(), null, null, Long.valueOf(tokenResponse.getExpires_in()));
        return new AuthorizationResultDO(AuthResult.AUTHORIZED, jagToken);
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO) {
        log.info("getAccessTokenFromResourceAuthorizationServer");
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder
                .newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_JWT_BEARER)
                .assertion(tokenExchangeDO.tokenWrapper().idToken())
                .clientAssertionType(OAuthTokenRequestBuilder.OAUTH_ASSERTION_TYPE_JWT_BEARER)
                .audience(tokenExchangeDO.namespace())
                .roleNames(tokenExchangeDO.scopes())
                .openIdIssuer(true);

        AccessTokenResponse tokenResponse = ztsClient.getJAGExchangeToken(builder);
        TokenWrapper resourceAccessToken = new TokenWrapper(tokenExchangeDO.tokenWrapper().key(), tokenExchangeDO.remoteServer(), null, tokenResponse.getAccess_token(), null, Long.valueOf(tokenResponse.getExpires_in()));
        return new AuthorizationResultDO(AuthResult.AUTHORIZED, resourceAccessToken);
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(TokenExchangeDO tokenExchangeDO) {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder("client_credentials");
        builder.openIdIssuer(true).expiryTime(3600L).roleNames(tokenExchangeDO.scopes()).domainName(tokenExchangeDO.namespace());
        AccessTokenResponse tokenResponse = ztsClient.getAccessToken(builder, true);
        TokenWrapper resourceAccessToken = new TokenWrapper(tokenExchangeDO.tokenWrapper().key(), tokenExchangeDO.remoteServer(), null, tokenResponse.getAccess_token(), null, Long.valueOf(tokenResponse.getExpires_in()));
        return new AuthorizationResultDO(AuthResult.AUTHORIZED, resourceAccessToken);
    }
}
