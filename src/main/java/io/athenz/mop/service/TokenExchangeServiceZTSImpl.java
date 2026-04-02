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
import com.yahoo.athenz.zts.ZTSClientException;
import io.athenz.mop.client.ZTSClientProducer;
import io.athenz.mop.config.AthenzTokenExchangeConfig;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.OAuth2ErrorResponse;
import io.athenz.mop.model.RequestedZtsTokenType;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.telemetry.ExchangeStep;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryProviderResolver;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.lang.invoke.MethodHandles;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class TokenExchangeServiceZTSImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    ZTSClientProducer ztsClientProducer;

    @Inject
    AthenzTokenExchangeConfig athenzTokenExchangeConfig;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    TelemetryProviderResolver telemetryProviderResolver;

    @Inject
    TelemetryRequestContext telemetryRequestContext;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    @Override
    public AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO) {
        long t0 = System.nanoTime();
        log.info("getJWTAuthorizationGrantFromIdentityProvider: domain: {} scopes: {}",
                tokenExchangeDO.namespace(), tokenExchangeDO.scopes());
        try {
            OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder
                    .newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_TOKEN_EXCHANGE)
                    .requestedTokenType(OAuthTokenRequestBuilder.OAUTH_TOKEN_TYPE_JAG)
                    .audience(tokenExchangeDO.remoteServer())
                    .roleNames(tokenExchangeDO.scopes())
                    .subjectTokenType(OAuthTokenRequestBuilder.OAUTH_TOKEN_TYPE_ID)
                    .subjectToken(tokenExchangeDO.tokenWrapper().idToken())
                    .openIdIssuer(true);

            ZTSClient ztsClient = ztsClientProducer.getZTSClient();
            AccessTokenResponse tokenResponse;
            try {
                tokenResponse = ztsClient.getJAGToken(builder);
            } catch (ZTSClientException e) {
                throw mapZtsException(e);
            }
            TokenWrapper jagToken = new TokenWrapper(tokenExchangeDO.tokenWrapper().key(), tokenExchangeDO.remoteServer(), tokenResponse.getAccess_token(), null, null, Long.valueOf(tokenResponse.getExpires_in()));
            recordZtsStep(ExchangeStep.ZTS_JAG_GRANT, tokenExchangeDO.resource(), true, null, t0);
            return new AuthorizationResultDO(AuthResult.AUTHORIZED, jagToken);
        } catch (WebApplicationException e) {
            recordZtsStep(ExchangeStep.ZTS_JAG_GRANT, tokenExchangeDO.resource(), false, "unauthorized", t0);
            throw e;
        }
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO) {
        if (tokenExchangeDO.requestedZtsTokenType() == RequestedZtsTokenType.ID_TOKEN) {
            return getAthenzIdTokenViaZts(tokenExchangeDO);
        }
        long t0 = System.nanoTime();
        log.info("getAccessTokenFromResourceAuthorizationServer");
        try {
            OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder
                    .newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_JWT_BEARER)
                    .assertion(tokenExchangeDO.tokenWrapper().idToken())
                    .clientAssertionType(OAuthTokenRequestBuilder.OAUTH_ASSERTION_TYPE_JWT_BEARER)
                    .audience(tokenExchangeDO.namespace())
                    .roleNames(tokenExchangeDO.scopes())
                    .openIdIssuer(true);

            ZTSClient ztsClient = ztsClientProducer.getZTSClient();
            AccessTokenResponse tokenResponse;
            try {
                tokenResponse = ztsClient.getJAGExchangeToken(builder);
            } catch (ZTSClientException e) {
                throw mapZtsException(e);
            }
            TokenWrapper resourceAccessToken = new TokenWrapper(tokenExchangeDO.tokenWrapper().key(), tokenExchangeDO.remoteServer(), null, tokenResponse.getAccess_token(), null, Long.valueOf(tokenResponse.getExpires_in()));
            recordZtsStep(ExchangeStep.ZTS_JAG_EXCHANGE, tokenExchangeDO.resource(), true, null, t0);
            return new AuthorizationResultDO(AuthResult.AUTHORIZED, resourceAccessToken);
        } catch (WebApplicationException e) {
            recordZtsStep(ExchangeStep.ZTS_JAG_EXCHANGE, tokenExchangeDO.resource(), false, "unauthorized", t0);
            throw e;
        }
    }

    /**
     * Token exchange path: Okta id_token → Athenz id_token via ZTS (same builder as user code).
     * Uses getJAGToken which posts token-exchange request; ZTS returns AccessTokenResponse with id_token.
     */
    private AuthorizationResultDO getAthenzIdTokenViaZts(TokenExchangeDO tokenExchangeDO) {
        long t0 = System.nanoTime();
        log.info("getAccessTokenFromResourceAuthorizationServer: token exchange for Athenz id_token");
        try {
            OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder
                    .newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_TOKEN_EXCHANGE)
                    .requestedTokenType(OAuthTokenRequestBuilder.OAUTH_TOKEN_TYPE_ID)
                    .audience(athenzTokenExchangeConfig.audience())
                    .roleNames(tokenExchangeDO.scopes())
                    .subjectTokenType(OAuthTokenRequestBuilder.OAUTH_TOKEN_TYPE_ID)
                    .subjectToken(tokenExchangeDO.tokenWrapper().idToken())
                    .openIdIssuer(true);

            ZTSClient ztsClient = ztsClientProducer.getZTSClient();
            AccessTokenResponse tokenResponse;
            try {
                tokenResponse = ztsClient.getAccessToken(builder, true);
            } catch (ZTSClientException e) {
                throw mapZtsException(e);
            }
            String idTokenValue = tokenResponse.getId_token();
            if (idTokenValue == null || idTokenValue.isBlank()) {
                log.warn("Token exchange for id_token: ZTS response had no id_token");
                recordZtsStep(ExchangeStep.ZTS_ATHENZ_ID_TOKEN, tokenExchangeDO.resource(), false, "unauthorized", t0);
                return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
            }
            Long expiresIn = tokenResponse.getExpires_in() != null ? tokenResponse.getExpires_in().longValue() : 3600L;
            TokenWrapper idToken = new TokenWrapper(
                    tokenExchangeDO.tokenWrapper().key(),
                    tokenExchangeDO.remoteServer(),
                    idTokenValue,
                    null,
                    null,
                    expiresIn);
            recordZtsStep(ExchangeStep.ZTS_ATHENZ_ID_TOKEN, tokenExchangeDO.resource(), true, null, t0);
            return new AuthorizationResultDO(AuthResult.AUTHORIZED, idToken);
        } catch (WebApplicationException e) {
            recordZtsStep(ExchangeStep.ZTS_ATHENZ_ID_TOKEN, tokenExchangeDO.resource(), false, "unauthorized", t0);
            throw e;
        }
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(TokenExchangeDO tokenExchangeDO) {
        long t0 = System.nanoTime();
        try {
            OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder("client_credentials");
            builder.openIdIssuer(true).expiryTime(3600L).roleNames(tokenExchangeDO.scopes()).domainName(tokenExchangeDO.namespace());
            ZTSClient ztsClient = ztsClientProducer.getZTSClient();
            AccessTokenResponse tokenResponse;
            try {
                tokenResponse = ztsClient.getAccessToken(builder, true);
            } catch (ZTSClientException e) {
                throw mapZtsException(e);
            }
            TokenWrapper resourceAccessToken = new TokenWrapper(tokenExchangeDO.tokenWrapper().key(), tokenExchangeDO.remoteServer(), null, tokenResponse.getAccess_token(), null, Long.valueOf(tokenResponse.getExpires_in()));
            recordZtsStep(ExchangeStep.ZTS_CLIENT_CREDENTIALS, tokenExchangeDO.resource(), true, null, t0);
            return new AuthorizationResultDO(AuthResult.AUTHORIZED, resourceAccessToken);
        } catch (WebApplicationException e) {
            recordZtsStep(ExchangeStep.ZTS_CLIENT_CREDENTIALS, tokenExchangeDO.resource(), false, "unauthorized", t0);
            throw e;
        }
    }

    private void recordZtsStep(ExchangeStep step, String resourceUri, boolean success, String errorType, long startNanos) {
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        String oauthProvider = telemetryProviderResolver.fromResourceUri(resourceUri);
        oauthProxyMetrics.recordExchangeStep(step, oauthProvider, success,
                success ? null : (errorType != null ? errorType : "unauthorized"),
                telemetryRequestContext.oauthClient(), metricsRegionProvider.primaryRegion(), seconds);
    }

    @Override
    public TokenWrapper refreshWithUpstreamToken(String upstreamRefreshToken) {
        // ZTS is the Athenz token service (authorization server), not an upstream IDP that issues refresh tokens in this flow.
        return null;
    }

    private WebApplicationException mapZtsException(ZTSClientException e) {
        String description = e.getMessage();
        if (description == null || description.isBlank()) {
            description = e.toString();
        }
        log.warn("ZTS client error: {}", description, e);
        return new WebApplicationException(
                Response.status(Response.Status.UNAUTHORIZED)
                        .entity(OAuth2ErrorResponse.of(
                                OAuth2ErrorResponse.ErrorCode.INVALID_GRANT,
                                description))
                        .build());
    }
}
