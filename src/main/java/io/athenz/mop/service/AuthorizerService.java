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

import com.yahoo.athenz.zms.Access;
import com.yahoo.athenz.zms.ZMSClient;
import io.athenz.mop.model.*;
import io.athenz.mop.store.TokenStore;
import io.quarkus.oidc.RefreshToken;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class AuthorizerService {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String TOKEN_TYPE = "Bearer";

    @Inject
    ZMSClient zmsClient;

    @ConfigProperty(name = "server.athenz.user-prefix")
    String userPrefix;

    @Inject
    TokenStore tokenStore;

    @Inject
    TokenExchangeServiceProducer tokenExchangeServiceProducer;

    @ConfigProperty(name = "server.token-store.expiry", defaultValue = "300")
    Long ttl;

    @ConfigProperty(name = "server.athenz.authorization-domain")
    String authorizationDomain;

    @ConfigProperty(name = "server.athenz.authorization-action")
    String authorizationAction;

    @ConfigProperty(name = "server.athenz.resource-authorization", defaultValue = "false")
    boolean zmsResourceAuthorization;

    @Inject
    ConfigService configService;

    public void storeTokens(String lookupKey, JsonWebToken idToken, JsonWebToken accessToken, RefreshToken refreshToken, String provider) {
        String user = userPrefix + accessToken.getName();
        storeTokens(
                user,
                lookupKey,
                idToken != null ? idToken.getRawToken() : null,
                accessToken.getRawToken(),
                refreshToken != null ? refreshToken.getToken() : null,
                provider
        );
    }

    public void storeTokens(String user, String lookupKey, String idToken, String accessToken, String refreshToken, String provider) {
        log.info("storing tokens for lookupKey: {} and user: {} from provider: {}", lookupKey, user, provider);
        long nowSeconds = Instant.now().getEpochSecond();
        TokenWrapper cachedToken = new TokenWrapper(
                user,
                provider,
                idToken,
                accessToken,
                refreshToken,
                nowSeconds + ttl
        );
        tokenStore.storeUserToken(lookupKey, provider, cachedToken);
    }

    public TokenWrapper getUserToken(String lookupKey, String provider) {
        return tokenStore.getUserToken(lookupKey, provider);
    }

    public AuthorizationResultDO authorize(String subject, String scopes, String resource) {
        log.info("check authorization for subject: {} scopes: {} resource: {}", subject, scopes, resource);
        ResourceMeta resourceMeta = configService.getResourceMeta(resource);
        String provider = resourceMeta != null ? resourceMeta.idpServer() : configService.getDefaultIDP();
        TokenWrapper token = tokenStore.getUserToken(subject, provider);

        if (token == null) {
            return new AuthorizationResultDO(AuthResult.EXPIRED, null);
        }
        String userFromToken = token.key();
        log.info("{} logged in within last X minutes", userFromToken);
        // TODO: This is broken until we implement okta uid to zms user mapping
        if (zmsResourceAuthorization) {
            String zmsAction = authorizationAction;
            String zmsResource = authorizationDomain + ":" + resource;
            log.info("making zms access call for action: {} and resource: {} for userFromToken: {}", zmsAction, zmsResource, userFromToken);
            Access access = zmsClient.getAccessExt(zmsAction, zmsResource, null, userFromToken);
            if (!access.getGranted()) {
                return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
            }
        }
        return new AuthorizationResultDO(AuthResult.AUTHORIZED, token);
    }

    public TokenResponse getTokenFromAuthorizationServer(String subject, String scopes, String resource, TokenWrapper token) {
        TokenResponse tokenResponse;
        ResourceMeta resourceMeta = configService.getResourceMeta(resource);
        if (resourceMeta == null) {
            log.error("no resource meta found for resource: {}", resource);
            return null;
        }

        TokenExchangeService accessTokenIssuer = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(resourceMeta.authorizationServer());
        if (resourceMeta.jagEnabled()) {
            // TODO: validate that requested scopes are part of resourceMeta.scopes()
            // as of now we are ignoring the requested scopes and using the ones defined in resource meta
            TokenExchangeService jagTokenIssuer = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(resourceMeta.jagIssuer());

            TokenExchangeDO jagTokenRequestDO = new TokenExchangeDO(
                    resourceMeta.scopes(),
                    resource,
                    resourceMeta.domain(),
                    configService.getRemoteServerEndpoint(resourceMeta.jagIssuer()),
                    token
            );

            AuthorizationResultDO jagDO = jagTokenIssuer.getJWTAuthorizationGrantFromIdentityProvider(jagTokenRequestDO);
            TokenExchangeDO accessTokenRequestDO = new TokenExchangeDO(
                    resourceMeta.scopes(),
                    resource,
                    resourceMeta.domain(),
                    configService.getRemoteServerEndpoint(resourceMeta.authorizationServer()),
                    jagDO.token()
            );
            AuthorizationResultDO atDO = accessTokenIssuer.getAccessTokenFromResourceAuthorizationServer(accessTokenRequestDO);

            log.info("token-exchange response: ttl: {}", atDO.token().ttl());

            tokenResponse = new TokenResponse(
                    atDO.token().accessToken(),
                    TOKEN_TYPE,
                    atDO.token().ttl(),
                    resourceMeta.scopes().toString()
            );

        } else {

            TokenExchangeDO accessTokenRequestDO = new TokenExchangeDO(
                    resourceMeta.scopes(),
                    resource,
                    resourceMeta.domain(),
                    configService.getRemoteServerEndpoint(resourceMeta.authorizationServer()),
                    token
            );
            AuthorizationResultDO atDO = accessTokenIssuer.getAccessTokenFromResourceAuthorizationServer(accessTokenRequestDO);

            log.info("non token-exchange response: ttl: {}", atDO.token().ttl());

            storeGleanTokenIfNeeded(resource, token, atDO.token());

            tokenResponse = new TokenResponse(
                    atDO.token().accessToken(),
                    TOKEN_TYPE,
                    atDO.token().ttl(),
                    resourceMeta.scopes().toString()
            );
        }
        return tokenResponse;
    }

    /**
     * Store Glean token in DynamoDB after successful token exchange.
     * This method checks if the resource is Glean and stores the exchanged token
     * with provider="glean" using the same subject/user from the Okta token.
     *
     * @param resource The resource URI being accessed
     * @param oktaToken The original Okta token containing the user/subject
     * @param exchangedToken The token obtained from token exchange
     */
    private void storeGleanTokenIfNeeded(String resource, TokenWrapper oktaToken, TokenWrapper exchangedToken) {
        ResourceMeta resourceMeta = configService.getResourceMeta(resource);
        if (resourceMeta == null || resourceMeta.audience() == null || !"glean".equals(resourceMeta.audience())) {
            return;
        }
        log.info("Storing Glean token for user: {}", oktaToken.key());

        long nowSeconds = Instant.now().getEpochSecond();
        long absoluteTtl = nowSeconds + exchangedToken.ttl();

        TokenWrapper gleanToken = new TokenWrapper(
                oktaToken.key(),
                "glean",
                null,
                exchangedToken.accessToken(),
                null,
                absoluteTtl
        );

        tokenStore.storeUserToken(oktaToken.key(), "glean", gleanToken);
        log.info("Successfully stored Glean token for user: {} with ttl: {}", oktaToken.key(), gleanToken.ttl());
    }

    /**
     * Refresh upstream IDP tokens using the given refresh token, update the token store,
     * then exchange the new access token for the resource (e.g. Okta/Glean exchange at
     * TokenExchangeServiceOktaImpl 87-92) and return that exchanged token. Used by refresh_token grant.
     * When the IDP returns a new refresh token, it is included in the result so the caller can
     * persist it in the new refresh token table.
     *
     * @param userId                  internal user id (lookup key)
     * @param provider                upstream IDP (e.g. okta)
     * @param resource                resource URI for scope/metadata
     * @param upstreamRefreshToken    decrypted upstream refresh token from refresh table
     * @return RefreshAndTokenResult with new access token and new upstream refresh (if IDP returned one), or null on failure
     */
    public RefreshAndTokenResult refreshUpstreamAndGetToken(String userId, String provider, String resource,
                                                           String upstreamRefreshToken) {
        if (upstreamRefreshToken == null || upstreamRefreshToken.isEmpty()) {
            log.warn("refreshUpstreamAndGetToken: no upstream refresh token for user {} provider {}", userId, provider);
            return null;
        }
        TokenExchangeService exchangeService = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(provider);
        TokenWrapper newToken = exchangeService.refreshWithUpstreamToken(upstreamRefreshToken);
        if (newToken == null) {
            log.warn("refreshUpstreamAndGetToken: upstream IDP refresh failed (refreshWithUpstreamToken returned null) for user {} provider {}", userId, provider);
            return null;
        }
        long nowSeconds = Instant.now().getEpochSecond();
        long absoluteTtl = nowSeconds + (newToken.ttl() != null ? newToken.ttl() : 3600L);
        String newUpstreamRefresh = (newToken.refreshToken() != null && !newToken.refreshToken().isEmpty())
                ? newToken.refreshToken() : null;
        TokenWrapper toStore = new TokenWrapper(
                userId,
                provider,
                newToken.idToken(),
                newToken.accessToken(),
                newToken.refreshToken(),
                absoluteTtl
        );
        tokenStore.storeUserToken(userId, provider, toStore);

        ResourceMeta resourceMeta = configService.getResourceMeta(resource);
        String scopeStr = resourceMeta != null ? resourceMeta.scopes().toString() : "";
        // Run the new access token through the resource's authorization server (e.g. Okta/Glean exchange)
        // so the client receives the same exchanged token as in the auth_code flow (TokenExchangeServiceOktaImpl 87-92)
        TokenExchangeService accessTokenIssuer = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(
                resourceMeta != null ? resourceMeta.authorizationServer() : provider);
        TokenExchangeDO accessTokenRequestDO = new TokenExchangeDO(
                resourceMeta != null ? resourceMeta.scopes() : null,
                resource,
                resourceMeta != null ? resourceMeta.domain() : null,
                resourceMeta != null ? configService.getRemoteServerEndpoint(resourceMeta.authorizationServer()) : null,
                toStore
        );
        AuthorizationResultDO atDO = accessTokenIssuer.getAccessTokenFromResourceAuthorizationServer(accessTokenRequestDO);
        if (atDO == null || atDO.token() == null || atDO.authResult() != AuthResult.AUTHORIZED) {
            log.warn("Token exchange after refresh failed for user {} resource {}", userId, resource);
            return null;
        }
        TokenResponse tokenResponse = new TokenResponse(
                atDO.token().accessToken(),
                TOKEN_TYPE,
                atDO.token().ttl(),
                scopeStr
        );
        return new RefreshAndTokenResult(tokenResponse, newUpstreamRefresh);
    }

}
