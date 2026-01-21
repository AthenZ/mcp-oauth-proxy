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
package io.athenz.mop.quarkus;

import io.athenz.mop.model.AuthorizationCodeTokensDO;
import io.athenz.mop.store.TokenStoreAsync;
import io.quarkus.arc.Unremovable;
import io.quarkus.oidc.AuthorizationCodeTokens;
import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.TokenStateManager;
import io.quarkus.security.AuthenticationFailedException;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.Priority;
import jakarta.enterprise.inject.Alternative;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.lang.invoke.MethodHandles;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
@Alternative
@Unremovable
@Priority(1)
public class CustomTokenStateManager implements TokenStateManager {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    TokenStoreAsync tokenStore;

    private static final String STORE_KEY_PREFIX = "oidc:token:";

    @ConfigProperty(name = "server.token-exchange.idp")
    String providerDefault;

    @Override
    public Uni<String> createTokenState(RoutingContext routingContext, OidcTenantConfig oidcConfig, AuthorizationCodeTokens tokens, OidcRequestContext<String> requestContext) {
        String provider = getProviderFromOidcConfig(oidcConfig);
        log.info("Creating token state for {}", provider);
        final String tokenState = UUID.randomUUID().toString();
        AuthorizationCodeTokensDO token = new AuthorizationCodeTokensDO();
        token.setAccessToken(tokens.getAccessToken());
        token.setIdToken(tokens.getIdToken());
        token.setRefreshToken(tokens.getRefreshToken());
        token.setAccessTokenExpiresIn(tokens.getAccessTokenExpiresIn());
        token.setAccessTokenScope(tokens.getAccessTokenScope());
        return tokenStore.storeTokenAsync(toTokenKey(tokenState), provider, token);
    }

    @Override
    public Uni<AuthorizationCodeTokens> getTokens(RoutingContext routingContext, OidcTenantConfig oidcConfig, String tokenState, OidcRequestContext<AuthorizationCodeTokens> requestContext) {
        String provider = getProviderFromOidcConfig(oidcConfig);
        log.info("Getting tokens for {}, provider: {}", tokenState, provider);
        return tokenStore.getTokenAsync(tokenState, provider).
        onItem().ifNotNull().transform(tokenDO -> {
            AuthorizationCodeTokens tokens = new AuthorizationCodeTokens();
            tokens.setAccessToken(tokenDO.getAccessToken());
            tokens.setIdToken(tokenDO.getIdToken());
            tokens.setRefreshToken(tokenDO.getRefreshToken());
            tokens.setAccessTokenExpiresIn(tokenDO.getAccessTokenExpiresIn());
            tokens.setAccessTokenScope(tokenDO.getAccessTokenScope());
            return tokens;
        }).onFailure().transform(AuthenticationFailedException::new);
    }

    @Override
    public Uni<Void> deleteTokens(RoutingContext routingContext, OidcTenantConfig oidcConfig, String tokenState, OidcRequestContext<Void> requestContext) {
        String provider = getProviderFromOidcConfig(oidcConfig);
        log.info("Deleting tokens for {}, provider: {}", tokenState, provider);
        return tokenStore.deleteTokenAsync(tokenState, getProviderFromOidcConfig(oidcConfig)).onFailure().recoverWithNull().replaceWithVoid();
    }

    private static String toTokenKey(String tokenState) {
        return STORE_KEY_PREFIX + tokenState;
    }

    private String getProviderFromOidcConfig(OidcTenantConfig oidcConfig) {
        if (oidcConfig.provider().isPresent()) {
            return oidcConfig.provider().get().name().toLowerCase();
        } else {
            return providerDefault;
        }
    }
}
