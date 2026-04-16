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
package io.athenz.mop.store.impl.memory;

import io.athenz.mop.model.AuthorizationCode;
import io.athenz.mop.model.AuthorizationCodeTokensDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.store.AuthCodeStore;
import io.athenz.mop.store.MemoryStoreQualifier;
import io.athenz.mop.store.TokenStore;
import io.athenz.mop.store.TokenStoreAsync;
import io.athenz.mop.util.JwtUtils;
import io.quarkus.cache.Cache;
import io.quarkus.cache.CacheName;
import io.quarkus.cache.CaffeineCache;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import java.lang.invoke.MethodHandles;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
@MemoryStoreQualifier
public class TokenStoreInMemoryImpl implements TokenStore, AuthCodeStore, TokenStoreAsync {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @CacheName("token-cache")
    Cache tokenCache;

    @CacheName("token-cache")
    Cache codeCache;

    private final ConcurrentHashMap<String, String> hashToUserMap = new ConcurrentHashMap<>();

    @Override
    public void storeUserToken(String user, String provider, TokenWrapper token) {
        tokenCache.as(CaffeineCache.class).put(user, CompletableFuture.completedFuture(token));
        if (token.accessToken() != null) {
            String hash = JwtUtils.hashAccessToken(token.accessToken());
            hashToUserMap.put(hash, user);
        }
    }

    @Override
    public TokenWrapper getUserToken(String user, String provider) {
        CompletableFuture<TokenWrapper> cachedTokenValue = tokenCache.as(CaffeineCache.class).getIfPresent(user);
        if (cachedTokenValue != null) {
            try {
                TokenWrapper token = cachedTokenValue.get();
                if (token != null && token.isExpired()) {
                    log.info("Token expired for user={}, provider={}, ttl={} — evicting from cache", user, provider, token.ttl());
                    deleteUserToken(user, provider);
                    return null;
                }
                return token;
            } catch (Exception ex) {
                log.error("Unable to retrieve token from cache");
                return null;
            }
        }
        return null;
    }

    @Override
    public void deleteUserToken(String user, String provider) {
        CompletableFuture<TokenWrapper> cachedTokenValue = tokenCache.as(CaffeineCache.class).getIfPresent(user);
        if (cachedTokenValue == null) {
            return;
        }
        try {
            TokenWrapper token = cachedTokenValue.get();
            if (token == null || !provider.equals(token.provider())) {
                return;
            }
            if (token.accessToken() != null) {
                hashToUserMap.remove(JwtUtils.hashAccessToken(token.accessToken()));
            }
            tokenCache.invalidate(user).await().indefinitely();
            log.info("deleteUserToken: removed cache entry for user {} provider {}", user, provider);
        } catch (Exception ex) {
            log.warn("deleteUserToken: unable to evict user {} provider {}: {}", user, provider, ex.getMessage());
        }
    }

    @Override
    public void storeAuthCode(String code, String provider, AuthorizationCode codeObj) {
        codeCache.as(CaffeineCache.class).put(code, CompletableFuture.completedFuture(codeObj));
    }

    @Override
    public AuthorizationCode getAuthCode(String code, String provider) {
        CompletableFuture<AuthorizationCode> authCodeValue = codeCache.as(CaffeineCache.class).getIfPresent(code);
        if (authCodeValue != null) {
            try {
                return authCodeValue.get();
            } catch (Exception ex) {
                log.error("Unable to retrieve auth code from cache");
                return null;
            }
        }
        return null;
    }

    @Override
    public void deleteAuthCode(String code, String provider) {
        codeCache.invalidate(code).await().indefinitely();
    }

    @Override
    public Uni<String> storeTokenAsync(String id, String provider, AuthorizationCodeTokensDO token) {
        log.info("Storing auth code tokens on the server for id {}, resource {}", id, provider);
        tokenCache.as(CaffeineCache.class).put(id, CompletableFuture.completedFuture(token));
        return Uni.createFrom().item(id);
    }

    @Override
    public Uni<AuthorizationCodeTokensDO> getTokenAsync(String id, String provider) {
        CompletionStage<AuthorizationCodeTokensDO> cachedTokenValue = tokenCache.as(CaffeineCache.class).getIfPresent(id);
        try {
            return Uni.createFrom().completionStage(cachedTokenValue);
        } catch (Exception ex) {
            log.error("Unable to retrieve auth code token from cache");
            return Uni.createFrom().failure(ex);
        }
    }

    @Override
    public Uni<Boolean> deleteTokenAsync(String id, String provider) {
        log.info("Deleting auth code tokens on the server for id {}, resource {}", id, provider);
        return tokenCache.invalidate(id).replaceWith(true);
    }

    @Override
    public TokenWrapper getUserTokenByAccessTokenHash(String accessTokenHash) {
        log.info("Looking up user token by bearer credential in memory cache (hash not logged)");
        String user = hashToUserMap.get(accessTokenHash);
        if (user == null) {
            log.info("No token found for bearer credential lookup in memory cache");
            return null;
        }
        CompletableFuture<TokenWrapper> cachedTokenValue = tokenCache.as(CaffeineCache.class).getIfPresent(user);
        if (cachedTokenValue != null) {
            try {
                TokenWrapper token = cachedTokenValue.get();
                if (token != null && token.isExpired()) {
                    log.info("Token expired for user={}, provider={}, ttl={} — evicting from cache", user, token.provider(), token.ttl());
                    deleteUserToken(user, token.provider());
                    return null;
                }
                log.info("Found token in memory cache for bearer lookup");
                return token;
            } catch (Exception ex) {
                log.error("Unable to retrieve token from cache", ex);
                return null;
            }
        }
        log.info("No token found for bearer credential lookup in memory cache");
        return null;
    }
}
