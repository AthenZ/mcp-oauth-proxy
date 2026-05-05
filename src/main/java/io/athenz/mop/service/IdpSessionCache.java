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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.athenz.mop.config.OktaSessionCacheConfig;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.time.Duration;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Per-pod, per-client L0 access-token cache used by promoted upstream IdP providers
 * (Google Workspace today; the abstraction is provider-agnostic).
 *
 * <p>Keyed by {@code clientKey = client_id#provider#sub} so that two MCP clients of the same
 * Yahoo user (e.g. Cursor + Claude) each get their own AT cell. Concurrent windows of the
 * <em>same</em> MCP client share that cell. Different MCP clients see misses on each other's
 * keys and fall through to the L2 path, where the L2 row's staged AT enables coalescing within
 * a 30-second window so contended refreshes still cost at most one upstream call.
 *
 * <p>This cache is NOT used for Okta — the existing {@link OktaSessionCache} keys by
 * {@code provider#sub} (one shared cell per user) and is preserved as-is. The plan for a future
 * unification keeps {@code OktaSessionCache} as a thin wrapper but that is out of scope here.
 *
 * <p>Tunables (size, write TTL, master enabled flag) reuse {@link OktaSessionCacheConfig} since
 * the operational profile is the same. We deliberately do not introduce a parallel config block;
 * adding one would let the two caches drift in stage vs prod and complicate observability for
 * minimal upside. The {@code minRemainingSeconds} skew is interpreted by callers, not by this
 * cache.
 */
@ApplicationScoped
public class IdpSessionCache {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    OktaSessionCacheConfig config;

    private Cache<String, IdpSessionEntry> cache;

    @PostConstruct
    void init() {
        if (!config.enabled()) {
            log.info("IdpSessionCache: disabled (server.upstream.okta.session-cache.enabled=false; same master switch)");
            return;
        }
        this.cache = Caffeine.newBuilder()
                .maximumSize(config.l0MaxSize())
                .expireAfterWrite(Duration.ofSeconds(config.l0ExpireAfterWriteSeconds()))
                .build();
        log.info("IdpSessionCache: enabled (maxSize={}, expireAfterWriteSeconds={}, minRemainingSeconds={})",
                config.l0MaxSize(), config.l0ExpireAfterWriteSeconds(), config.minRemainingSeconds());
    }

    /**
     * Build the canonical L0/L1 key for per-client AT cells.
     *
     * <p>Format: {@code <clientId>#<provider>#<sub>}. {@code provider} and {@code sub} are
     * required; {@code clientId} may be null/empty for callers that haven't propagated it yet
     * — we substitute the literal {@code "_no_client_"} so those reads still cohabit a stable
     * (and clearly-flagged) bucket. Callers SHOULD always pass a real {@code clientId}.
     */
    public static String clientKey(String clientId, String provider, String sub) {
        if (provider == null || provider.isEmpty() || sub == null || sub.isEmpty()) {
            return null;
        }
        String c = (clientId == null || clientId.isEmpty()) ? "_no_client_" : clientId;
        return c + "#" + provider + "#" + sub;
    }

    /**
     * Returns the cached entry for {@code clientKey} if one is present. Freshness is the caller's
     * responsibility — callers compare {@link IdpSessionEntry#accessTokenExpEpoch()} against now
     * with their own skew. When the cache is disabled, always returns empty.
     */
    public Optional<IdpSessionEntry> get(String clientKey) {
        if (cache == null || clientKey == null || clientKey.isEmpty()) {
            return Optional.empty();
        }
        return Optional.ofNullable(cache.getIfPresent(clientKey));
    }

    /**
     * Stores or overwrites the entry for {@code clientKey}. No-op when the cache is disabled,
     * the key is null/blank, or the entry is null.
     */
    public void put(String clientKey, IdpSessionEntry entry) {
        if (cache == null || clientKey == null || clientKey.isEmpty() || entry == null) {
            return;
        }
        cache.put(clientKey, entry);
    }

    /** Removes the entry for {@code clientKey}. No-op when the cache is disabled. */
    public void invalidate(String clientKey) {
        if (cache == null || clientKey == null) {
            return;
        }
        cache.invalidate(clientKey);
    }

    /** Approximate current entry count. Test/diagnostic helper. */
    public long estimatedSize() {
        return cache == null ? 0L : cache.estimatedSize();
    }

    /** Test helper. */
    void invalidateAll() {
        if (cache != null) {
            cache.invalidateAll();
        }
    }
}
