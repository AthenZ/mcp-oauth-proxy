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
import com.github.benmanes.caffeine.cache.RemovalCause;
import io.athenz.mop.config.OktaSessionCacheConfig;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.time.Duration;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * L0 in-memory tier of the shared Okta upstream session cache. Per-pod, Caffeine-backed,
 * keyed by {@code providerUserId} (e.g. {@code "okta#<sub>"}).
 *
 * <p>Strict read-through cache fronting the bare {@code (userId, "okta")} DDB row (L1).
 * Never the source of truth and never writes back to L1. Population is the responsibility
 * of callers right after a known-fresh L1 write:
 * <ol>
 *   <li>{@code AuthorizerService.storeTokens} (login)</li>
 *   <li>{@code AuthorizerService.completeRefreshWithOktaTokens}</li>
 *   <li>{@code UpstreamRefreshService.refreshUpstream} (after a successful L2 call)</li>
 * </ol>
 *
 * <p>Disabling the cache via {@link OktaSessionCacheConfig#enabled()} forces every read to
 * empty and every write to a no-op; the surrounding code therefore behaves identically to
 * pre-cache state.
 *
 * <p>Thread-safety: Caffeine is lock-free for both reads and writes. No additional
 * synchronization is needed.
 */
@ApplicationScoped
public class OktaSessionCache {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    OktaSessionCacheConfig config;

    @Inject
    OauthProxyMetrics metrics;

    private Cache<String, OktaSessionEntry> cache;

    @PostConstruct
    void init() {
        validateConfig();
        if (!config.enabled()) {
            log.info("OktaSessionCache: disabled (server.upstream.okta.session-cache.enabled=false)");
            return;
        }
        this.cache = Caffeine.newBuilder()
                .maximumSize(config.l0MaxSize())
                .expireAfterWrite(Duration.ofSeconds(config.l0ExpireAfterWriteSeconds()))
                .executor(Runnable::run)
                .removalListener((String key, OktaSessionEntry value, RemovalCause cause) -> {
                    if (cause == null) {
                        return;
                    }
                    String reason = switch (cause) {
                        case SIZE -> "size";
                        case EXPIRED -> "expired_write";
                        case EXPLICIT -> "explicit";
                        case REPLACED -> null;
                        case COLLECTED -> "collected";
                    };
                    if (reason != null) {
                        metrics.recordOktaSessionCacheEviction(reason);
                    }
                })
                .build();
        metrics.registerOktaSessionCacheSizeGauge(this::estimatedSize);
        log.info("OktaSessionCache: enabled (maxSize={}, expireAfterWriteSeconds={}, minRemainingSeconds={})",
                config.l0MaxSize(), config.l0ExpireAfterWriteSeconds(), config.minRemainingSeconds());
    }

    /**
     * Returns the cached entry for {@code providerUserId} if one is present. Freshness is the
     * caller's responsibility — caller passes its own skew (120s for {@code /token}, 0s for
     * {@code /userinfo}). When the cache is disabled, always returns empty.
     */
    public Optional<OktaSessionEntry> get(String providerUserId) {
        if (cache == null || providerUserId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(cache.getIfPresent(providerUserId));
    }

    /**
     * Stores or overwrites the entry for {@code providerUserId}. No-op when the cache is
     * disabled, when {@code providerUserId} is null/blank, or when {@code entry} is null.
     */
    public void put(String providerUserId, OktaSessionEntry entry) {
        if (cache == null || providerUserId == null || providerUserId.isEmpty() || entry == null) {
            return;
        }
        cache.put(providerUserId, entry);
    }

    /** Removes the entry for {@code providerUserId}. No-op when the cache is disabled. */
    public void invalidate(String providerUserId) {
        if (cache == null || providerUserId == null) {
            return;
        }
        cache.invalidate(providerUserId);
    }

    /** Approximate current entry count. Used for the size gauge. */
    public long estimatedSize() {
        return cache == null ? 0L : cache.estimatedSize();
    }

    /** Test helper: drop everything. */
    void invalidateAll() {
        if (cache != null) {
            cache.invalidateAll();
        }
    }

    private void validateConfig() {
        int skew = config.minRemainingSeconds();
        if (skew < 30 || skew > 600) {
            throw new IllegalStateException(
                    "server.upstream.okta.session-cache.min-remaining-seconds must be in [30, 600]; got " + skew);
        }
        int max = config.l0MaxSize();
        if (max < 100 || max > 100_000) {
            throw new IllegalStateException(
                    "server.upstream.okta.session-cache.l0-max-size must be in [100, 100000]; got " + max);
        }
        int writeTtl = config.l0ExpireAfterWriteSeconds();
        if (writeTtl < 600 || writeTtl > 7200) {
            throw new IllegalStateException(
                    "server.upstream.okta.session-cache.l0-expire-after-write-seconds must be in [600, 7200]; got "
                            + writeTtl);
        }
    }
}
