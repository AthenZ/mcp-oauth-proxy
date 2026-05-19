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
import io.athenz.mop.config.UserInfoClaimsCacheConfig;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Per-pod, strict-write-once cache of stripped {@code /userinfo} claim maps keyed by
 * Athenz-stripped {@code userId} (the "subject" — i.e. the {@code sub} claim from the Okta
 * id_token, with the {@code server.athenz.user-prefix} stripped).
 *
 * <p><b>Lifecycle</b>:
 * <ul>
 *   <li>First successful {@code /userinfo} response for a user populates the cache via
 *       {@link #getOrCompute(String, Supplier)} (atomic load-or-compute under Caffeine).</li>
 *   <li>All subsequent {@code /userinfo} reads for that user within {@link UserInfoClaimsCacheConfig#ttl()}
 *       return the same cached snapshot — no Okta upstream call, no DDB read of the Okta row.</li>
 *   <li>The entry ages out purely on Caffeine's {@code expireAfterWrite} timer or LRU
 *       eviction at {@code maximumSize}. There is no mid-life mutation and no
 *       caller-driven invalidation, by design.</li>
 * </ul>
 *
 * <p><b>Thread safety</b>: Caffeine's internal storage is concurrent-hash-map-equivalent and
 * lock-free for reads; {@link #getOrCompute(String, Supplier)} uses
 * {@link Cache#get(Object, java.util.function.Function)} which serializes concurrent loads
 * for the same key (the loader runs at most once per key per expiration window).
 *
 * <p><b>Immutability</b>: the cached value is wrapped in {@link Collections#unmodifiableMap}
 * over a defensive copy of the loader's return value. Callers cannot mutate cached state by
 * retaining a reference to the loader's output or to the returned map.
 *
 * <p><b>Disabled mode</b>: when {@link UserInfoClaimsCacheConfig#enabled()} is {@code false},
 * {@link #getIfPresent(String)} returns {@link Optional#empty()} and
 * {@link #getOrCompute(String, Supplier)} calls the loader and returns its result without
 * writing the cache (pure pass-through). The behavior is byte-identical to the pre-cache
 * implementation, so a stage/prod flag flip from {@code true} back to {@code false} is a
 * complete rollback with no code change required.
 */
@ApplicationScoped
public class UserInfoClaimsCache {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final int MIN_MAX_SIZE = 100;
    private static final int MAX_MAX_SIZE = 100_000;
    private static final long MIN_EXPIRE_AFTER_WRITE_SECONDS = 3600L;   // 1h
    private static final long MAX_EXPIRE_AFTER_WRITE_SECONDS = 172_800L; // 48h

    @Inject
    UserInfoClaimsCacheConfig config;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    /**
     * Underlying Caffeine cache. {@code null} when {@link UserInfoClaimsCacheConfig#enabled()}
     * is {@code false} at init time — keeps the disabled-path allocation-free and makes the
     * "no cache" semantics obvious in stack traces.
     */
    private volatile Cache<String, Map<String, Object>> cache;

    @PostConstruct
    void init() {
        validateConfig();
        if (!config.enabled()) {
            log.info("UserInfoClaimsCache disabled (server.userinfo.claims-cache.enabled=false); "
                    + "all reads return empty and writes are pure pass-throughs");
            // Still register a zero-supplier so the gauge series is alive but flat.
            oauthProxyMetrics.registerUserinfoClaimsCacheSizeGauge(() -> 0L);
            return;
        }
        long ttlSeconds = config.expireAfterWriteSeconds();
        cache = Caffeine.newBuilder()
                .maximumSize(config.maxSize())
                .expireAfterWrite(Duration.ofSeconds(ttlSeconds))
                .removalListener((String key, Map<String, Object> value, RemovalCause cause) -> {
                    String reason = mapRemovalCause(cause);
                    if (reason != null) {
                        oauthProxyMetrics.recordUserinfoClaimsCacheEviction(reason);
                    }
                })
                .build();
        oauthProxyMetrics.registerUserinfoClaimsCacheSizeGauge(() -> cache.estimatedSize());
        log.info("UserInfoClaimsCache enabled: maxSize={} expireAfterWriteSeconds={}",
                config.maxSize(), ttlSeconds);
    }

    private void validateConfig() {
        int maxSize = config.maxSize();
        if (maxSize < MIN_MAX_SIZE || maxSize > MAX_MAX_SIZE) {
            throw new IllegalStateException("server.userinfo.claims-cache.max-size=" + maxSize
                    + " out of range [" + MIN_MAX_SIZE + ", " + MAX_MAX_SIZE + "]");
        }
        long ttlSeconds = config.expireAfterWriteSeconds();
        if (ttlSeconds < MIN_EXPIRE_AFTER_WRITE_SECONDS || ttlSeconds > MAX_EXPIRE_AFTER_WRITE_SECONDS) {
            throw new IllegalStateException("server.userinfo.claims-cache.expire-after-write-seconds="
                    + ttlSeconds + " out of range [" + MIN_EXPIRE_AFTER_WRITE_SECONDS
                    + ", " + MAX_EXPIRE_AFTER_WRITE_SECONDS + "]");
        }
    }

    /**
     * Pure read; never invokes a loader and never writes the cache. Returns the immutable
     * cached snapshot if present and not yet evicted, otherwise {@link Optional#empty()}.
     *
     * <p>Returns {@link Optional#empty()} when the feature flag is off, when the userId is
     * {@code null}/blank, or when no entry is currently in the cache.
     */
    public Optional<Map<String, Object>> getIfPresent(String userId) {
        if (cache == null || userId == null || userId.isEmpty()) {
            return Optional.empty();
        }
        return Optional.ofNullable(cache.getIfPresent(userId));
    }

    /**
     * Strict write-once load-or-compute. If an entry already exists for {@code userId}, returns
     * it unchanged. Otherwise invokes {@code loader} <b>at most once across concurrent callers</b>
     * (Caffeine atomicity) and stores a defensive-copied, unmodifiable view of its return value.
     *
     * <p>The loader is null-tolerant: if it returns {@code null} or an empty map, nothing is
     * cached and a subsequent call will retry. This matches the existing {@code buildUserInfo}
     * behavior which returns an empty map on an unparseable id_token.
     *
     * <p>When the feature flag is off, the loader is invoked synchronously and its result is
     * returned without any caching (pure pass-through). The returned map is the loader's own
     * reference in this case; callers must not assume immutability in disabled mode.
     *
     * @param userId Athenz-stripped subject ("sub" with user-prefix removed). Must be non-blank;
     *               a blank key behaves like disabled mode (pure pass-through).
     * @param loader produces the stripped claim map on cache miss. Must not throw checked
     *               exceptions; a {@code RuntimeException} propagates to the caller.
     * @return the cached (or loader-produced) stripped claim map; never {@code null}
     */
    public Map<String, Object> getOrCompute(String userId, Supplier<Map<String, Object>> loader) {
        if (loader == null) {
            throw new IllegalArgumentException("loader must not be null");
        }
        if (cache == null || userId == null || userId.isEmpty()) {
            // Disabled-mode pass-through. Preserve today's semantics exactly.
            Map<String, Object> direct = loader.get();
            return direct != null ? direct : Map.of();
        }
        Map<String, Object> result = cache.get(userId, k -> {
            Map<String, Object> built = loader.get();
            if (built == null || built.isEmpty()) {
                // Returning null from a Caffeine loader means "do not cache" — Caffeine treats
                // the load as failed/empty and does not store an entry for this key.
                return null;
            }
            // Defensive copy so post-write mutation of the loader's reference can't corrupt the
            // cached snapshot; unmodifiable view so readers can't either.
            return Collections.unmodifiableMap(new HashMap<>(built));
        });
        return result != null ? result : Map.of();
    }

    /**
     * Translates Caffeine's {@link RemovalCause} into the eviction-reason labels emitted by
     * {@link OauthProxyMetrics#recordUserinfoClaimsCacheEviction(String)}. Returns {@code null}
     * for {@code REPLACED} (we never replace; would indicate a bug) so we don't pollute the
     * dashboard with a phantom outcome.
     */
    static String mapRemovalCause(RemovalCause cause) {
        return switch (cause) {
            case EXPIRED -> "expired_write";
            case SIZE -> "size";
            case COLLECTED -> "collected";
            case EXPLICIT, REPLACED -> null;
        };
    }

    /**
     * Test seam: returns Caffeine's approximate size. Production callers should consult the
     * {@code mop_userinfo_claims_cache_size} gauge instead.
     */
    long estimatedSize() {
        return cache == null ? 0L : cache.estimatedSize();
    }
}
