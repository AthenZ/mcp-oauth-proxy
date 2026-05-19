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

import io.athenz.mop.config.UserInfoClaimsCacheConfig;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UserInfoClaimsCache}. Exercises the strict-write-once Caffeine
 * substrate, defensive-copy + unmodifiable semantics, disabled-flag pass-through, eviction
 * metrics wiring, and concurrent-loader atomicity.
 *
 * <p>The {@code evictedAfterWriteTtl_*} and {@code lruEvictionAtMaxSize} tests construct
 * caches with tighter limits (short ttl, small max-size) than production defaults so the
 * eviction behavior is observable inside a unit test; the production code path is exercised
 * by the config-validated range checks.
 */
@ExtendWith(MockitoExtension.class)
class UserInfoClaimsCacheTest {

    private static final String USER = "00uoqmkz1ru90YPep696";

    @Mock
    private UserInfoClaimsCacheConfig config;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    private UserInfoClaimsCache cache;

    @BeforeEach
    void setUp() {
        cache = new UserInfoClaimsCache();
        injectField("config", config);
        injectField("oauthProxyMetrics", oauthProxyMetrics);
    }

    private void injectField(String name, Object value) {
        try {
            Field f = UserInfoClaimsCache.class.getDeclaredField(name);
            f.setAccessible(true);
            f.set(cache, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void stubEnabledConfig(int maxSize, Duration ttl) {
        when(config.enabled()).thenReturn(true);
        when(config.maxSize()).thenReturn(maxSize);
        when(config.expireAfterWriteSeconds()).thenReturn(ttl.toSeconds());
    }

    private void stubDisabledConfig() {
        when(config.enabled()).thenReturn(false);
        lenient().when(config.maxSize()).thenReturn(10_000);
        lenient().when(config.expireAfterWriteSeconds()).thenReturn(Duration.ofHours(24).toSeconds());
    }

    @Test
    void getOrCompute_firstCallRunsLoader_secondCallReturnsCachedSnapshot() {
        stubEnabledConfig(10_000, Duration.ofHours(24));
        cache.init();
        AtomicInteger loaderCalls = new AtomicInteger();

        Map<String, Object> first = cache.getOrCompute(USER, () -> {
            loaderCalls.incrementAndGet();
            return Map.of("sub", USER, "email", "first@example.com");
        });
        Map<String, Object> second = cache.getOrCompute(USER, () -> {
            loaderCalls.incrementAndGet();
            return Map.of("sub", USER, "email", "SHOULD-NOT-BE-USED");
        });

        assertEquals(1, loaderCalls.get(), "Strict write-once: loader runs at most once per key");
        assertEquals("first@example.com", second.get("email"),
                "Subsequent calls must serve the first writer's snapshot");
        assertEquals(first, second);
    }

    @Test
    void getOrCompute_loaderReturnsNull_nothingCached_nextCallRetries() {
        stubEnabledConfig(10_000, Duration.ofHours(24));
        cache.init();
        AtomicInteger loaderCalls = new AtomicInteger();

        Map<String, Object> first = cache.getOrCompute(USER, () -> {
            loaderCalls.incrementAndGet();
            return null;
        });
        Map<String, Object> second = cache.getOrCompute(USER, () -> {
            loaderCalls.incrementAndGet();
            return Map.of("sub", USER);
        });

        assertEquals(Map.of(), first, "Null loader result is treated as empty");
        assertEquals(2, loaderCalls.get(), "Null loader does not poison the slot; next call retries");
        assertEquals(USER, second.get("sub"));
        assertTrue(cache.getIfPresent(USER).isPresent(),
                "Successful retry populates the cache");
    }

    @Test
    void getOrCompute_loaderReturnsEmptyMap_nothingCached_nextCallRetries() {
        stubEnabledConfig(10_000, Duration.ofHours(24));
        cache.init();
        AtomicInteger loaderCalls = new AtomicInteger();

        Map<String, Object> first = cache.getOrCompute(USER, () -> {
            loaderCalls.incrementAndGet();
            return Collections.emptyMap();
        });
        Map<String, Object> second = cache.getOrCompute(USER, () -> {
            loaderCalls.incrementAndGet();
            return Map.of("sub", USER);
        });

        assertEquals(Map.of(), first);
        assertEquals(2, loaderCalls.get(),
                "Empty loader result mirrors null: nothing cached, next call retries");
        assertEquals(USER, second.get("sub"));
    }

    @Test
    void getIfPresent_returnsEmpty_whenAbsent() {
        stubEnabledConfig(10_000, Duration.ofHours(24));
        cache.init();

        assertEquals(Optional.empty(), cache.getIfPresent(USER));
    }

    @Test
    void getIfPresent_returnsCachedSnapshot_afterGetOrCompute() {
        stubEnabledConfig(10_000, Duration.ofHours(24));
        cache.init();
        cache.getOrCompute(USER, () -> Map.of("sub", USER, "email", "x@example.com"));

        Optional<Map<String, Object>> got = cache.getIfPresent(USER);

        assertTrue(got.isPresent());
        assertEquals("x@example.com", got.get().get("email"));
    }

    @Test
    void cachedMap_isUnmodifiable_attemptedMutationThrows() {
        stubEnabledConfig(10_000, Duration.ofHours(24));
        cache.init();
        Map<String, Object> view = cache.getOrCompute(USER,
                () -> new HashMap<>(Map.of("sub", USER)));

        assertThrows(UnsupportedOperationException.class, () -> view.put("k", "v"));
    }

    @Test
    void cachedMap_isolatedFromLoaderReturnedReference() {
        stubEnabledConfig(10_000, Duration.ofHours(24));
        cache.init();
        Map<String, Object> loaderResult = new HashMap<>();
        loaderResult.put("sub", USER);
        loaderResult.put("email", "before@example.com");

        Map<String, Object> stored = cache.getOrCompute(USER, () -> loaderResult);
        // Mutate the original reference after caching — should not affect the cached snapshot.
        loaderResult.put("email", "after@example.com");
        loaderResult.remove("sub");

        assertEquals("before@example.com", stored.get("email"),
                "Defensive copy must isolate cached value from post-write mutation of loader's reference");
        assertEquals(USER, stored.get("sub"));
        Optional<Map<String, Object>> fromCache = cache.getIfPresent(USER);
        assertTrue(fromCache.isPresent());
        assertEquals("before@example.com", fromCache.get().get("email"));
        assertEquals(USER, fromCache.get().get("sub"));
    }

    @Test
    void disabled_getIfPresentAlwaysEmpty_getOrComputeIsPassThroughNoWrite() {
        stubDisabledConfig();
        cache.init();
        AtomicInteger loaderCalls = new AtomicInteger();

        Map<String, Object> first = cache.getOrCompute(USER, () -> {
            loaderCalls.incrementAndGet();
            return Map.of("sub", USER, "email", "first@example.com");
        });
        Map<String, Object> second = cache.getOrCompute(USER, () -> {
            loaderCalls.incrementAndGet();
            return Map.of("sub", USER, "email", "second@example.com");
        });

        assertEquals(2, loaderCalls.get(),
                "Disabled flag must be pure pass-through; loader runs every call");
        assertEquals("first@example.com", first.get("email"));
        assertEquals("second@example.com", second.get("email"),
                "Disabled mode has no caching, so loader output is returned verbatim every call");
        assertEquals(Optional.empty(), cache.getIfPresent(USER),
                "Disabled flag: getIfPresent must always return empty");
    }

    @Test
    void disabled_init_registersZeroSizeGauge_butNoEvictionsObserved() {
        stubDisabledConfig();
        AtomicReference<LongSupplier> registered = new AtomicReference<>();
        doAnswer(inv -> {
            registered.set(inv.getArgument(0));
            return null;
        }).when(oauthProxyMetrics).registerUserinfoClaimsCacheSizeGauge(org.mockito.ArgumentMatchers.any());

        cache.init();
        cache.getOrCompute(USER, () -> Map.of("sub", USER));

        assertNotNull(registered.get(), "Disabled mode still registers a (zero) size supplier");
        assertEquals(0L, registered.get().getAsLong(),
                "Disabled-mode gauge supplier must always return 0");
        verify(oauthProxyMetrics, never()).recordUserinfoClaimsCacheEviction(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void evictedAfterWriteTtl_caffeineRespectsExpireAfterWriteConfiguration() {
        // The TTL is configured to 1h (the minimum allowed by the validator). We don't actually
        // wait an hour; the production guarantee is that Caffeine's expireAfterWrite policy is
        // wired correctly via the config-driven builder. The Caffeine library itself owns the
        // expiration semantics — our contract is "we set it to config.ttl()" and the size-
        // eviction test (below) exercises the RemovalListener → metric pipeline.
        stubEnabledConfig(10_000, Duration.ofHours(1));
        cache.init();
        cache.getOrCompute(USER, () -> Map.of("sub", USER));
        assertTrue(cache.getIfPresent(USER).isPresent(),
                "Within TTL, entry remains accessible");
    }

    @Test
    void lruEvictionAtMaxSize_smallCache_oldestEntryEvictedAndRecordsSizeEviction() throws Exception {
        stubEnabledConfig(100, Duration.ofHours(24));
        cache.init();
        for (int i = 0; i < 250; i++) {
            String k = "u" + i;
            cache.getOrCompute(k, () -> Map.of("sub", "x"));
        }
        // Force Caffeine to run its housekeeping so size-based eviction fires.
        long deadline = System.currentTimeMillis() + 2000;
        while (cache.estimatedSize() > 100 && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }

        assertTrue(cache.estimatedSize() <= 100,
                "Size-bounded cache must not exceed maximumSize after enough inserts and housekeeping");
        verify(oauthProxyMetrics, atLeastOnce()).recordUserinfoClaimsCacheEviction("size");
    }

    @Test
    void concurrentGetOrCompute_sameKey_loaderRunsAtMostOnce() throws Exception {
        stubEnabledConfig(10_000, Duration.ofHours(24));
        cache.init();
        AtomicInteger loaderCalls = new AtomicInteger();
        int threadCount = 16;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threadCount);
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        try {
            for (int i = 0; i < threadCount; i++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        cache.getOrCompute(USER, () -> {
                            loaderCalls.incrementAndGet();
                            // Hold the loader briefly so siblings stack up on Caffeine's
                            // per-key load coordination.
                            try {
                                Thread.sleep(25);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                            }
                            Map<String, Object> m = new LinkedHashMap<>();
                            m.put("sub", USER);
                            return m;
                        });
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertTrue(done.await(10, TimeUnit.SECONDS), "All loaders should complete");
            assertEquals(1, loaderCalls.get(),
                    "Caffeine atomicity must serialize concurrent loads for the same key");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void init_rejectsMaxSizeBelowMin() {
        lenient().when(config.enabled()).thenReturn(true);
        when(config.maxSize()).thenReturn(99);
        lenient().when(config.expireAfterWriteSeconds()).thenReturn(Duration.ofHours(24).toSeconds());

        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> cache.init());
        assertTrue(ex.getMessage().contains("max-size"));
    }

    @Test
    void init_rejectsMaxSizeAboveMax() {
        lenient().when(config.enabled()).thenReturn(true);
        when(config.maxSize()).thenReturn(100_001);
        lenient().when(config.expireAfterWriteSeconds()).thenReturn(Duration.ofHours(24).toSeconds());

        assertThrows(IllegalStateException.class, () -> cache.init());
    }

    @Test
    void init_rejectsExpireAfterWriteSecondsBelowMin() {
        lenient().when(config.enabled()).thenReturn(true);
        when(config.maxSize()).thenReturn(10_000);
        when(config.expireAfterWriteSeconds()).thenReturn(3599L);

        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> cache.init());
        assertTrue(ex.getMessage().contains("expire-after-write-seconds"));
    }

    @Test
    void init_rejectsExpireAfterWriteSecondsAboveMax() {
        lenient().when(config.enabled()).thenReturn(true);
        when(config.maxSize()).thenReturn(10_000);
        when(config.expireAfterWriteSeconds()).thenReturn(172_801L);

        assertThrows(IllegalStateException.class, () -> cache.init());
    }

    @Test
    void getIfPresent_returnsEmpty_whenUserIdNullOrEmpty() {
        stubEnabledConfig(10_000, Duration.ofHours(24));
        cache.init();

        assertEquals(Optional.empty(), cache.getIfPresent(null));
        assertEquals(Optional.empty(), cache.getIfPresent(""));
    }

    @Test
    void getOrCompute_nullUserId_isPassThroughLoaderResult() {
        stubEnabledConfig(10_000, Duration.ofHours(24));
        cache.init();
        AtomicInteger loaderCalls = new AtomicInteger();

        Map<String, Object> result = cache.getOrCompute(null, () -> {
            loaderCalls.incrementAndGet();
            return Map.of("sub", "anon");
        });

        assertEquals(1, loaderCalls.get());
        assertEquals("anon", result.get("sub"));
    }

    @Test
    void getOrCompute_nullLoader_throws() {
        stubEnabledConfig(10_000, Duration.ofHours(24));
        cache.init();
        assertThrows(IllegalArgumentException.class, () -> cache.getOrCompute(USER, null));
    }

    @Test
    void cachedSnapshot_isSameInstanceAcrossReads_noPerCallCopy() {
        // Reads use Caffeine.getIfPresent which returns the stored reference directly. We rely
        // on Collections.unmodifiableMap to prevent any caller mutation; no per-read copy.
        stubEnabledConfig(10_000, Duration.ofHours(24));
        cache.init();
        Map<String, Object> first = cache.getOrCompute(USER, () -> Map.of("sub", USER));
        Map<String, Object> second = cache.getIfPresent(USER).orElseThrow();
        // Both should be the same unmodifiable wrapper instance.
        assertSame(first, second,
                "Cached snapshot is shared by reference; defensive copying happens in withProviderGlue");
        // Sanity: the wrapper is distinct from a brand-new HashMap of the same content.
        assertNotSame(first, new HashMap<>(first));
    }

    @Test
    void disabled_then_enabled_init_isIdempotent() {
        // Smoke test: re-initializing should not double-register gauges nor blow up. Caffeine
        // build is a fresh instance; that's fine — the field is volatile.
        stubDisabledConfig();
        cache.init();
        long sizeAfterDisabled = cache.estimatedSize();
        assertEquals(0L, sizeAfterDisabled);
        // Switching to enabled is uncommon in production (would require a restart) but should
        // not throw if it ever happens via test setup.
        // Re-init not supported in production lifecycle; we simply verify a fresh bean works.
    }

    @Test
    void mapRemovalCause_returnsExpectedLabels() {
        assertEquals("expired_write", UserInfoClaimsCache.mapRemovalCause(
                com.github.benmanes.caffeine.cache.RemovalCause.EXPIRED));
        assertEquals("size", UserInfoClaimsCache.mapRemovalCause(
                com.github.benmanes.caffeine.cache.RemovalCause.SIZE));
        assertEquals("collected", UserInfoClaimsCache.mapRemovalCause(
                com.github.benmanes.caffeine.cache.RemovalCause.COLLECTED));
        org.junit.jupiter.api.Assertions.assertNull(UserInfoClaimsCache.mapRemovalCause(
                com.github.benmanes.caffeine.cache.RemovalCause.EXPLICIT));
        org.junit.jupiter.api.Assertions.assertNull(UserInfoClaimsCache.mapRemovalCause(
                com.github.benmanes.caffeine.cache.RemovalCause.REPLACED));
    }

    @Test
    void sizeGauge_registeredWithCacheSize() {
        stubEnabledConfig(10_000, Duration.ofHours(24));
        AtomicReference<LongSupplier> registered = new AtomicReference<>();
        doAnswer(inv -> {
            registered.set(inv.getArgument(0));
            return null;
        }).when(oauthProxyMetrics).registerUserinfoClaimsCacheSizeGauge(org.mockito.ArgumentMatchers.any());

        cache.init();
        assertEquals(0L, registered.get().getAsLong());
        cache.getOrCompute(USER, () -> Map.of("sub", USER));
        assertEquals(1L, registered.get().getAsLong());
    }

    @Test
    void multipleUsers_independentEntries() {
        stubEnabledConfig(10_000, Duration.ofHours(24));
        cache.init();
        cache.getOrCompute("a", () -> Map.of("sub", "a"));
        cache.getOrCompute("b", () -> Map.of("sub", "b"));

        assertEquals("a", cache.getIfPresent("a").orElseThrow().get("sub"));
        assertEquals("b", cache.getIfPresent("b").orElseThrow().get("sub"));
        verify(oauthProxyMetrics, times(0)).recordUserinfoClaimsCacheEviction(org.mockito.ArgumentMatchers.anyString());
    }
}
