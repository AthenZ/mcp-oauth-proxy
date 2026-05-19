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
package io.athenz.mop.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;

/**
 * Configuration for the per-pod, strict-write-once cache of stripped {@code /userinfo} claim
 * maps keyed by user subject. The cache fronts {@code UserInfoResource}'s Okta resolution
 * flow: when a bearer-index lookup succeeds and an entry exists for the user,
 * {@code /userinfo} returns 200 without touching {@code tryRefreshOktaToken} or any Okta
 * upstream code. Otherwise the existing flow runs unchanged and the first successful claim
 * map is written into the cache; subsequent writes are silent no-ops (strict write-once) until
 * {@link #expireAfterWriteSeconds()} fires.
 *
 * <p>Off by default ({@link #enabled()} = {@code false}). When disabled, the cache bean's
 * {@code getIfPresent} returns empty and {@code getOrCompute} is a pure pass-through, so
 * {@code /userinfo} behavior is byte-identical to the pre-cache implementation. Flip on after
 * the stage soak.
 *
 * <p>Validation is performed at startup inside {@code UserInfoClaimsCache.init(...)} and refuses
 * to boot if {@link #maxSize()} or {@link #expireAfterWriteSeconds()} are outside the allowed
 * ranges.
 */
@ConfigMapping(prefix = "server.userinfo.claims-cache")
public interface UserInfoClaimsCacheConfig {

    /** Master switch. When false, reads return empty and writes are pure pass-throughs. */
    @WithDefault("false")
    boolean enabled();

    /**
     * Caffeine {@code maximumSize}. LRU eviction at the limit. Validated to
     * {@code [100, 100000]} at startup. Default 10000 entries gives ~50 MB heap headroom at
     * p95 claim-map size, well under 1% of pod heap.
     */
    @WithName("max-size")
    @WithDefault("10000")
    int maxSize();

    /**
     * Caffeine {@code expireAfterWrite} in seconds. Hard upper bound for cached claim
     * staleness — the snapshot is written once on first miss and not refreshed until eviction.
     * Validated to {@code [3600, 172800]} (1h to 48h) at startup. Default 86400 (24h) matches
     * typical Okta session lifetimes.
     */
    @WithName("expire-after-write-seconds")
    @WithDefault("86400")
    long expireAfterWriteSeconds();
}
