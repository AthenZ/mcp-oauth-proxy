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
 * Configuration for the shared Okta upstream session cache (L0 in-memory tier fronting the bare
 * {@code (userId, "okta")} DynamoDB row).
 *
 * <p>Off by default; flip {@link #enabled()} to true after the stage soak. All values use the
 * same {@code 120s/5000/3600s} defaults in stage and prod so the stage observation reflects the
 * exact behavior prod will see.
 */
@ConfigMapping(prefix = "server.upstream.okta.session-cache")
public interface OktaSessionCacheConfig {

    /** Master switch. When false, all reads return empty and all writes are no-ops. */
    @WithDefault("false")
    boolean enabled();

    /**
     * Required remaining lifetime (seconds) for a cache hit on the {@code /token} refresh path.
     * 120s comfortably covers the longest downstream-exchange chain (Athenz ZTS + Google STS)
     * with retries and clock skew. Validated to {@code [30, 600]} at startup.
     *
     * <p>{@code /userinfo} uses 0s skew (strict {@code exp > now}) instead — the id_token is
     * never forwarded to a downstream AS on that path, so the only requirement is "not yet
     * expired."
     */
    @WithName("min-remaining-seconds")
    @WithDefault("120")
    int minRemainingSeconds();

    /**
     * Caffeine {@code maximumSize}. LRU eviction at the limit. Validated to
     * {@code [100, 100000]} at startup.
     */
    @WithName("l0-max-size")
    @WithDefault("5000")
    int l0MaxSize();

    /**
     * Caffeine {@code expireAfterWrite} in seconds. Defaults to one Okta access-token lifetime
     * (1h). Validated to {@code [600, 7200]} at startup. There is intentionally no
     * {@code expireAfterAccess} — read-time freshness is enforced via {@code OktaSessionEntry.minExp()}.
     */
    @WithName("l0-expire-after-write-seconds")
    @WithDefault("3600")
    int l0ExpireAfterWriteSeconds();
}
