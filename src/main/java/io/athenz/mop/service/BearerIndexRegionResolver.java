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

import io.athenz.mop.model.BearerIndexRecord;
import io.athenz.mop.store.BearerIndexStore;
import io.athenz.mop.store.impl.aws.CrossRegionTokenStoreFallback;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * Resolves bearer-index rows by hash from the local store first, then the configured cross-region
 * peer (if enabled). Mirrors {@link UserTokenRegionResolver} for the new
 * {@code mcp-oauth-proxy-bearer-index} table.
 *
 * <p>Reads on miss / cross-region replication lag stay covered by the existing fallback bean
 * (single fallback client; the bearer-index table is unencrypted so no extra interceptor wiring
 * is needed). Writes go through {@link BearerIndexStore} directly into the local region;
 * Global Tables replication propagates them.
 */
@ApplicationScoped
public class BearerIndexRegionResolver {

    public static final String CALL_SITE_USERINFO_BEARER_LOOKUP = "userinfo_bearer_lookup";

    @Inject
    BearerIndexStore bearerIndexStore;

    @Inject
    CrossRegionTokenStoreFallback crossRegionFallback;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    @ConfigProperty(name = "server.cross-region-fallback.region")
    Optional<String> fallbackRegionConfig;

    /**
     * Resolve a bearer-index row by hash. Tries local first; on miss, consults the peer region
     * when the master fallback flag is on. Provider label is unknown until a row is found, so the
     * miss/exhaust metric uses {@code "unknown"} for {@code oauth_provider}.
     */
    public BearerIndexResolution resolveByHash(String accessTokenHash) {
        BearerIndexRecord local = bearerIndexStore.getBearer(accessTokenHash);
        if (local != null) {
            oauthProxyMetrics.recordBearerIndexLookup("hit");
            return new BearerIndexResolution(local, false);
        }
        if (!crossRegionFallback.isActive()) {
            oauthProxyMetrics.recordBearerIndexLookup("miss");
            return new BearerIndexResolution(null, false);
        }
        BearerIndexRecord peer = crossRegionFallback.getBearerIndex(accessTokenHash);
        if (peer != null) {
            String providerLabel = OauthProviderLabel.normalize(peer.provider());
            recordTriggered(providerLabel);
            oauthProxyMetrics.recordBearerIndexLookup("from_fallback");
            return new BearerIndexResolution(peer, true);
        }
        recordExhausted("unknown");
        oauthProxyMetrics.recordBearerIndexLookup("miss");
        return new BearerIndexResolution(null, false);
    }

    private void recordTriggered(String providerLabel) {
        String primary = metricsRegionProvider.primaryRegion();
        String fallback = fallbackRegionConfig.map(String::trim).filter(s -> !s.isEmpty()).orElse("unknown");
        oauthProxyMetrics.recordCrossRegionFallbackTriggered(providerLabel, CALL_SITE_USERINFO_BEARER_LOOKUP,
                primary, fallback);
    }

    private void recordExhausted(String providerLabel) {
        String primary = metricsRegionProvider.primaryRegion();
        String fallback = fallbackRegionConfig.map(String::trim).filter(s -> !s.isEmpty()).orElse("unknown");
        oauthProxyMetrics.recordCrossRegionFallbackExhausted(providerLabel, CALL_SITE_USERINFO_BEARER_LOOKUP,
                primary, fallback, 401, "not_found");
    }
}
