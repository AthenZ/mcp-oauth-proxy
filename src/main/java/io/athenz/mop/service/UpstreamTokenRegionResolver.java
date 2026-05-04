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

import io.athenz.mop.model.UpstreamTokenRecord;
import io.athenz.mop.store.UpstreamTokenStore;
import io.athenz.mop.store.impl.aws.CrossRegionTokenStoreFallback;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves an upstream-token row (the centralized Okta refresh token) from local DynamoDB first,
 * then the configured cross-region peer (if enabled). Used by {@code UpstreamRefreshService} for
 * the read path AND for the CAS preflight inside {@code updateWithVersionCheck}: the resolver
 * exposes whether the peer carries a higher {@code version}, so the local CAS can abort instead of
 * overwriting a newer Okta refresh token written by the peer pod.
 *
 * <p>Strict no-peer-writes semantics: this resolver only reads the peer table; the actual CAS
 * write still goes against the local table with the same {@code expectedVersion}.
 */
@ApplicationScoped
public class UpstreamTokenRegionResolver {

    private static final Logger log = LoggerFactory.getLogger(UpstreamTokenRegionResolver.class);

    public static final String CALL_SITE_UPSTREAM_TOKEN_GET = "upstream_token_get";

    @Inject
    UpstreamTokenStore upstreamTokenStore;

    @Inject
    CrossRegionTokenStoreFallback crossRegionFallback;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    @ConfigProperty(name = "server.cross-region-fallback.region")
    Optional<String> fallbackRegionConfig;

    /**
     * Resolve an upstream token row by {@code provider_user_id}. Tries local first; on miss,
     * consults the peer region when the fallback bean is active. Emits triggered/exhausted metrics
     * mirroring the other resolvers. Provider label is unknown on this path (the row itself does
     * not carry one), so triggered/exhausted metrics use {@code "unknown"}.
     */
    public UpstreamTokenResolution resolveByProviderUserId(String providerUserId) {
        Optional<UpstreamTokenRecord> local = upstreamTokenStore.get(providerUserId).filter(UpstreamTokenRecord::isActive);
        if (local.isPresent()) {
            return new UpstreamTokenResolution(local.get(), false);
        }
        if (!crossRegionFallback.isRefreshAndUpstreamActive()) {
            return new UpstreamTokenResolution(null, false);
        }
        Optional<UpstreamTokenRecord> peer = crossRegionFallback.getUpstreamToken(providerUserId)
                .filter(UpstreamTokenRecord::isActive);
        if (peer.isPresent()) {
            recordTriggered();
            return new UpstreamTokenResolution(peer.get(), true);
        }
        recordExhausted();
        return new UpstreamTokenResolution(null, false);
    }

    /**
     * CAS preflight: returns the peer-region version of the upstream row, when the fallback is
     * active and a row is present. Returns {@link Optional#empty()} otherwise. Caller compares
     * this against the local {@code expectedVersion} and aborts the local CAS if the peer is
     * strictly newer.
     */
    public Optional<Long> peerVersionForCas(String providerUserId) {
        if (!crossRegionFallback.isRefreshAndUpstreamActive()) {
            return Optional.empty();
        }
        Optional<UpstreamTokenRecord> peer = crossRegionFallback.getUpstreamToken(providerUserId)
                .filter(UpstreamTokenRecord::isActive);
        if (peer.isEmpty()) {
            return Optional.empty();
        }
        long peerVersion = peer.get().version();
        log.debug("Peer upstream token version for provider_user_id={} is {}", providerUserId, peerVersion);
        return Optional.of(peerVersion);
    }

    private void recordTriggered() {
        String primary = metricsRegionProvider.primaryRegion();
        String fallback = fallbackRegionConfig.map(String::trim).filter(s -> !s.isEmpty()).orElse("unknown");
        oauthProxyMetrics.recordCrossRegionFallbackTriggered(
                "unknown", CALL_SITE_UPSTREAM_TOKEN_GET, primary, fallback);
    }

    private void recordExhausted() {
        String primary = metricsRegionProvider.primaryRegion();
        String fallback = fallbackRegionConfig.map(String::trim).filter(s -> !s.isEmpty()).orElse("unknown");
        oauthProxyMetrics.recordCrossRegionFallbackExhausted(
                "unknown", CALL_SITE_UPSTREAM_TOKEN_GET, primary, fallback,
                401, "not_found");
    }
}
