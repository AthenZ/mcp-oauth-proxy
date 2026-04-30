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

import io.athenz.mop.model.RefreshTokenRecord;
import io.athenz.mop.store.impl.aws.CrossRegionTokenStoreFallback;
import io.athenz.mop.store.impl.aws.RefreshTokenStoreDynamodbHelpers;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Map;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * Resolves refresh-token rows from the local DynamoDB table first, then the configured
 * cross-region peer (if enabled). Mirrors {@link UserTokenRegionResolver} for refresh-token reads.
 *
 * <p>Used by {@code RefreshTokenServiceImpl} for hash-based validation lookups, primary-key fetches
 * during rotation, and the user-provider GSI query in {@code getUpstreamRefreshToken}. Writes
 * (rotate / store / revokeFamily) stay local; replication propagates them.
 */
@ApplicationScoped
public class RefreshTokenRegionResolver {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenRegionResolver.class);

    public static final String CALL_SITE_REFRESH_TOKEN_VALIDATE = "refresh_token_validate";
    public static final String CALL_SITE_REFRESH_TOKEN_GET_PK = "refresh_token_get_pk";
    public static final String CALL_SITE_REFRESH_TOKEN_GET_UPSTREAM = "refresh_token_get_upstream";

    @Inject
    DynamoDbClient dynamoDbClient;

    @Inject
    CrossRegionTokenStoreFallback crossRegionFallback;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    @ConfigProperty(name = "server.refresh-token.table-name")
    String tableName;

    @ConfigProperty(name = "server.cross-region-fallback.region")
    Optional<String> fallbackRegionConfig;

    /**
     * Lookup a refresh-token row by hash. Tries local first; on miss, consults the peer region.
     * On peer hit, emits {@code recordCrossRegionFallbackTriggered}. On both-miss with active
     * fallback, emits {@code recordCrossRegionFallbackExhausted}.
     */
    public RefreshTokenResolution resolveByHash(String hash) {
        RefreshTokenRecord local = RefreshTokenStoreDynamodbHelpers.lookupByHash(dynamoDbClient, tableName, hash);
        if (local != null) {
            return new RefreshTokenResolution(local, false);
        }
        if (!crossRegionFallback.isRefreshAndUpstreamActive()) {
            return new RefreshTokenResolution(null, false);
        }
        RefreshTokenRecord peer = crossRegionFallback.lookupRefreshTokenByHash(hash);
        if (peer != null) {
            recordTriggered(OauthProviderLabel.normalize(peer.provider()), CALL_SITE_REFRESH_TOKEN_VALIDATE);
            return new RefreshTokenResolution(peer, true);
        }
        recordExhausted("unknown", CALL_SITE_REFRESH_TOKEN_VALIDATE);
        return new RefreshTokenResolution(null, false);
    }

    /**
     * Fetch a refresh-token row by primary key from the peer region only. The caller has already
     * checked the local region; this method exists so {@code RefreshTokenServiceImpl} can consult
     * the peer for {@code rotate}'s PK preflight without duplicating local read code.
     */
    public Map<String, AttributeValue> resolveItemByPrimaryKey(String refreshTokenId, String providerUserId) {
        if (!crossRegionFallback.isRefreshAndUpstreamActive()) {
            return null;
        }
        Map<String, AttributeValue> peer = crossRegionFallback.getRefreshTokenItemByPrimaryKey(refreshTokenId, providerUserId);
        if (peer != null) {
            String providerLabel = extractProviderLabel(peer);
            recordTriggered(providerLabel, CALL_SITE_REFRESH_TOKEN_GET_PK);
            return peer;
        }
        recordExhausted("unknown", CALL_SITE_REFRESH_TOKEN_GET_PK);
        return null;
    }

    /**
     * Resolve the best non-revoked, unexpired refresh-token row for a user/provider pair. Picks the
     * highest issued_at across both regions when both have rows.
     */
    public RefreshTokenResolution resolveBestUpstream(String userId, String provider) {
        RefreshTokenRecord local = RefreshTokenStoreDynamodbHelpers.queryBestUpstreamRefresh(
                dynamoDbClient, tableName, userId, provider);
        if (!crossRegionFallback.isRefreshAndUpstreamActive()) {
            return new RefreshTokenResolution(local, false);
        }
        RefreshTokenRecord peer = crossRegionFallback.queryBestUpstreamRefresh(userId, provider);
        String providerLabel = OauthProviderLabel.normalize(provider);
        if (local == null && peer == null) {
            recordExhausted(providerLabel, CALL_SITE_REFRESH_TOKEN_GET_UPSTREAM);
            return new RefreshTokenResolution(null, false);
        }
        if (local == null) {
            recordTriggered(providerLabel, CALL_SITE_REFRESH_TOKEN_GET_UPSTREAM);
            return new RefreshTokenResolution(peer, true);
        }
        if (peer == null) {
            return new RefreshTokenResolution(local, false);
        }
        if (peer.issuedAt() > local.issuedAt()) {
            log.info("Peer region refresh-token row is newer than local for userId={} provider={} (peer issued_at={} local issued_at={})",
                    userId, provider, peer.issuedAt(), local.issuedAt());
            recordTriggered(providerLabel, CALL_SITE_REFRESH_TOKEN_GET_UPSTREAM);
            return new RefreshTokenResolution(peer, true);
        }
        return new RefreshTokenResolution(local, false);
    }

    private static String extractProviderLabel(Map<String, AttributeValue> item) {
        AttributeValue v = item.get("provider");
        if (v == null || v.s() == null) {
            return OauthProviderLabel.UNKNOWN;
        }
        return OauthProviderLabel.normalize(v.s());
    }

    private void recordTriggered(String providerLabel, String callSite) {
        String primary = metricsRegionProvider.primaryRegion();
        String fallback = fallbackRegionConfig.map(String::trim).filter(s -> !s.isEmpty()).orElse("unknown");
        oauthProxyMetrics.recordCrossRegionFallbackTriggered(providerLabel, callSite, primary, fallback);
    }

    private void recordExhausted(String providerLabel, String callSite) {
        String primary = metricsRegionProvider.primaryRegion();
        String fallback = fallbackRegionConfig.map(String::trim).filter(s -> !s.isEmpty()).orElse("unknown");
        oauthProxyMetrics.recordCrossRegionFallbackExhausted(providerLabel, callSite, primary, fallback,
                401, "not_found");
    }
}
