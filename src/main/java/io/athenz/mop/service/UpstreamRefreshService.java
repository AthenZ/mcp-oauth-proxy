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

import io.athenz.mop.config.UpstreamTokenConfig;
import io.athenz.mop.model.RefreshTokenRecord;
import io.athenz.mop.model.UpstreamTokenRecord;
import io.athenz.mop.store.UpstreamTokenStore;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Centralized Okta upstream refresh token: one DynamoDB item per {@code provider_user_id}, with
 * distributed lock and optimistic versioning on update.
 */
@ApplicationScoped
public class UpstreamRefreshService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final int MAX_VERSION_RETRIES = 3;

    /**
     * When we detect that the peer region has a newer view of the upstream-token row (either because
     * the row only exists in the peer, or because the peer's version is ahead), we briefly wait once
     * for DynamoDB Global Tables replication to land locally before giving up. This avoids turning a
     * sub-second replication lag into a forced re-authentication. Tests may shrink this to keep
     * suite runtime low.
     */
    static long replicationWaitMillis = 750L;

    @Inject
    UpstreamTokenStore upstreamTokenStore;

    @Inject
    OktaTokenClient oktaTokenClient;

    @Inject
    UpstreamTokenConfig upstreamTokenConfig;

    @Inject
    RefreshCoordinationService refreshCoordinationService;

    @Inject
    UpstreamTokenRegionResolver upstreamTokenRegionResolver;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    public Optional<UpstreamTokenRecord> getCurrentUpstream(String providerUserId) {
        UpstreamTokenResolution resolution = upstreamTokenRegionResolver.resolveByProviderUserId(providerUserId);
        return resolution.record() == null ? Optional.empty() : Optional.of(resolution.record());
    }

    /**
     * Persist the initial Okta refresh token after login (plaintext at app layer; encrypted at rest by DynamoDB).
     * If a row already exists with a non-empty refresh token and the incoming value differs, does not overwrite
     * (avoids stale Quarkus OIDC session tokens replacing a newer token written by refresh rotation).
     */
    public void storeInitialUpstreamToken(String providerUserId, String oktaRefreshTokenPlain) {
        if (providerUserId == null || providerUserId.isEmpty()
                || oktaRefreshTokenPlain == null || oktaRefreshTokenPlain.isEmpty()) {
            return;
        }
        UpstreamTokenResolution existingResolution = upstreamTokenRegionResolver.resolveByProviderUserId(providerUserId);
        UpstreamTokenRecord existing = existingResolution.record();
        if (existing != null) {
            String current = existing.encryptedOktaRefreshToken();
            if (current != null && !current.isEmpty()) {
                if (oktaRefreshTokenPlain.equals(current)) {
                    return;
                }
                log.info("Skipping upstream store for provider_user_id={}: centralized token already set (avoid stale session downgrade, fromFallback={})",
                        providerUserId, existingResolution.resolvedFromFallback());
                return;
            }
        }
        String now = Instant.now().toString();
        long ttl = computeTtlEpochSeconds();
        UpstreamTokenRecord record = UpstreamTokenRecord.builder()
                .providerUserId(providerUserId)
                .encryptedOktaRefreshToken(oktaRefreshTokenPlain)
                .lastRotatedAt(now)
                .version(1L)
                .ttl(ttl)
                .createdAt(now)
                .updatedAt(now)
                .build();
        upstreamTokenStore.save(record);
        log.info("Stored initial upstream Okta refresh token for provider_user_id={}", providerUserId);
    }

    /**
     * If the centralized row is missing but the legacy per-row refresh record still has an upstream token,
     * copy it into the upstream table (migration).
     */
    public void ensureMigratedFromLegacyIfNeeded(String providerUserId, RefreshTokenRecord legacyRecord) {
        if (providerUserId == null || providerUserId.isEmpty() || legacyRecord == null) {
            return;
        }
        if (upstreamTokenRegionResolver.resolveByProviderUserId(providerUserId).record() != null) {
            return;
        }
        String legacyRt = legacyRecord.encryptedUpstreamRefreshToken();
        if (legacyRt == null || legacyRt.isEmpty()) {
            return;
        }
        // TODO: Remove after migration window (legacy per-row upstream reads no longer needed)
        log.info("Migrating legacy upstream Okta refresh into centralized store for provider_user_id={}", providerUserId);
        storeInitialUpstreamToken(providerUserId, legacyRt);
    }

    /**
     * Refresh Okta tokens using the centralized store, under a distributed lock and with version retries.
     */
    public OktaTokens refreshUpstream(String providerUserId) {
        refreshCoordinationService.acquireUpstream(providerUserId);
        try {
            // We only ever wait for cross-region replication once per /token request: a single
            // sub-second sleep is enough for Global Tables to converge in the common case, and
            // anything longer should fail fast as transient so the client can retry.
            boolean waitedForReplication = false;
            for (int attempt = 0; attempt < MAX_VERSION_RETRIES; attempt++) {
                UpstreamTokenResolution resolution = upstreamTokenRegionResolver.resolveByProviderUserId(providerUserId);
                UpstreamTokenRecord rec = resolution.record();
                if (rec == null) {
                    throw new UpstreamRefreshException("No upstream Okta refresh token; re-authentication required");
                }
                String plainRt = rec.encryptedOktaRefreshToken();
                if (plainRt == null || plainRt.isEmpty()) {
                    throw new UpstreamRefreshException("Upstream record has no Okta refresh token; re-authentication required");
                }
                if (resolution.resolvedFromFallback()) {
                    if (!waitedForReplication) {
                        waitedForReplication = true;
                        sleepForReplicationOrInterrupt(providerUserId, "row only in peer", rec.version());
                        continue;
                    }
                    log.info("Aborting upstream refresh attempt for provider_user_id={}: row only present in peer region (version={}) after replication wait. Returning transient error so client can retry.",
                            providerUserId, rec.version());
                    oauthProxyMetrics.recordUpstreamTokenCasAbortedPeerNewer(providerUserId);
                    oauthProxyMetrics.recordUpstreamTokenReplicationWait("still_stale");
                    throw new UpstreamRefreshTransientException(
                            "Upstream Okta refresh token only present in peer region; awaiting cross-region replication");
                }
                Optional<Long> peerVersion = upstreamTokenRegionResolver.peerVersionForCas(providerUserId);
                if (peerVersion.isPresent() && peerVersion.get() > rec.version()) {
                    if (!waitedForReplication) {
                        waitedForReplication = true;
                        sleepForReplicationOrInterrupt(providerUserId,
                                "peer version " + peerVersion.get() + " > local " + rec.version(),
                                rec.version());
                        continue;
                    }
                    log.info("Aborting local CAS write for provider_user_id={}: peer version {} > local version {} after replication wait; returning transient error",
                            providerUserId, peerVersion.get(), rec.version());
                    oauthProxyMetrics.recordUpstreamTokenCasAbortedPeerNewer(providerUserId);
                    oauthProxyMetrics.recordUpstreamTokenReplicationWait("still_stale");
                    throw new UpstreamRefreshTransientException(
                            "Upstream Okta refresh token rotated in peer region; awaiting cross-region replication");
                }
                if (waitedForReplication) {
                    log.info("Replication wait succeeded for provider_user_id={}: local row caught up (version={}); proceeding with Okta refresh",
                            providerUserId, rec.version());
                    oauthProxyMetrics.recordUpstreamTokenReplicationWait("succeeded");
                }
                try {
                    OktaTokens tokens = oktaTokenClient.refreshToken(plainRt);
                    boolean updated = upstreamTokenStore.updateWithVersionCheck(
                            providerUserId, tokens.refreshToken(), rec.version());
                    if (updated) {
                        return tokens;
                    }
                } catch (OktaTokenRevokedException e) {
                    upstreamTokenStore.delete(providerUserId);
                    throw new UpstreamRefreshException("Upstream Okta token revoked; re-authentication required", e);
                }
                log.debug("Upstream version conflict for provider_user_id={} attempt={}", providerUserId, attempt + 1);
            }
            throw new UpstreamRefreshException("Could not update centralized upstream token after retries");
        } finally {
            refreshCoordinationService.releaseUpstream(providerUserId);
        }
    }

    private void sleepForReplicationOrInterrupt(String providerUserId, String reason, long localVersion) {
        long waitMillis = replicationWaitMillis;
        log.info("Waiting {}ms for cross-region replication on provider_user_id={} ({}), local version={}",
                waitMillis, providerUserId, reason, localVersion);
        if (waitMillis <= 0) {
            return;
        }
        try {
            Thread.sleep(waitMillis);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new UpstreamRefreshTransientException(
                    "Interrupted while waiting for cross-region upstream-token replication");
        }
    }

    private long computeTtlEpochSeconds() {
        return Instant.now()
                .plus(upstreamTokenConfig.expirySeconds(), ChronoUnit.SECONDS)
                .plus(upstreamTokenConfig.ttlBufferDays(), ChronoUnit.DAYS)
                .getEpochSecond();
    }
}
