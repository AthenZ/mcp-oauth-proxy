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

import io.athenz.mop.config.OktaSessionCacheConfig;
import io.athenz.mop.config.UpstreamTokenConfig;
import io.athenz.mop.model.RefreshTokenRecord;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.model.UpstreamTokenRecord;
import io.athenz.mop.store.UpstreamTokenStore;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Centralized upstream refresh-token service: one DynamoDB item per {@code provider#sub} in the
 * {@code mcp-oauth-proxy-upstream-tokens} table, with a distributed lock plus optimistic
 * versioning on update.
 *
 * <p>Originally Okta-only, the service is now generalized for any promoted upstream IdP. Today
 * the allow-list is {@code okta + 12 google-workspace}; see {@link UpstreamProviderClassifier}.
 *
 * <p>Two refresh entry points exist:
 * <ul>
 *   <li>{@link #refreshUpstream(String)} — legacy Okta-only entry returning {@link OktaTokens}.
 *       Kept so existing TokenResource Okta callers compile unchanged. Internally calls the new
 *       overload with {@code provider="okta", clientId=null}.</li>
 *   <li>{@link #refreshUpstream(String, String, String)} — provider-aware entry returning
 *       {@link UpstreamRefreshResponse}. Used by the new Google Workspace path. Per-client AT
 *       cells (L0 + L1) are populated under the supplied {@code clientId}; pass null for legacy
 *       behavior (single shared cell, Okta path).</li>
 * </ul>
 *
 * <p>Path E (reuse-within-grace): when a second client acquires the L2 lock within
 * {@link #l2AtReuseGraceSeconds} of another client rotating, AND the staged AT still has at
 * least {@link #l2AtReuseMinRemainingSeconds} of TTL left, this service copies the staged
 * AT into the calling client's per-client L0/L1 cells without issuing a fresh upstream refresh.
 * That is what coalesces concurrent multi-client refresh storms into a single Google call.
 */
@ApplicationScoped
public class UpstreamRefreshService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final int MAX_VERSION_RETRIES = 3;

    /**
     * Rotation freshness window for Path E (reuse-within-grace). When a client arrives at the L2
     * lock and the staged AT was minted within this many seconds, it is eligible for reuse.
     * Package-visible (non-final) so tests can override deterministically without standing up
     * the full ConfigProperty wiring.
     */
    @ConfigProperty(name = "server.upstream-token.l2-at-reuse-grace-seconds", defaultValue = "30")
    long l2AtReuseGraceSeconds;

    /**
     * Minimum remaining TTL on the staged AT for Path E to fire. Defends against handing out an
     * AT that's about to expire mid-flight even if it was rotated within the grace window.
     */
    @ConfigProperty(name = "server.upstream-token.l2-at-reuse-min-remaining-seconds", defaultValue = "60")
    long l2AtReuseMinRemainingSeconds;

    /**
     * When we detect that the peer region has a newer view of the upstream-token row (either because
     * the row only exists in the peer, or because the peer's version is ahead), we briefly wait once
     * for DynamoDB Global Tables replication to land locally before giving up. This avoids turning a
     * sub-second replication lag into a forced re-authentication. Tests may shrink this to keep
     * suite runtime low.
     */
    @ConfigProperty(name = "server.upstream-token.replication-wait-millis", defaultValue = "750")
    long replicationWaitMillis;

    @Inject
    UpstreamTokenStore upstreamTokenStore;

    @Inject
    OktaTokenClient oktaTokenClient;

    @Inject
    GoogleWorkspaceUpstreamRefreshClient googleWorkspaceUpstreamRefreshClient;

    @Inject
    UpstreamProviderClassifier upstreamProviderClassifier;

    @Inject
    UpstreamTokenConfig upstreamTokenConfig;

    @Inject
    RefreshCoordinationService refreshCoordinationService;

    @Inject
    UpstreamTokenRegionResolver upstreamTokenRegionResolver;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    OktaSessionCache oktaSessionCache;

    @Inject
    OktaSessionCacheConfig oktaSessionCacheConfig;

    @Inject
    UserTokenRegionResolver userTokenRegionResolver;

    @Inject
    IdpSessionCache idpSessionCache;

    /**
     * Returns the current ACTIVE upstream Okta record for {@code providerUserId}, or {@link Optional#empty()}
     * if no row exists or the existing row is non-ACTIVE (e.g. REVOKED_INVALID_GRANT).
     *
     * <p>Callers (notably {@code AuthorizeResource}'s sibling-borrow path) MUST treat a non-ACTIVE row
     * the same as a missing row: an explicit re-login should be required to recover. Returning the
     * REVOKED row here would let a borrower attempt to refresh against a known-bad RT and produce
     * confusing {@code invalid_grant} errors mid-flight.
     */
    public Optional<UpstreamTokenRecord> getCurrentUpstream(String providerUserId) {
        UpstreamTokenResolution resolution = upstreamTokenRegionResolver.resolveByProviderUserId(providerUserId);
        UpstreamTokenRecord rec = resolution.record();
        if (rec == null) {
            return Optional.empty();
        }
        if (!rec.isActive()) {
            log.info(
                    "getCurrentUpstream returning empty for provider_user_id={}: row is non-active (status={} version={})",
                    providerUserId, rec.status(), rec.version());
            return Optional.empty();
        }
        return Optional.of(rec);
    }

    /**
     * Persist the initial Okta refresh token after login (plaintext at app layer; encrypted at rest by DynamoDB).
     *
     * <p>Skips the write when an <em>active</em> row already carries a non-empty refresh token, so a
     * stale Quarkus OIDC session value can't downgrade a freshly-rotated RT written by the refresh
     * path. When the existing row is in a non-ACTIVE state (e.g. {@code REVOKED_INVALID_GRANT}),
     * the row is treated as absent and the new login's RT re-seeds it as a clean ACTIVE row with
     * {@code version=1} — this is the explicit "log in again after revoke" recovery path. Without
     * this, recovery would silently rely on {@code markRevoked} having cleared
     * {@code encryptedOktaRefreshToken} to {@code ""}, which is a fragile invariant for any future
     * code path that writes a non-ACTIVE row without clearing the secret material.
     */
    public void storeInitialUpstreamToken(String providerUserId, String oktaRefreshTokenPlain) {
        if (providerUserId == null || providerUserId.isEmpty()
                || oktaRefreshTokenPlain == null || oktaRefreshTokenPlain.isEmpty()) {
            return;
        }
        UpstreamTokenResolution existingResolution = upstreamTokenRegionResolver.resolveByProviderUserId(providerUserId);
        UpstreamTokenRecord existing = existingResolution.record();
        if (existing != null && existing.isActive()) {
            String current = existing.encryptedOktaRefreshToken();
            if (current != null && !current.isEmpty()) {
                if (oktaRefreshTokenPlain.equals(current)) {
                    return;
                }
                log.info("Skipping upstream store for provider_user_id={}: active centralized token already set (avoid stale session downgrade, fromFallback={})",
                        providerUserId, existingResolution.resolvedFromFallback());
                return;
            }
        } else if (existing != null) {
            log.info("Re-seeding upstream refresh token for provider_user_id={}: existing row is non-active (status={} version={}); writing fresh ACTIVE row with version=1",
                    providerUserId, existing.status(), existing.version());
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
        log.info("Stored initial upstream refresh token for provider_user_id={}", providerUserId);
    }

    /**
     * Okta-only legacy migration shim — kept for back-compat with existing call sites that pass an
     * Okta {@code RefreshTokenRecord}. Delegates to the provider-aware overload below using the
     * "okta" provider label. New callers should prefer
     * {@link #ensureMigratedFromLegacyIfNeeded(String, String, RefreshTokenRecord)}.
     */
    public void ensureMigratedFromLegacyIfNeeded(String providerUserId, RefreshTokenRecord legacyRecord) {
        ensureMigratedFromLegacyIfNeeded(providerUserId, AudienceConstants.PROVIDER_OKTA, legacyRecord);
    }

    /**
     * Provider-aware legacy-RT migration. If the centralized L2 row for {@code providerUserId} is
     * either missing entirely or present but carries no usable RT, and the in-hand
     * {@link RefreshTokenRecord} still has an {@code encrypted_upstream_refresh_token}, copy that
     * legacy value into the L2 table so the next {@link #refreshUpstream(String, String, String)}
     * call has a row to read from.
     *
     * <p>This is the read-side migration step that lets in-flight families (those minted before the
     * L2 promotion was deployed for a given provider) keep working. Without it, the very first
     * {@code /token refresh_token} call after deployment would fail with "no upstream RT" and
     * revoke the family — which is exactly what we observed for google-slides on 2026-05-04.
     *
     * <p>Idempotency: this method is safe to call repeatedly; once the L2 row exists with a usable
     * RT, subsequent invocations are no-ops because {@link #storeInitialUpstreamToken} short-
     * circuits when an active row is already present.
     *
     * @param providerUserId canonical L2 row key (e.g. {@code "google-slides#alice-sub"}, {@code "okta#…"}).
     * @param provider       provider id; used only for log/event labels. May be null/empty (the
     *                       method falls back to a generic label).
     * @param legacyRecord   refresh-token row from the MoP refresh-tokens table whose
     *                       {@code encrypted_upstream_refresh_token} column holds the legacy seed.
     */
    public void ensureMigratedFromLegacyIfNeeded(String providerUserId, String provider, RefreshTokenRecord legacyRecord) {
        if (providerUserId == null || providerUserId.isEmpty() || legacyRecord == null) {
            return;
        }
        UpstreamTokenRecord current = upstreamTokenRegionResolver.resolveByProviderUserId(providerUserId).record();
        if (current != null) {
            // Row exists. Migrate only if the row is missing a usable RT — covers the rare case
            // where a row was created (e.g. by a prior abortive seed attempt) but never populated.
            String currentRt = current.encryptedOktaRefreshToken();
            if (currentRt != null && !currentRt.isEmpty()) {
                return;
            }
        }
        String legacyRt = legacyRecord.encryptedUpstreamRefreshToken();
        if (legacyRt == null || legacyRt.isEmpty()) {
            return;
        }
        // TODO: Remove after migration window (legacy per-row upstream reads no longer needed).
        // Logged at INFO so an operator running tail -f /tmp/mop.log can confirm the migration
        // happened on the very first refresh after the L2 promotion ships.
        log.info("event=upstream_legacy_migration provider={} provider_user_id={} from=refresh_tokens.encrypted_upstream_refresh_token to=mcp-oauth-proxy-upstream-tokens",
                provider == null || provider.isEmpty() ? "unknown" : provider, providerUserId);
        storeInitialUpstreamToken(providerUserId, legacyRt);
    }

    /**
     * Provider-aware upstream refresh entry point. Returns the freshly-rotated tokens as a
     * {@link UpstreamRefreshResponse} after acquiring the L2 lock, dispatching to the right
     * {@link UpstreamRefreshClient} for the provider, writing the rotated RT and staged AT to L2
     * via version-CAS, and populating per-client L0 cells under {@code clientId}.
     *
     * <p>Concurrency: a second client arriving at the L2 lock within
     * {@link #l2AtReuseGraceSeconds} of another client rotating takes Path E — it copies the
     * staged AT into its own per-client L0 cell without issuing a fresh upstream call. This is
     * what amortizes Google calls across concurrent MCP clients of the same user.
     *
     * @param providerUserId canonical L2 row key, e.g. {@code "google-slides#alice-sub"}.
     * @param provider       upstream IdP id (used to dispatch to the right
     *                       {@link UpstreamRefreshClient} and to gate Path E to promoted
     *                       providers only). MUST match the prefix of {@code providerUserId}.
     * @param clientId       MCP client_id for per-client L0 cell population. May be null on
     *                       legacy/Okta paths; the cell is then keyed under a sentinel.
     */
    public UpstreamRefreshResponse refreshUpstream(String providerUserId, String provider, String clientId) {
        if (provider == null || provider.isEmpty()) {
            // Best-effort: derive provider from the prefix of providerUserId so legacy callers
            // that haven't been updated still work without throwing here.
            provider = providerOf(providerUserId);
        }
        // Okta keeps its existing single-arg path which uses OktaTokens; route through the
        // legacy entry to preserve precise behavior (replication wait counters, etc.).
        if (AudienceConstants.PROVIDER_OKTA.equals(provider)) {
            OktaTokens tokens = refreshUpstream(providerUserId);
            String scope = null;
            return new UpstreamRefreshResponse(
                    tokens.accessToken(), tokens.refreshToken(), tokens.idToken(), tokens.expiresIn(), scope);
        }
        // Promoted Google providers go through the new path.
        UpstreamRefreshClient client = clientFor(provider);
        return refreshUpstreamPromoted(providerUserId, provider, clientId, client);
    }

    /**
     * Internal Path C/E body for promoted (non-Okta) providers. Acquires the L2 lock, checks the
     * staged AT for Path E reuse-within-grace, otherwise performs Path C (call upstream, CAS-
     * write rotated RT + staged AT). Per-client L0 is populated for the calling {@code clientId}.
     */
    private UpstreamRefreshResponse refreshUpstreamPromoted(String providerUserId, String provider,
                                                            String clientId, UpstreamRefreshClient client) {
        if (providerUserId == null || providerUserId.isEmpty()) {
            throw new UpstreamRefreshException("provider_user_id required for upstream refresh");
        }
        // Pre-lock L0 fast path on the per-client cell.
        String sub = stripProviderPrefix(providerUserId, provider);
        String clientKey = IdpSessionCache.clientKey(clientId, provider, sub);
        Optional<UpstreamRefreshResponse> preLock = tryGetCachedFreshPromoted(clientKey);
        if (preLock.isPresent()) {
            log.debug("event=upstream_refresh_l0_hit provider={} client_id={} sub={} at_remaining_seconds={}",
                    provider, clientId, sub, preLock.get().expiresInSeconds());
            oauthProxyMetrics.recordUpstreamPromotedCacheOutcome(provider, "l0_hit");
            return preLock.get();
        }

        refreshCoordinationService.acquireUpstream(providerUserId);
        try {
            // Post-lock L0 re-read so a sibling that won the lock before us seeds our per-client
            // cell via Path E below; we still re-check L0 in case Path E already populated it.
            Optional<UpstreamRefreshResponse> postLock = tryGetCachedFreshPromoted(clientKey);
            if (postLock.isPresent()) {
                log.debug("event=upstream_refresh_hit_post_lock provider={} client_id={} sub={} at_remaining_seconds={}",
                        provider, clientId, sub, postLock.get().expiresInSeconds());
                oauthProxyMetrics.recordUpstreamPromotedCacheOutcome(provider, "hit_post_lock");
                return postLock.get();
            }

            boolean waitedForReplication = false;
            for (int attempt = 0; attempt < MAX_VERSION_RETRIES; attempt++) {
                UpstreamTokenResolution resolution = upstreamTokenRegionResolver.resolveByProviderUserId(providerUserId);
                UpstreamTokenRecord rec = resolution.record();
                if (rec == null) {
                    // The resolver returns null for two distinct cases that look identical to the
                    // caller but are very different to operators:
                    //   (A) the row is genuinely absent (never seeded; pre-flight migration had
                    //       nothing to copy from the legacy column);
                    //   (B) the row exists but is non-ACTIVE (REVOKED_INVALID_GRANT after a peer
                    //       pod just rejected the upstream RT, or REVOKED_USER_REVOKED, etc.) and
                    //       UpstreamTokenRegionResolver filtered it out via .filter(isActive).
                    // Both paths converge on the same UpstreamRefreshException because the user's
                    // only recovery is fresh consent. But the WARN line should distinguish them so
                    // an operator scanning logs can immediately tell whether a fleet of
                    // upstream_refresh_no_l2_row entries means "migration didn't run" or "Google
                    // is rejecting RTs for this user". A raw .get() (no isActive filter) on the
                    // local store gives us that signal cheaply and only on the failure path.
                    Optional<UpstreamTokenRecord> rawLocal = upstreamTokenStore.get(providerUserId);
                    if (rawLocal.isPresent() && !rawLocal.get().isActive()) {
                        UpstreamTokenRecord revoked = rawLocal.get();
                        log.warn("event=upstream_refresh_aborted_revoked_at_read provider={} provider_user_id={} attempt={} " +
                                "version={} status={} revoked_at={} revoked_reason={}: " +
                                "L2 row exists but is non-ACTIVE; resolver filtered it out. " +
                                "Re-authentication is required to recover.",
                                provider, providerUserId, attempt,
                                revoked.version(), revoked.status(), revoked.revokedAt(), revoked.revokedReason());
                    } else {
                        log.warn("event=upstream_refresh_no_l2_row provider={} provider_user_id={} attempt={}: " +
                                "L2 row is missing AND pre-flight legacy migration did not seed it. " +
                                "Either the caller skipped ensureMigratedFromLegacyIfNeeded or the legacy " +
                                "encrypted_upstream_refresh_token column was also empty for this family. " +
                                "Re-authentication is required to recover.",
                                provider, providerUserId, attempt);
                    }
                    throw new UpstreamRefreshException(
                            "No upstream " + provider + " refresh token; re-authentication required");
                }
                if (!rec.isActive()) {
                    log.info(
                            "event=upstream_refresh_aborted_revoked provider={} provider_user_id={} version={} status={}",
                            provider, providerUserId, rec.version(), rec.status());
                    throw new UpstreamRefreshException(
                            "Upstream " + provider + " token is revoked; re-authentication required");
                }
                String plainRt = rec.encryptedOktaRefreshToken();
                if (plainRt == null || plainRt.isEmpty()) {
                    throw new UpstreamRefreshException(
                            "Upstream record has no " + provider + " refresh token; re-authentication required");
                }
                long now = Instant.now().getEpochSecond();
                // Path E: reuse-within-grace. The staged AT was minted by the most recent
                // rotation; we only reuse it when (a) the rotation_version pin still matches the
                // current row (no peer rotated again since), (b) it has comfortable lifetime
                // remaining, and (c) the row is the local copy (not pulled from peer fallback,
                // where the staged AT may be ahead of our own clock perception).
                if (!resolution.resolvedFromFallback()
                        && rec.lastMintedAtRotationVersion() == rec.version()
                        && rec.stagedAtIsFresh(now, l2AtReuseGraceSeconds, l2AtReuseMinRemainingSeconds)) {
                    long expiresIn = Math.max(0L, rec.lastMintedAtExpiresAt() - now);
                    UpstreamRefreshResponse staged = new UpstreamRefreshResponse(
                            rec.lastMintedAccessToken(), plainRt, /* idToken */ null, expiresIn, /* scope */ null);
                    // Populate this client's per-client L0 cell so subsequent same-client calls
                    // hit Path B without re-acquiring the lock.
                    if (clientKey != null) {
                        idpSessionCache.put(clientKey,
                                IdpSessionEntry.from(staged.accessToken(), null, expiresIn, now));
                    }
                    log.info(
                            "event=upstream_refresh_reuse_within_grace provider={} provider_user_id={} client_id={} version={} staged_at_remaining_seconds={}",
                            provider, providerUserId, clientId, rec.version(), expiresIn);
                    oauthProxyMetrics.recordUpstreamPromotedCacheOutcome(provider, "reuse_within_grace");
                    return staged;
                }
                // Replication-wait handling, identical in shape to the Okta path.
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
                            "Upstream " + provider + " refresh token only present in peer region; awaiting cross-region replication");
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
                            "Upstream " + provider + " refresh token rotated in peer region; awaiting cross-region replication");
                }
                if (waitedForReplication) {
                    log.info("Replication wait succeeded for provider_user_id={}: local row caught up (version={}); proceeding with upstream refresh",
                            providerUserId, rec.version());
                    oauthProxyMetrics.recordUpstreamTokenReplicationWait("succeeded");
                }
                // Path C: call upstream, write rotated RT + staged AT atomically.
                try {
                    UpstreamRefreshResponse response = client.refresh(providerUserId, plainRt);
                    long stagedExpiresAt = Instant.now().getEpochSecond()
                            + Math.max(0L, response.expiresInSeconds());
                    boolean updated = upstreamTokenStore.updateWithVersionCheckAndStagedAt(
                            providerUserId,
                            response.refreshToken(),
                            response.accessToken(),
                            stagedExpiresAt,
                            rec.version());
                    if (updated) {
                        if (clientKey != null) {
                            idpSessionCache.put(clientKey, IdpSessionEntry.from(
                                    response.accessToken(), response.idToken(),
                                    response.expiresInSeconds(), Instant.now().getEpochSecond()));
                        }
                        log.info(
                                "event=upstream_refresh_rotated provider={} provider_user_id={} client_id={} prior_version={} new_version={}",
                                provider, providerUserId, clientId, rec.version(), rec.version() + 1);
                        oauthProxyMetrics.recordUpstreamPromotedCacheOutcome(provider, "miss_refreshed");
                        return response;
                    }
                } catch (OktaTokenRevokedException e) {
                    if (clientKey != null) {
                        idpSessionCache.invalidate(clientKey);
                    }
                    String reason = e.getMessage() != null ? e.getMessage() : "invalid_grant";
                    boolean marked = upstreamTokenStore.markRevoked(providerUserId, rec.version(), reason);
                    log.warn(
                            "Upstream {} refresh rejected with invalid_grant for provider_user_id={} version={} marked_revoked={} reason=\"{}\"",
                            provider, providerUserId, rec.version(), marked, reason);
                    oauthProxyMetrics.recordUpstreamOktaRevoked(
                            UpstreamTokenRecord.STATUS_REVOKED_INVALID_GRANT);
                    throw new UpstreamRefreshException(
                            "Upstream " + provider + " token revoked; re-authentication required", e);
                }
                log.debug("Upstream version conflict for provider_user_id={} attempt={}", providerUserId, attempt + 1);
            }
            throw new UpstreamRefreshException(
                    "Could not update centralized upstream token after retries for " + provider);
        } finally {
            refreshCoordinationService.releaseUpstream(providerUserId);
        }
    }

    private Optional<UpstreamRefreshResponse> tryGetCachedFreshPromoted(String clientKey) {
        if (clientKey == null) {
            return Optional.empty();
        }
        Optional<IdpSessionEntry> entryOpt = idpSessionCache.get(clientKey);
        if (entryOpt.isEmpty()) {
            return Optional.empty();
        }
        IdpSessionEntry entry = entryOpt.get();
        long now = Instant.now().getEpochSecond();
        long remaining = entry.accessTokenExpEpoch() - now;
        // Use the same skew as the Okta-side cache (configured min-remaining-seconds), so the
        // operational profile is consistent across promoted providers and Okta. When the shared
        // cache is disabled, OktaSessionCacheConfig.enabled() is false and IdpSessionCache.get
        // already returns empty.
        long minRemaining = oktaSessionCacheConfig.minRemainingSeconds();
        if (remaining < minRemaining) {
            return Optional.empty();
        }
        UpstreamRefreshResponse response = new UpstreamRefreshResponse(
                entry.accessToken(), /* refreshToken (canonical lives in L2) */ null,
                entry.idToken(), remaining, /* scope */ null);
        return Optional.of(response);
    }

    private UpstreamRefreshClient clientFor(String provider) {
        if (AudienceConstants.PROVIDER_OKTA.equals(provider)) {
            // Adapter so the Okta path can flow through the same code shape if a future caller
            // wants it. Today this is unused (the legacy single-arg path handles Okta directly).
            return (puid, rt) -> {
                OktaTokens t = oktaTokenClient.refreshToken(rt);
                return new UpstreamRefreshResponse(t.accessToken(), t.refreshToken(), t.idToken(),
                        t.expiresIn(), null);
            };
        }
        if (upstreamProviderClassifier.isGoogleWorkspace(provider)) {
            return googleWorkspaceUpstreamRefreshClient;
        }
        throw new UpstreamRefreshException(
                "No UpstreamRefreshClient registered for provider=" + provider);
    }

    private static String providerOf(String providerUserId) {
        if (providerUserId == null) return "";
        int idx = providerUserId.indexOf('#');
        return idx > 0 ? providerUserId.substring(0, idx) : "";
    }

    private static String stripProviderPrefix(String providerUserId, String provider) {
        if (providerUserId == null) return null;
        String prefix = provider + "#";
        if (providerUserId.startsWith(prefix)) {
            return providerUserId.substring(prefix.length());
        }
        return providerUserId;
    }

    /**
     * Refresh Okta tokens using the centralized store, under a distributed lock and with version retries.
     *
     * <p>When the shared Okta upstream session cache is enabled, two fast-paths short-circuit
     * the Okta call:
     * <ol>
     *   <li><b>Pre-lock</b>: L0 (per-pod Caffeine) → L1 (bare {@code (userId, "okta")} DDB row)
     *       lookup. If the cached id_token's {@code exp - now} clears
     *       {@link OktaSessionCacheConfig#minRemainingSeconds()}, we hand the cached tokens back
     *       without acquiring the distributed lock.</li>
     *   <li><b>Post-lock</b>: same lookup repeated immediately after acquiring the lock so
     *       siblings that queued behind a winning refresher coalesce on the lock-holder's
     *       newly-written row instead of issuing redundant Okta calls.</li>
     * </ol>
     *
     * <p>On a true L2 miss, the existing version-CAS write path runs, and we additionally
     * populate L0 with the freshly-minted id/access tokens. Cache invalidation on
     * {@code OktaTokenRevokedException} is folded into the existing terminal-failure handler.
     */
    public OktaTokens refreshUpstream(String providerUserId) {
        if (oktaSessionCacheConfig.enabled()) {
            Optional<OktaTokens> preLock = tryGetCachedFresh(providerUserId,
                    oktaSessionCacheConfig.minRemainingSeconds(), /* postLock= */ false);
            if (preLock.isPresent()) {
                return preLock.get();
            }
        }

        refreshCoordinationService.acquireUpstream(providerUserId);
        try {
            if (oktaSessionCacheConfig.enabled()) {
                Optional<OktaTokens> postLock = tryGetCachedFresh(providerUserId,
                        oktaSessionCacheConfig.minRemainingSeconds(), /* postLock= */ true);
                if (postLock.isPresent()) {
                    return postLock.get();
                }
            }
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
                // Defense-in-depth: a row in any non-ACTIVE state (e.g. REVOKED_INVALID_GRANT) must be
                // treated as if it weren't there. Today markRevoked also clears
                // encryptedOktaRefreshToken to "" so the empty-RT check below would catch it; this
                // status check guards against any future write path that lands a non-ACTIVE row
                // without clearing the secret material.
                if (!rec.isActive()) {
                    log.info(
                            "event=upstream_okta_refresh_aborted_revoked provider_user_id={} version={} status={}",
                            providerUserId, rec.version(), rec.status());
                    throw new UpstreamRefreshException(
                            "Upstream Okta token is revoked; re-authentication required");
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
                        if (oktaSessionCacheConfig.enabled()) {
                            // Populate L0 with the freshly-minted id/access tokens. The bare
                            // (userId, "okta") L1 row is rewritten by AuthorizerService.completeRefreshWithOktaTokens
                            // (which also calls oktaSessionCache.put) downstream of every Okta-rooted
                            // /token caller; updating L0 here keeps subsequent same-pod siblings hot
                            // even if they bypass that path (e.g. /userinfo's tryRefreshOktaToken).
                            oktaSessionCache.put(providerUserId, OktaSessionEntry.from(tokens));
                            oauthProxyMetrics.recordUpstreamOktaCacheOutcome("miss_refreshed");
                        }
                        return tokens;
                    }
                } catch (OktaTokenRevokedException e) {
                    if (oktaSessionCacheConfig.enabled()) {
                        oktaSessionCache.invalidate(providerUserId);
                    }
                    String reason = e.getMessage() != null ? e.getMessage() : "invalid_grant";
                    boolean marked = upstreamTokenStore.markRevoked(providerUserId, rec.version(), reason);
                    log.warn(
                            "Upstream Okta refresh rejected with invalid_grant for provider_user_id={} version={} marked_revoked={} reason=\"{}\"",
                            providerUserId, rec.version(), marked, reason);
                    oauthProxyMetrics.recordUpstreamOktaRevoked(
                            UpstreamTokenRecord.STATUS_REVOKED_INVALID_GRANT);
                    throw new UpstreamRefreshException("Upstream Okta token revoked; re-authentication required", e);
                }
                log.debug("Upstream version conflict for provider_user_id={} attempt={}", providerUserId, attempt + 1);
            }
            throw new UpstreamRefreshException("Could not update centralized upstream token after retries");
        } finally {
            refreshCoordinationService.releaseUpstream(providerUserId);
        }
    }

    /**
     * Resolve a fresh-enough Okta token pair from the shared session cache. L0 (per-pod
     * Caffeine) is consulted first, then L1 (bare {@code (userId, "okta")} DDB row with
     * cross-region peer fallback). On an L1 hit, L0 is populated for the next pod-local read.
     *
     * <p>Freshness is enforced via the entry's pre-parsed {@code minExp()} (the earlier of
     * {@code idTokenExpEpoch} and {@code accessTokenExpEpoch}). When neither is parseable (e.g.
     * opaque access tokens with no id_token), the entry is treated as a miss so the caller falls
     * through to the L2 path. {@code minRemainingSeconds} comes from
     * {@link OktaSessionCacheConfig#minRemainingSeconds()} for the {@code /token} flow; other
     * callers may pass a different skew.
     *
     * @param providerUserId        e.g. {@code "okta#<sub>"}
     * @param minRemainingSeconds   required headroom in seconds for the freshness check
     * @param postLock              when {@code true}, an L0/L1 hit emits the {@code hit_post_lock}
     *                              outcome; when {@code false}, hits emit {@code l0_hit}/{@code l1_hit}
     */
    Optional<OktaTokens> tryGetCachedFresh(String providerUserId, long minRemainingSeconds, boolean postLock) {
        if (providerUserId == null || providerUserId.isEmpty()) {
            return Optional.empty();
        }
        long now = Instant.now().getEpochSecond();

        Optional<OktaSessionEntry> l0 = oktaSessionCache.get(providerUserId);
        if (l0.isPresent()) {
            OktaSessionEntry entry = l0.get();
            long minExp = entry.minExp();
            if (minExp > 0 && (minExp - now) >= minRemainingSeconds) {
                oauthProxyMetrics.recordUpstreamOktaCacheOutcome(postLock ? "hit_post_lock" : "l0_hit");
                return Optional.of(toOktaTokens(entry, now));
            }
        }

        String userId = stripOktaPrefix(providerUserId);
        if (userId == null || userId.isEmpty()) {
            return Optional.empty();
        }
        UserTokenResolution resolution = userTokenRegionResolver.resolveByUserProvider(
                userId, AudienceConstants.PROVIDER_OKTA,
                UserTokenRegionResolver.CALL_SITE_UPSTREAM_OKTA_CACHE_LOOKUP);
        TokenWrapper row = resolution.token();
        if (row == null) {
            return Optional.empty();
        }
        if (row.idToken() == null || row.idToken().isEmpty()) {
            return Optional.empty();
        }
        OktaSessionEntry candidate = OktaSessionEntry.from(row.idToken(), row.accessToken(), row.refreshToken());
        long minExp = candidate.minExp();
        if (minExp <= 0 || (minExp - now) < minRemainingSeconds) {
            return Optional.empty();
        }
        oktaSessionCache.put(providerUserId, candidate);
        oauthProxyMetrics.recordUpstreamOktaCacheOutcome(postLock ? "hit_post_lock" : "l1_hit");
        return Optional.of(toOktaTokens(candidate, now));
    }

    private static OktaTokens toOktaTokens(OktaSessionEntry entry, long nowEpoch) {
        long minExp = entry.minExp();
        int expiresIn = minExp > 0 ? (int) Math.max(0L, minExp - nowEpoch) : 0;
        return new OktaTokens(entry.accessToken(), entry.refreshToken(), entry.idToken(), expiresIn);
    }

    private static String stripOktaPrefix(String providerUserId) {
        String prefix = AudienceConstants.PROVIDER_OKTA + "#";
        if (providerUserId.startsWith(prefix)) {
            return providerUserId.substring(prefix.length());
        }
        return providerUserId;
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
