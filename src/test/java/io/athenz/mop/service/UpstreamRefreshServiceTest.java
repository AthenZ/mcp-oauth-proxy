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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UpstreamRefreshServiceTest {

    private static final String OKTA_PID_U1 = AudienceConstants.PROVIDER_OKTA + "#u1";

    @Mock
    UpstreamTokenStore upstreamTokenStore;

    @Mock
    OktaTokenClient oktaTokenClient;

    @Mock
    UpstreamTokenConfig upstreamTokenConfig;

    @Mock
    RefreshCoordinationService refreshCoordinationService;

    @Mock
    UpstreamTokenRegionResolver upstreamTokenRegionResolver;

    @Mock
    OauthProxyMetrics oauthProxyMetrics;

    @Mock
    OktaSessionCache oktaSessionCache;

    @Mock
    OktaSessionCacheConfig oktaSessionCacheConfig;

    @Mock
    UserTokenRegionResolver userTokenRegionResolver;

    @Mock
    GoogleWorkspaceUpstreamRefreshClient googleWorkspaceUpstreamRefreshClient;

    @Mock
    UpstreamProviderClassifier upstreamProviderClassifier;

    @Mock
    IdpSessionCache idpSessionCache;

    @InjectMocks
    UpstreamRefreshService upstreamRefreshService;

    @BeforeEach
    void setUp() {
        lenient().when(upstreamTokenConfig.expirySeconds()).thenReturn(7776000L);
        lenient().when(upstreamTokenConfig.ttlBufferDays()).thenReturn(7);
        // Default cache disabled; cache-aware tests opt in by overriding.
        lenient().when(oktaSessionCacheConfig.enabled()).thenReturn(false);
        lenient().when(oktaSessionCacheConfig.minRemainingSeconds()).thenReturn(120);
        lenient().when(oktaSessionCache.get(org.mockito.ArgumentMatchers.anyString()))
                .thenReturn(java.util.Optional.empty());
        // Keep cross-region replication-wait fast in tests; production default is 750ms.
        upstreamRefreshService.replicationWaitMillis = 0L;
        // Path E grace defaults match production unless a specific test wants to widen them.
        upstreamRefreshService.l2AtReuseGraceSeconds = 30L;
        upstreamRefreshService.l2AtReuseMinRemainingSeconds = 60L;
    }

    /** Build a minimal HS256-signed JWT carrying just an {@code exp} claim. */
    private static String jwtWithExp(long expEpochSeconds) {
        try {
            byte[] secret = "01234567890123456789012345678901".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .expirationTime(new Date(expEpochSeconds * 1000L))
                    .build();
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).build(), claims);
            jwt.sign(new MACSigner(secret));
            return jwt.serialize();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static UpstreamTokenResolution localResolution(UpstreamTokenRecord rec) {
        return new UpstreamTokenResolution(rec, false);
    }

    private static UpstreamTokenResolution peerResolution(UpstreamTokenRecord rec) {
        return new UpstreamTokenResolution(rec, true);
    }

    @Test
    void refreshUpstream_happyPath_lockRefreshUnlock() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 1L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1)).thenReturn(localResolution(rec));
        when(upstreamTokenRegionResolver.peerVersionForCas(OKTA_PID_U1)).thenReturn(Optional.empty());
        when(oktaTokenClient.refreshToken("plain-rt")).thenReturn(new OktaTokens("at", "rt2", "id", 3600));
        when(upstreamTokenStore.updateWithVersionCheck(OKTA_PID_U1, "rt2", 1L)).thenReturn(true);

        OktaTokens out = upstreamRefreshService.refreshUpstream(OKTA_PID_U1);

        assertEquals("at", out.accessToken());
        verify(refreshCoordinationService).acquireUpstream(OKTA_PID_U1);
        verify(refreshCoordinationService).releaseUpstream(OKTA_PID_U1);
    }

    @Test
    void refreshUpstream_revoked_marksRevokedAndThrows() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 1L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1)).thenReturn(localResolution(rec));
        when(upstreamTokenRegionResolver.peerVersionForCas(OKTA_PID_U1)).thenReturn(Optional.empty());
        when(oktaTokenClient.refreshToken("plain-rt")).thenThrow(new OktaTokenRevokedException("revoked"));

        assertThrows(UpstreamRefreshException.class, () -> upstreamRefreshService.refreshUpstream(OKTA_PID_U1));
        verify(upstreamTokenStore).markRevoked(OKTA_PID_U1, 1L, "revoked");
        verify(upstreamTokenStore, never()).delete(OKTA_PID_U1);
        verify(oauthProxyMetrics).recordUpstreamOktaRevoked(UpstreamTokenRecord.STATUS_REVOKED_INVALID_GRANT);
        verify(refreshCoordinationService).releaseUpstream(OKTA_PID_U1);
    }

    @Test
    void refreshUpstream_aborts_whenRowOnlyInPeerRegion_afterReplicationWait() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 4L, 0L, "", "");
        // Both resolutions (initial + post-sleep retry) still come back from the peer: replication
        // has not landed locally, so we must throw a transient (retryable) error.
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1)).thenReturn(peerResolution(rec));

        assertThrows(UpstreamRefreshTransientException.class,
                () -> upstreamRefreshService.refreshUpstream(OKTA_PID_U1));
        verify(oktaTokenClient, never()).refreshToken(any());
        verify(upstreamTokenStore, never()).updateWithVersionCheck(any(), any(), org.mockito.ArgumentMatchers.anyLong());
        verify(oauthProxyMetrics).recordUpstreamTokenCasAbortedPeerNewer(OKTA_PID_U1);
        verify(oauthProxyMetrics).recordUpstreamTokenReplicationWait("still_stale");
        verify(upstreamTokenRegionResolver, org.mockito.Mockito.times(2)).resolveByProviderUserId(OKTA_PID_U1);
    }

    @Test
    void refreshUpstream_replicationCatchesUp_whenRowOnlyInPeerRegion() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 4L, 0L, "", "");
        // First resolution: row is only in peer (replication lag). Second resolution (after the
        // brief in-process wait) returns the same record locally — replication has converged.
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1))
                .thenReturn(peerResolution(rec))
                .thenReturn(localResolution(rec));
        when(upstreamTokenRegionResolver.peerVersionForCas(OKTA_PID_U1)).thenReturn(Optional.empty());
        when(oktaTokenClient.refreshToken("plain-rt")).thenReturn(new OktaTokens("at", "rt2", "id", 3600));
        when(upstreamTokenStore.updateWithVersionCheck(OKTA_PID_U1, "rt2", 4L)).thenReturn(true);

        OktaTokens out = upstreamRefreshService.refreshUpstream(OKTA_PID_U1);

        assertEquals("at", out.accessToken());
        verify(oauthProxyMetrics).recordUpstreamTokenReplicationWait("succeeded");
        verify(oauthProxyMetrics, never()).recordUpstreamTokenCasAbortedPeerNewer(any());
    }

    @Test
    void refreshUpstream_aborts_whenPeerVersionHigher_afterReplicationWait() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 4L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1)).thenReturn(localResolution(rec));
        // Peer reports a higher version on both checks (initial + post-sleep retry).
        when(upstreamTokenRegionResolver.peerVersionForCas(OKTA_PID_U1)).thenReturn(Optional.of(7L));

        assertThrows(UpstreamRefreshTransientException.class,
                () -> upstreamRefreshService.refreshUpstream(OKTA_PID_U1));
        verify(oktaTokenClient, never()).refreshToken(any());
        verify(upstreamTokenStore, never()).updateWithVersionCheck(any(), any(), org.mockito.ArgumentMatchers.anyLong());
        verify(oauthProxyMetrics).recordUpstreamTokenCasAbortedPeerNewer(OKTA_PID_U1);
        verify(oauthProxyMetrics).recordUpstreamTokenReplicationWait("still_stale");
        verify(upstreamTokenRegionResolver, org.mockito.Mockito.times(2)).peerVersionForCas(OKTA_PID_U1);
    }

    @Test
    void refreshUpstream_replicationCatchesUp_whenPeerVersionWasHigher() {
        // First check: local v4, peer v7. Sleep, re-resolve. Second check: local v7 (replicated),
        // peer reports v7 (equal) → proceed to Okta refresh.
        UpstreamTokenRecord recStale = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 4L, 0L, "", "");
        UpstreamTokenRecord recCaughtUp = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 7L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1))
                .thenReturn(localResolution(recStale))
                .thenReturn(localResolution(recCaughtUp));
        when(upstreamTokenRegionResolver.peerVersionForCas(OKTA_PID_U1))
                .thenReturn(Optional.of(7L))
                .thenReturn(Optional.of(7L));
        when(oktaTokenClient.refreshToken("plain-rt")).thenReturn(new OktaTokens("at", "rt8", "id", 3600));
        when(upstreamTokenStore.updateWithVersionCheck(OKTA_PID_U1, "rt8", 7L)).thenReturn(true);

        OktaTokens out = upstreamRefreshService.refreshUpstream(OKTA_PID_U1);

        assertEquals("at", out.accessToken());
        verify(oauthProxyMetrics).recordUpstreamTokenReplicationWait("succeeded");
        verify(oauthProxyMetrics, never()).recordUpstreamTokenCasAbortedPeerNewer(any());
    }

    @Test
    void refreshUpstream_proceeds_whenPeerVersionEqualOrLower() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 4L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1)).thenReturn(localResolution(rec));
        when(upstreamTokenRegionResolver.peerVersionForCas(OKTA_PID_U1)).thenReturn(Optional.of(4L));
        when(oktaTokenClient.refreshToken("plain-rt")).thenReturn(new OktaTokens("at", "rt5", "id", 3600));
        when(upstreamTokenStore.updateWithVersionCheck(OKTA_PID_U1, "rt5", 4L)).thenReturn(true);

        OktaTokens out = upstreamRefreshService.refreshUpstream(OKTA_PID_U1);

        assertEquals("at", out.accessToken());
        verify(oauthProxyMetrics, never()).recordUpstreamTokenCasAbortedPeerNewer(any());
    }

    @Test
    void ensureMigratedFromLegacyIfNeeded_copiesWhenCentralizedMissing() {
        RefreshTokenRecord legacy = new RefreshTokenRecord(
                "id", OKTA_PID_U1, "u1", "c1", AudienceConstants.PROVIDER_OKTA, null, "s", "legacy-rt", "ACTIVE", "fam",
                null, null, 0L, 0L, 0L, 0L);
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1))
                .thenReturn(new UpstreamTokenResolution(null, false));

        upstreamRefreshService.ensureMigratedFromLegacyIfNeeded(OKTA_PID_U1, legacy);

        verify(upstreamTokenStore).save(any(UpstreamTokenRecord.class));
    }

    @Test
    void ensureMigratedFromLegacyIfNeeded_copiesForGoogleSlidesWhenCentralizedMissing() {
        // The whole point of generalizing this method beyond Okta: a Google family that was
        // minted before the L2 promotion was rolled out has its upstream Google RT only in the
        // legacy refresh-tokens.encrypted_upstream_refresh_token column. The first /token call
        // post-rollout MUST seed L2 from that column instead of failing with "no upstream RT".
        String puid = "google-slides#alice-sub";
        RefreshTokenRecord legacy = new RefreshTokenRecord(
                "id-gs-1", puid, "alice-sub", "gslidestrial6", "google-slides", null, "alice-sub",
                "legacy-google-rt", "ACTIVE", "fam-gs-1", null, null, 0L, 0L, 0L, 0L);
        when(upstreamTokenRegionResolver.resolveByProviderUserId(puid))
                .thenReturn(new UpstreamTokenResolution(null, false));

        upstreamRefreshService.ensureMigratedFromLegacyIfNeeded(puid, "google-slides", legacy);

        verify(upstreamTokenStore).save(any(UpstreamTokenRecord.class));
    }

    @Test
    void ensureMigratedFromLegacyIfNeeded_isNoOpWhenL2RowAlreadyHasRt() {
        // Re-running the migration after a successful seed must not cause a second write —
        // otherwise concurrent /token calls on the same family would each try to seed and only
        // one would win the version-CAS, generating spurious WARN log noise.
        String puid = "google-slides#alice-sub";
        RefreshTokenRecord legacy = new RefreshTokenRecord(
                "id-gs-1", puid, "alice-sub", "gslidestrial6", "google-slides", null, "alice-sub",
                "legacy-google-rt", "ACTIVE", "fam-gs-1", null, null, 0L, 0L, 0L, 0L);
        UpstreamTokenRecord existing = UpstreamTokenRecord.builder()
                .providerUserId(puid)
                .encryptedOktaRefreshToken("already-seeded-rt")
                .version(2L)
                .status(UpstreamTokenRecord.STATUS_ACTIVE)
                .build();
        when(upstreamTokenRegionResolver.resolveByProviderUserId(puid))
                .thenReturn(localResolution(existing));

        upstreamRefreshService.ensureMigratedFromLegacyIfNeeded(puid, "google-slides", legacy);

        verify(upstreamTokenStore, never()).save(any());
    }

    @Test
    void ensureMigratedFromLegacyIfNeeded_seedsWhenL2RowExistsButHasNoRt() {
        // Edge case: an L2 row exists (e.g. left over from a partial seed attempt) but is missing
        // its RT. We should still copy the legacy RT in to make the row usable.
        String puid = "google-slides#alice-sub";
        RefreshTokenRecord legacy = new RefreshTokenRecord(
                "id-gs-1", puid, "alice-sub", "gslidestrial6", "google-slides", null, "alice-sub",
                "legacy-google-rt", "ACTIVE", "fam-gs-1", null, null, 0L, 0L, 0L, 0L);
        UpstreamTokenRecord emptyRtRow = UpstreamTokenRecord.builder()
                .providerUserId(puid)
                .encryptedOktaRefreshToken("")
                .version(1L)
                .status(UpstreamTokenRecord.STATUS_ACTIVE)
                .build();
        when(upstreamTokenRegionResolver.resolveByProviderUserId(puid))
                .thenReturn(localResolution(emptyRtRow));

        upstreamRefreshService.ensureMigratedFromLegacyIfNeeded(puid, "google-slides", legacy);

        verify(upstreamTokenStore).save(any(UpstreamTokenRecord.class));
    }

    @Test
    void ensureMigratedFromLegacyIfNeeded_isNoOpWhenLegacyRtAlsoEmpty() {
        // Both the L2 row AND the legacy column are empty. This is the irrecoverable case;
        // the method must be a clean no-op (the subsequent refreshUpstream call will throw
        // "no upstream RT — re-authentication required", which is the correct user-visible
        // behavior).
        String puid = "google-slides#alice-sub";
        RefreshTokenRecord noLegacyRt = new RefreshTokenRecord(
                "id-gs-1", puid, "alice-sub", "gslidestrial6", "google-slides", null, "alice-sub",
                /* encryptedUpstreamRefreshToken */ null, "ACTIVE", "fam-gs-1", null, null,
                0L, 0L, 0L, 0L);
        when(upstreamTokenRegionResolver.resolveByProviderUserId(puid))
                .thenReturn(new UpstreamTokenResolution(null, false));

        upstreamRefreshService.ensureMigratedFromLegacyIfNeeded(puid, "google-slides", noLegacyRt);

        verify(upstreamTokenStore, never()).save(any());
    }

    @Test
    void ensureMigratedFromLegacyIfNeeded_singleArgOverloadStillWorksForOktaCallers() {
        // Back-compat: existing call sites that pass only (puid, legacyRecord) must continue to
        // function. The overload routes them through the new generalized method with the "okta"
        // provider label.
        RefreshTokenRecord legacy = new RefreshTokenRecord(
                "id", OKTA_PID_U1, "u1", "c1", AudienceConstants.PROVIDER_OKTA, null, "s",
                "legacy-rt", "ACTIVE", "fam", null, null, 0L, 0L, 0L, 0L);
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1))
                .thenReturn(new UpstreamTokenResolution(null, false));

        upstreamRefreshService.ensureMigratedFromLegacyIfNeeded(OKTA_PID_U1, legacy);

        verify(upstreamTokenStore).save(any(UpstreamTokenRecord.class));
    }

    @Test
    void storeInitialUpstreamToken_whenNoRow_saves() {
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1))
                .thenReturn(new UpstreamTokenResolution(null, false));

        upstreamRefreshService.storeInitialUpstreamToken(OKTA_PID_U1, "incoming-rt");

        verify(upstreamTokenStore).save(any(UpstreamTokenRecord.class));
    }

    @Test
    void storeInitialUpstreamToken_whenRowSameRt_doesNotSaveAgain() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "same-rt", "", 2L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1)).thenReturn(localResolution(rec));

        upstreamRefreshService.storeInitialUpstreamToken(OKTA_PID_U1, "same-rt");

        verify(upstreamTokenStore, never()).save(any());
    }

    @Test
    void storeInitialUpstreamToken_whenRowDifferentRt_doesNotOverwrite() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "rotated-rt", "", 3L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1)).thenReturn(localResolution(rec));

        upstreamRefreshService.storeInitialUpstreamToken(OKTA_PID_U1, "stale-session-rt");

        verify(upstreamTokenStore, never()).save(any());
    }

    @Test
    void storeInitialUpstreamToken_whenRowOnlyInPeerRegion_doesNotOverwrite() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "rotated-rt", "", 3L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1)).thenReturn(peerResolution(rec));

        upstreamRefreshService.storeInitialUpstreamToken(OKTA_PID_U1, "incoming-rt");

        verify(upstreamTokenStore, never()).save(any());
    }

    @Test
    void storeInitialUpstreamToken_whenRowEmptyRt_allowsSave() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "", "", 1L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1)).thenReturn(localResolution(rec));

        upstreamRefreshService.storeInitialUpstreamToken(OKTA_PID_U1, "fill-rt");

        verify(upstreamTokenStore).save(any(UpstreamTokenRecord.class));
    }

    @Test
    void storeInitialUpstreamToken_whenRowRevoked_reSeedsAsActiveVersion1() {
        // A REVOKED row whose RT field somehow still carries ciphertext (defensive case for any
        // future write path that forgets to clear it). Without the status check we'd treat the row
        // as "centralized token already set" and skip — which would block recovery via re-login.
        UpstreamTokenRecord revokedButRtPresent = UpstreamTokenRecord.builder()
                .providerUserId(OKTA_PID_U1)
                .encryptedOktaRefreshToken("stale-revoked-rt")
                .lastRotatedAt("2026-05-01T00:00:00Z")
                .version(7L)
                .ttl(0L)
                .createdAt("2026-04-01T00:00:00Z")
                .updatedAt("2026-05-01T00:00:00Z")
                .status(UpstreamTokenRecord.STATUS_REVOKED_INVALID_GRANT)
                .revokedAt("2026-05-01T00:00:00Z")
                .revokedReason("invalid_grant")
                .rotationCount(6L)
                .build();
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1))
                .thenReturn(localResolution(revokedButRtPresent));

        upstreamRefreshService.storeInitialUpstreamToken(OKTA_PID_U1, "fresh-rt-from-relogin");

        org.mockito.ArgumentCaptor<UpstreamTokenRecord> captor =
                org.mockito.ArgumentCaptor.forClass(UpstreamTokenRecord.class);
        verify(upstreamTokenStore).save(captor.capture());
        UpstreamTokenRecord saved = captor.getValue();
        assertEquals("fresh-rt-from-relogin", saved.encryptedOktaRefreshToken(),
                "re-seed must use the freshly returned Okta RT, not the stale revoked one");
        assertEquals(1L, saved.version(),
                "re-seeded ACTIVE row resets version to 1 (write path is plain PutItem, not CAS)");
        assertEquals(UpstreamTokenRecord.STATUS_ACTIVE, saved.status(),
                "re-seeded row must come back as ACTIVE so refresh path consumes it");
    }

    // ---------------- Shared Okta upstream session cache (L0/L1 fast paths) ----------------

    @Test
    void refreshUpstream_l0Hit_skipsLockAndOkta() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        long futureExp = Instant.now().getEpochSecond() + 3600;
        OktaSessionEntry hot = OktaSessionEntry.from(jwtWithExp(futureExp), jwtWithExp(futureExp), "rt");
        when(oktaSessionCache.get(OKTA_PID_U1)).thenReturn(Optional.of(hot));

        OktaTokens out = upstreamRefreshService.refreshUpstream(OKTA_PID_U1);

        assertNotNull(out);
        verify(refreshCoordinationService, never()).acquireUpstream(any());
        verify(oktaTokenClient, never()).refreshToken(any());
        verify(oauthProxyMetrics).recordUpstreamOktaCacheOutcome("l0_hit");
    }

    @Test
    void refreshUpstream_l0Miss_l1Hit_warmsL0_skipsOkta() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        when(oktaSessionCache.get(OKTA_PID_U1)).thenReturn(Optional.empty());
        long futureExp = Instant.now().getEpochSecond() + 3600;
        TokenWrapper row = new TokenWrapper("u1", AudienceConstants.PROVIDER_OKTA,
                jwtWithExp(futureExp), jwtWithExp(futureExp), "rt", futureExp);
        when(userTokenRegionResolver.resolveByUserProvider("u1", AudienceConstants.PROVIDER_OKTA,
                UserTokenRegionResolver.CALL_SITE_UPSTREAM_OKTA_CACHE_LOOKUP))
                .thenReturn(new UserTokenResolution(row, false));

        OktaTokens out = upstreamRefreshService.refreshUpstream(OKTA_PID_U1);

        assertNotNull(out);
        verify(refreshCoordinationService, never()).acquireUpstream(any());
        verify(oktaTokenClient, never()).refreshToken(any());
        verify(oktaSessionCache).put(org.mockito.ArgumentMatchers.eq(OKTA_PID_U1),
                any(OktaSessionEntry.class));
        verify(oauthProxyMetrics).recordUpstreamOktaCacheOutcome("l1_hit");
    }

    @Test
    void refreshUpstream_l1Stale_callsOkta_writesL0() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        when(oktaSessionCache.get(OKTA_PID_U1)).thenReturn(Optional.empty());
        // L1 row exists but its id_token's exp is within the 120s skew → treat as miss.
        long borderlineExp = Instant.now().getEpochSecond() + 30;
        TokenWrapper staleRow = new TokenWrapper("u1", AudienceConstants.PROVIDER_OKTA,
                jwtWithExp(borderlineExp), jwtWithExp(borderlineExp), "rt", borderlineExp);
        when(userTokenRegionResolver.resolveByUserProvider("u1", AudienceConstants.PROVIDER_OKTA,
                UserTokenRegionResolver.CALL_SITE_UPSTREAM_OKTA_CACHE_LOOKUP))
                .thenReturn(new UserTokenResolution(staleRow, false));

        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 1L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1)).thenReturn(localResolution(rec));
        when(upstreamTokenRegionResolver.peerVersionForCas(OKTA_PID_U1)).thenReturn(Optional.empty());
        long futureExp = Instant.now().getEpochSecond() + 3600;
        OktaTokens fresh = new OktaTokens(jwtWithExp(futureExp), "rt2", jwtWithExp(futureExp), 3600);
        when(oktaTokenClient.refreshToken("plain-rt")).thenReturn(fresh);
        when(upstreamTokenStore.updateWithVersionCheck(OKTA_PID_U1, "rt2", 1L)).thenReturn(true);

        OktaTokens out = upstreamRefreshService.refreshUpstream(OKTA_PID_U1);

        assertEquals(fresh.accessToken(), out.accessToken());
        verify(refreshCoordinationService).acquireUpstream(OKTA_PID_U1);
        verify(refreshCoordinationService).releaseUpstream(OKTA_PID_U1);
        verify(oktaSessionCache).put(org.mockito.ArgumentMatchers.eq(OKTA_PID_U1),
                any(OktaSessionEntry.class));
        verify(oauthProxyMetrics).recordUpstreamOktaCacheOutcome("miss_refreshed");
    }

    @Test
    void refreshUpstream_l1RowUnparseable_treatsAsMiss_callsOkta() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        when(oktaSessionCache.get(OKTA_PID_U1)).thenReturn(Optional.empty());
        TokenWrapper opaqueRow = new TokenWrapper("u1", AudienceConstants.PROVIDER_OKTA,
                "not.a.jwt", "also-opaque", "rt", 0L);
        when(userTokenRegionResolver.resolveByUserProvider("u1", AudienceConstants.PROVIDER_OKTA,
                UserTokenRegionResolver.CALL_SITE_UPSTREAM_OKTA_CACHE_LOOKUP))
                .thenReturn(new UserTokenResolution(opaqueRow, false));

        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 1L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1)).thenReturn(localResolution(rec));
        when(upstreamTokenRegionResolver.peerVersionForCas(OKTA_PID_U1)).thenReturn(Optional.empty());
        when(oktaTokenClient.refreshToken("plain-rt"))
                .thenReturn(new OktaTokens("at", "rt2", "id", 3600));
        when(upstreamTokenStore.updateWithVersionCheck(OKTA_PID_U1, "rt2", 1L)).thenReturn(true);

        OktaTokens out = upstreamRefreshService.refreshUpstream(OKTA_PID_U1);
        assertEquals("at", out.accessToken());
        verify(oktaTokenClient).refreshToken("plain-rt");
    }

    @Test
    void refreshUpstream_postLockHit_secondCallerSkipsOkta() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        long futureExp = Instant.now().getEpochSecond() + 3600;
        OktaSessionEntry hot = OktaSessionEntry.from(jwtWithExp(futureExp), jwtWithExp(futureExp), "rt");
        // Pre-lock L0 check: empty (sibling has not populated L0 yet).
        // Pre-lock L1 fall-through: empty so we acquire the lock.
        // Post-lock L0 check: populated (sibling won the race, wrote L0/L1, released the lock).
        when(oktaSessionCache.get(OKTA_PID_U1))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.of(hot));
        when(userTokenRegionResolver.resolveByUserProvider("u1", AudienceConstants.PROVIDER_OKTA,
                UserTokenRegionResolver.CALL_SITE_UPSTREAM_OKTA_CACHE_LOOKUP))
                .thenReturn(new UserTokenResolution(null, false));

        OktaTokens out = upstreamRefreshService.refreshUpstream(OKTA_PID_U1);

        assertNotNull(out);
        verify(refreshCoordinationService).acquireUpstream(OKTA_PID_U1);
        verify(refreshCoordinationService).releaseUpstream(OKTA_PID_U1);
        verify(oktaTokenClient, never()).refreshToken(any());
        verify(oauthProxyMetrics).recordUpstreamOktaCacheOutcome("hit_post_lock");
    }

    @Test
    void refreshUpstream_revokedInvalidatesL0_andSoftDeletesL2() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        when(oktaSessionCache.get(OKTA_PID_U1)).thenReturn(Optional.empty());
        when(userTokenRegionResolver.resolveByUserProvider("u1", AudienceConstants.PROVIDER_OKTA,
                UserTokenRegionResolver.CALL_SITE_UPSTREAM_OKTA_CACHE_LOOKUP))
                .thenReturn(new UserTokenResolution(null, false));

        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 1L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1)).thenReturn(localResolution(rec));
        when(upstreamTokenRegionResolver.peerVersionForCas(OKTA_PID_U1)).thenReturn(Optional.empty());
        when(oktaTokenClient.refreshToken("plain-rt")).thenThrow(new OktaTokenRevokedException("revoked"));

        assertThrows(UpstreamRefreshException.class, () -> upstreamRefreshService.refreshUpstream(OKTA_PID_U1));
        verify(oktaSessionCache).invalidate(OKTA_PID_U1);
        verify(upstreamTokenStore).markRevoked(OKTA_PID_U1, 1L, "revoked");
        verify(upstreamTokenStore, never()).delete(OKTA_PID_U1);
        verify(oauthProxyMetrics).recordUpstreamOktaRevoked(UpstreamTokenRecord.STATUS_REVOKED_INVALID_GRANT);
    }

    @Test
    void refreshUpstream_cacheDisabled_alwaysCallsOkta() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(false);
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 1L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1)).thenReturn(localResolution(rec));
        when(upstreamTokenRegionResolver.peerVersionForCas(OKTA_PID_U1)).thenReturn(Optional.empty());
        when(oktaTokenClient.refreshToken("plain-rt")).thenReturn(new OktaTokens("at", "rt2", "id", 3600));
        when(upstreamTokenStore.updateWithVersionCheck(OKTA_PID_U1, "rt2", 1L)).thenReturn(true);

        OktaTokens out = upstreamRefreshService.refreshUpstream(OKTA_PID_U1);

        assertEquals("at", out.accessToken());
        verify(oktaSessionCache, never()).get(any());
        verify(oktaSessionCache, never()).put(any(), any());
        verify(oauthProxyMetrics, never()).recordUpstreamOktaCacheOutcome(any());
    }

    @Test
    void refreshUpstream_whenRowRevoked_throwsAndDoesNotCallOkta() {
        // A REVOKED_INVALID_GRANT row must be treated as if it weren't there even if a stale write
        // somehow left ciphertext in encryptedOktaRefreshToken. The refresh path must NOT attempt to
        // mint a new token from a known-bad RT; the caller will surface re-authentication required.
        UpstreamTokenRecord revoked = UpstreamTokenRecord.builder()
                .providerUserId(OKTA_PID_U1)
                .encryptedOktaRefreshToken("stale-revoked-rt")
                .lastRotatedAt("2026-05-01T00:00:00Z")
                .version(7L)
                .ttl(0L)
                .createdAt("2026-04-01T00:00:00Z")
                .updatedAt("2026-05-01T00:00:00Z")
                .status(UpstreamTokenRecord.STATUS_REVOKED_INVALID_GRANT)
                .revokedAt("2026-05-01T00:00:00Z")
                .revokedReason("invalid_grant")
                .rotationCount(6L)
                .build();
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1))
                .thenReturn(localResolution(revoked));

        UpstreamRefreshException ex = assertThrows(UpstreamRefreshException.class,
                () -> upstreamRefreshService.refreshUpstream(OKTA_PID_U1));
        assertTrue(ex.getMessage().toLowerCase().contains("revoked"),
                "exception message must signal the row is revoked: " + ex.getMessage());

        verify(oktaTokenClient, never()).refreshToken(any());
        verify(upstreamTokenStore, never()).updateWithVersionCheck(any(), any(), org.mockito.ArgumentMatchers.anyLong());
        verify(upstreamTokenStore, never()).markRevoked(any(), org.mockito.ArgumentMatchers.anyLong(), any());
    }

    @Test
    void getCurrentUpstream_whenRowActive_returnsRecord() {
        UpstreamTokenRecord active = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 1L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1))
                .thenReturn(localResolution(active));

        Optional<UpstreamTokenRecord> result = upstreamRefreshService.getCurrentUpstream(OKTA_PID_U1);

        assertTrue(result.isPresent(), "ACTIVE row must be returned");
        assertEquals("plain-rt", result.get().encryptedOktaRefreshToken());
    }

    @Test
    void getCurrentUpstream_whenRowRevoked_returnsEmpty() {
        // The borrow path (AuthorizeResource) and the per-client refresh path (TokenResource) both
        // call this method to fetch the centralized RT before falling back to a client-supplied
        // value. Returning a REVOKED row would cause confusing invalid_grant errors mid-flight; an
        // explicit re-login should be required instead.
        UpstreamTokenRecord revoked = UpstreamTokenRecord.builder()
                .providerUserId(OKTA_PID_U1)
                .encryptedOktaRefreshToken("")
                .lastRotatedAt("2026-05-01T00:00:00Z")
                .version(7L)
                .ttl(0L)
                .createdAt("2026-04-01T00:00:00Z")
                .updatedAt("2026-05-01T00:00:00Z")
                .status(UpstreamTokenRecord.STATUS_REVOKED_INVALID_GRANT)
                .revokedAt("2026-05-01T00:00:00Z")
                .revokedReason("invalid_grant")
                .rotationCount(6L)
                .build();
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1))
                .thenReturn(localResolution(revoked));

        Optional<UpstreamTokenRecord> result = upstreamRefreshService.getCurrentUpstream(OKTA_PID_U1);

        assertTrue(result.isEmpty(), "non-ACTIVE row must be hidden from callers");
    }

    // ---------- Promoted-provider (Google Workspace) path ----------

    private static final String GSLIDES_PID = "google-slides#alice";

    @Test
    void refreshUpstream_promoted_pathC_callsGoogleAndCasWritesStagedAt() {
        when(upstreamProviderClassifier.isGoogleWorkspace("google-slides")).thenReturn(true);
        when(idpSessionCache.get(any())).thenReturn(Optional.empty());

        UpstreamTokenRecord rec = UpstreamTokenRecord.builder()
                .providerUserId(GSLIDES_PID)
                .encryptedOktaRefreshToken("plain-google-rt")
                .version(3L)
                .status(UpstreamTokenRecord.STATUS_ACTIVE)
                .build();
        when(upstreamTokenRegionResolver.resolveByProviderUserId(GSLIDES_PID))
                .thenReturn(localResolution(rec));
        when(upstreamTokenRegionResolver.peerVersionForCas(GSLIDES_PID)).thenReturn(Optional.empty());
        when(googleWorkspaceUpstreamRefreshClient.refresh(GSLIDES_PID, "plain-google-rt"))
                .thenReturn(new UpstreamRefreshResponse("g-at", "g-rt2", null, 3599L, "scope"));
        when(upstreamTokenStore.updateWithVersionCheckAndStagedAt(
                org.mockito.ArgumentMatchers.eq(GSLIDES_PID),
                org.mockito.ArgumentMatchers.eq("g-rt2"),
                org.mockito.ArgumentMatchers.eq("g-at"),
                org.mockito.ArgumentMatchers.anyLong(),
                org.mockito.ArgumentMatchers.eq(3L)))
                .thenReturn(true);

        UpstreamRefreshResponse out = upstreamRefreshService.refreshUpstream(GSLIDES_PID, "google-slides", "cursor");

        assertNotNull(out);
        assertEquals("g-at", out.accessToken());
        assertEquals("g-rt2", out.refreshToken());
        verify(googleWorkspaceUpstreamRefreshClient).refresh(GSLIDES_PID, "plain-google-rt");
        // Staged-AT trio must be CAS-written atomically with the rotated RT.
        verify(upstreamTokenStore).updateWithVersionCheckAndStagedAt(
                org.mockito.ArgumentMatchers.eq(GSLIDES_PID),
                org.mockito.ArgumentMatchers.eq("g-rt2"),
                org.mockito.ArgumentMatchers.eq("g-at"),
                org.mockito.ArgumentMatchers.anyLong(),
                org.mockito.ArgumentMatchers.eq(3L));
        // L0 cell for THIS client gets populated.
        verify(idpSessionCache).put(
                org.mockito.ArgumentMatchers.eq("cursor#google-slides#alice"),
                org.mockito.ArgumentMatchers.any(IdpSessionEntry.class));
        // Path C => miss_refreshed counter increments on this provider.
        verify(oauthProxyMetrics).recordUpstreamPromotedCacheOutcome("google-slides", "miss_refreshed");
    }

    @Test
    void refreshUpstream_promoted_pathE_reusesStagedAtWithinGrace() {
        when(upstreamProviderClassifier.isGoogleWorkspace("google-slides")).thenReturn(true);
        when(idpSessionCache.get(any())).thenReturn(Optional.empty());

        // Row staged ~5 seconds ago: AT lifetime ~3599, remaining ~3594. With grace=30, the
        // freshness heuristic accepts it; the rotation_version equals the row version so the
        // pin-check passes and Path E fires (no upstream Google call).
        long now = Instant.now().getEpochSecond();
        UpstreamTokenRecord rec = UpstreamTokenRecord.builder()
                .providerUserId(GSLIDES_PID)
                .encryptedOktaRefreshToken("plain-google-rt")
                .version(7L)
                .status(UpstreamTokenRecord.STATUS_ACTIVE)
                .lastMintedAccessToken("staged-at")
                .lastMintedAtExpiresAt(now + 3594L)
                .lastMintedAtRotationVersion(7L)
                .build();
        when(upstreamTokenRegionResolver.resolveByProviderUserId(GSLIDES_PID))
                .thenReturn(localResolution(rec));

        UpstreamRefreshResponse out = upstreamRefreshService.refreshUpstream(GSLIDES_PID, "google-slides", "claude");

        assertNotNull(out);
        assertEquals("staged-at", out.accessToken(),
                "Path E must serve the staged AT verbatim — that is the whole point of the coalescing window");
        assertEquals("plain-google-rt", out.refreshToken(),
                "Path E does not rotate the RT; it reuses the L2 row's current RT");
        // Critical contract: Path E never calls the Google client.
        verify(googleWorkspaceUpstreamRefreshClient, never())
                .refresh(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
        verify(upstreamTokenStore, never()).updateWithVersionCheckAndStagedAt(
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyLong(),
                org.mockito.ArgumentMatchers.anyLong());
        // Per-client L0 still populated for THIS client so it can hit Path B next time.
        verify(idpSessionCache).put(
                org.mockito.ArgumentMatchers.eq("claude#google-slides#alice"),
                org.mockito.ArgumentMatchers.any(IdpSessionEntry.class));
        // Path E => reuse_within_grace counter increments on this provider.
        verify(oauthProxyMetrics).recordUpstreamPromotedCacheOutcome("google-slides", "reuse_within_grace");
    }

    @Test
    void refreshUpstream_promoted_pathB_l0HitEmitsMetric() {
        // Path B observability: when the per-client L0 cell still has a fresh AT, refreshUpstream
        // returns it WITHOUT consulting L2 or calling Google. Before this change the hit was
        // silent; now it ticks mop_upstream_promoted_cache_total{provider, outcome="l0_hit"} so the
        // dashboard can see what fraction of refresh requests are amortized by per-client cache.
        when(upstreamProviderClassifier.isGoogleWorkspace("google-slides")).thenReturn(true);
        long now = Instant.now().getEpochSecond();
        IdpSessionEntry cached = IdpSessionEntry.from("cached-at", null, /* expiresIn */ 3500L, now);
        when(idpSessionCache.get("cursor#google-slides#alice")).thenReturn(Optional.of(cached));

        UpstreamRefreshResponse out = upstreamRefreshService.refreshUpstream(GSLIDES_PID, "google-slides", "cursor");

        assertNotNull(out);
        assertEquals("cached-at", out.accessToken(), "Path B serves the cached AT verbatim");
        // Critical contract: NEITHER L2 NOR Google was consulted.
        verify(upstreamTokenRegionResolver, never()).resolveByProviderUserId(org.mockito.ArgumentMatchers.anyString());
        verify(googleWorkspaceUpstreamRefreshClient, never())
                .refresh(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
        // The metric increment is the whole point of this test.
        verify(oauthProxyMetrics).recordUpstreamPromotedCacheOutcome("google-slides", "l0_hit");
    }

    @Test
    void refreshUpstream_promoted_invalidGrant_revokesL2Row() {
        when(upstreamProviderClassifier.isGoogleWorkspace("google-slides")).thenReturn(true);
        when(idpSessionCache.get(any())).thenReturn(Optional.empty());

        UpstreamTokenRecord rec = UpstreamTokenRecord.builder()
                .providerUserId(GSLIDES_PID)
                .encryptedOktaRefreshToken("plain-google-rt")
                .version(2L)
                .status(UpstreamTokenRecord.STATUS_ACTIVE)
                .build();
        when(upstreamTokenRegionResolver.resolveByProviderUserId(GSLIDES_PID))
                .thenReturn(localResolution(rec));
        when(upstreamTokenRegionResolver.peerVersionForCas(GSLIDES_PID)).thenReturn(Optional.empty());
        // OktaTokenRevokedException is the shared "invalid_grant" sentinel both Okta and Google
        // clients throw — UpstreamRefreshService must mark the L2 row revoked regardless of which
        // promoted provider is at the wheel.
        when(googleWorkspaceUpstreamRefreshClient.refresh(GSLIDES_PID, "plain-google-rt"))
                .thenThrow(new OktaTokenRevokedException("Google refresh token invalid or revoked"));

        assertThrows(UpstreamRefreshException.class, () ->
                upstreamRefreshService.refreshUpstream(GSLIDES_PID, "google-slides", "cursor"));
        verify(upstreamTokenStore).markRevoked(
                org.mockito.ArgumentMatchers.eq(GSLIDES_PID),
                org.mockito.ArgumentMatchers.eq(2L),
                org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void refreshUpstream_promoted_whenL2Absent_consultsRawStoreForDiagnostic() {
        // Diagnostic-accuracy contract: when the resolver returns null because the row is
        // genuinely missing, refreshUpstreamPromoted does a raw .get() to confirm absence and then
        // logs event=upstream_refresh_no_l2_row. The exception is still thrown unchanged.
        when(upstreamProviderClassifier.isGoogleWorkspace("google-slides")).thenReturn(true);
        when(idpSessionCache.get(any())).thenReturn(Optional.empty());
        when(upstreamTokenRegionResolver.resolveByProviderUserId(GSLIDES_PID))
                .thenReturn(new UpstreamTokenResolution(null, false));
        when(upstreamTokenStore.get(GSLIDES_PID)).thenReturn(Optional.empty());

        UpstreamRefreshException ex = assertThrows(UpstreamRefreshException.class, () ->
                upstreamRefreshService.refreshUpstream(GSLIDES_PID, "google-slides", "cursor"));
        assertTrue(ex.getMessage().contains("re-authentication required"),
                "Caller-visible message must still say re-auth required");
        // Diagnostic peek MUST happen on this path; without it we cannot distinguish (A) absent
        // from (B) revoked-but-present in production logs. Once per failed loop attempt.
        verify(upstreamTokenStore, atLeastOnce()).get(GSLIDES_PID);
        // No upstream Google call attempted — the row was truly absent.
        verify(googleWorkspaceUpstreamRefreshClient, never())
                .refresh(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void refreshUpstream_promoted_whenL2RevokedAndFilteredOut_consultsRawStoreForDiagnostic() {
        // The bug we are fixing: a peer pod just rejected the upstream RT and flipped the L2 row
        // to REVOKED_INVALID_GRANT. The resolver's .filter(isActive) hides the row from the
        // active-row read, so refreshUpstreamPromoted sees null and previously logged
        // "no_l2_row" (misleading: row exists, just revoked). With the fix, the raw .get() returns
        // the inactive row and the log line switches to event=upstream_refresh_aborted_revoked_at_read.
        when(upstreamProviderClassifier.isGoogleWorkspace("google-slides")).thenReturn(true);
        when(idpSessionCache.get(any())).thenReturn(Optional.empty());
        when(upstreamTokenRegionResolver.resolveByProviderUserId(GSLIDES_PID))
                .thenReturn(new UpstreamTokenResolution(null, false));

        UpstreamTokenRecord revoked = UpstreamTokenRecord.builder()
                .providerUserId(GSLIDES_PID)
                .encryptedOktaRefreshToken("")
                .version(5L)
                .status(UpstreamTokenRecord.STATUS_REVOKED_INVALID_GRANT)
                .revokedAt("2026-05-04T16:50:58Z")
                .revokedReason("revoked")
                .build();
        when(upstreamTokenStore.get(GSLIDES_PID)).thenReturn(Optional.of(revoked));

        UpstreamRefreshException ex = assertThrows(UpstreamRefreshException.class, () ->
                upstreamRefreshService.refreshUpstream(GSLIDES_PID, "google-slides", "cursor"));
        assertTrue(ex.getMessage().contains("re-authentication required"),
                "User-visible behavior is unchanged — only the log line is more accurate");
        verify(upstreamTokenStore, atLeastOnce()).get(GSLIDES_PID);
        // Critically, this is the diagnostic-only path: we must NOT attempt to revoke a row that
        // is already revoked, NOT call Google, NOT touch the staged AT.
        verify(upstreamTokenStore, never()).markRevoked(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyLong(),
                org.mockito.ArgumentMatchers.anyString());
        verify(googleWorkspaceUpstreamRefreshClient, never())
                .refresh(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
        verify(upstreamTokenStore, never()).updateWithVersionCheckAndStagedAt(
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyLong(),
                org.mockito.ArgumentMatchers.anyLong());
    }
}
