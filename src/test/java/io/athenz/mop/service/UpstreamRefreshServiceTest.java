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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
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

    @InjectMocks
    UpstreamRefreshService upstreamRefreshService;

    @BeforeEach
    void setUp() {
        lenient().when(upstreamTokenConfig.expirySeconds()).thenReturn(7776000L);
        lenient().when(upstreamTokenConfig.ttlBufferDays()).thenReturn(7);
        // Keep cross-region replication-wait fast in tests; production default is 750ms.
        UpstreamRefreshService.replicationWaitMillis = 0L;
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
    void refreshUpstream_revoked_deletesAndThrows() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 1L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(OKTA_PID_U1)).thenReturn(localResolution(rec));
        when(upstreamTokenRegionResolver.peerVersionForCas(OKTA_PID_U1)).thenReturn(Optional.empty());
        when(oktaTokenClient.refreshToken("plain-rt")).thenThrow(new OktaTokenRevokedException("revoked"));

        assertThrows(UpstreamRefreshException.class, () -> upstreamRefreshService.refreshUpstream(OKTA_PID_U1));
        verify(upstreamTokenStore).delete(OKTA_PID_U1);
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
                "id", OKTA_PID_U1, "u1", "c1", AudienceConstants.PROVIDER_OKTA, "s", "legacy-rt", "ACTIVE", "fam",
                null, null, 0L, 0L, 0L, 0L);
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
}
