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

    @InjectMocks
    UpstreamRefreshService upstreamRefreshService;

    @BeforeEach
    void setUp() {
        lenient().when(upstreamTokenConfig.expirySeconds()).thenReturn(7776000L);
        lenient().when(upstreamTokenConfig.ttlBufferDays()).thenReturn(7);
    }

    @Test
    void refreshUpstream_happyPath_lockRefreshUnlock() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "plain-rt", "", 1L, 0L, "", "");
        when(upstreamTokenStore.get(OKTA_PID_U1)).thenReturn(Optional.of(rec));
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
        when(upstreamTokenStore.get(OKTA_PID_U1)).thenReturn(Optional.of(rec));
        when(oktaTokenClient.refreshToken("plain-rt")).thenThrow(new OktaTokenRevokedException("revoked"));

        assertThrows(UpstreamRefreshException.class, () -> upstreamRefreshService.refreshUpstream(OKTA_PID_U1));
        verify(upstreamTokenStore).delete(OKTA_PID_U1);
        verify(refreshCoordinationService).releaseUpstream(OKTA_PID_U1);
    }

    @Test
    void ensureMigratedFromLegacyIfNeeded_copiesWhenCentralizedMissing() {
        RefreshTokenRecord legacy = new RefreshTokenRecord(
                "id", OKTA_PID_U1, "u1", "c1", AudienceConstants.PROVIDER_OKTA, "s", "legacy-rt", "ACTIVE", "fam",
                null, null, 0L, 0L, 0L, 0L);
        when(upstreamTokenStore.get(OKTA_PID_U1)).thenReturn(Optional.empty());

        upstreamRefreshService.ensureMigratedFromLegacyIfNeeded(OKTA_PID_U1, legacy);

        verify(upstreamTokenStore).save(any(UpstreamTokenRecord.class));
    }

    @Test
    void storeInitialUpstreamToken_whenNoRow_saves() {
        when(upstreamTokenStore.get(OKTA_PID_U1)).thenReturn(Optional.empty());

        upstreamRefreshService.storeInitialUpstreamToken(OKTA_PID_U1, "incoming-rt");

        verify(upstreamTokenStore).save(any(UpstreamTokenRecord.class));
    }

    @Test
    void storeInitialUpstreamToken_whenRowSameRt_doesNotSaveAgain() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "same-rt", "", 2L, 0L, "", "");
        when(upstreamTokenStore.get(OKTA_PID_U1)).thenReturn(Optional.of(rec));

        upstreamRefreshService.storeInitialUpstreamToken(OKTA_PID_U1, "same-rt");

        verify(upstreamTokenStore, never()).save(any());
    }

    @Test
    void storeInitialUpstreamToken_whenRowDifferentRt_doesNotOverwrite() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "rotated-rt", "", 3L, 0L, "", "");
        when(upstreamTokenStore.get(OKTA_PID_U1)).thenReturn(Optional.of(rec));

        upstreamRefreshService.storeInitialUpstreamToken(OKTA_PID_U1, "stale-session-rt");

        verify(upstreamTokenStore, never()).save(any());
    }

    @Test
    void storeInitialUpstreamToken_whenRowEmptyRt_allowsSave() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(OKTA_PID_U1, "", "", 1L, 0L, "", "");
        when(upstreamTokenStore.get(OKTA_PID_U1)).thenReturn(Optional.of(rec));

        upstreamRefreshService.storeInitialUpstreamToken(OKTA_PID_U1, "fill-rt");

        verify(upstreamTokenStore).save(any(UpstreamTokenRecord.class));
    }
}
