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
package io.athenz.mop.token.sweeper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.athenz.mop.config.SplunkTokenExchangeConfig;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.secret.K8SSecretsProvider;
import io.athenz.mop.service.SplunkManagementClient;
import io.athenz.mop.service.SplunkManagementClient.SplunkExpiredToken;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SplunkTokenCleanerTest {

    private static final String BASE = "https://splunk-mgmt.test:8089";
    private static final String SECRET_KEY = "splunk-api-prod";
    private static final String BEARER = "admin-bearer";
    private static final String PREFIX = "mcp.";
    private static final long NOW = 2_000_000L;

    @Mock
    SplunkTokenExchangeConfig splunkConfig;

    @Mock
    SplunkManagementClient splunkClient;

    @Mock
    K8SSecretsProvider k8SSecretsProvider;

    @Mock
    ConfigService configService;

    @InjectMocks
    SplunkTokenCleaner cleaner;

    @BeforeEach
    void baseConfig() {
        when(splunkConfig.cleanupEnabled()).thenReturn(true);
        when(splunkConfig.adminTokenSecretKey()).thenReturn(SECRET_KEY);
        when(splunkConfig.mirrorUserPrefix()).thenReturn(PREFIX);
        when(configService.getRemoteServerEndpoint("splunk")).thenReturn(BASE);
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of(SECRET_KEY, BEARER));
        cleaner.clock = Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC);
    }

    @Test
    void providerId_isSplunk() {
        assertEquals("splunk", cleaner.providerId());
    }

    @Test
    void cleanupOnce_disabled_returnsEmptyAndSkipsHttp() {
        when(splunkConfig.cleanupEnabled()).thenReturn(false);

        CleanupResult r = cleaner.cleanupOnce();

        assertEquals(0, r.deleted());
        assertEquals(0, r.failed());
        assertTrue(r.isSuccess());
        verify(splunkClient, never()).listExpiredMcpTokens(anyString(), anyString(), anyString(), anyLong());
        verify(splunkClient, never()).deleteToken(anyString(), anyString(), anyString());
    }

    @Test
    void cleanupOnce_missingEndpoint_returnsEmpty() {
        when(configService.getRemoteServerEndpoint("splunk")).thenReturn(null);

        assertEquals(CleanupResult.EMPTY, cleaner.cleanupOnce());
        verify(splunkClient, never()).listExpiredMcpTokens(anyString(), anyString(), anyString(), anyLong());
    }

    @Test
    void cleanupOnce_blankEndpoint_returnsEmpty() {
        when(configService.getRemoteServerEndpoint("splunk")).thenReturn("  ");

        assertEquals(CleanupResult.EMPTY, cleaner.cleanupOnce());
        verify(splunkClient, never()).listExpiredMcpTokens(anyString(), anyString(), anyString(), anyLong());
    }

    @Test
    void cleanupOnce_missingAdminBearer_returnsEmpty() {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of());

        assertEquals(CleanupResult.EMPTY, cleaner.cleanupOnce());
        verify(splunkClient, never()).listExpiredMcpTokens(anyString(), anyString(), anyString(), anyLong());
    }

    @Test
    void cleanupOnce_nullCredsMap_returnsEmpty() {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(null);

        assertEquals(CleanupResult.EMPTY, cleaner.cleanupOnce());
        verify(splunkClient, never()).listExpiredMcpTokens(anyString(), anyString(), anyString(), anyLong());
    }

    @Test
    void cleanupOnce_blankPrefix_returnsEmpty() {
        when(splunkConfig.mirrorUserPrefix()).thenReturn("");

        assertEquals(CleanupResult.EMPTY, cleaner.cleanupOnce());
        verify(splunkClient, never()).listExpiredMcpTokens(anyString(), anyString(), anyString(), anyLong());
    }

    @Test
    void cleanupOnce_passesNowFromClockToList() {
        when(splunkClient.listExpiredMcpTokens(BASE, BEARER, PREFIX, NOW)).thenReturn(List.of());

        assertEquals(CleanupResult.EMPTY, cleaner.cleanupOnce());

        verify(splunkClient).listExpiredMcpTokens(BASE, BEARER, PREFIX, NOW);
        verify(splunkClient, never()).deleteToken(anyString(), anyString(), anyString());
    }

    @Test
    void cleanupOnce_noTokens_returnsEmpty() {
        when(splunkClient.listExpiredMcpTokens(BASE, BEARER, PREFIX, NOW)).thenReturn(List.of());

        assertEquals(CleanupResult.EMPTY, cleaner.cleanupOnce());
        verify(splunkClient, never()).deleteToken(anyString(), anyString(), anyString());
    }

    @Test
    void cleanupOnce_nullListResult_treatedAsEmpty() {
        when(splunkClient.listExpiredMcpTokens(BASE, BEARER, PREFIX, NOW)).thenReturn(null);

        assertEquals(CleanupResult.EMPTY, cleaner.cleanupOnce());
        verify(splunkClient, never()).deleteToken(anyString(), anyString(), anyString());
    }

    @Test
    void cleanupOnce_deletesEveryReturnedToken() {
        SplunkExpiredToken t1 = new SplunkExpiredToken("id-1", "mcp.alice", 1L);
        SplunkExpiredToken t2 = new SplunkExpiredToken("id-2", "mcp.bob", 2L);
        SplunkExpiredToken t3 = new SplunkExpiredToken("id-3", "mcp.carol", 3L);
        when(splunkClient.listExpiredMcpTokens(BASE, BEARER, PREFIX, NOW))
                .thenReturn(List.of(t1, t2, t3));
        when(splunkClient.deleteToken(eq(BASE), eq(BEARER), anyString())).thenReturn(true);

        CleanupResult r = cleaner.cleanupOnce();

        assertEquals(3, r.deleted());
        assertEquals(0, r.failed());
        assertTrue(r.isSuccess());
        verify(splunkClient).deleteToken(BASE, BEARER, "id-1");
        verify(splunkClient).deleteToken(BASE, BEARER, "id-2");
        verify(splunkClient).deleteToken(BASE, BEARER, "id-3");
    }

    @Test
    void cleanupOnce_partialDeleteFailures_countedInFailed() {
        SplunkExpiredToken e1 = new SplunkExpiredToken("ok", "mcp.a", 1L);
        SplunkExpiredToken e2 = new SplunkExpiredToken("false", "mcp.b", 1L);
        SplunkExpiredToken e3 = new SplunkExpiredToken("throws", "mcp.c", 1L);
        when(splunkClient.listExpiredMcpTokens(BASE, BEARER, PREFIX, NOW))
                .thenReturn(List.of(e1, e2, e3));
        when(splunkClient.deleteToken(BASE, BEARER, "ok")).thenReturn(true);
        when(splunkClient.deleteToken(BASE, BEARER, "false")).thenReturn(false);
        when(splunkClient.deleteToken(BASE, BEARER, "throws")).thenThrow(new RuntimeException("boom"));

        CleanupResult r = cleaner.cleanupOnce();

        assertEquals(1, r.deleted());
        assertEquals(2, r.failed());
        assertFalse(r.isSuccess());
    }

    @Test
    void cleanupOnce_nullEntryAndBlankIdSkipped() {
        SplunkExpiredToken keep = new SplunkExpiredToken("good", "mcp.x", 1L);
        SplunkExpiredToken blank = new SplunkExpiredToken("  ", "mcp.y", 1L);
        List<SplunkExpiredToken> list = new ArrayList<>();
        list.add(null);
        list.add(blank);
        list.add(keep);
        when(splunkClient.listExpiredMcpTokens(BASE, BEARER, PREFIX, NOW)).thenReturn(list);
        when(splunkClient.deleteToken(BASE, BEARER, "good")).thenReturn(true);

        CleanupResult r = cleaner.cleanupOnce();

        assertEquals(1, r.deleted());
        assertEquals(0, r.failed());
        verify(splunkClient).deleteToken(BASE, BEARER, "good");
        verify(splunkClient, never()).deleteToken(eq(BASE), eq(BEARER), eq(""));
    }
}
