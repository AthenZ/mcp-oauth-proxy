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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.athenz.mop.config.GrafanaTokenExchangeConfig;
import io.athenz.mop.model.grafana.GrafanaTokenInfo;
import io.athenz.mop.secret.K8SSecretsProvider;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.GrafanaManagementClient;
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
class GrafanaTokenCleanerTest {

    private static final String BASE = "https://yahooinc.grafana.net";
    private static final String SA = "cfja56rp4ix34e";
    private static final String SECRET_KEY = "grafana-api-prod";
    private static final String BEARER = "admin-bearer";

    @Mock
    GrafanaTokenExchangeConfig grafanaConfig;

    @Mock
    GrafanaManagementClient grafanaClient;

    @Mock
    K8SSecretsProvider k8SSecretsProvider;

    @Mock
    ConfigService configService;

    @InjectMocks
    GrafanaTokenCleaner cleaner;

    @BeforeEach
    void baseConfig() {
        when(grafanaConfig.cleanupEnabled()).thenReturn(true);
        when(grafanaConfig.adminTokenSecretKey()).thenReturn(SECRET_KEY);
        when(configService.getRemoteServerEndpoint("grafana")).thenReturn(BASE);
        when(configService.getRemoteServerServiceAccountId("grafana")).thenReturn(SA);
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of(SECRET_KEY, BEARER));
    }

    @Test
    void providerId_isGrafana() {
        assertEquals("grafana", cleaner.providerId());
    }

    @Test
    void cleanupOnce_disabled_returnsEmptyAndSkipsHttp() {
        when(grafanaConfig.cleanupEnabled()).thenReturn(false);

        CleanupResult r = cleaner.cleanupOnce();

        assertEquals(0, r.deleted());
        assertEquals(0, r.failed());
        assertTrue(r.isSuccess());
        verify(grafanaClient, never()).listTokens(anyString(), anyString(), anyString());
        verify(grafanaClient, never()).deleteToken(anyString(), anyString(), anyString(), anyLong());
    }

    @Test
    void cleanupOnce_missingEndpoint_returnsEmpty() {
        when(configService.getRemoteServerEndpoint("grafana")).thenReturn(null);

        assertEquals(CleanupResult.EMPTY, cleaner.cleanupOnce());
        verify(grafanaClient, never()).listTokens(anyString(), anyString(), anyString());
    }

    @Test
    void cleanupOnce_missingServiceAccountId_returnsEmpty() {
        when(configService.getRemoteServerServiceAccountId("grafana")).thenReturn(null);

        assertEquals(CleanupResult.EMPTY, cleaner.cleanupOnce());
        verify(grafanaClient, never()).listTokens(anyString(), anyString(), anyString());
    }

    @Test
    void cleanupOnce_missingAdminBearer_returnsEmpty() {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of());

        assertEquals(CleanupResult.EMPTY, cleaner.cleanupOnce());
        verify(grafanaClient, never()).listTokens(anyString(), anyString(), anyString());
    }

    @Test
    void cleanupOnce_noTokens_returnsEmpty() {
        when(grafanaClient.listTokens(BASE, SA, BEARER)).thenReturn(List.of());

        assertEquals(CleanupResult.EMPTY, cleaner.cleanupOnce());
        verify(grafanaClient, never()).deleteToken(anyString(), anyString(), anyString(), anyLong());
    }

    @Test
    void cleanupOnce_deletesOnlyExpiredOrRevokedTokens() {
        GrafanaTokenInfo live = new GrafanaTokenInfo(1L, "mcp.a.1", null, false, false);
        GrafanaTokenInfo expired = new GrafanaTokenInfo(2L, "mcp.b.2", null, true, false);
        GrafanaTokenInfo revoked = new GrafanaTokenInfo(3L, "mcp.c.3", null, false, true);
        GrafanaTokenInfo both = new GrafanaTokenInfo(4L, "mcp.d.4", null, true, true);
        when(grafanaClient.listTokens(BASE, SA, BEARER)).thenReturn(List.of(live, expired, revoked, both));
        when(grafanaClient.deleteToken(eq(BASE), eq(SA), eq(BEARER), anyLong())).thenReturn(true);

        CleanupResult r = cleaner.cleanupOnce();

        assertEquals(3, r.deleted());
        assertEquals(0, r.failed());
        verify(grafanaClient).deleteToken(BASE, SA, BEARER, 2L);
        verify(grafanaClient).deleteToken(BASE, SA, BEARER, 3L);
        verify(grafanaClient).deleteToken(BASE, SA, BEARER, 4L);
        verify(grafanaClient, never()).deleteToken(eq(BASE), eq(SA), eq(BEARER), eq(1L));
    }

    @Test
    void cleanupOnce_partialDeleteFailures_countedInFailed() {
        GrafanaTokenInfo e1 = new GrafanaTokenInfo(10L, "e1", null, true, false);
        GrafanaTokenInfo e2 = new GrafanaTokenInfo(11L, "e2", null, true, false);
        GrafanaTokenInfo e3 = new GrafanaTokenInfo(12L, "e3", null, true, false);
        when(grafanaClient.listTokens(BASE, SA, BEARER)).thenReturn(List.of(e1, e2, e3));
        when(grafanaClient.deleteToken(BASE, SA, BEARER, 10L)).thenReturn(true);
        when(grafanaClient.deleteToken(BASE, SA, BEARER, 11L)).thenReturn(false);
        when(grafanaClient.deleteToken(BASE, SA, BEARER, 12L)).thenThrow(new RuntimeException("boom"));

        CleanupResult r = cleaner.cleanupOnce();

        assertEquals(1, r.deleted());
        assertEquals(2, r.failed());
        assertEquals(false, r.isSuccess());
    }

    @Test
    void cleanupOnce_nullEntryInList_skipped() {
        GrafanaTokenInfo expired = new GrafanaTokenInfo(1L, "e", null, true, false);
        List<GrafanaTokenInfo> tokens = new java.util.ArrayList<>();
        tokens.add(null);
        tokens.add(expired);
        when(grafanaClient.listTokens(BASE, SA, BEARER)).thenReturn(tokens);
        when(grafanaClient.deleteToken(eq(BASE), eq(SA), eq(BEARER), anyLong())).thenReturn(true);

        CleanupResult r = cleaner.cleanupOnce();

        assertEquals(1, r.deleted());
        assertEquals(0, r.failed());
        verify(grafanaClient).deleteToken(BASE, SA, BEARER, 1L);
    }
}
