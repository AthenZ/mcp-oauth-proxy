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
import io.athenz.mop.model.UpstreamTokenRecord;
import io.athenz.mop.store.UpstreamTokenStore;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

/**
 * Service-level interaction tests (mocked DynamoDB / Okta).
 */
@ExtendWith(MockitoExtension.class)
class UpstreamRefreshIntegrationTest {

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

    @Test
    void secondProviderRefresh_usesLatestVersionAfterConflict() {
        lenient().when(upstreamTokenConfig.expirySeconds()).thenReturn(7776000L);
        lenient().when(upstreamTokenConfig.ttlBufferDays()).thenReturn(7);
        lenient().when(oktaSessionCacheConfig.enabled()).thenReturn(false);

        UpstreamRefreshService svc = new UpstreamRefreshService();
        inject(svc, "upstreamTokenStore", upstreamTokenStore);
        inject(svc, "oktaTokenClient", oktaTokenClient);
        inject(svc, "upstreamTokenConfig", upstreamTokenConfig);
        inject(svc, "refreshCoordinationService", refreshCoordinationService);
        inject(svc, "upstreamTokenRegionResolver", upstreamTokenRegionResolver);
        inject(svc, "oauthProxyMetrics", oauthProxyMetrics);
        inject(svc, "oktaSessionCache", oktaSessionCache);
        inject(svc, "oktaSessionCacheConfig", oktaSessionCacheConfig);
        inject(svc, "userTokenRegionResolver", userTokenRegionResolver);

        String pid = AudienceConstants.PROVIDER_OKTA + "#user1";
        UpstreamTokenRecord v1 = new UpstreamTokenRecord(pid, "rt1", "", 1L, 0L, "", "");
        UpstreamTokenRecord v2 = new UpstreamTokenRecord(pid, "rt2", "", 2L, 0L, "", "");
        when(upstreamTokenRegionResolver.resolveByProviderUserId(pid)).thenReturn(
                new UpstreamTokenResolution(v1, false),
                new UpstreamTokenResolution(v2, false));
        when(upstreamTokenRegionResolver.peerVersionForCas(pid)).thenReturn(Optional.empty());
        when(oktaTokenClient.refreshToken("rt1")).thenReturn(new OktaTokens("a1", "rt2", null, 3600));
        when(oktaTokenClient.refreshToken("rt2")).thenReturn(new OktaTokens("a2", "rt3", null, 3600));
        when(upstreamTokenStore.updateWithVersionCheck(pid, "rt2", 1L)).thenReturn(false);
        when(upstreamTokenStore.updateWithVersionCheck(pid, "rt3", 2L)).thenReturn(true);

        OktaTokens out = svc.refreshUpstream(pid);

        assertEquals("a2", out.accessToken());
        verify(upstreamTokenRegionResolver, times(2)).resolveByProviderUserId(pid);
    }

    private static void inject(Object target, String field, Object value) {
        try {
            var f = target.getClass().getDeclaredField(field);
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
