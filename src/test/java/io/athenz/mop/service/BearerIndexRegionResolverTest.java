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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.athenz.mop.model.BearerIndexRecord;
import io.athenz.mop.store.BearerIndexStore;
import io.athenz.mop.store.impl.aws.CrossRegionTokenStoreFallback;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import java.lang.reflect.Field;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class BearerIndexRegionResolverTest {

    private static final String HASH = "deadbeef";
    private static final String PRIMARY_REGION = "us-east-1";
    private static final String FALLBACK_REGION = "us-west-2";

    @Mock
    private BearerIndexStore bearerIndexStore;

    @Mock
    private CrossRegionTokenStoreFallback crossRegionFallback;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private MetricsRegionProvider metricsRegionProvider;

    @InjectMocks
    private BearerIndexRegionResolver resolver;

    private BearerIndexRecord row(String provider) {
        return new BearerIndexRecord(HASH, "u1", "client-1", provider, 1700000000L, 1700003600L);
    }

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        when(metricsRegionProvider.primaryRegion()).thenReturn(PRIMARY_REGION);
        Field f = BearerIndexRegionResolver.class.getDeclaredField("fallbackRegionConfig");
        f.setAccessible(true);
        f.set(resolver, Optional.of(FALLBACK_REGION));
    }

    @Test
    void localHit_returnsLocalAndDoesNotConsultPeer() {
        BearerIndexRecord local = row("okta");
        when(bearerIndexStore.getBearer(HASH)).thenReturn(local);

        BearerIndexResolution r = resolver.resolveByHash(HASH);

        assertSame(local, r.record());
        assertFalse(r.resolvedFromFallback());
        verify(crossRegionFallback, never()).getBearerIndex(anyString());
        verify(crossRegionFallback, never()).isActive();
        verify(oauthProxyMetrics).recordBearerIndexLookup(eq("hit"));
    }

    @Test
    void localMissPeerHit_recordsTriggeredAndFromFallback() {
        BearerIndexRecord peer = row("google-gmail");
        when(bearerIndexStore.getBearer(HASH)).thenReturn(null);
        when(crossRegionFallback.isActive()).thenReturn(true);
        when(crossRegionFallback.getBearerIndex(HASH)).thenReturn(peer);

        BearerIndexResolution r = resolver.resolveByHash(HASH);

        assertSame(peer, r.record());
        assertTrue(r.resolvedFromFallback());
        verify(oauthProxyMetrics).recordCrossRegionFallbackTriggered(
                eq("google-gmail"),
                eq(BearerIndexRegionResolver.CALL_SITE_USERINFO_BEARER_LOOKUP),
                eq(PRIMARY_REGION),
                eq(FALLBACK_REGION));
        verify(oauthProxyMetrics).recordBearerIndexLookup(eq("from_fallback"));
        verify(oauthProxyMetrics, never()).recordCrossRegionFallbackExhausted(
                anyString(), anyString(), anyString(), anyString(), anyInt(), anyString());
    }

    @Test
    void bothMiss_recordsExhaustedWithUnknownProvider() {
        when(bearerIndexStore.getBearer(HASH)).thenReturn(null);
        when(crossRegionFallback.isActive()).thenReturn(true);
        when(crossRegionFallback.getBearerIndex(HASH)).thenReturn(null);

        BearerIndexResolution r = resolver.resolveByHash(HASH);

        assertNull(r.record());
        assertFalse(r.resolvedFromFallback());
        verify(oauthProxyMetrics).recordCrossRegionFallbackExhausted(
                eq("unknown"),
                eq(BearerIndexRegionResolver.CALL_SITE_USERINFO_BEARER_LOOKUP),
                eq(PRIMARY_REGION),
                eq(FALLBACK_REGION),
                eq(401),
                eq("not_found"));
        verify(oauthProxyMetrics).recordBearerIndexLookup(eq("miss"));
    }

    @Test
    void fallbackInactive_doesNotConsultPeerOrEmitFallbackMetrics() {
        when(bearerIndexStore.getBearer(HASH)).thenReturn(null);
        when(crossRegionFallback.isActive()).thenReturn(false);

        BearerIndexResolution r = resolver.resolveByHash(HASH);

        assertNull(r.record());
        assertFalse(r.resolvedFromFallback());
        verify(crossRegionFallback, never()).getBearerIndex(anyString());
        verify(oauthProxyMetrics).recordBearerIndexLookup(eq("miss"));
        verify(oauthProxyMetrics, never()).recordCrossRegionFallbackExhausted(
                anyString(), anyString(), anyString(), anyString(), anyInt(), anyString());
        verify(oauthProxyMetrics, never()).recordCrossRegionFallbackTriggered(
                anyString(), anyString(), anyString(), anyString());
    }
}
