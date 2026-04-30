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

import io.athenz.mop.model.UpstreamTokenRecord;
import io.athenz.mop.store.UpstreamTokenStore;
import io.athenz.mop.store.impl.aws.CrossRegionTokenStoreFallback;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.Field;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class UpstreamTokenRegionResolverTest {

    private static final String PRIMARY_REGION = "us-east-1";
    private static final String FALLBACK_REGION = "us-west-2";
    private static final String OKTA_PID_U1 = AudienceConstants.PROVIDER_OKTA + "#u1";

    @Mock
    private UpstreamTokenStore upstreamTokenStore;

    @Mock
    private CrossRegionTokenStoreFallback crossRegionFallback;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private MetricsRegionProvider metricsRegionProvider;

    @InjectMocks
    private UpstreamTokenRegionResolver resolver;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        when(metricsRegionProvider.primaryRegion()).thenReturn(PRIMARY_REGION);
        Field f = UpstreamTokenRegionResolver.class.getDeclaredField("fallbackRegionConfig");
        f.setAccessible(true);
        f.set(resolver, Optional.of(FALLBACK_REGION));
    }

    private static UpstreamTokenRecord rec(long version) {
        return new UpstreamTokenRecord(OKTA_PID_U1, "rt", "now", version, 0L, "now", "now");
    }

    @Test
    void resolveByProviderUserId_localHit_doesNotConsultPeer() {
        when(upstreamTokenStore.get(OKTA_PID_U1)).thenReturn(Optional.of(rec(3)));

        UpstreamTokenResolution r = resolver.resolveByProviderUserId(OKTA_PID_U1);

        assertNotNull(r.record());
        assertEquals(3L, r.record().version());
        assertFalse(r.resolvedFromFallback());
        verify(crossRegionFallback, never()).getUpstreamToken(anyString());
        verifyNoInteractions(oauthProxyMetrics);
    }

    @Test
    void resolveByProviderUserId_localMissPeerHit_recordsTriggered() {
        when(upstreamTokenStore.get(OKTA_PID_U1)).thenReturn(Optional.empty());
        when(crossRegionFallback.isActive()).thenReturn(true);
        when(crossRegionFallback.getUpstreamToken(OKTA_PID_U1)).thenReturn(Optional.of(rec(5)));

        UpstreamTokenResolution r = resolver.resolveByProviderUserId(OKTA_PID_U1);

        assertNotNull(r.record());
        assertTrue(r.resolvedFromFallback());
        verify(oauthProxyMetrics).recordCrossRegionFallbackTriggered(
                eq("unknown"),
                eq(UpstreamTokenRegionResolver.CALL_SITE_UPSTREAM_TOKEN_GET),
                eq(PRIMARY_REGION),
                eq(FALLBACK_REGION));
    }

    @Test
    void resolveByProviderUserId_bothMiss_recordsExhausted() {
        when(upstreamTokenStore.get(OKTA_PID_U1)).thenReturn(Optional.empty());
        when(crossRegionFallback.isActive()).thenReturn(true);
        when(crossRegionFallback.getUpstreamToken(OKTA_PID_U1)).thenReturn(Optional.empty());

        UpstreamTokenResolution r = resolver.resolveByProviderUserId(OKTA_PID_U1);

        assertNull(r.record());
        verify(oauthProxyMetrics).recordCrossRegionFallbackExhausted(
                eq("unknown"),
                eq(UpstreamTokenRegionResolver.CALL_SITE_UPSTREAM_TOKEN_GET),
                eq(PRIMARY_REGION),
                eq(FALLBACK_REGION),
                anyInt(),
                anyString());
    }

    @Test
    void resolveByProviderUserId_fallbackInactive_returnsLocalOnly() {
        when(upstreamTokenStore.get(OKTA_PID_U1)).thenReturn(Optional.empty());
        when(crossRegionFallback.isActive()).thenReturn(false);

        UpstreamTokenResolution r = resolver.resolveByProviderUserId(OKTA_PID_U1);

        assertNull(r.record());
        verify(crossRegionFallback, never()).getUpstreamToken(anyString());
        verifyNoInteractions(oauthProxyMetrics);
    }

    @Test
    void peerVersionForCas_returnsPeerVersionWhenActiveAndPresent() {
        when(crossRegionFallback.isActive()).thenReturn(true);
        when(crossRegionFallback.getUpstreamToken(OKTA_PID_U1)).thenReturn(Optional.of(rec(8)));

        Optional<Long> v = resolver.peerVersionForCas(OKTA_PID_U1);

        assertTrue(v.isPresent());
        assertEquals(8L, v.get());
    }

    @Test
    void peerVersionForCas_returnsEmpty_whenInactive() {
        when(crossRegionFallback.isActive()).thenReturn(false);

        Optional<Long> v = resolver.peerVersionForCas(OKTA_PID_U1);

        assertTrue(v.isEmpty());
        verify(crossRegionFallback, never()).getUpstreamToken(anyString());
    }

    @Test
    void peerVersionForCas_returnsEmpty_whenPeerMisses() {
        when(crossRegionFallback.isActive()).thenReturn(true);
        when(crossRegionFallback.getUpstreamToken(OKTA_PID_U1)).thenReturn(Optional.empty());

        Optional<Long> v = resolver.peerVersionForCas(OKTA_PID_U1);

        assertTrue(v.isEmpty());
    }
}
