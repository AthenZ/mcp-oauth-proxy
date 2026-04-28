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

import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.store.TokenStore;
import io.athenz.mop.store.impl.aws.CrossRegionTokenStoreFallback;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class UserTokenRegionResolverTest {

    private static final String USER = "user.test";
    private static final String PROVIDER = AudienceConstants.PROVIDER_OKTA;
    private static final String HASH = "deadbeef";
    private static final String PRIMARY_REGION = "us-east-1";
    private static final String FALLBACK_REGION = "us-west-2";

    @Mock
    private TokenStore tokenStore;

    @Mock
    private CrossRegionTokenStoreFallback crossRegionFallback;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private MetricsRegionProvider metricsRegionProvider;

    @InjectMocks
    private UserTokenRegionResolver resolver;

    private TokenWrapper makeToken(String provider) {
        return new TokenWrapper(USER, provider, "id", "access", "refresh",
                Instant.now().getEpochSecond() + 300);
    }

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        when(metricsRegionProvider.primaryRegion()).thenReturn(PRIMARY_REGION);
        Field f = UserTokenRegionResolver.class.getDeclaredField("fallbackRegionConfig");
        f.setAccessible(true);
        f.set(resolver, Optional.of(FALLBACK_REGION));
    }

    @Test
    void resolveByUserProvider_LocalHit_ReturnsLocalAndDoesNotConsultPeer() {
        TokenWrapper local = makeToken(PROVIDER);
        when(tokenStore.getUserToken(USER, PROVIDER)).thenReturn(local);

        UserTokenResolution r = resolver.resolveByUserProvider(USER, PROVIDER,
                UserTokenRegionResolver.CALL_SITE_AUTHORIZE_USER_TOKEN);

        assertSame(local, r.token());
        assertFalse(r.resolvedFromFallback());
        verify(crossRegionFallback, never()).getUserToken(anyString(), anyString());
        verify(crossRegionFallback, never()).isActive();
        verifyNoInteractions(oauthProxyMetrics);
    }

    @Test
    void resolveByUserProvider_LocalMissPeerHit_RecordsTriggeredMetric() {
        TokenWrapper peer = makeToken(PROVIDER);
        when(tokenStore.getUserToken(USER, PROVIDER)).thenReturn(null);
        when(crossRegionFallback.isActive()).thenReturn(true);
        when(crossRegionFallback.getUserToken(USER, PROVIDER)).thenReturn(peer);

        UserTokenResolution r = resolver.resolveByUserProvider(USER, PROVIDER,
                UserTokenRegionResolver.CALL_SITE_AUTHORIZE_USER_TOKEN);

        assertSame(peer, r.token());
        assertTrue(r.resolvedFromFallback());
        verify(oauthProxyMetrics).recordCrossRegionFallbackTriggered(
                eq("okta"),
                eq(UserTokenRegionResolver.CALL_SITE_AUTHORIZE_USER_TOKEN),
                eq(PRIMARY_REGION),
                eq(FALLBACK_REGION));
        verify(oauthProxyMetrics, never()).recordCrossRegionFallbackExhausted(
                anyString(), anyString(), anyString(), anyString(), anyInt(), anyString());
    }

    @Test
    void resolveByUserProvider_BothMiss_RecordsExhaustedMetric() {
        when(tokenStore.getUserToken(USER, PROVIDER)).thenReturn(null);
        when(crossRegionFallback.isActive()).thenReturn(true);
        when(crossRegionFallback.getUserToken(USER, PROVIDER)).thenReturn(null);

        UserTokenResolution r = resolver.resolveByUserProvider(USER, PROVIDER,
                UserTokenRegionResolver.CALL_SITE_AUTHORIZE_USER_TOKEN);

        assertNull(r.token());
        assertFalse(r.resolvedFromFallback());
        verify(oauthProxyMetrics).recordCrossRegionFallbackExhausted(
                eq("okta"),
                eq(UserTokenRegionResolver.CALL_SITE_AUTHORIZE_USER_TOKEN),
                eq(PRIMARY_REGION),
                eq(FALLBACK_REGION),
                eq(401),
                eq("not_found"));
    }

    @Test
    void resolveByUserProvider_FallbackInactive_DoesNotConsultPeerOrEmitMetrics() {
        when(tokenStore.getUserToken(USER, PROVIDER)).thenReturn(null);
        when(crossRegionFallback.isActive()).thenReturn(false);

        UserTokenResolution r = resolver.resolveByUserProvider(USER, PROVIDER,
                UserTokenRegionResolver.CALL_SITE_AUTHORIZE_USER_TOKEN);

        assertNull(r.token());
        assertFalse(r.resolvedFromFallback());
        verify(crossRegionFallback, never()).getUserToken(anyString(), anyString());
        verifyNoInteractions(oauthProxyMetrics);
    }

    @Test
    void resolveByAccessTokenHash_LocalHit_ReturnsLocalAndDoesNotConsultPeer() {
        TokenWrapper local = makeToken(PROVIDER);
        when(tokenStore.getUserTokenByAccessTokenHash(HASH)).thenReturn(local);

        UserTokenResolution r = resolver.resolveByAccessTokenHash(HASH,
                UserTokenRegionResolver.CALL_SITE_USERINFO_TOKEN_LOOKUP);

        assertSame(local, r.token());
        assertFalse(r.resolvedFromFallback());
        verify(crossRegionFallback, never()).getUserTokenByAccessTokenHash(anyString());
        verifyNoInteractions(oauthProxyMetrics);
    }

    @Test
    void resolveByAccessTokenHash_LocalMissPeerHit_RecordsTriggeredWithProviderLabel() {
        TokenWrapper peer = makeToken("google-gmail");
        when(tokenStore.getUserTokenByAccessTokenHash(HASH)).thenReturn(null);
        when(crossRegionFallback.isActive()).thenReturn(true);
        when(crossRegionFallback.getUserTokenByAccessTokenHash(HASH)).thenReturn(peer);

        UserTokenResolution r = resolver.resolveByAccessTokenHash(HASH,
                UserTokenRegionResolver.CALL_SITE_USERINFO_TOKEN_LOOKUP);

        assertSame(peer, r.token());
        assertTrue(r.resolvedFromFallback());
        verify(oauthProxyMetrics).recordCrossRegionFallbackTriggered(
                eq("google-gmail"),
                eq(UserTokenRegionResolver.CALL_SITE_USERINFO_TOKEN_LOOKUP),
                eq(PRIMARY_REGION),
                eq(FALLBACK_REGION));
    }

    @Test
    void resolveByAccessTokenHash_BothMiss_RecordsExhaustedWithUnknownProvider() {
        when(tokenStore.getUserTokenByAccessTokenHash(HASH)).thenReturn(null);
        when(crossRegionFallback.isActive()).thenReturn(true);
        when(crossRegionFallback.getUserTokenByAccessTokenHash(HASH)).thenReturn(null);

        UserTokenResolution r = resolver.resolveByAccessTokenHash(HASH,
                UserTokenRegionResolver.CALL_SITE_USERINFO_TOKEN_LOOKUP);

        assertNull(r.token());
        assertFalse(r.resolvedFromFallback());
        verify(oauthProxyMetrics).recordCrossRegionFallbackExhausted(
                eq("unknown"),
                eq(UserTokenRegionResolver.CALL_SITE_USERINFO_TOKEN_LOOKUP),
                eq(PRIMARY_REGION),
                eq(FALLBACK_REGION),
                eq(401),
                eq("not_found"));
    }

    @Test
    void resolveByAccessTokenHash_FallbackInactive_DoesNotConsultPeer() {
        when(tokenStore.getUserTokenByAccessTokenHash(HASH)).thenReturn(null);
        when(crossRegionFallback.isActive()).thenReturn(false);

        UserTokenResolution r = resolver.resolveByAccessTokenHash(HASH,
                UserTokenRegionResolver.CALL_SITE_USERINFO_TOKEN_LOOKUP);

        assertNull(r.token());
        assertFalse(r.resolvedFromFallback());
        verify(crossRegionFallback, never()).getUserTokenByAccessTokenHash(anyString());
        verifyNoInteractions(oauthProxyMetrics);
    }
}
