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

import io.athenz.mop.model.AuthorizationCodeTokensDO;
import io.athenz.mop.store.TokenStoreAsync;
import io.athenz.mop.store.impl.aws.CrossRegionTokenStoreFallback;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.smallrye.mutiny.Uni;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.Field;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class AuthCodeTokensRegionResolverTest {

    private static final String PRIMARY_REGION = "us-east-1";
    private static final String FALLBACK_REGION = "us-west-2";

    @Mock
    private TokenStoreAsync tokenStoreAsync;

    @Mock
    private CrossRegionTokenStoreFallback crossRegionFallback;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private MetricsRegionProvider metricsRegionProvider;

    @InjectMocks
    private AuthCodeTokensRegionResolver resolver;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        when(metricsRegionProvider.primaryRegion()).thenReturn(PRIMARY_REGION);
        Field f = AuthCodeTokensRegionResolver.class.getDeclaredField("fallbackRegionConfig");
        f.setAccessible(true);
        f.set(resolver, Optional.of(FALLBACK_REGION));
    }

    private static AuthorizationCodeTokensDO sampleToken(String at) {
        AuthorizationCodeTokensDO t = new AuthorizationCodeTokensDO();
        t.setAccessToken(at);
        return t;
    }

    @Test
    void resolve_localHit_returnsLocal() {
        AuthorizationCodeTokensDO local = sampleToken("at-local");
        when(tokenStoreAsync.getTokenAsync("id1", AudienceConstants.PROVIDER_OKTA))
                .thenReturn(Uni.createFrom().item(local));

        AuthorizationCodeTokensDO out = resolver.resolve("id1", AudienceConstants.PROVIDER_OKTA).await().indefinitely();

        assertSame(local, out);
        verifyNoInteractions(crossRegionFallback);
        verifyNoInteractions(oauthProxyMetrics);
    }

    @Test
    void resolve_localFailurePeerHit_recordsTriggered() {
        AuthorizationCodeTokensDO peer = sampleToken("at-peer");
        when(tokenStoreAsync.getTokenAsync("id1", AudienceConstants.PROVIDER_OKTA))
                .thenReturn(Uni.createFrom().failure(new RuntimeException("not found")));
        when(crossRegionFallback.isActive()).thenReturn(true);
        when(crossRegionFallback.getTokenAsync("id1", AudienceConstants.PROVIDER_OKTA)).thenReturn(peer);

        AuthorizationCodeTokensDO out = resolver.resolve("id1", AudienceConstants.PROVIDER_OKTA).await().indefinitely();

        assertSame(peer, out);
        verify(oauthProxyMetrics).recordCrossRegionFallbackTriggered(
                eq(AudienceConstants.PROVIDER_OKTA),
                eq(AuthCodeTokensRegionResolver.CALL_SITE_AUTH_CODE_TOKENS_GET),
                eq(PRIMARY_REGION),
                eq(FALLBACK_REGION));
    }

    @Test
    void resolve_localNullPeerHit_recordsTriggered() {
        AuthorizationCodeTokensDO peer = sampleToken("at-peer");
        when(tokenStoreAsync.getTokenAsync("id1", AudienceConstants.PROVIDER_OKTA))
                .thenReturn(Uni.createFrom().nullItem());
        when(crossRegionFallback.isActive()).thenReturn(true);
        when(crossRegionFallback.getTokenAsync("id1", AudienceConstants.PROVIDER_OKTA)).thenReturn(peer);

        AuthorizationCodeTokensDO out = resolver.resolve("id1", AudienceConstants.PROVIDER_OKTA).await().indefinitely();

        assertSame(peer, out);
        verify(oauthProxyMetrics).recordCrossRegionFallbackTriggered(
                eq(AudienceConstants.PROVIDER_OKTA),
                eq(AuthCodeTokensRegionResolver.CALL_SITE_AUTH_CODE_TOKENS_GET),
                anyString(),
                anyString());
    }

    @Test
    void resolve_bothMiss_recordsExhaustedAndFails() {
        when(tokenStoreAsync.getTokenAsync("id1", AudienceConstants.PROVIDER_OKTA))
                .thenReturn(Uni.createFrom().failure(new RuntimeException("local-not-found")));
        when(crossRegionFallback.isActive()).thenReturn(true);
        when(crossRegionFallback.getTokenAsync("id1", AudienceConstants.PROVIDER_OKTA)).thenReturn(null);

        ExecutionException ex = assertThrows(ExecutionException.class, () ->
                resolver.resolve("id1", AudienceConstants.PROVIDER_OKTA).subscribeAsCompletionStage().get());
        assertNotNull(ex.getCause());
        verify(oauthProxyMetrics).recordCrossRegionFallbackExhausted(
                eq(AudienceConstants.PROVIDER_OKTA),
                eq(AuthCodeTokensRegionResolver.CALL_SITE_AUTH_CODE_TOKENS_GET),
                anyString(),
                anyString(),
                anyInt(),
                anyString());
    }

    @Test
    void resolve_fallbackInactive_propagatesLocalFailure() {
        when(tokenStoreAsync.getTokenAsync("id1", AudienceConstants.PROVIDER_OKTA))
                .thenReturn(Uni.createFrom().failure(new RuntimeException("local-not-found")));
        when(crossRegionFallback.isActive()).thenReturn(false);

        assertThrows(ExecutionException.class, () ->
                resolver.resolve("id1", AudienceConstants.PROVIDER_OKTA).subscribeAsCompletionStage().get());
        verify(crossRegionFallback, never()).getTokenAsync(anyString(), anyString());
        verifyNoInteractions(oauthProxyMetrics);
    }
}
