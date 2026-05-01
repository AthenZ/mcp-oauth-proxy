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

import io.athenz.mop.model.RefreshTokenRecord;
import io.athenz.mop.store.impl.aws.CrossRegionTokenStoreFallback;
import io.athenz.mop.store.impl.aws.RefreshTableAttribute;
import io.athenz.mop.store.impl.aws.RefreshTableConstants;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class RefreshTokenRegionResolverTest {

    private static final String PRIMARY_REGION = "us-east-1";
    private static final String FALLBACK_REGION = "us-west-2";
    private static final String OKTA_PID_U1 = AudienceConstants.PROVIDER_OKTA + "#u1";

    @Mock
    private DynamoDbClient dynamoDbClient;

    @Mock
    private CrossRegionTokenStoreFallback crossRegionFallback;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private MetricsRegionProvider metricsRegionProvider;

    @InjectMocks
    private RefreshTokenRegionResolver resolver;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        when(metricsRegionProvider.primaryRegion()).thenReturn(PRIMARY_REGION);
        Field f = RefreshTokenRegionResolver.class.getDeclaredField("fallbackRegionConfig");
        f.setAccessible(true);
        f.set(resolver, Optional.of(FALLBACK_REGION));
        Field tableField = RefreshTokenRegionResolver.class.getDeclaredField("tableName");
        tableField.setAccessible(true);
        tableField.set(resolver, "test-refresh-tokens");
    }

    private static Map<String, AttributeValue> activeItem(String id) {
        return Map.of(
                RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s(id).build(),
                RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_U1).build(),
                RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s("u1").build(),
                RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s("c1").build(),
                RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(AudienceConstants.PROVIDER_OKTA).build(),
                RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build(),
                RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(),
                        AttributeValue.builder().s("enc-" + id).build(),
                RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n("100").build(),
                RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(System.currentTimeMillis() / 1000 + 3600)).build());
    }

    @Test
    void resolveByHash_localHit_returnsLocalAndDoesNotConsultPeer() {
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(activeItem("id-local"))).build());

        RefreshTokenResolution r = resolver.resolveByHash("h");

        assertNotNull(r.record());
        assertEquals("id-local", r.record().refreshTokenId());
        assertFalse(r.resolvedFromFallback());
        verify(crossRegionFallback, never()).lookupRefreshTokenByHash(anyString());
        verifyNoInteractions(oauthProxyMetrics);
    }

    @Test
    void resolveByHash_localMissPeerHit_recordsTriggered() {
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of()).build());
        when(crossRegionFallback.isRefreshAndUpstreamActive()).thenReturn(true);
        RefreshTokenRecord peer = new RefreshTokenRecord("id-peer", OKTA_PID_U1, "u1", "c1",
                AudienceConstants.PROVIDER_OKTA, "s", null, RefreshTableConstants.STATUS_ACTIVE, "f1", null, null,
                0L, 200L, 99999L, 99999L);
        when(crossRegionFallback.lookupRefreshTokenByHash("h")).thenReturn(peer);

        RefreshTokenResolution r = resolver.resolveByHash("h");

        assertSame(peer, r.record());
        assertTrue(r.resolvedFromFallback());
        verify(oauthProxyMetrics).recordCrossRegionFallbackTriggered(
                eq(AudienceConstants.PROVIDER_OKTA),
                eq(RefreshTokenRegionResolver.CALL_SITE_REFRESH_TOKEN_VALIDATE),
                eq(PRIMARY_REGION),
                eq(FALLBACK_REGION));
    }

    @Test
    void resolveByHash_bothMiss_recordsExhausted() {
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of()).build());
        when(crossRegionFallback.isRefreshAndUpstreamActive()).thenReturn(true);
        when(crossRegionFallback.lookupRefreshTokenByHash("h")).thenReturn(null);

        RefreshTokenResolution r = resolver.resolveByHash("h");

        assertNull(r.record());
        verify(oauthProxyMetrics).recordCrossRegionFallbackExhausted(
                eq("unknown"),
                eq(RefreshTokenRegionResolver.CALL_SITE_REFRESH_TOKEN_VALIDATE),
                eq(PRIMARY_REGION),
                eq(FALLBACK_REGION),
                eq(401),
                eq("not_found"));
    }

    @Test
    void resolveByHash_fallbackInactive_doesNotConsultPeerOrEmitMetrics() {
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of()).build());
        when(crossRegionFallback.isRefreshAndUpstreamActive()).thenReturn(false);

        RefreshTokenResolution r = resolver.resolveByHash("h");

        assertNull(r.record());
        verify(crossRegionFallback, never()).lookupRefreshTokenByHash(anyString());
        verifyNoInteractions(oauthProxyMetrics);
    }

    @Test
    void resolveItemByPrimaryKey_fallbackInactive_returnsNull() {
        when(crossRegionFallback.isRefreshAndUpstreamActive()).thenReturn(false);

        Map<String, AttributeValue> item = resolver.resolveItemByPrimaryKey("id1", OKTA_PID_U1);

        assertNull(item);
        verifyNoInteractions(oauthProxyMetrics);
    }

    @Test
    void resolveItemByPrimaryKey_peerHit_recordsTriggered() {
        when(crossRegionFallback.isRefreshAndUpstreamActive()).thenReturn(true);
        Map<String, AttributeValue> peerItem = activeItem("id-peer");
        when(crossRegionFallback.getRefreshTokenItemByPrimaryKey("id1", OKTA_PID_U1)).thenReturn(peerItem);

        Map<String, AttributeValue> item = resolver.resolveItemByPrimaryKey("id1", OKTA_PID_U1);

        assertNotNull(item);
        verify(oauthProxyMetrics).recordCrossRegionFallbackTriggered(
                eq(AudienceConstants.PROVIDER_OKTA),
                eq(RefreshTokenRegionResolver.CALL_SITE_REFRESH_TOKEN_GET_PK),
                anyString(),
                anyString());
    }

    @Test
    void resolveBestUpstream_picksPeerWhenPeerNewer() {
        // Local query returns one item with low issued_at
        Map<String, AttributeValue> localItem = activeItem("id-local");
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(localItem)).build());
        when(crossRegionFallback.isRefreshAndUpstreamActive()).thenReturn(true);
        // Peer record with higher issued_at
        RefreshTokenRecord peer = new RefreshTokenRecord("id-peer", OKTA_PID_U1, "u1", "c1",
                AudienceConstants.PROVIDER_OKTA, "s", "enc-peer", RefreshTableConstants.STATUS_ACTIVE,
                "f1", null, null, 0L, 99999L, 99999L, 99999L);
        when(crossRegionFallback.queryBestUpstreamRefresh("u1", AudienceConstants.PROVIDER_OKTA))
                .thenReturn(peer);

        RefreshTokenResolution r = resolver.resolveBestUpstream("u1", AudienceConstants.PROVIDER_OKTA);

        assertSame(peer, r.record());
        assertTrue(r.resolvedFromFallback());
        verify(oauthProxyMetrics).recordCrossRegionFallbackTriggered(
                eq(AudienceConstants.PROVIDER_OKTA),
                eq(RefreshTokenRegionResolver.CALL_SITE_REFRESH_TOKEN_GET_UPSTREAM),
                anyString(),
                anyString());
    }

    @Test
    void resolveBestUpstream_picksLocalWhenLocalNewer() {
        Map<String, AttributeValue> localItem = Map.of(
                RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s("id-local").build(),
                RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_U1).build(),
                RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s("u1").build(),
                RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s("c1").build(),
                RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(AudienceConstants.PROVIDER_OKTA).build(),
                RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build(),
                RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), AttributeValue.builder().s("enc-local").build(),
                RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n("99999").build(),
                RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(System.currentTimeMillis() / 1000 + 3600)).build());
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(localItem)).build());
        when(crossRegionFallback.isRefreshAndUpstreamActive()).thenReturn(true);
        RefreshTokenRecord peer = new RefreshTokenRecord("id-peer", OKTA_PID_U1, "u1", "c1",
                AudienceConstants.PROVIDER_OKTA, "s", "enc-peer", RefreshTableConstants.STATUS_ACTIVE,
                "f1", null, null, 0L, 100L, 99999L, 99999L);
        when(crossRegionFallback.queryBestUpstreamRefresh("u1", AudienceConstants.PROVIDER_OKTA))
                .thenReturn(peer);

        RefreshTokenResolution r = resolver.resolveBestUpstream("u1", AudienceConstants.PROVIDER_OKTA);

        assertNotNull(r.record());
        assertEquals("id-local", r.record().refreshTokenId());
        assertFalse(r.resolvedFromFallback());
        verify(oauthProxyMetrics, never()).recordCrossRegionFallbackTriggered(
                anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void resolveBestUpstream_recordsExhausted_whenBothMiss() {
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of()).build());
        when(crossRegionFallback.isRefreshAndUpstreamActive()).thenReturn(true);
        when(crossRegionFallback.queryBestUpstreamRefresh(anyString(), anyString())).thenReturn(null);

        RefreshTokenResolution r = resolver.resolveBestUpstream("u1", AudienceConstants.PROVIDER_OKTA);

        assertNull(r.record());
        verify(oauthProxyMetrics).recordCrossRegionFallbackExhausted(
                eq(AudienceConstants.PROVIDER_OKTA),
                eq(RefreshTokenRegionResolver.CALL_SITE_REFRESH_TOKEN_GET_UPSTREAM),
                anyString(), anyString(), anyInt(), anyString());
    }

    /** Suppress unused-imports warning for GetItemResponse (used by some tests via Mockito reflection). */
    @SuppressWarnings("unused")
    private GetItemResponse unused() {
        return null;
    }
}
