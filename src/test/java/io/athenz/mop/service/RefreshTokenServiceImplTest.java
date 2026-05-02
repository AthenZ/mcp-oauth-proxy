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
import io.athenz.mop.model.RefreshTokenValidationResult;
import io.athenz.mop.store.impl.aws.RefreshTableAttribute;
import io.athenz.mop.store.impl.aws.RefreshTableConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.mockito.Mockito.lenient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;

import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceImplTest {

    private static final String OKTA_PID_USER1 = AudienceConstants.PROVIDER_OKTA + "#user1";

    @Mock
    DynamoDbClient dynamoDbClient;

    @Mock
    RefreshLockStore refreshLockStore;

    RefreshTokenServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new RefreshTokenServiceImpl();
        service.dynamoDbClient = dynamoDbClient;
        service.tableName = "test-refresh-tokens";
        service.expirySeconds = 7776000L;
        service.ttlBufferDays = 7;
        service.rotatedGraceSeconds = 10;
        service.familyIdleGraceSeconds = 0;
        service.inflightCacheSeconds = 30;
        service.inflightLockTtlSeconds = 10;
        service.inflightLockMaxRetries = 7;
        service.inflightLockInitialBackoffMs = 5;
        service.refreshLockStore = refreshLockStore;
        service.init();
        // Per-RT lock is taken on every rotate; default to "always granted" for unit tests.
        // Tests that need to exercise lock contention can override per-call.
        lenient().when(refreshLockStore.tryAcquire(anyString(), anyString(), anyLong())).thenReturn(true);
    }

    @Test
    void generateSecureToken_hasPrefixAndFormat() {
        String token = service.generateSecureToken();
        assertNotNull(token);
        assertTrue(token.startsWith("rt_"), "Token should start with rt_");
        String encoded = token.substring(3);
        assertDoesNotThrow(() -> Base64.getUrlDecoder().decode(encoded));
        assertEquals(43, encoded.length(), "Base64url 32 bytes without padding = 43 chars");
    }

    @Test
    void generateSecureToken_isUnique() {
        String a = service.generateSecureToken();
        String b = service.generateSecureToken();
        assertNotEquals(a, b);
    }

    @Test
    void hashToken_isConsistent() {
        String raw = "rt_" + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
        String h1 = service.hashToken(raw);
        String h2 = service.hashToken(raw);
        assertEquals(h1, h2);
    }

    @Test
    void hashToken_producesHexOutput() {
        String raw = "rt_" + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
        String h = service.hashToken(raw);
        assertNotNull(h);
        assertTrue(h.matches("[0-9a-f]{64}"), "SHA-256 hash should be 64 hex chars");
    }

    @Test
    void secureEquals_constantTimeComparison() {
        assertTrue(RefreshTokenServiceImpl.secureEquals("same", "same"));
        assertFalse(RefreshTokenServiceImpl.secureEquals("a", "b"));
        assertFalse(RefreshTokenServiceImpl.secureEquals("ab", "a"));
        assertTrue(RefreshTokenServiceImpl.secureEquals(null, null));
        assertFalse(RefreshTokenServiceImpl.secureEquals("a", null));
        assertFalse(RefreshTokenServiceImpl.secureEquals(null, "a"));
    }

    @Test
    void validate_returnsInvalidWhenTokenNull() {
        RefreshTokenValidationResult result = service.validate(null, "client1");
        assertEquals(RefreshTokenValidationResult.Status.INVALID, result.status());
    }

    @Test
    void validate_returnsInvalidWhenTokenEmpty() {
        RefreshTokenValidationResult result = service.validate("", "client1");
        assertEquals(RefreshTokenValidationResult.Status.INVALID, result.status());
    }

    @Test
    void validate_returnsInvalidWhenClientIdEmpty() {
        String token = service.generateSecureToken();
        RefreshTokenValidationResult result = service.validate(token, "");
        assertEquals(RefreshTokenValidationResult.Status.INVALID, result.status());
    }

    @Test
    void validate_returnsInvalidWhenExpired() {
        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        long pastExpiry = now - 3600;
        Map<String, AttributeValue> item = Map.of(
                RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s("id1").build(),
                RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_USER1).build(),
                RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s("user1").build(),
                RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s("client1").build(),
                RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(AudienceConstants.PROVIDER_OKTA).build(),
                RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build(),
                RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), AttributeValue.builder().s("f1").build(),
                RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(pastExpiry)).build(),
                RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n(String.valueOf(now - 7200)).build(),
                RefreshTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(pastExpiry)).build()
        );
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(item)).build());
        RefreshTokenValidationResult result = service.validate(token, "client1");
        assertEquals(RefreshTokenValidationResult.Status.INVALID, result.status());
    }

    @Test
    void validate_returnsInvalidWhenNoItemInDynamo() {
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of()).build());
        String token = service.generateSecureToken();
        RefreshTokenValidationResult result = service.validate(token, "client1");
        assertEquals(RefreshTokenValidationResult.Status.INVALID, result.status());
    }

    @Test
    void validate_returnsActiveWhenItemFoundAndActive() {
        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> item = Map.of(
                RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s("id1").build(),
                RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_USER1).build(),
                RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s("user1").build(),
                RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s("client1").build(),
                RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(AudienceConstants.PROVIDER_OKTA).build(),
                RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build(),
                RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), AttributeValue.builder().s("f1").build(),
                RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build(),
                RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n(String.valueOf(now)).build(),
                RefreshTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build()
        );
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(item)).build());
        RefreshTokenValidationResult result = service.validate(token, "client1");
        assertEquals(RefreshTokenValidationResult.Status.ACTIVE, result.status());
        assertNotNull(result.record());
        assertEquals("user1", result.record().userId());
        assertEquals(AudienceConstants.PROVIDER_OKTA, result.record().provider());
    }

    @Test
    void validate_returnsInvalidWhenClientIdMismatch() {
        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> item = Map.of(
                RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s("id1").build(),
                RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_USER1).build(),
                RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s("user1").build(),
                RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s("other-client").build(),
                RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(AudienceConstants.PROVIDER_OKTA).build(),
                RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build(),
                RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), AttributeValue.builder().s("f1").build(),
                RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build(),
                RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n(String.valueOf(now)).build(),
                RefreshTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build()
        );
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(item)).build());
        RefreshTokenValidationResult result = service.validate(token, "client1");
        assertEquals(RefreshTokenValidationResult.Status.INVALID, result.status());
    }

    @Test
    void validate_returnsRotatedReplayWhenStatusRotatedOutsideGraceWindow() {
        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> item = new java.util.HashMap<>(Map.of(
                RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s("id1").build(),
                RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_USER1).build(),
                RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s("user1").build(),
                RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s("client1").build(),
                RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(AudienceConstants.PROVIDER_OKTA).build(),
                RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ROTATED).build(),
                RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), AttributeValue.builder().s("f1").build(),
                RefreshTableAttribute.REPLACED_BY.attr(), AttributeValue.builder().s("id2").build(),
                // Rotated well outside the configured 10s grace window (60s ago).
                RefreshTableAttribute.ROTATED_AT.attr(), AttributeValue.builder().n(String.valueOf(now - 60)).build(),
                RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build()
        ));
        item.put(RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n(String.valueOf(now - 3600)).build());
        item.put(RefreshTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build());
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(item)).build());
        RefreshTokenValidationResult result = service.validate(token, "client1");
        assertEquals(RefreshTokenValidationResult.Status.ROTATED_REPLAY, result.status());
        assertNotNull(result.record());
    }

    @Test
    void validate_returnsRevokedWhenStatusRevoked() {
        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> item = Map.of(
                RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s("id1").build(),
                RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_USER1).build(),
                RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s("user1").build(),
                RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s("client1").build(),
                RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(AudienceConstants.PROVIDER_OKTA).build(),
                RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_REVOKED).build(),
                RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), AttributeValue.builder().s("f1").build(),
                RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build(),
                RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n(String.valueOf(now)).build(),
                RefreshTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build()
        );
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(item)).build());
        RefreshTokenValidationResult result = service.validate(token, "client1");
        assertEquals(RefreshTokenValidationResult.Status.REVOKED, result.status());
    }

    @Test
    void rotate_returnsNullWithoutHandlingReplayWhenConditionalCheckFailsUnderLock() {
        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> activeItem = new java.util.HashMap<>(Map.of(
                RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s("id1").build(),
                RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_USER1).build(),
                RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s("user1").build(),
                RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s("client1").build(),
                RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(AudienceConstants.PROVIDER_OKTA).build(),
                RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build(),
                RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), AttributeValue.builder().s("f1").build(),
                RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build(),
                RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n(String.valueOf(now)).build(),
                RefreshTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build()
        ));
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(activeItem)).build());
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(activeItem).build());
        when(dynamoDbClient.transactWriteItems(any(TransactWriteItemsRequest.class)))
                .thenThrow(ConditionalCheckFailedException.builder().build());

        var result = service.rotate(token, "client1");

        assertNull(result);
    }

    @Test
    void getUpstreamRefreshToken_returnsNullWhenUserIdNull() {
        assertNull(service.getUpstreamRefreshToken(null, AudienceConstants.PROVIDER_OKTA));
    }

    @Test
    void getUpstreamRefreshToken_returnsNullWhenUserIdEmpty() {
        assertNull(service.getUpstreamRefreshToken("", AudienceConstants.PROVIDER_OKTA));
    }

    @Test
    void getUpstreamRefreshToken_returnsNullWhenProviderNull() {
        assertNull(service.getUpstreamRefreshToken("user1", null));
    }

    @Test
    void getUpstreamRefreshToken_returnsNullWhenProviderEmpty() {
        assertNull(service.getUpstreamRefreshToken("user1", ""));
    }

    @Test
    void getUpstreamRefreshToken_returnsNullWhenNoItems() {
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of()).build());
        assertNull(service.getUpstreamRefreshToken("user1", AudienceConstants.PROVIDER_OKTA));
    }

    @Test
    void getUpstreamRefreshToken_returnsEncryptedUpstreamWhenOneActiveItem() {
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> item = new HashMap<>();
        item.put(RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s("id1").build());
        item.put(RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_USER1).build());
        item.put(RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s("user1").build());
        item.put(RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s("c1").build());
        item.put(RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(AudienceConstants.PROVIDER_OKTA).build());
        item.put(RefreshTableAttribute.PROVIDER_SUBJECT.attr(), AttributeValue.builder().s("sub1").build());
        item.put(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), AttributeValue.builder().s("enc-upstream-1").build());
        item.put(RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build());
        item.put(RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), AttributeValue.builder().s("f1").build());
        item.put(RefreshTableAttribute.ROTATED_FROM.attr(), AttributeValue.builder().s("").build());
        item.put(RefreshTableAttribute.REPLACED_BY.attr(), AttributeValue.builder().s("").build());
        item.put(RefreshTableAttribute.ROTATED_AT.attr(), AttributeValue.builder().n("0").build());
        item.put(RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n(String.valueOf(now)).build());
        item.put(RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build());
        item.put(RefreshTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build());
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(item)).build());
        String result = service.getUpstreamRefreshToken("user1", AudienceConstants.PROVIDER_OKTA);
        assertEquals("enc-upstream-1", result);
    }

    @Test
    void updateUpstreamRefreshForToken_byId_noOpWhenRefreshTokenIdNull() {
        service.updateUpstreamRefreshForToken(null, "pu", "newUpstream");
    }

    @Test
    void updateUpstreamRefreshForToken_byId_noOpWhenNewUpstreamEmpty() {
        service.updateUpstreamRefreshForToken("id1", OKTA_PID_USER1, "");
    }

    @Test
    void handleReplay_noOpWhenTokenNull() {
        service.handleReplay(null);
    }

    @Test
    void handleReplay_noOpWhenTokenEmpty() {
        service.handleReplay("");
    }

    @Test
    void revokeFamily_noOpWhenTokenFamilyIdNull() {
        service.revokeFamily(null);
    }

    @Test
    void revokeFamily_noOpWhenTokenFamilyIdEmpty() {
        service.revokeFamily("");
    }

    @Test
    void getByPrimaryKey_returnsRecordWhenItemFound() {
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> item = new HashMap<>();
        item.put(RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s("id1").build());
        item.put(RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_USER1).build());
        item.put(RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s("user1").build());
        item.put(RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s("c1").build());
        item.put(RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(AudienceConstants.PROVIDER_OKTA).build());
        item.put(RefreshTableAttribute.PROVIDER_SUBJECT.attr(), AttributeValue.builder().s("sub1").build());
        item.put(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), AttributeValue.builder().s("enc").build());
        item.put(RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build());
        item.put(RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), AttributeValue.builder().s("f1").build());
        item.put(RefreshTableAttribute.ROTATED_FROM.attr(), AttributeValue.builder().s("oldId").build());
        item.put(RefreshTableAttribute.REPLACED_BY.attr(), AttributeValue.builder().s("newId").build());
        item.put(RefreshTableAttribute.ROTATED_AT.attr(), AttributeValue.builder().n("12345").build());
        item.put(RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n(String.valueOf(now)).build());
        item.put(RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build());
        item.put(RefreshTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build());
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(item).build());
        RefreshTokenRecord record = service.getByPrimaryKey("id1", "okta#user1");
        assertNotNull(record);
        assertEquals("id1", record.refreshTokenId());
        assertEquals(OKTA_PID_USER1, record.providerUserId());
        assertEquals("user1", record.userId());
        assertEquals(AudienceConstants.PROVIDER_OKTA, record.provider());
        assertEquals("enc", record.encryptedUpstreamRefreshToken());
        assertEquals(RefreshTableConstants.STATUS_ACTIVE, record.status());
        assertEquals(12345L, record.rotatedAt());
    }

    @Test
    void getByPrimaryKey_returnsNullWhenItemNotFound() {
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().build());
        RefreshTokenRecord record = service.getByPrimaryKey("id1", "okta#user1");
        assertNull(record);
    }

    @Test
    void validate_returnsActive_whenRowOnlyInPeerRegion() {
        RefreshTokenRegionResolver resolver = org.mockito.Mockito.mock(RefreshTokenRegionResolver.class);
        service.refreshTokenRegionResolver = resolver;
        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        RefreshTokenRecord peerRecord = new RefreshTokenRecord(
                "id1", OKTA_PID_USER1, "user1", "client1", AudienceConstants.PROVIDER_OKTA, "sub1",
                null, RefreshTableConstants.STATUS_ACTIVE, "f1", null, null,
                0L, now, now + 3600, now + 3600);
        lenient().when(resolver.resolveByHash(org.mockito.ArgumentMatchers.anyString()))
                .thenReturn(new RefreshTokenResolution(peerRecord, true));

        RefreshTokenValidationResult result = service.validate(token, "client1");
        assertEquals(RefreshTokenValidationResult.Status.ACTIVE, result.status());
        assertNotNull(result.record());
        assertEquals("user1", result.record().userId());
    }

    @Test
    void getUpstreamRefreshToken_picksBestAcrossRegions() {
        RefreshTokenRegionResolver resolver = org.mockito.Mockito.mock(RefreshTokenRegionResolver.class);
        service.refreshTokenRegionResolver = resolver;
        long now = System.currentTimeMillis() / 1000;
        RefreshTokenRecord peerRecord = new RefreshTokenRecord(
                "id-peer", OKTA_PID_USER1, "user1", "c1", AudienceConstants.PROVIDER_OKTA, "sub",
                "enc-peer-newer", RefreshTableConstants.STATUS_ACTIVE, "f1", null, null,
                0L, now + 100, now + 7200, now + 7200);
        lenient().when(resolver.resolveBestUpstream("user1", AudienceConstants.PROVIDER_OKTA))
                .thenReturn(new RefreshTokenResolution(peerRecord, true));

        String result = service.getUpstreamRefreshToken("user1", AudienceConstants.PROVIDER_OKTA);
        assertEquals("enc-peer-newer", result);
    }

    @Test
    void getByPrimaryKey_findsInPeerWhenLocalMissing() {
        RefreshTokenRegionResolver resolver = org.mockito.Mockito.mock(RefreshTokenRegionResolver.class);
        service.refreshTokenRegionResolver = resolver;
        long now = System.currentTimeMillis() / 1000;
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().build());
        Map<String, AttributeValue> peerItem = new HashMap<>();
        peerItem.put(RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s("id1").build());
        peerItem.put(RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_USER1).build());
        peerItem.put(RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s("user1").build());
        peerItem.put(RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s("c1").build());
        peerItem.put(RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(AudienceConstants.PROVIDER_OKTA).build());
        peerItem.put(RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build());
        peerItem.put(RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), AttributeValue.builder().s("f1").build());
        peerItem.put(RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n(String.valueOf(now)).build());
        peerItem.put(RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build());
        peerItem.put(RefreshTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build());
        lenient().when(resolver.resolveItemByPrimaryKey("id1", OKTA_PID_USER1)).thenReturn(peerItem);

        RefreshTokenRecord record = service.getByPrimaryKey("id1", OKTA_PID_USER1);
        assertNotNull(record);
        assertEquals("id1", record.refreshTokenId());
        assertEquals("user1", record.userId());
    }

    // ---------------------------------------------------------------------------------------
    // Layer 1 (per-RT singleflight) and Layer 2 (rotated-grace) coverage.
    // ---------------------------------------------------------------------------------------

    private static Map<String, AttributeValue> activeRow(String tokenId, long now) {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put(RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s(tokenId).build());
        item.put(RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_USER1).build());
        item.put(RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s("user1").build());
        item.put(RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s("client1").build());
        item.put(RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(AudienceConstants.PROVIDER_OKTA).build());
        item.put(RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build());
        item.put(RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), AttributeValue.builder().s("f1").build());
        item.put(RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n(String.valueOf(now)).build());
        item.put(RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build());
        item.put(RefreshTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(now + 3600)).build());
        return item;
    }

    private static Map<String, AttributeValue> rotatedRow(String tokenId, long now, long rotatedAgo, String replacedBy) {
        Map<String, AttributeValue> item = activeRow(tokenId, now - 3600);
        item.put(RefreshTableAttribute.STATUS.attr(),
                AttributeValue.builder().s(RefreshTableConstants.STATUS_ROTATED).build());
        item.put(RefreshTableAttribute.ROTATED_AT.attr(),
                AttributeValue.builder().n(String.valueOf(now - rotatedAgo)).build());
        item.put(RefreshTableAttribute.REPLACED_BY.attr(),
                AttributeValue.builder().s(replacedBy).build());
        return item;
    }

    @Test
    void rotate_takesPerRtLockBeforeRotating() {
        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> active = activeRow("id1", now);
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(active)).build());
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(active).build());

        var result = service.rotate(token, "client1");

        assertNotNull(result);
        verify(refreshLockStore).tryAcquire(eq("rt-rotate:" + service.hashToken(token)),
                anyString(), anyLong());
        verify(refreshLockStore).release(eq("rt-rotate:" + service.hashToken(token)), anyString());
    }

    @Test
    void rotate_returnsNullAndDoesNotRotateWhenLockNotAcquired() {
        String token = service.generateSecureToken();
        // Force lock failure on every retry.
        when(refreshLockStore.tryAcquire(anyString(), anyString(), anyLong())).thenReturn(false);

        var result = service.rotate(token, "client1");

        assertNull(result);
        verify(dynamoDbClient, never()).transactWriteItems(any(TransactWriteItemsRequest.class));
        verify(refreshLockStore, never()).release(anyString(), anyString());
    }

    @Test
    void rotate_servesSecondCallerFromInflightCacheWithoutSecondTransactWrite() {
        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> active = activeRow("id1", now);
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(active)).build());
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(active).build());

        var first = service.rotate(token, "client1");
        var second = service.rotate(token, "client1");

        assertNotNull(first);
        assertNotNull(second);
        assertEquals(first.rawToken(), second.rawToken(),
                "Singleflight: duplicate caller must receive the same raw RT");
        assertEquals(first.refreshTokenId(), second.refreshTokenId());
        verify(dynamoDbClient, times(1)).transactWriteItems(any(TransactWriteItemsRequest.class));
    }

    @Test
    void rotate_conditionalCheckFailedUnderLockDoesNotRevokeFamily() {
        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> active = activeRow("id1", now);
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(active)).build());
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(active).build());
        when(dynamoDbClient.transactWriteItems(any(TransactWriteItemsRequest.class)))
                .thenThrow(ConditionalCheckFailedException.builder().build());

        var result = service.rotate(token, "client1");

        assertNull(result);
        // Crucially: NO putItem call to flip rows to REVOKED. Family stays intact; the caller's
        // next attempt will hit the grace path in validate().
        verify(dynamoDbClient, never())
                .putItem(any(software.amazon.awssdk.services.dynamodb.model.PutItemRequest.class));
    }

    @Test
    void validate_returnsRotatedGraceSuccessorWhenInsideGraceWindow() {
        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> rotated = rotatedRow("id1", now, /*rotatedAgo*/ 3, "id2");
        Map<String, AttributeValue> successor = activeRow("id2", now - 3);
        // Two query call sites: lookupByHash (returns rotated) then queryLatestActiveInFamily
        // (returns successor). Use sequenced returns so order matters.
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(rotated)).build())
                .thenReturn(QueryResponse.builder().items(List.of(successor)).build());

        RefreshTokenValidationResult result = service.validate(token, "client1");

        assertEquals(RefreshTokenValidationResult.Status.ROTATED_GRACE_SUCCESSOR, result.status());
        assertNotNull(result.successor());
        assertEquals("id2", result.successor().refreshTokenId());
    }

    @Test
    void validate_fallsBackToReplayWhenGraceWindowHasNoLiveSuccessor() {
        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> rotated = rotatedRow("id1", now, /*rotatedAgo*/ 3, "id2");
        // Family-index query returns only ROTATED rows; no live ACTIVE successor exists.
        Map<String, AttributeValue> rotatedSuccessor = rotatedRow("id2", now, /*rotatedAgo*/ 1, "id3");
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(rotated)).build())
                .thenReturn(QueryResponse.builder().items(List.of(rotatedSuccessor)).build());

        RefreshTokenValidationResult result = service.validate(token, "client1");

        assertEquals(RefreshTokenValidationResult.Status.ROTATED_REPLAY, result.status());
        assertNull(result.successor());
    }

    @Test
    void rotateGraceSuccessor_mintsNewRtFromActiveSuccessor() {
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> successorItem = activeRow("id2", now - 3);
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(successorItem).build());

        RefreshTokenRecord successor = io.athenz.mop.store.impl.aws.RefreshTokenStoreDynamodbHelpers
                .itemToRecord(successorItem);

        var result = service.rotateGraceSuccessor(successor);

        assertNotNull(result);
        assertNotNull(result.rawToken());
        assertNotEquals("id2", result.refreshTokenId(), "Should mint a brand-new id, not reuse the parent's");
        verify(dynamoDbClient, times(1)).transactWriteItems(any(TransactWriteItemsRequest.class));
    }

    @Test
    void validate_familyIdleGate_servesGraceWhenFamilyRecentlyActive() {
        // 2h token-age window; 48h family-idle gate; family successor was rotated 30 min ago.
        service.rotatedGraceSeconds = 7200;
        service.familyIdleGraceSeconds = 172800;

        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> rotated = rotatedRow("id1", now, /*rotatedAgo*/ 5400, "id2");
        Map<String, AttributeValue> successor = activeRow("id2", now - 1800);
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(rotated)).build())
                .thenReturn(QueryResponse.builder().items(List.of(successor)).build());

        RefreshTokenValidationResult result = service.validate(token, "client1");

        assertEquals(RefreshTokenValidationResult.Status.ROTATED_GRACE_SUCCESSOR, result.status());
        assertNotNull(result.successor());
        assertEquals("id2", result.successor().refreshTokenId());
    }

    @Test
    void validate_familyIdleGate_revokesWhenFamilyAbandoned() {
        // 2h token-age window; 48h family-idle gate; presented row is 1h old (in token-age grace),
        // but the family's most recent ACTIVE leaf was issued 49h ago — family looks abandoned.
        service.rotatedGraceSeconds = 7200;
        service.familyIdleGraceSeconds = 172800;

        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> rotated = rotatedRow("id1", now, /*rotatedAgo*/ 3600, "id2");
        Map<String, AttributeValue> staleSuccessor = activeRow("id2", now - 176400);
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(rotated)).build())
                .thenReturn(QueryResponse.builder().items(List.of(staleSuccessor)).build());

        RefreshTokenValidationResult result = service.validate(token, "client1");

        assertEquals(RefreshTokenValidationResult.Status.ROTATED_REPLAY, result.status());
        assertNull(result.successor());
    }

    @Test
    void validate_familyIdleGate_disabledByDefaultMatchesTokenAgeOnlyBehavior() {
        // 2h token-age window; family-idle gate OFF — even when the successor's last activity
        // is well outside what the family-idle gate would allow, the call should still get the
        // grace path because the gate is disabled (this is today's ship-now default).
        service.rotatedGraceSeconds = 7200;
        service.familyIdleGraceSeconds = 0;

        String token = service.generateSecureToken();
        long now = System.currentTimeMillis() / 1000;
        Map<String, AttributeValue> rotated = rotatedRow("id1", now, /*rotatedAgo*/ 3600, "id2");
        // Successor was issued 49h ago but is still unexpired (90d expiry on RTs); the gate
        // would reject this if enabled (49h > 48h family-idle), but with gate=0 we accept.
        Map<String, AttributeValue> agedSuccessor = new HashMap<>(activeRow("id2", now));
        agedSuccessor.put(RefreshTableAttribute.ISSUED_AT.attr(),
                AttributeValue.builder().n(String.valueOf(now - 176400)).build());
        when(dynamoDbClient.query(any(QueryRequest.class)))
                .thenReturn(QueryResponse.builder().items(List.of(rotated)).build())
                .thenReturn(QueryResponse.builder().items(List.of(agedSuccessor)).build());

        RefreshTokenValidationResult result = service.validate(token, "client1");

        assertEquals(RefreshTokenValidationResult.Status.ROTATED_GRACE_SUCCESSOR, result.status(),
                "With family-idle gate disabled, only the token-age check governs grace");
    }

    @Test
    void rotateGraceSuccessor_returnsNullWhenSuccessorNoLongerActive() {
        long now = System.currentTimeMillis() / 1000;
        // Successor has been rotated since validate() snapshotted it.
        Map<String, AttributeValue> rotatedSuccessor = rotatedRow("id2", now, 1, "id3");
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(rotatedSuccessor).build());

        RefreshTokenRecord successor = io.athenz.mop.store.impl.aws.RefreshTokenStoreDynamodbHelpers
                .itemToRecord(rotatedSuccessor);

        var result = service.rotateGraceSuccessor(successor);

        assertNull(result);
        verify(dynamoDbClient, never()).transactWriteItems(any(TransactWriteItemsRequest.class));
    }
}
