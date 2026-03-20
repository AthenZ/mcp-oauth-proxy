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
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceImplTest {

    private static final String OKTA_PID_USER1 = AudienceConstants.PROVIDER_OKTA + "#user1";

    @Mock
    DynamoDbClient dynamoDbClient;

    RefreshTokenServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new RefreshTokenServiceImpl();
        service.dynamoDbClient = dynamoDbClient;
        service.tableName = "test-refresh-tokens";
        service.expirySeconds = 7776000L;
        service.ttlBufferDays = 7;
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
    void validate_returnsRotatedReplayWhenStatusRotated() {
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
                RefreshTableAttribute.ROTATED_AT.attr(), AttributeValue.builder().n(String.valueOf(now - 10)).build(),
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
    void rotate_returnsNullAndHandlesReplayWhenConditionalCheckFails() {
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
}
