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
package io.athenz.mop.store.impl.aws;

import io.athenz.mop.config.UpstreamTokenConfig;
import io.athenz.mop.model.UpstreamTokenRecord;
import io.athenz.mop.service.AudienceConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UpstreamTokenStoreDynamoDbImplTest {

    private static final String TABLE = "mcp-oauth-proxy-upstream-tokens";
    private static final String OKTA_PID_U1 = AudienceConstants.PROVIDER_OKTA + "#u1";

    @Mock
    DynamoDbClient dynamoDbClient;

    @Mock
    UpstreamTokenConfig upstreamTokenConfig;

    @InjectMocks
    UpstreamTokenStoreDynamoDbImpl store;

    @BeforeEach
    void setUp() {
        when(upstreamTokenConfig.tableName()).thenReturn(TABLE);
        when(upstreamTokenConfig.expirySeconds()).thenReturn(7776000L);
        when(upstreamTokenConfig.ttlBufferDays()).thenReturn(7);
    }

    @Test
    void save_putItemContainsPartitionKey() {
        UpstreamTokenRecord rec = UpstreamTokenRecord.builder()
                .providerUserId(OKTA_PID_U1)
                .encryptedOktaRefreshToken("rt-plain")
                .lastRotatedAt("2025-01-01T00:00:00Z")
                .version(1L)
                .ttl(2000000000L)
                .createdAt("2025-01-01T00:00:00Z")
                .updatedAt("2025-01-01T00:00:00Z")
                .build();

        store.save(rec);

        ArgumentCaptor<PutItemRequest> cap = ArgumentCaptor.forClass(PutItemRequest.class);
        verify(dynamoDbClient).putItem(cap.capture());
        assertEquals(TABLE, cap.getValue().tableName());
        assertEquals(OKTA_PID_U1, cap.getValue().item().get(UpstreamTableAttribute.PROVIDER_USER_ID.attr()).s());
    }

    @Test
    void get_returnsEmptyWhenNoItem() {
        when(dynamoDbClient.getItem(any(GetItemRequest.class))).thenReturn(GetItemResponse.builder().build());

        assertTrue(store.get(OKTA_PID_U1).isEmpty());
    }

    @Test
    void get_mapsItem() {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put(UpstreamTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_U1).build());
        item.put(UpstreamTableAttribute.ENCRYPTED_OKTA_REFRESH_TOKEN.attr(), AttributeValue.builder().s("tok").build());
        item.put(UpstreamTableAttribute.LAST_ROTATED_AT.attr(), AttributeValue.builder().s("t0").build());
        item.put(UpstreamTableAttribute.VERSION.attr(), AttributeValue.builder().n("3").build());
        item.put(UpstreamTableAttribute.TTL.attr(), AttributeValue.builder().n("9").build());
        item.put(UpstreamTableAttribute.CREATED_AT.attr(), AttributeValue.builder().s("c").build());
        item.put(UpstreamTableAttribute.UPDATED_AT.attr(), AttributeValue.builder().s("u").build());
        when(dynamoDbClient.getItem(any(GetItemRequest.class))).thenReturn(GetItemResponse.builder().item(item).build());

        var opt = store.get(OKTA_PID_U1);
        assertTrue(opt.isPresent());
        assertEquals(3L, opt.get().version());
        assertEquals("tok", opt.get().encryptedOktaRefreshToken());
    }

    @Test
    void updateWithVersionCheck_returnsFalseWhenNoRow() {
        when(dynamoDbClient.getItem(any(GetItemRequest.class))).thenReturn(GetItemResponse.builder().build());
        assertFalse(store.updateWithVersionCheck(OKTA_PID_U1, "new-rt", 1L));
    }

    @Test
    void delete_callsDeleteItem() {
        store.delete(OKTA_PID_U1);
        verify(dynamoDbClient).deleteItem(any(DeleteItemRequest.class));
    }

    @Test
    void markRevoked_returnsFalseWhenRowMissing() {
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().build());

        assertFalse(store.markRevoked(OKTA_PID_U1, 1L, "reason"));
        verify(dynamoDbClient, never()).putItem(any(PutItemRequest.class));
    }

    @Test
    void markRevoked_returnsFalseWhenVersionDoesNotMatch() {
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(activeRowItem("rt", 5L)).build());

        assertFalse(store.markRevoked(OKTA_PID_U1, 4L, "reason"));
        verify(dynamoDbClient, never()).putItem(any(PutItemRequest.class));
    }

    @Test
    void markRevoked_returnsFalseWhenAlreadyRevoked() {
        Map<String, AttributeValue> already = activeRowItem("rt", 7L);
        already.put(UpstreamTableAttribute.STATUS.attr(),
                AttributeValue.builder().s(UpstreamTokenRecord.STATUS_REVOKED_INVALID_GRANT).build());
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(already).build());

        assertFalse(store.markRevoked(OKTA_PID_U1, 7L, "reason"));
        verify(dynamoDbClient, never()).putItem(any(PutItemRequest.class));
    }

    @Test
    void markRevoked_writesSoftDeleteRowWithCasAndShortTtl() {
        when(upstreamTokenConfig.revokedRetentionDays()).thenReturn(14);
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(activeRowItem("plain-rt", 7L)).build());

        long beforeEpoch = Instant.now().getEpochSecond();
        assertTrue(store.markRevoked(OKTA_PID_U1, 7L, "Okta refresh token invalid or revoked: ..."));
        long afterEpoch = Instant.now().getEpochSecond();

        ArgumentCaptor<PutItemRequest> cap = ArgumentCaptor.forClass(PutItemRequest.class);
        verify(dynamoDbClient).putItem(cap.capture());
        PutItemRequest put = cap.getValue();
        Map<String, AttributeValue> item = put.item();

        assertEquals(UpstreamTokenRecord.STATUS_REVOKED_INVALID_GRANT,
                item.get(UpstreamTableAttribute.STATUS.attr()).s());
        assertEquals("Okta refresh token invalid or revoked: ...",
                item.get(UpstreamTableAttribute.REVOKED_REASON.attr()).s());
        assertFalse(item.get(UpstreamTableAttribute.REVOKED_AT.attr()).s().isEmpty());
        assertEquals("",
                item.get(UpstreamTableAttribute.ENCRYPTED_OKTA_REFRESH_TOKEN.attr()).s(),
                "encrypted RT must be cleared on revoke so we don't keep ciphertext beyond its useful life");
        assertEquals("7", item.get(UpstreamTableAttribute.VERSION.attr()).n(),
                "revoke must not bump version (CAS expects expectedVersion to still match)");
        assertEquals("#ver = :expected", put.conditionExpression());

        long ttl = Long.parseLong(item.get(UpstreamTableAttribute.TTL.attr()).n());
        long expectedMin = beforeEpoch + 14L * 86400L;
        long expectedMax = afterEpoch + 14L * 86400L;
        assertTrue(ttl >= expectedMin && ttl <= expectedMax,
                "revoke TTL should be ~now + revokedRetentionDays; got " + ttl
                        + ", expected in [" + expectedMin + "," + expectedMax + "]");
    }

    @Test
    void markRevoked_returnsFalseOnConditionalCheckFailure() {
        when(upstreamTokenConfig.revokedRetentionDays()).thenReturn(14);
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(activeRowItem("plain-rt", 7L)).build());
        when(dynamoDbClient.putItem(any(PutItemRequest.class)))
                .thenThrow(ConditionalCheckFailedException.builder().message("peer rotated").build());

        assertFalse(store.markRevoked(OKTA_PID_U1, 7L, "reason"));
    }

    @Test
    void updateWithVersionCheck_skipsWhenRowAlreadyRevoked() {
        Map<String, AttributeValue> revoked = activeRowItem("plain-rt", 7L);
        revoked.put(UpstreamTableAttribute.STATUS.attr(),
                AttributeValue.builder().s(UpstreamTokenRecord.STATUS_REVOKED_INVALID_GRANT).build());
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(revoked).build());

        assertFalse(store.updateWithVersionCheck(OKTA_PID_U1, "rt8", 7L));
        verify(dynamoDbClient, never()).putItem(any(PutItemRequest.class));
    }

    @Test
    void updateWithVersionCheck_bumpsRotationCount() {
        Map<String, AttributeValue> existing = activeRowItem("plain-rt", 7L);
        existing.put(UpstreamTableAttribute.ROTATION_COUNT.attr(), AttributeValue.builder().n("6").build());
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(existing).build());

        assertTrue(store.updateWithVersionCheck(OKTA_PID_U1, "rt8", 7L));

        ArgumentCaptor<PutItemRequest> cap = ArgumentCaptor.forClass(PutItemRequest.class);
        verify(dynamoDbClient).putItem(cap.capture());
        Map<String, AttributeValue> item = cap.getValue().item();
        assertEquals("8", item.get(UpstreamTableAttribute.VERSION.attr()).n());
        assertEquals("7", item.get(UpstreamTableAttribute.ROTATION_COUNT.attr()).n(),
                "rotation_count should increment by 1 on each successful rotation");
        assertEquals(UpstreamTokenRecord.STATUS_ACTIVE,
                item.get(UpstreamTableAttribute.STATUS.attr()).s());
    }

    @Test
    void get_treatsMissingStatusAttrAsActive_backwardCompat() {
        Map<String, AttributeValue> oldRow = new HashMap<>();
        oldRow.put(UpstreamTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_U1).build());
        oldRow.put(UpstreamTableAttribute.ENCRYPTED_OKTA_REFRESH_TOKEN.attr(), AttributeValue.builder().s("rt").build());
        oldRow.put(UpstreamTableAttribute.VERSION.attr(), AttributeValue.builder().n("3").build());
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(oldRow).build());

        var got = store.get(OKTA_PID_U1).orElseThrow();
        assertTrue(got.isActive(), "rows that predate the status attr must default to ACTIVE");
    }

    private static Map<String, AttributeValue> activeRowItem(String token, long version) {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put(UpstreamTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(OKTA_PID_U1).build());
        item.put(UpstreamTableAttribute.ENCRYPTED_OKTA_REFRESH_TOKEN.attr(), AttributeValue.builder().s(token).build());
        item.put(UpstreamTableAttribute.LAST_ROTATED_AT.attr(), AttributeValue.builder().s("2026-05-03T00:00:00Z").build());
        item.put(UpstreamTableAttribute.VERSION.attr(), AttributeValue.builder().n(String.valueOf(version)).build());
        item.put(UpstreamTableAttribute.TTL.attr(), AttributeValue.builder().n("2000000000").build());
        item.put(UpstreamTableAttribute.CREATED_AT.attr(), AttributeValue.builder().s("2026-01-01T00:00:00Z").build());
        item.put(UpstreamTableAttribute.UPDATED_AT.attr(), AttributeValue.builder().s("2026-05-03T00:00:00Z").build());
        item.put(UpstreamTableAttribute.STATUS.attr(),
                AttributeValue.builder().s(UpstreamTokenRecord.STATUS_ACTIVE).build());
        return item;
    }
}
