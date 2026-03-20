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
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

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
}
