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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.athenz.mop.model.BearerIndexRecord;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemResponse;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemResponse;

@ExtendWith(MockitoExtension.class)
class BearerIndexStoreDynamodbImplTest {

    private static final String TABLE = "mcp-oauth-proxy-bearer-index";
    private static final String HASH = "deadbeef";
    private static final String USER = "u1";
    private static final String CLIENT = "client-1";
    private static final String PROVIDER = "okta";
    private static final long EXP = 1_700_000_000L;
    private static final long TTL = 1_700_003_600L;

    @Mock
    DynamoDbClient dynamoDbClient;

    @Mock
    SdkHttpResponse mockHttpResponse;

    @InjectMocks
    BearerIndexStoreDynamodbImpl store;

    @BeforeEach
    void setUp() {
        store.tableName = TABLE;
    }

    private PutItemResponse putOk() {
        return (PutItemResponse) PutItemResponse.builder().sdkHttpResponse(mockHttpResponse).build();
    }

    private DeleteItemResponse deleteOk() {
        return (DeleteItemResponse) DeleteItemResponse.builder().sdkHttpResponse(mockHttpResponse).build();
    }

    @Test
    void putBearer_writesAllAttributes() {
        when(dynamoDbClient.putItem(any(PutItemRequest.class))).thenReturn(putOk());

        store.putBearer(HASH, USER, CLIENT, PROVIDER, EXP, TTL);

        ArgumentCaptor<PutItemRequest> cap = ArgumentCaptor.forClass(PutItemRequest.class);
        verify(dynamoDbClient).putItem(cap.capture());
        PutItemRequest req = cap.getValue();
        assertEquals(TABLE, req.tableName());
        Map<String, AttributeValue> item = req.item();
        assertEquals(HASH, item.get(BearerIndexTableAttribute.ACCESS_TOKEN_HASH.attr()).s());
        assertEquals(USER, item.get(BearerIndexTableAttribute.USER_ID.attr()).s());
        assertEquals(CLIENT, item.get(BearerIndexTableAttribute.CLIENT_ID.attr()).s());
        assertEquals(PROVIDER, item.get(BearerIndexTableAttribute.PROVIDER.attr()).s());
        assertEquals(Long.toString(EXP), item.get(BearerIndexTableAttribute.EXP.attr()).n());
        assertEquals(Long.toString(TTL), item.get(BearerIndexTableAttribute.TTL.attr()).n());
    }

    @Test
    void putBearer_skipsEmptyOptionalFields() {
        when(dynamoDbClient.putItem(any(PutItemRequest.class))).thenReturn(putOk());

        store.putBearer(HASH, USER, "", "", EXP, TTL);

        ArgumentCaptor<PutItemRequest> cap = ArgumentCaptor.forClass(PutItemRequest.class);
        verify(dynamoDbClient).putItem(cap.capture());
        Map<String, AttributeValue> item = cap.getValue().item();
        assertEquals(USER, item.get(BearerIndexTableAttribute.USER_ID.attr()).s());
        assertNull(item.get(BearerIndexTableAttribute.CLIENT_ID.attr()));
        assertNull(item.get(BearerIndexTableAttribute.PROVIDER.attr()));
    }

    @Test
    void putBearer_skipsWhenHashIsEmpty() {
        store.putBearer("", USER, CLIENT, PROVIDER, EXP, TTL);
        verify(dynamoDbClient, never()).putItem(any(PutItemRequest.class));

        store.putBearer(null, USER, CLIENT, PROVIDER, EXP, TTL);
        verify(dynamoDbClient, never()).putItem(any(PutItemRequest.class));
    }

    @Test
    void getBearer_returnsRecord() {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put(BearerIndexTableAttribute.ACCESS_TOKEN_HASH.attr(),
                AttributeValue.builder().s(HASH).build());
        item.put(BearerIndexTableAttribute.USER_ID.attr(),
                AttributeValue.builder().s(USER).build());
        item.put(BearerIndexTableAttribute.CLIENT_ID.attr(),
                AttributeValue.builder().s(CLIENT).build());
        item.put(BearerIndexTableAttribute.PROVIDER.attr(),
                AttributeValue.builder().s(PROVIDER).build());
        item.put(BearerIndexTableAttribute.EXP.attr(),
                AttributeValue.builder().n(Long.toString(EXP)).build());
        item.put(BearerIndexTableAttribute.TTL.attr(),
                AttributeValue.builder().n(Long.toString(TTL)).build());
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().item(item).build());

        BearerIndexRecord rec = store.getBearer(HASH);
        assertNotNull(rec);
        assertEquals(HASH, rec.accessTokenHash());
        assertEquals(USER, rec.userId());
        assertEquals(CLIENT, rec.clientId());
        assertEquals(PROVIDER, rec.provider());
        assertEquals(EXP, rec.exp());
        assertEquals(TTL, rec.ttl());
    }

    @Test
    void getBearer_returnsNullForMiss() {
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(GetItemResponse.builder().build());

        assertNull(store.getBearer(HASH));
    }

    @Test
    void getBearer_returnsNullForEmptyHash() {
        assertNull(store.getBearer(""));
        assertNull(store.getBearer(null));
        verify(dynamoDbClient, never()).getItem(any(GetItemRequest.class));
    }

    @Test
    void deleteBearer_callsDeleteItem() {
        when(dynamoDbClient.deleteItem(any(DeleteItemRequest.class))).thenReturn(deleteOk());

        store.deleteBearer(HASH);

        ArgumentCaptor<DeleteItemRequest> cap = ArgumentCaptor.forClass(DeleteItemRequest.class);
        verify(dynamoDbClient).deleteItem(cap.capture());
        assertEquals(TABLE, cap.getValue().tableName());
        assertEquals(HASH, cap.getValue().key().get(BearerIndexTableAttribute.ACCESS_TOKEN_HASH.attr()).s());
    }

    @Test
    void deleteBearer_skipsWhenHashIsEmpty() {
        store.deleteBearer("");
        store.deleteBearer(null);
        verify(dynamoDbClient, never()).deleteItem(any(DeleteItemRequest.class));
    }
}
