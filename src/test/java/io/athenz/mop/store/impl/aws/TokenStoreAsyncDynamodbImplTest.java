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

import io.athenz.mop.model.AuthorizationCodeTokensDO;
import io.athenz.mop.store.impl.aws.TokenStoreAsyncDynamodbImpl;
import io.athenz.mop.store.impl.aws.TokenTableAttribute;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.helpers.test.UniAssertSubscriber;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TokenStoreAsyncDynamodbImplTest {

    @Mock
    DynamoDbClient dynamoDbClient;

    @Mock
    SdkHttpResponse mockHttpResponse;

    @InjectMocks
    TokenStoreAsyncDynamodbImpl tokenStore;

    private static final String TEST_TABLE_NAME = "test-token-table";
    private static final String TEST_ID = "test-id-123";
    private static final String TEST_PROVIDER = "oidc";
    private static final String TEST_ID_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.id";
    private static final String TEST_ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.access";
    private static final String TEST_REFRESH_TOKEN = "refresh_token_value";
    private static final Long TEST_EXPIRES_IN = 3600L;
    private static final String TEST_SCOPE = "openid profile";

    private AuthorizationCodeTokensDO testTokenDO;

    @BeforeEach
    void setUp() {
        tokenStore.tableName = TEST_TABLE_NAME;

        // Initialize the ObjectMapper
        tokenStore.init();

        testTokenDO = new AuthorizationCodeTokensDO();
        testTokenDO.setIdToken(TEST_ID_TOKEN);
        testTokenDO.setAccessToken(TEST_ACCESS_TOKEN);
        testTokenDO.setRefreshToken(TEST_REFRESH_TOKEN);
        testTokenDO.setAccessTokenExpiresIn(TEST_EXPIRES_IN);
        testTokenDO.setAccessTokenScope(TEST_SCOPE);

        // Mock HTTP response
        when(mockHttpResponse.statusCode()).thenReturn(200);
    }

    @Test
    void testStoreTokenAsyncSuccess() {
        // Arrange
        PutItemResponse putItemResponse = (PutItemResponse) PutItemResponse.builder()
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.putItem(any(PutItemRequest.class)))
                .thenReturn(putItemResponse);

        // Act
        Uni<String> result = tokenStore.storeTokenAsync(TEST_ID, TEST_PROVIDER, testTokenDO);

        // Assert
        String storedId = result.subscribe().withSubscriber(UniAssertSubscriber.create())
                .awaitItem()
                .getItem();

        assertEquals(TEST_ID, storedId);

        ArgumentCaptor<PutItemRequest> requestCaptor = ArgumentCaptor.forClass(PutItemRequest.class);
        verify(dynamoDbClient).putItem(requestCaptor.capture());

        PutItemRequest capturedRequest = requestCaptor.getValue();
        assertEquals(TEST_TABLE_NAME, capturedRequest.tableName());

        Map<String, AttributeValue> item = capturedRequest.item();
        assertEquals(TEST_ID, item.get(TokenTableAttribute.USER.attr()).s());
        assertEquals(TEST_PROVIDER, item.get(TokenTableAttribute.PROVIDER.attr()).s());
        assertNotNull(item.get(TokenTableAttribute.AUTH_TOKENS_JSON.attr()).s());

        // Verify TTL is approximately current time + expires_in (allow 5 second tolerance)
        long actualTtl = Long.parseLong(item.get(TokenTableAttribute.TTL.attr()).n());
        long expectedTtl = java.time.Instant.now().getEpochSecond() + TEST_EXPIRES_IN;
        assertTrue(Math.abs(actualTtl - expectedTtl) <= 5,
                "TTL should be approximately current time + expires_in");
    }

    @Test
    void testGetTokenAsyncSuccess() {
        // Arrange
        String authTokensJson = "{\"idToken\":\"" + TEST_ID_TOKEN + "\",\"accessToken\":\"" + TEST_ACCESS_TOKEN +
                "\",\"refreshToken\":\"" + TEST_REFRESH_TOKEN + "\",\"accessTokenExpiresIn\":" + TEST_EXPIRES_IN +
                ",\"accessTokenScope\":\"" + TEST_SCOPE + "\"}";

        Map<String, AttributeValue> returnedItem = new HashMap<>();
        returnedItem.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(TEST_ID).build());
        returnedItem.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(TEST_PROVIDER).build());
        returnedItem.put(TokenTableAttribute.AUTH_TOKENS_JSON.attr(), AttributeValue.builder().s(authTokensJson).build());
        returnedItem.put(TokenTableAttribute.TTL.attr(), AttributeValue.builder().n(TEST_EXPIRES_IN.toString()).build());

        GetItemResponse getItemResponse = (GetItemResponse) GetItemResponse.builder()
                .item(returnedItem)
                .sdkHttpResponse(mockHttpResponse)
                .build();

        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(getItemResponse);

        // Act
        Uni<AuthorizationCodeTokensDO> result = tokenStore.getTokenAsync(TEST_ID, TEST_PROVIDER);

        // Assert
        AuthorizationCodeTokensDO retrievedToken = result.subscribe().withSubscriber(UniAssertSubscriber.create())
                .awaitItem()
                .getItem();

        assertNotNull(retrievedToken);
        assertEquals(TEST_ID_TOKEN, retrievedToken.getIdToken());
        assertEquals(TEST_ACCESS_TOKEN, retrievedToken.getAccessToken());
        assertEquals(TEST_REFRESH_TOKEN, retrievedToken.getRefreshToken());
        assertEquals(TEST_EXPIRES_IN, retrievedToken.getAccessTokenExpiresIn());
        assertEquals(TEST_SCOPE, retrievedToken.getAccessTokenScope());

        ArgumentCaptor<GetItemRequest> requestCaptor = ArgumentCaptor.forClass(GetItemRequest.class);
        verify(dynamoDbClient).getItem(requestCaptor.capture());

        GetItemRequest capturedRequest = requestCaptor.getValue();
        assertEquals(TEST_TABLE_NAME, capturedRequest.tableName());
        assertEquals(TEST_ID, capturedRequest.key().get(TokenTableAttribute.USER.attr()).s());
        assertEquals(TEST_PROVIDER, capturedRequest.key().get(TokenTableAttribute.PROVIDER.attr()).s());
        assertTrue(capturedRequest.consistentRead());
    }

    @Test
    void testGetTokenAsyncNotFound() {
        // Arrange - Return empty item
        GetItemResponse getItemResponse = (GetItemResponse) GetItemResponse.builder()
                .item(new HashMap<>())
                .sdkHttpResponse(mockHttpResponse)
                .build();

        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(getItemResponse);

        // Act
        Uni<AuthorizationCodeTokensDO> result = tokenStore.getTokenAsync(TEST_ID, TEST_PROVIDER);

        // Assert
        result.subscribe().withSubscriber(UniAssertSubscriber.create())
                .awaitFailure()
                .assertFailedWith(RuntimeException.class, "No auth code tokens found for id " + TEST_ID);

        verify(dynamoDbClient).getItem(any(GetItemRequest.class));
    }

    @Test
    void testGetTokenAsyncNullItem() {
        // Arrange - Return null item
        GetItemResponse getItemResponse = (GetItemResponse) GetItemResponse.builder()
                .sdkHttpResponse(mockHttpResponse)
                .build();

        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(getItemResponse);

        // Act
        Uni<AuthorizationCodeTokensDO> result = tokenStore.getTokenAsync(TEST_ID, TEST_PROVIDER);

        // Assert
        result.subscribe().withSubscriber(UniAssertSubscriber.create())
                .awaitFailure()
                .assertFailedWith(RuntimeException.class, "No auth code tokens found for id " + TEST_ID);

        verify(dynamoDbClient).getItem(any(GetItemRequest.class));
    }

    @Test
    void testDeleteTokenAsyncSuccess() {
        // Arrange
        DeleteItemResponse deleteItemResponse = (DeleteItemResponse) DeleteItemResponse.builder()
                .sdkHttpResponse(mockHttpResponse)
                .build();

        when(dynamoDbClient.deleteItem(any(DeleteItemRequest.class)))
                .thenReturn(deleteItemResponse);

        // Act
        Uni<Boolean> result = tokenStore.deleteTokenAsync(TEST_ID, TEST_PROVIDER);

        // Assert
        Boolean deleted = result.subscribe().withSubscriber(UniAssertSubscriber.create())
                .awaitItem()
                .getItem();

        assertTrue(deleted);

        ArgumentCaptor<DeleteItemRequest> requestCaptor = ArgumentCaptor.forClass(DeleteItemRequest.class);
        verify(dynamoDbClient).deleteItem(requestCaptor.capture());

        DeleteItemRequest capturedRequest = requestCaptor.getValue();
        assertEquals(TEST_TABLE_NAME, capturedRequest.tableName());
        assertEquals(TEST_ID, capturedRequest.key().get(TokenTableAttribute.USER.attr()).s());
        assertEquals(TEST_PROVIDER, capturedRequest.key().get(TokenTableAttribute.PROVIDER.attr()).s());
    }

    @Test
    void testStoreTokenAsyncDynamoDbException() {
        // Arrange
        when(dynamoDbClient.putItem(any(PutItemRequest.class)))
                .thenThrow(DynamoDbException.builder()
                        .message("DynamoDB error")
                        .build());

        // Act
        Uni<String> result = tokenStore.storeTokenAsync(TEST_ID, TEST_PROVIDER, testTokenDO);

        // Assert
        result.subscribe().withSubscriber(UniAssertSubscriber.create())
                .awaitFailure()
                .assertFailedWith(DynamoDbException.class);

        verify(dynamoDbClient).putItem(any(PutItemRequest.class));
    }

    @Test
    void testGetTokenAsyncDynamoDbException() {
        // Arrange
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenThrow(DynamoDbException.builder()
                        .message("DynamoDB error")
                        .build());

        // Act
        Uni<AuthorizationCodeTokensDO> result = tokenStore.getTokenAsync(TEST_ID, TEST_PROVIDER);

        // Assert
        result.subscribe().withSubscriber(UniAssertSubscriber.create())
                .awaitFailure()
                .assertFailedWith(DynamoDbException.class);

        verify(dynamoDbClient).getItem(any(GetItemRequest.class));
    }

    @Test
    void testDeleteTokenAsyncDynamoDbException() {
        // Arrange
        when(dynamoDbClient.deleteItem(any(DeleteItemRequest.class)))
                .thenThrow(DynamoDbException.builder()
                        .message("DynamoDB error")
                        .build());

        // Act
        Uni<Boolean> result = tokenStore.deleteTokenAsync(TEST_ID, TEST_PROVIDER);

        // Assert
        result.subscribe().withSubscriber(UniAssertSubscriber.create())
                .awaitFailure()
                .assertFailedWith(DynamoDbException.class);

        verify(dynamoDbClient).deleteItem(any(DeleteItemRequest.class));
    }

    @Test
    void testGetTokenAsyncWithInvalidJson() {
        // Arrange - Return item with invalid JSON
        Map<String, AttributeValue> returnedItem = new HashMap<>();
        returnedItem.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(TEST_ID).build());
        returnedItem.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(TEST_PROVIDER).build());
        returnedItem.put(TokenTableAttribute.AUTH_TOKENS_JSON.attr(), AttributeValue.builder().s("{invalid-json}").build());

        GetItemResponse getItemResponse = (GetItemResponse) GetItemResponse.builder()
                .item(returnedItem)
                .sdkHttpResponse(mockHttpResponse)
                .build();

        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(getItemResponse);

        // Act
        Uni<AuthorizationCodeTokensDO> result = tokenStore.getTokenAsync(TEST_ID, TEST_PROVIDER);

        // Assert
        result.subscribe().withSubscriber(UniAssertSubscriber.create())
                .awaitFailure()
                .assertFailed();

        verify(dynamoDbClient).getItem(any(GetItemRequest.class));
    }

    @Test
    void testStoreTokenAsyncWithNullRefreshToken() {
        // Arrange
        AuthorizationCodeTokensDO tokenWithoutRefresh = new AuthorizationCodeTokensDO();
        tokenWithoutRefresh.setIdToken(TEST_ID_TOKEN);
        tokenWithoutRefresh.setAccessToken(TEST_ACCESS_TOKEN);
        tokenWithoutRefresh.setRefreshToken(null);
        tokenWithoutRefresh.setAccessTokenExpiresIn(TEST_EXPIRES_IN);
        tokenWithoutRefresh.setAccessTokenScope(TEST_SCOPE);

        PutItemResponse putItemResponse = (PutItemResponse) PutItemResponse.builder()
                .sdkHttpResponse(mockHttpResponse)
                .build();

        when(dynamoDbClient.putItem(any(PutItemRequest.class)))
                .thenReturn(putItemResponse);

        // Act
        Uni<String> result = tokenStore.storeTokenAsync(TEST_ID, TEST_PROVIDER, tokenWithoutRefresh);

        // Assert
        String storedId = result.subscribe().withSubscriber(UniAssertSubscriber.create())
                .awaitItem()
                .getItem();

        assertEquals(TEST_ID, storedId);
        verify(dynamoDbClient).putItem(any(PutItemRequest.class));
    }

    @Test
    void testStoreTokenAsyncValidatesTableName() {
        // Arrange
        PutItemResponse putItemResponse = (PutItemResponse) PutItemResponse.builder()
                .sdkHttpResponse(mockHttpResponse)
                .build();

        when(dynamoDbClient.putItem(any(PutItemRequest.class)))
                .thenReturn(putItemResponse);

        // Act
        tokenStore.storeTokenAsync(TEST_ID, TEST_PROVIDER, testTokenDO)
                .subscribe().withSubscriber(UniAssertSubscriber.create())
                .awaitItem();

        // Assert
        ArgumentCaptor<PutItemRequest> requestCaptor = ArgumentCaptor.forClass(PutItemRequest.class);
        verify(dynamoDbClient).putItem(requestCaptor.capture());
        assertEquals(TEST_TABLE_NAME, requestCaptor.getValue().tableName());
    }

    @Test
    void testGetTokenAsyncUsesConsistentRead() {
        // Arrange
        GetItemResponse getItemResponse = (GetItemResponse) GetItemResponse.builder()
                .item(new HashMap<>())
                .sdkHttpResponse(mockHttpResponse)
                .build();

        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenReturn(getItemResponse);

        // Act
        tokenStore.getTokenAsync(TEST_ID, TEST_PROVIDER)
                .subscribe().withSubscriber(UniAssertSubscriber.create())
                .awaitFailure();

        // Assert
        ArgumentCaptor<GetItemRequest> requestCaptor = ArgumentCaptor.forClass(GetItemRequest.class);
        verify(dynamoDbClient).getItem(requestCaptor.capture());

        GetItemRequest capturedRequest = requestCaptor.getValue();
        assertTrue(capturedRequest.consistentRead(), "GetItem should use consistent read");
    }
}
