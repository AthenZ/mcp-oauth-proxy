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

import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.util.JwtUtils;
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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TokenStoreDynamodbImplTest {

    @Mock
    DynamoDbClient dynamoDbClient;

    @Mock
    SdkHttpResponse mockHttpResponse;

    @InjectMocks
    TokenStoreDynamodbImpl tokenStore;

    private static final String TEST_TABLE_NAME = "test-token-table";
    private static final String TEST_USER = "user.testuser";
    private static final String TEST_SUBJECT = "test-subject";
    private static final String TEST_PROVIDER = "https://test-provider.com";
    private static final String TEST_REFRESH_TOKEN = "refresh_token_value";
    private static final Long TEST_TTL = Instant.now().getEpochSecond() + 3600L;
    private static final Long EXPIRED_TTL = Instant.now().getEpochSecond() - 60L;

    private TokenWrapper testToken;
    private String testIdToken;
    private String testAccessToken;

    @BeforeEach
    void setUp() throws Exception {
        tokenStore.tableName = TEST_TABLE_NAME;
        tokenStore.userPrefix = "user.";

        // Create valid JWT tokens for testing
        testIdToken = createTestJWT(TEST_SUBJECT);
        testAccessToken = createTestJWT(TEST_SUBJECT);

        testToken = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                testIdToken,
                testAccessToken,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        // Mock HTTP response
        when(mockHttpResponse.statusCode()).thenReturn(200);
    }

    private String createTestJWT(String subject) throws Exception {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(TEST_PROVIDER)
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.HS256),
                claimsSet);

        signedJWT.sign(new MACSigner("your-256-bit-secret-key-for-testing-only-1234567890"));
        return signedJWT.serialize();
    }

    @Test
    void testStoreUserToken() {
        // Arrange
        PutItemResponse putItemResponse = (PutItemResponse) PutItemResponse.builder()
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.putItem(any(PutItemRequest.class))).thenReturn(putItemResponse);

        // Act
        tokenStore.storeUserToken(TEST_USER, TEST_PROVIDER, testToken);

        // Assert
        ArgumentCaptor<PutItemRequest> requestCaptor = ArgumentCaptor.forClass(PutItemRequest.class);
        verify(dynamoDbClient).putItem(requestCaptor.capture());

        PutItemRequest capturedRequest = requestCaptor.getValue();
        assertEquals(TEST_TABLE_NAME, capturedRequest.tableName());

        Map<String, AttributeValue> item = capturedRequest.item();
        assertEquals(TEST_USER, item.get(TokenTableAttribute.USER.attr()).s());
        assertEquals(TEST_PROVIDER, item.get(TokenTableAttribute.PROVIDER.attr()).s());
        assertEquals(testIdToken, item.get(TokenTableAttribute.ID_TOKEN.attr()).s());
        assertEquals(testAccessToken, item.get(TokenTableAttribute.ACCESS_TOKEN.attr()).s());
        assertEquals(TEST_REFRESH_TOKEN, item.get(TokenTableAttribute.REFRESH_TOKEN.attr()).s());
        assertEquals(TEST_TTL.toString(), item.get(TokenTableAttribute.TTL.attr()).n());
        // Verify ACCESS_TOKEN_HASH is stored
        assertTrue(item.containsKey(TokenTableAttribute.ACCESS_TOKEN_HASH.attr()));
        String expectedHash = JwtUtils.hashAccessToken(testAccessToken);
        assertEquals(expectedHash, item.get(TokenTableAttribute.ACCESS_TOKEN_HASH.attr()).s());
    }

    @Test
    void testStoreUserTokenWithNullRefreshToken() {
        // Arrange
        TokenWrapper tokenWithoutRefresh = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                testIdToken,
                testAccessToken,
                null,  // null refresh token
                TEST_TTL
        );
        PutItemResponse putItemResponse = (PutItemResponse) PutItemResponse.builder()
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.putItem(any(PutItemRequest.class))).thenReturn(putItemResponse);

        // Act
        tokenStore.storeUserToken(TEST_USER, TEST_PROVIDER, tokenWithoutRefresh);

        // Assert
        ArgumentCaptor<PutItemRequest> requestCaptor = ArgumentCaptor.forClass(PutItemRequest.class);
        verify(dynamoDbClient).putItem(requestCaptor.capture());

        PutItemRequest capturedRequest = requestCaptor.getValue();
        Map<String, AttributeValue> item = capturedRequest.item();
        // When refresh token is null, it should not be in the item map
        assertFalse(item.containsKey(TokenTableAttribute.REFRESH_TOKEN.attr()));
    }

    @Test
    void testGetUserTokenSuccess() {
        // Arrange
        Map<String, AttributeValue> returnedItem = new HashMap<>();
        returnedItem.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(TEST_USER).build());
        returnedItem.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(TEST_PROVIDER).build());
        returnedItem.put(TokenTableAttribute.ID_TOKEN.attr(), AttributeValue.builder().s(testIdToken).build());
        returnedItem.put(TokenTableAttribute.ACCESS_TOKEN.attr(), AttributeValue.builder().s(testAccessToken).build());
        returnedItem.put(TokenTableAttribute.REFRESH_TOKEN.attr(), AttributeValue.builder().s(TEST_REFRESH_TOKEN).build());
        returnedItem.put(TokenTableAttribute.TTL.attr(), AttributeValue.builder().n(TEST_TTL.toString()).build());

        GetItemResponse getItemResponse = (GetItemResponse) GetItemResponse.builder()
                .item(returnedItem)
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.getItem(any(GetItemRequest.class))).thenReturn(getItemResponse);

        // Act
        TokenWrapper result = tokenStore.getUserToken(TEST_USER, TEST_PROVIDER);

        // Assert
        assertNotNull(result);
        assertEquals(TEST_USER, result.key());  // User is extracted from JWT sub claim
        assertEquals(TEST_PROVIDER, result.provider());
        assertEquals(testIdToken, result.idToken());
        assertEquals(testAccessToken, result.accessToken());
        assertEquals(TEST_REFRESH_TOKEN, result.refreshToken());
        assertEquals(TEST_TTL, result.ttl());

        ArgumentCaptor<GetItemRequest> requestCaptor = ArgumentCaptor.forClass(GetItemRequest.class);
        verify(dynamoDbClient).getItem(requestCaptor.capture());

        GetItemRequest capturedRequest = requestCaptor.getValue();
        assertEquals(TEST_TABLE_NAME, capturedRequest.tableName());
        assertEquals(TEST_USER, capturedRequest.key().get(TokenTableAttribute.USER.attr()).s());
        assertEquals(TEST_PROVIDER, capturedRequest.key().get(TokenTableAttribute.PROVIDER.attr()).s());
    }

    @Test
    void testGetUserTokenNotFound() {
        // Arrange - Return empty item
        GetItemResponse getItemResponse = (GetItemResponse) GetItemResponse.builder()
                .item(new HashMap<>())  // Empty item
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.getItem(any(GetItemRequest.class))).thenReturn(getItemResponse);

        // Act
        TokenWrapper result = tokenStore.getUserToken(TEST_USER, TEST_PROVIDER);

        // Assert
        assertNull(result);
        verify(dynamoDbClient).getItem(any(GetItemRequest.class));
    }

    @Test
    void testGetUserTokenNullItem() {
        // Arrange - Return null item
        GetItemResponse getItemResponse = (GetItemResponse) GetItemResponse.builder()
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.getItem(any(GetItemRequest.class))).thenReturn(getItemResponse);

        // Act
        TokenWrapper result = tokenStore.getUserToken(TEST_USER, TEST_PROVIDER);

        // Assert
        assertNull(result);
        verify(dynamoDbClient).getItem(any(GetItemRequest.class));
    }

    @Test
    void testStoreUserTokenDynamoDbException() {
        // Arrange
        when(dynamoDbClient.putItem(any(PutItemRequest.class)))
                .thenThrow(DynamoDbException.builder()
                        .message("DynamoDB error")
                        .build());

        // Act & Assert
        assertThrows(DynamoDbException.class, () -> {
            tokenStore.storeUserToken(TEST_USER, TEST_PROVIDER, testToken);
        });
        verify(dynamoDbClient).putItem(any(PutItemRequest.class));
    }

    @Test
    void testGetUserTokenDynamoDbException() {
        // Arrange
        when(dynamoDbClient.getItem(any(GetItemRequest.class)))
                .thenThrow(DynamoDbException.builder()
                        .message("DynamoDB error")
                        .build());

        // Act & Assert
        assertThrows(DynamoDbException.class, () -> {
            tokenStore.getUserToken(TEST_USER, TEST_PROVIDER);
        });
        verify(dynamoDbClient).getItem(any(GetItemRequest.class));
    }

    @Test
    void testStoreUserTokenValidatesTableName() {
        // Arrange
        PutItemResponse putItemResponse = (PutItemResponse) PutItemResponse.builder()
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.putItem(any(PutItemRequest.class))).thenReturn(putItemResponse);

        // Act
        tokenStore.storeUserToken(TEST_USER, TEST_PROVIDER, testToken);

        // Assert
        ArgumentCaptor<PutItemRequest> requestCaptor = ArgumentCaptor.forClass(PutItemRequest.class);
        verify(dynamoDbClient).putItem(requestCaptor.capture());
        assertEquals(TEST_TABLE_NAME, requestCaptor.getValue().tableName());
    }

    @Test
    void testGetUserTokenUsesCorrectKeys() {
        // Arrange
        GetItemResponse getItemResponse = (GetItemResponse) GetItemResponse.builder()
                .item(new HashMap<>())
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.getItem(any(GetItemRequest.class))).thenReturn(getItemResponse);

        // Act
        tokenStore.getUserToken(TEST_USER, TEST_PROVIDER);

        // Assert
        ArgumentCaptor<GetItemRequest> requestCaptor = ArgumentCaptor.forClass(GetItemRequest.class);
        verify(dynamoDbClient).getItem(requestCaptor.capture());

        GetItemRequest capturedRequest = requestCaptor.getValue();
        Map<String, AttributeValue> key = capturedRequest.key();
        assertTrue(key.containsKey(TokenTableAttribute.USER.attr()));
        assertTrue(key.containsKey(TokenTableAttribute.PROVIDER.attr()));
        assertEquals(2, key.size());  // Should only have partition and sort key
    }

    @Test
    void testStoreMultipleTokensForDifferentUsers() {
        // Arrange
        String user1 = "user.alice";
        String user2 = "user.bob";
        long futureTtl = Instant.now().getEpochSecond() + 7200L;
        TokenWrapper token1 = new TokenWrapper(user1, TEST_PROVIDER, "id1", "access1", "refresh1", futureTtl);
        TokenWrapper token2 = new TokenWrapper(user2, TEST_PROVIDER, "id2", "access2", "refresh2", futureTtl);

        PutItemResponse putItemResponse = (PutItemResponse) PutItemResponse.builder()
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.putItem(any(PutItemRequest.class))).thenReturn(putItemResponse);

        // Act
        tokenStore.storeUserToken(user1, TEST_PROVIDER, token1);
        tokenStore.storeUserToken(user2, TEST_PROVIDER, token2);

        // Assert
        verify(dynamoDbClient, times(2)).putItem(any(PutItemRequest.class));
    }

    @Test
    void testGetUserTokenByAccessTokenHash_Success() {
        // Arrange
        String accessTokenHash = JwtUtils.hashAccessToken(testAccessToken);
        Map<String, AttributeValue> returnedItem = new HashMap<>();
        returnedItem.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(TEST_USER).build());
        returnedItem.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(TEST_PROVIDER).build());
        returnedItem.put(TokenTableAttribute.ID_TOKEN.attr(), AttributeValue.builder().s(testIdToken).build());
        returnedItem.put(TokenTableAttribute.ACCESS_TOKEN.attr(), AttributeValue.builder().s(testAccessToken).build());
        returnedItem.put(TokenTableAttribute.REFRESH_TOKEN.attr(), AttributeValue.builder().s(TEST_REFRESH_TOKEN).build());
        returnedItem.put(TokenTableAttribute.TTL.attr(), AttributeValue.builder().n(TEST_TTL.toString()).build());
        returnedItem.put(TokenTableAttribute.ACCESS_TOKEN_HASH.attr(), AttributeValue.builder().s(accessTokenHash).build());

        List<Map<String, AttributeValue>> itemsList = new ArrayList<>();
        itemsList.add(returnedItem);
        QueryResponse queryResponse = (QueryResponse) QueryResponse.builder()
                .items(itemsList)
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.query(any(QueryRequest.class))).thenReturn(queryResponse);

        // Act
        TokenWrapper result = tokenStore.getUserTokenByAccessTokenHash(accessTokenHash);

        // Assert
        assertNotNull(result);
        assertEquals(TEST_USER, result.key());
        assertEquals(TEST_PROVIDER, result.provider());
        assertEquals(testIdToken, result.idToken());
        assertEquals(testAccessToken, result.accessToken());
        assertEquals(TEST_REFRESH_TOKEN, result.refreshToken());
        assertEquals(TEST_TTL, result.ttl());

        ArgumentCaptor<QueryRequest> requestCaptor = ArgumentCaptor.forClass(QueryRequest.class);
        verify(dynamoDbClient).query(requestCaptor.capture());

        QueryRequest capturedRequest = requestCaptor.getValue();
        assertEquals("test-token-table", capturedRequest.tableName());
        assertEquals("access-token-hash-index", capturedRequest.indexName());
        assertEquals("access_token_hash = :hash", capturedRequest.keyConditionExpression());
    }

    @Test
    void testGetUserTokenByAccessTokenHash_NotFound() {
        // Arrange
        String accessTokenHash = JwtUtils.hashAccessToken(testAccessToken);
        QueryResponse queryResponse = (QueryResponse) QueryResponse.builder()
                .items(new ArrayList<>())  // Empty items list
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.query(any(QueryRequest.class))).thenReturn(queryResponse);

        // Act
        TokenWrapper result = tokenStore.getUserTokenByAccessTokenHash(accessTokenHash);

        // Assert
        assertNull(result);
        verify(dynamoDbClient).query(any(QueryRequest.class));
    }

    @Test
    void testGetUserTokenByAccessTokenHash_WithNullItems() {
        // Arrange
        String accessTokenHash = JwtUtils.hashAccessToken(testAccessToken);
        QueryResponse queryResponse = (QueryResponse) QueryResponse.builder()
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.query(any(QueryRequest.class))).thenReturn(queryResponse);

        // Act
        TokenWrapper result = tokenStore.getUserTokenByAccessTokenHash(accessTokenHash);

        // Assert
        assertNull(result);
        verify(dynamoDbClient).query(any(QueryRequest.class));
    }

    @Test
    void testGetUserToken_ExpiredToken_ReturnsNullAndDeletes() {
        Map<String, AttributeValue> returnedItem = new HashMap<>();
        returnedItem.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(TEST_USER).build());
        returnedItem.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(TEST_PROVIDER).build());
        returnedItem.put(TokenTableAttribute.ID_TOKEN.attr(), AttributeValue.builder().s(testIdToken).build());
        returnedItem.put(TokenTableAttribute.ACCESS_TOKEN.attr(), AttributeValue.builder().s(testAccessToken).build());
        returnedItem.put(TokenTableAttribute.REFRESH_TOKEN.attr(), AttributeValue.builder().s(TEST_REFRESH_TOKEN).build());
        returnedItem.put(TokenTableAttribute.TTL.attr(), AttributeValue.builder().n(EXPIRED_TTL.toString()).build());

        GetItemResponse getItemResponse = (GetItemResponse) GetItemResponse.builder()
                .item(returnedItem)
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.getItem(any(GetItemRequest.class))).thenReturn(getItemResponse);

        DeleteItemResponse deleteItemResponse = (DeleteItemResponse) DeleteItemResponse.builder()
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.deleteItem(any(DeleteItemRequest.class))).thenReturn(deleteItemResponse);

        TokenWrapper result = tokenStore.getUserToken(TEST_USER, TEST_PROVIDER);

        assertNull(result);
        verify(dynamoDbClient).deleteItem(any(DeleteItemRequest.class));
    }

    @Test
    void testGetUserTokenByAccessTokenHash_ExpiredToken_ReturnsNullAndDeletes() {
        String accessTokenHash = JwtUtils.hashAccessToken(testAccessToken);
        Map<String, AttributeValue> returnedItem = new HashMap<>();
        returnedItem.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(TEST_USER).build());
        returnedItem.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(TEST_PROVIDER).build());
        returnedItem.put(TokenTableAttribute.ID_TOKEN.attr(), AttributeValue.builder().s(testIdToken).build());
        returnedItem.put(TokenTableAttribute.ACCESS_TOKEN.attr(), AttributeValue.builder().s(testAccessToken).build());
        returnedItem.put(TokenTableAttribute.REFRESH_TOKEN.attr(), AttributeValue.builder().s(TEST_REFRESH_TOKEN).build());
        returnedItem.put(TokenTableAttribute.TTL.attr(), AttributeValue.builder().n(EXPIRED_TTL.toString()).build());

        List<Map<String, AttributeValue>> itemsList = new ArrayList<>();
        itemsList.add(returnedItem);
        QueryResponse queryResponse = (QueryResponse) QueryResponse.builder()
                .items(itemsList)
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.query(any(QueryRequest.class))).thenReturn(queryResponse);

        DeleteItemResponse deleteItemResponse = (DeleteItemResponse) DeleteItemResponse.builder()
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.deleteItem(any(DeleteItemRequest.class))).thenReturn(deleteItemResponse);

        TokenWrapper result = tokenStore.getUserTokenByAccessTokenHash(accessTokenHash);

        assertNull(result);
        verify(dynamoDbClient).deleteItem(any(DeleteItemRequest.class));
    }

    @Test
    void testIsExpired_PastTtl_ReturnsTrue() {
        TokenWrapper expired = new TokenWrapper("u", "p", null, "a", null, Instant.now().getEpochSecond() - 10);
        assertTrue(expired.isExpired());
    }

    @Test
    void testIsExpired_FutureTtl_ReturnsFalse() {
        TokenWrapper valid = new TokenWrapper("u", "p", null, "a", null, Instant.now().getEpochSecond() + 3600);
        assertFalse(valid.isExpired());
    }

    @Test
    void testIsExpired_NullTtl_ReturnsFalse() {
        TokenWrapper noTtl = new TokenWrapper("u", "p", null, "a", null, null);
        assertFalse(noTtl.isExpired());
    }

    // -- Per-MCP-client bearer-row tests (composite partition key) ----------------------------

    @Test
    void compositeUserKey_nullClientId_returnsBareUser() {
        assertEquals(TEST_USER, TokenStoreDynamodbImpl.compositeUserKey(null, TEST_USER));
    }

    @Test
    void compositeUserKey_emptyClientId_returnsBareUser() {
        assertEquals(TEST_USER, TokenStoreDynamodbImpl.compositeUserKey("", TEST_USER));
    }

    @Test
    void compositeUserKey_normalClientId_prefixes() {
        assertEquals("Cursor#" + TEST_USER, TokenStoreDynamodbImpl.compositeUserKey("Cursor", TEST_USER));
    }

    @Test
    void compositeUserKey_clientIdWithHash_sanitizes() {
        assertEquals("Cur_sor#" + TEST_USER, TokenStoreDynamodbImpl.compositeUserKey("Cur#sor", TEST_USER));
    }

    @Test
    void storeUserToken_withClientId_isNoOp() {
        tokenStore.storeUserToken(TEST_USER, TEST_PROVIDER, "Cursor", testToken);

        verify(dynamoDbClient, org.mockito.Mockito.never()).putItem(any(PutItemRequest.class));
    }

    @Test
    void storeUserToken_withNullClientId_isNoOp() {
        tokenStore.storeUserToken(TEST_USER, TEST_PROVIDER, (String) null, testToken);

        verify(dynamoDbClient, org.mockito.Mockito.never()).putItem(any(PutItemRequest.class));
    }

    @Test
    void getUserToken_perClientRow_stripsClientIdPrefixIntoTokenWrapperClientId() {
        // Simulate a per-client row: USER attribute is "Cursor#user.testuser".
        Map<String, AttributeValue> returnedItem = new HashMap<>();
        returnedItem.put(TokenTableAttribute.USER.attr(),
                AttributeValue.builder().s("Cursor#" + TEST_USER).build());
        returnedItem.put(TokenTableAttribute.PROVIDER.attr(),
                AttributeValue.builder().s(TEST_PROVIDER).build());
        returnedItem.put(TokenTableAttribute.ACCESS_TOKEN.attr(),
                AttributeValue.builder().s(testAccessToken).build());
        returnedItem.put(TokenTableAttribute.TTL.attr(),
                AttributeValue.builder().n(TEST_TTL.toString()).build());

        GetItemResponse getResp = (GetItemResponse) GetItemResponse.builder()
                .item(returnedItem)
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.getItem(any(GetItemRequest.class))).thenReturn(getResp);

        TokenWrapper result = tokenStore.getUserToken("Cursor#" + TEST_USER, TEST_PROVIDER);

        assertNotNull(result);
        assertEquals(TEST_USER, result.key(),
                "TokenWrapper.key() must be the bare userId so downstream Okta lookups by (userId, provider) keep working");
        assertEquals("Cursor", result.clientId(),
                "TokenWrapper.clientId() must surface the partition-key prefix so /userinfo can publish mcp_client_id");
    }

    @Test
    void getUserToken_legacyBareRow_clientIdIsNull() {
        Map<String, AttributeValue> returnedItem = new HashMap<>();
        returnedItem.put(TokenTableAttribute.USER.attr(),
                AttributeValue.builder().s(TEST_USER).build());
        returnedItem.put(TokenTableAttribute.PROVIDER.attr(),
                AttributeValue.builder().s(TEST_PROVIDER).build());
        returnedItem.put(TokenTableAttribute.ACCESS_TOKEN.attr(),
                AttributeValue.builder().s(testAccessToken).build());
        returnedItem.put(TokenTableAttribute.TTL.attr(),
                AttributeValue.builder().n(TEST_TTL.toString()).build());

        GetItemResponse getResp = (GetItemResponse) GetItemResponse.builder()
                .item(returnedItem)
                .sdkHttpResponse(mockHttpResponse)
                .build();
        when(dynamoDbClient.getItem(any(GetItemRequest.class))).thenReturn(getResp);

        TokenWrapper result = tokenStore.getUserToken(TEST_USER, TEST_PROVIDER);

        assertNotNull(result);
        assertEquals(TEST_USER, result.key());
        assertNull(result.clientId(),
                "Legacy bare rows have no '#' prefix; clientId must remain null so /userinfo omits the mcp_client_id claim");
    }
}
