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

import io.athenz.mop.model.AuthorizationCode;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.service.AudienceConstants;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class CrossRegionTokenStoreFallbackTest {

    @Mock
    private DynamodbClientProvider dynamodbClientProvider;

    @Mock
    private TokenStoreDynamodbImpl tokenStoreDynamodb;

    @Mock
    private DynamoDbClient fallbackClient;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @InjectMocks
    private CrossRegionTokenStoreFallback fallback;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        setField(fallback, "fallbackTableName", Optional.of("fallback-table"));
        setField(fallback, "fallbackTableNameResolved", "fallback-table");
        // Same @InjectMocks instance across tests: reset peer client and mock invocations
        setField(fallback, "fallbackClient", null);
        clearInvocations(tokenStoreDynamodb, dynamodbClientProvider, fallbackClient, oauthProxyMetrics);
    }

    private void setFallbackClient(DynamoDbClient client) throws Exception {
        setField(fallback, "fallbackClient", client);
    }

    private static void setField(Object target, String fieldName, Object value) throws Exception {
        Field f = findField(target.getClass(), fieldName);
        f.setAccessible(true);
        f.set(target, value);
    }

    private static Field findField(Class<?> c, String name) throws NoSuchFieldException {
        while (c != null) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    @Test
    void testGetUserTokenByAccessTokenHash_WhenFallbackClientNull_ReturnsNull() {
        assertNull(fallback.getUserTokenByAccessTokenHash("any-hash"));
    }

    @Test
    void testGetUserTokenByAccessTokenHash_WhenFallbackClientSet_DelegatesAndReturnsToken() throws Exception {
        setFallbackClient(fallbackClient);
        TokenWrapper expected = new TokenWrapper("key", AudienceConstants.PROVIDER_OKTA, "id", "access", "refresh", 3600L);
        when(tokenStoreDynamodb.getUserTokenByAccessTokenHash(eq(fallbackClient), eq("fallback-table"), eq("hash123")))
                .thenReturn(expected);

        TokenWrapper result = fallback.getUserTokenByAccessTokenHash("hash123");

        assertNotNull(result);
        assertEquals("key", result.key());
        assertEquals(AudienceConstants.PROVIDER_OKTA, result.provider());
        verify(tokenStoreDynamodb, times(1)).getUserTokenByAccessTokenHash(fallbackClient, "fallback-table", "hash123");
    }

    @Test
    void testGetUserTokenByAccessTokenHash_WhenStoreReturnsNull_ReturnsNull() throws Exception {
        setFallbackClient(fallbackClient);
        when(tokenStoreDynamodb.getUserTokenByAccessTokenHash(eq(fallbackClient), eq("fallback-table"), any()))
                .thenReturn(null);

        assertNull(fallback.getUserTokenByAccessTokenHash("unknown-hash"));
    }

    @Test
    void testGetUserTokenByAccessTokenHash_WhenStoreThrows_ReturnsNull() throws Exception {
        setFallbackClient(fallbackClient);
        when(tokenStoreDynamodb.getUserTokenByAccessTokenHash(eq(fallbackClient), eq("fallback-table"), any()))
                .thenThrow(new RuntimeException("DynamoDB error"));

        assertNull(fallback.getUserTokenByAccessTokenHash("hash"));
    }

    @Test
    void testGetUserToken_WhenFallbackClientNull_ReturnsNull() {
        assertNull(fallback.getUserToken("user1", AudienceConstants.PROVIDER_OKTA));
    }

    @Test
    void testGetUserToken_WhenFallbackClientSet_DelegatesAndReturnsToken() throws Exception {
        setFallbackClient(fallbackClient);
        TokenWrapper expected = new TokenWrapper("u1", "google-drive", "id", "access", "refresh", 3600L);
        when(tokenStoreDynamodb.getUserToken(eq(fallbackClient), eq("fallback-table"), eq("user1"), eq("google-drive")))
                .thenReturn(expected);

        TokenWrapper result = fallback.getUserToken("user1", "google-drive");

        assertNotNull(result);
        assertEquals("u1", result.key());
        verify(tokenStoreDynamodb, times(1)).getUserToken(fallbackClient, "fallback-table", "user1", "google-drive");
    }

    @Test
    void testGetUserToken_WhenStoreThrows_ReturnsNull() throws Exception {
        setFallbackClient(fallbackClient);
        when(tokenStoreDynamodb.getUserToken(eq(fallbackClient), eq("fallback-table"), any(), any()))
                .thenThrow(new RuntimeException("DynamoDB error"));

        assertNull(fallback.getUserToken("user1", AudienceConstants.PROVIDER_OKTA));
    }

    @Test
    void testGetAuthCode_WhenFallbackClientNull_ReturnsNull() {
        assertNull(fallback.getAuthCode("code1", AudienceConstants.PROVIDER_OKTA));
    }

    @Test
    void testGetAuthCode_WhenFallbackClientSet_Delegates() throws Exception {
        setFallbackClient(fallbackClient);
        AuthorizationCode expected = new AuthorizationCode(
                "c1", "cid", "sub", "https://r/cb", "s", "res", "ch", "S256",
                Instant.now().plusSeconds(600), "st");
        when(tokenStoreDynamodb.getAuthCode(eq(fallbackClient), eq("fallback-table"), eq("c1"), eq(AudienceConstants.PROVIDER_OKTA)))
                .thenReturn(expected);

        AuthorizationCode result = fallback.getAuthCode("c1", AudienceConstants.PROVIDER_OKTA);

        assertSame(expected, result);
        verify(tokenStoreDynamodb).getAuthCode(fallbackClient, "fallback-table", "c1", AudienceConstants.PROVIDER_OKTA);
    }

    @Test
    void testDeleteAuthCode_WhenFallbackClientNull_NoOp() {
        fallback.deleteAuthCode("c1", AudienceConstants.PROVIDER_OKTA);
        verify(tokenStoreDynamodb, never()).deleteAuthCode(any(), any(), any(), any());
    }

    @Test
    void testDeleteAuthCode_WhenFallbackClientSet_Delegates() throws Exception {
        setFallbackClient(fallbackClient);
        fallback.deleteAuthCode("c1", AudienceConstants.PROVIDER_OKTA);
        verify(tokenStoreDynamodb).deleteAuthCode(fallbackClient, "fallback-table", "c1", AudienceConstants.PROVIDER_OKTA);
    }
}
