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
package io.athenz.mop.store.impl.memory;

import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.store.impl.memory.TokenStoreInMemoryImpl;
import io.quarkus.cache.Cache;
import io.quarkus.cache.CaffeineCache;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.doReturn;

@ExtendWith(MockitoExtension.class)
class TokenStoreInMemoryImplTest {

    @Mock
    Cache tokenCache;

    @Mock
    Cache codeCache;

    @Mock
    CaffeineCache caffeineCache;

    @InjectMocks
    TokenStoreInMemoryImpl tokenStore;

    private TokenWrapper testToken;
    private static final String TEST_USER = "user.testuser";
    private static final String TEST_PROVIDER = "https://test-provider.com";
    private static final String TEST_ID_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.id";
    private static final String TEST_ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.access";
    private static final String TEST_REFRESH_TOKEN = "refresh_token_value";
    private static final Long TEST_TTL = 1735311600L;

    @BeforeEach
    void setUp() {
        testToken = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );
    }

    @Test
    void testStoreUserToken() {
        // Arrange
        when(tokenCache.as(CaffeineCache.class)).thenReturn(caffeineCache);

        // Act
        tokenStore.storeUserToken(TEST_USER, TEST_PROVIDER, testToken);

        // Assert
        verify(tokenCache).as(CaffeineCache.class);
        verify(caffeineCache).put(eq(TEST_USER), any(CompletableFuture.class));
    }

    @Test
    void testGetUserTokenSuccess() throws ExecutionException, InterruptedException {
        // Arrange
        CompletableFuture<TokenWrapper> tokenFuture = CompletableFuture.completedFuture(testToken);
        when(tokenCache.as(CaffeineCache.class)).thenReturn(caffeineCache);
        doReturn(tokenFuture).when(caffeineCache).getIfPresent(TEST_USER);

        // Act
        TokenWrapper result = tokenStore.getUserToken(TEST_USER, TEST_PROVIDER);

        // Assert
        assertNotNull(result);
        assertEquals(TEST_USER, result.key());
        assertEquals(TEST_PROVIDER, result.provider());
        assertEquals(TEST_ID_TOKEN, result.idToken());
        assertEquals(TEST_ACCESS_TOKEN, result.accessToken());
        assertEquals(TEST_REFRESH_TOKEN, result.refreshToken());
        assertEquals(TEST_TTL, result.ttl());
        verify(tokenCache).as(CaffeineCache.class);
        verify(caffeineCache).getIfPresent(TEST_USER);
    }

    @Test
    void testGetUserTokenNotFound() {
        // Arrange
        when(tokenCache.as(CaffeineCache.class)).thenReturn(caffeineCache);
        doReturn(null).when(caffeineCache).getIfPresent(TEST_USER);

        // Act
        TokenWrapper result = tokenStore.getUserToken(TEST_USER, TEST_PROVIDER);

        // Assert
        assertNull(result);
        verify(tokenCache).as(CaffeineCache.class);
        verify(caffeineCache).getIfPresent(TEST_USER);
    }

    @Test
    void testGetUserTokenExecutionException() throws ExecutionException, InterruptedException {
        // Arrange
        CompletableFuture<TokenWrapper> failedFuture = new CompletableFuture<>();
        failedFuture.completeExceptionally(new RuntimeException("Cache retrieval failed"));
        when(tokenCache.as(CaffeineCache.class)).thenReturn(caffeineCache);
        doReturn(failedFuture).when(caffeineCache).getIfPresent(TEST_USER);

        // Act
        TokenWrapper result = tokenStore.getUserToken(TEST_USER, TEST_PROVIDER);

        // Assert
        assertNull(result);
        verify(tokenCache).as(CaffeineCache.class);
        verify(caffeineCache).getIfPresent(TEST_USER);
    }

    @Test
    void testGetUserTokenInterruptedException() throws ExecutionException, InterruptedException {
        // Arrange
        CompletableFuture<TokenWrapper> mockFuture = mock(CompletableFuture.class);
        when(mockFuture.get()).thenThrow(new InterruptedException("Thread interrupted"));
        when(tokenCache.as(CaffeineCache.class)).thenReturn(caffeineCache);
        doReturn(mockFuture).when(caffeineCache).getIfPresent(TEST_USER);

        // Act
        TokenWrapper result = tokenStore.getUserToken(TEST_USER, TEST_PROVIDER);

        // Assert
        assertNull(result);
        verify(tokenCache).as(CaffeineCache.class);
        verify(caffeineCache).getIfPresent(TEST_USER);
    }

    @Test
    void testStoreAndRetrieveMultipleUsers() throws ExecutionException, InterruptedException {
        // Arrange
        String user1 = "user.alice";
        String user2 = "user.bob";
        TokenWrapper token1 = new TokenWrapper(user1, TEST_PROVIDER, "id1", "access1", "refresh1", 123456L);
        TokenWrapper token2 = new TokenWrapper(user2, TEST_PROVIDER, "id2", "access2", "refresh2", 789012L);

        CompletableFuture<TokenWrapper> tokenFuture1 = CompletableFuture.completedFuture(token1);
        CompletableFuture<TokenWrapper> tokenFuture2 = CompletableFuture.completedFuture(token2);

        when(tokenCache.as(CaffeineCache.class)).thenReturn(caffeineCache);
        doReturn(tokenFuture1).when(caffeineCache).getIfPresent(user1);
        doReturn(tokenFuture2).when(caffeineCache).getIfPresent(user2);

        // Act & Assert - Store tokens
        tokenStore.storeUserToken(user1, TEST_PROVIDER, token1);
        tokenStore.storeUserToken(user2, TEST_PROVIDER, token2);
        verify(caffeineCache, times(2)).put(any(), any());

        // Act & Assert - Retrieve tokens
        TokenWrapper retrieved1 = tokenStore.getUserToken(user1, TEST_PROVIDER);
        TokenWrapper retrieved2 = tokenStore.getUserToken(user2, TEST_PROVIDER);

        assertEquals(user1, retrieved1.key());
        assertEquals(user2, retrieved2.key());
        assertEquals("id1", retrieved1.idToken());
        assertEquals("id2", retrieved2.idToken());
    }

    @Test
    void testStoreUserTokenWithNullRefreshToken() {
        // Arrange
        TokenWrapper tokenWithoutRefresh = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                null,  // null refresh token
                TEST_TTL
        );
        when(tokenCache.as(CaffeineCache.class)).thenReturn(caffeineCache);

        // Act
        tokenStore.storeUserToken(TEST_USER, TEST_PROVIDER, tokenWithoutRefresh);

        // Assert
        verify(tokenCache).as(CaffeineCache.class);
        verify(caffeineCache).put(eq(TEST_USER), any(CompletableFuture.class));
    }
}
