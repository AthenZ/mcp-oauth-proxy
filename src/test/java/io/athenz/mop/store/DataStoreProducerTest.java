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
package io.athenz.mop.store;

import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.store.AuthCodeStore;
import io.athenz.mop.store.DataStoreProducer;
import io.athenz.mop.store.TokenStore;
import jakarta.enterprise.inject.Instance;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DataStoreProducerTest {

    @Mock
    Instance<TokenStore> tokenStores;

    @Mock
    Instance<TokenStore> memoryTokenStoreInstance;

    @Mock
    Instance<TokenStore> enterpriseTokenStoreInstance;

    @Mock
    TokenStore memoryTokenStore;

    @Mock
    TokenStore enterpriseTokenStore;

    @Mock
    Instance<AuthCodeStore> authCodeStores;

    @Mock
    Instance<AuthCodeStore> memoryAuthCodeStoreInstance;

    @Mock
    Instance<AuthCodeStore> enterpriseAuthCodeStoreInstance;

    @Mock
    AuthCodeStore memoryAuthCodeStore;

    @Mock
    AuthCodeStore enterpriseAuthCodeStore;

    @InjectMocks
    DataStoreProducer dataStoreProducer;

    @BeforeEach
    void setUp() {
        // Setup the TokenStore Instance mock to return specific instances based on qualifiers
        when(tokenStores.select(any())).thenAnswer(invocation -> {
            Object qualifier = invocation.getArgument(0);
            if (qualifier.toString().contains("MemoryStoreQualifier")) {
                return memoryTokenStoreInstance;
            } else if (qualifier.toString().contains("EnterpriseStoreQualifier")) {
                return enterpriseTokenStoreInstance;
            }
            return null;
        });

        when(memoryTokenStoreInstance.get()).thenReturn(memoryTokenStore);
        when(enterpriseTokenStoreInstance.get()).thenReturn(enterpriseTokenStore);

        // Setup the AuthCodeStore Instance mock to return specific instances based on qualifiers
        when(authCodeStores.select(any())).thenAnswer(invocation -> {
            Object qualifier = invocation.getArgument(0);
            if (qualifier.toString().contains("MemoryStoreQualifier")) {
                return memoryAuthCodeStoreInstance;
            } else if (qualifier.toString().contains("EnterpriseStoreQualifier")) {
                return enterpriseAuthCodeStoreInstance;
            }
            return null;
        });

        when(memoryAuthCodeStoreInstance.get()).thenReturn(memoryAuthCodeStore);
        when(enterpriseAuthCodeStoreInstance.get()).thenReturn(enterpriseAuthCodeStore);
    }

    @Test
    void testSelectTokenStoreMemory() {
        // Arrange
        dataStoreProducer.storeImplementation = "memory";

        // Act
        TokenStore result = dataStoreProducer.selectTokenStore();

        // Assert
        assertNotNull(result);
        assertEquals(memoryTokenStore, result);
        verify(tokenStores).select(any());
    }

    @Test
    void testSelectTokenStoreEnterprise() {
        // Arrange
        dataStoreProducer.storeImplementation = "enterprise";

        // Act
        TokenStore result = dataStoreProducer.selectTokenStore();

        // Assert
        assertNotNull(result);
        assertEquals(enterpriseTokenStore, result);
        verify(tokenStores).select(any());
    }

    @Test
    void testSelectTokenStoreUnknownImplementation() {
        // Arrange
        dataStoreProducer.storeImplementation = "unknown";

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            dataStoreProducer.selectTokenStore();
        });

        assertTrue(exception.getMessage().contains("Unknown token store implementation"));
        assertTrue(exception.getMessage().contains("unknown"));
    }

    @Test
    void testSelectTokenStoreInvalidImplementation() {
        // Arrange
        dataStoreProducer.storeImplementation = "redis";

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            dataStoreProducer.selectTokenStore();
        });

        assertTrue(exception.getMessage().contains("Unknown token store implementation"));
        assertTrue(exception.getMessage().contains("redis"));
    }

    @Test
    void testSelectTokenStoreNullImplementation() {
        // Arrange
        dataStoreProducer.storeImplementation = null;

        // Act & Assert
        // When tokenStoreImplementation is null, switch statement throws NullPointerException
        assertThrows(NullPointerException.class, () -> {
            dataStoreProducer.selectTokenStore();
        });
    }

    @Test
    void testSelectTokenStoreEmptyImplementation() {
        // Arrange
        dataStoreProducer.storeImplementation = "";

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            dataStoreProducer.selectTokenStore();
        });

        assertTrue(exception.getMessage().contains("Unknown token store implementation"));
    }

    @Test
    void testSelectTokenStoreCaseSensitivity() {
        // Arrange - Test that the implementation name is case-sensitive
        dataStoreProducer.storeImplementation = "Memory";  // Capital M

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            dataStoreProducer.selectTokenStore();
        });

        assertTrue(exception.getMessage().contains("Unknown token store implementation"));
        assertTrue(exception.getMessage().contains("Memory"));
    }

    @Test
    void testSelectTokenStoreEnterpriseUpperCase() {
        // Arrange - Test that the implementation name is case-sensitive
        dataStoreProducer.storeImplementation = "ENTERPRISE";  // All caps

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            dataStoreProducer.selectTokenStore();
        });

        assertTrue(exception.getMessage().contains("Unknown token store implementation"));
        assertTrue(exception.getMessage().contains("ENTERPRISE"));
    }

    @Test
    void testMultipleCallsReturnCorrectImplementations() {
        // Test that multiple calls with different configurations work correctly

        // First call with memory
        dataStoreProducer.storeImplementation = "memory";
        TokenStore memoryResult = dataStoreProducer.selectTokenStore();
        assertEquals(memoryTokenStore, memoryResult);

        // Second call with enterprise
        dataStoreProducer.storeImplementation = "enterprise";
        TokenStore enterpriseResult = dataStoreProducer.selectTokenStore();
        assertEquals(enterpriseTokenStore, enterpriseResult);

        // Verify both were called
        verify(tokenStores, times(2)).select(any());
    }

    @Test
    void testSelectAuthStoreMemory() {
        // Arrange
        dataStoreProducer.storeImplementation = "memory";

        // Act
        AuthCodeStore result = dataStoreProducer.selectAuthStore();

        // Assert
        assertNotNull(result);
        assertEquals(memoryAuthCodeStore, result);
        verify(authCodeStores).select(any());
    }

    @Test
    void testSelectAuthStoreEnterprise() {
        // Arrange
        dataStoreProducer.storeImplementation = "enterprise";

        // Act
        AuthCodeStore result = dataStoreProducer.selectAuthStore();

        // Assert
        assertNotNull(result);
        assertEquals(enterpriseAuthCodeStore, result);
        verify(authCodeStores).select(any());
    }

    @Test
    void testSelectAuthStoreUnknownImplementation() {
        // Arrange
        dataStoreProducer.storeImplementation = "unknown";

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            dataStoreProducer.selectAuthStore();
        });

        assertTrue(exception.getMessage().contains("Unknown auth code store implementation"));
        assertTrue(exception.getMessage().contains("unknown"));
    }

    @Test
    void testSelectAuthStoreCaseSensitivity() {
        // Arrange - Test that the implementation name is case-sensitive
        dataStoreProducer.storeImplementation = "Memory";  // Capital M

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            dataStoreProducer.selectAuthStore();
        });

        assertTrue(exception.getMessage().contains("Unknown auth code store implementation"));
        assertTrue(exception.getMessage().contains("Memory"));
    }

    /**
     * Mock implementation for testing purposes
     */
    static class MockTokenStore implements TokenStore {
        @Override
        public void storeUserToken(String user, String provider, TokenWrapper token) {
            // Mock implementation
        }

        @Override
        public TokenWrapper getUserToken(String user, String provider) {
            return null;
        }
    }
}
