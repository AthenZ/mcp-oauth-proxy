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

import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.service.TokenExchangeServiceGoogleImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TokenExchangeServiceGoogleImplTest {

    @InjectMocks
    private TokenExchangeServiceGoogleImpl tokenExchangeService;

    private TokenWrapper tokenWrapper;
    private TokenExchangeDO tokenExchangeDO;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        // Setup common test data
        tokenWrapper = new TokenWrapper(
                "google-key",
                "google-provider",
                "google-id-token",
                "google-access-token",
                "google-refresh-token",
                3600L
        );
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_ThrowsRuntimeException() {
        // Arrange
        List<String> scopes = Arrays.asList("openid", "email", "profile");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);
        });

        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_WithNullTokenExchangeDO() {
        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(null);
        });

        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_WithEmptyScopes() {
        // Arrange
        List<String> scopes = Collections.emptyList();
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);
        });

        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_WithGoogleDriveScope() {
        // Arrange
        List<String> scopes = Collections.singletonList("https://www.googleapis.com/auth/drive");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);
        });

        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_Success() {
        // Arrange
        List<String> scopes = Arrays.asList("openid", "email", "profile");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "google-resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertNotNull(result.token());
        assertEquals(tokenWrapper, result.token());
        assertEquals("google-key", result.token().key());
        assertEquals("google-provider", result.token().provider());
        assertEquals("google-id-token", result.token().idToken());
        assertEquals("google-access-token", result.token().accessToken());
        assertEquals("google-refresh-token", result.token().refreshToken());
        assertEquals(3600L, result.token().ttl());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithGmailScope() {
        // Arrange
        List<String> scopes = Collections.singletonList("https://www.googleapis.com/auth/gmail.readonly");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "gmail-resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(tokenWrapper, result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithCalendarScope() {
        // Arrange
        List<String> scopes = Collections.singletonList("https://www.googleapis.com/auth/calendar");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "calendar-resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(tokenWrapper, result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithMultipleScopes() {
        // Arrange
        List<String> scopes = Arrays.asList(
                "openid",
                "email",
                "profile",
                "https://www.googleapis.com/auth/drive.readonly",
                "https://www.googleapis.com/auth/calendar.readonly"
        );
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "multi-resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(tokenWrapper, result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithEmptyScopes() {
        // Arrange
        List<String> scopes = Collections.emptyList();
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(tokenWrapper, result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithDifferentTokenWrapper() {
        // Arrange
        TokenWrapper differentWrapper = new TokenWrapper(
                "different-google-key",
                "different-google-provider",
                "different-google-id-token",
                "different-google-access-token",
                "different-google-refresh-token",
                7200L
        );

        List<String> scopes = Arrays.asList("openid");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                differentWrapper
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(differentWrapper, result.token());
        assertEquals("different-google-key", result.token().key());
        assertEquals("different-google-provider", result.token().provider());
        assertEquals(7200L, result.token().ttl());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithNullTokens() {
        // Arrange
        TokenWrapper wrapperWithNulls = new TokenWrapper(
                "key",
                "google",
                null,
                null,
                null,
                1800L
        );

        List<String> scopes = Arrays.asList("openid");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                wrapperWithNulls
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(wrapperWithNulls, result.token());
        assertNull(result.token().idToken());
        assertNull(result.token().accessToken());
        assertNull(result.token().refreshToken());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithNullResource() {
        // Arrange
        List<String> scopes = Arrays.asList("openid");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                null,
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(tokenWrapper, result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithNullNamespace() {
        // Arrange
        List<String> scopes = Arrays.asList("openid");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                null,
                "google-remote-server",
                tokenWrapper
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(tokenWrapper, result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithNullRemoteServer() {
        // Arrange
        List<String> scopes = Arrays.asList("openid");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                null,
                tokenWrapper
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(tokenWrapper, result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_ReturnsOriginalTokenWrapper() {
        // Arrange
        List<String> scopes = Arrays.asList("openid");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertSame(tokenWrapper, result.token(), "Should return the exact same TokenWrapper instance");
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_ThrowsRuntimeException() {
        // Arrange
        List<String> scopes = Arrays.asList("openid", "email");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO);
        });

        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_WithNullTokenExchangeDO() {
        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(null);
        });

        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_WithEmptyScopes() {
        // Arrange
        List<String> scopes = Collections.emptyList();
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO);
        });

        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithNullTokenExchangeDO_ThrowsNullPointerException() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> {
            tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(null);
        });
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_MultipleCallsReturnSameResult() {
        // Arrange
        List<String> scopes = Arrays.asList("openid");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act
        AuthorizationResultDO result1 = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);
        AuthorizationResultDO result2 = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result1);
        assertNotNull(result2);
        assertEquals(result1.authResult(), result2.authResult());
        assertSame(result1.token(), result2.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithZeroTTL() {
        // Arrange
        TokenWrapper wrapperWithZeroTTL = new TokenWrapper(
                "key",
                "google",
                "id-token",
                "access-token",
                "refresh-token",
                0L
        );

        List<String> scopes = Arrays.asList("openid");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                wrapperWithZeroTTL
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(0L, result.token().ttl());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithNegativeTTL() {
        // Arrange
        TokenWrapper wrapperWithNegativeTTL = new TokenWrapper(
                "key",
                "google",
                "id-token",
                "access-token",
                "refresh-token",
                -100L
        );

        List<String> scopes = Arrays.asList("openid");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                wrapperWithNegativeTTL
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(-100L, result.token().ttl());
    }

    @Test
    void testImplementedVsNotImplementedMethods() {
        // Arrange
        List<String> scopes = Arrays.asList("openid");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act & Assert
        // This method is implemented and should not throw
        assertDoesNotThrow(() -> {
            AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);
            assertNotNull(result);
        });

        // These methods are not implemented and should throw
        assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);
        });

        assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO);
        });
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithGoogleCloudScopes() {
        // Arrange
        List<String> scopes = Arrays.asList(
                "https://www.googleapis.com/auth/cloud-platform",
                "https://www.googleapis.com/auth/compute"
        );
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(tokenWrapper, result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithYouTubeScopes() {
        // Arrange
        List<String> scopes = Arrays.asList(
                "https://www.googleapis.com/auth/youtube.readonly",
                "https://www.googleapis.com/auth/youtube.upload"
        );
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "google-namespace",
                "google-remote-server",
                tokenWrapper
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(tokenWrapper, result.token());
    }
}
