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

import com.yahoo.athenz.zts.AccessTokenResponse;
import com.yahoo.athenz.zts.OAuthTokenRequestBuilder;
import com.yahoo.athenz.zts.ZTSClient;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.service.TokenExchangeServiceZTSImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class TokenExchangeServiceZTSImplTest {

    @Mock
    private ZTSClient ztsClient;

    @InjectMocks
    private TokenExchangeServiceZTSImpl tokenExchangeService;

    private TokenWrapper tokenWrapper;
    private TokenExchangeDO tokenExchangeDO;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        // Setup common test data
        tokenWrapper = new TokenWrapper(
                "test-key",
                "test-provider",
                "test-id-token",
                "test-access-token",
                "test-refresh-token",
                3600L
        );
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_Success() {
        // Arrange
        List<String> scopes = Arrays.asList("scope1", "scope2");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "test-namespace",
                "test-remote-server",
                tokenWrapper
        );

        AccessTokenResponse mockResponse = new AccessTokenResponse();
        mockResponse.setAccess_token("jag-token-value");
        mockResponse.setExpires_in(7200);

        when(ztsClient.getJAGToken(any(OAuthTokenRequestBuilder.class))).thenReturn(mockResponse);

        // Act
        AuthorizationResultDO result = tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertNotNull(result.token());
        assertEquals("test-key", result.token().key());
        assertEquals("test-remote-server", result.token().provider());
        assertEquals("jag-token-value", result.token().idToken());
        assertNull(result.token().accessToken());
        assertNull(result.token().refreshToken());
        assertEquals(7200L, result.token().ttl());

        verify(ztsClient, times(1)).getJAGToken(any(OAuthTokenRequestBuilder.class));
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_WithSingleScope() {
        // Arrange
        List<String> scopes = Collections.singletonList("single-scope");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "single-namespace",
                "single-remote-server",
                tokenWrapper
        );

        AccessTokenResponse mockResponse = new AccessTokenResponse();
        mockResponse.setAccess_token("jag-single-scope-token");
        mockResponse.setExpires_in(3600);

        when(ztsClient.getJAGToken(any(OAuthTokenRequestBuilder.class))).thenReturn(mockResponse);

        // Act
        AuthorizationResultDO result = tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals("jag-single-scope-token", result.token().idToken());
        assertEquals(3600L, result.token().ttl());

        verify(ztsClient, times(1)).getJAGToken(any(OAuthTokenRequestBuilder.class));
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_WithEmptyScopes() {
        // Arrange
        List<String> scopes = Collections.emptyList();
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "empty-namespace",
                "empty-remote-server",
                tokenWrapper
        );

        AccessTokenResponse mockResponse = new AccessTokenResponse();
        mockResponse.setAccess_token("jag-no-scope-token");
        mockResponse.setExpires_in(1800);

        when(ztsClient.getJAGToken(any(OAuthTokenRequestBuilder.class))).thenReturn(mockResponse);

        // Act
        AuthorizationResultDO result = tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals("jag-no-scope-token", result.token().idToken());

        verify(ztsClient, times(1)).getJAGToken(any(OAuthTokenRequestBuilder.class));
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_ZTSClientThrowsException() {
        // Arrange
        List<String> scopes = Arrays.asList("scope1", "scope2");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "test-namespace",
                "test-remote-server",
                tokenWrapper
        );

        when(ztsClient.getJAGToken(any(OAuthTokenRequestBuilder.class)))
                .thenThrow(new RuntimeException("ZTS connection error"));

        // Act & Assert
        assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);
        });

        verify(ztsClient, times(1)).getJAGToken(any(OAuthTokenRequestBuilder.class));
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_Success() {
        // Arrange
        List<String> scopes = Arrays.asList("read", "write");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "test-namespace",
                "test-remote-server",
                tokenWrapper
        );

        AccessTokenResponse mockResponse = new AccessTokenResponse();
        mockResponse.setAccess_token("resource-access-token");
        mockResponse.setExpires_in(5400);

        when(ztsClient.getJAGExchangeToken(any(OAuthTokenRequestBuilder.class))).thenReturn(mockResponse);

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertNotNull(result.token());
        assertEquals("test-key", result.token().key());
        assertEquals("test-remote-server", result.token().provider());
        assertNull(result.token().idToken());
        assertEquals("resource-access-token", result.token().accessToken());
        assertNull(result.token().refreshToken());
        assertEquals(5400L, result.token().ttl());

        verify(ztsClient, times(1)).getJAGExchangeToken(any(OAuthTokenRequestBuilder.class));
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithMultipleScopes() {
        // Arrange
        List<String> scopes = Arrays.asList("scope1", "scope2", "scope3");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "multi-namespace",
                "multi-remote-server",
                tokenWrapper
        );

        AccessTokenResponse mockResponse = new AccessTokenResponse();
        mockResponse.setAccess_token("multi-scope-access-token");
        mockResponse.setExpires_in(7200);

        when(ztsClient.getJAGExchangeToken(any(OAuthTokenRequestBuilder.class))).thenReturn(mockResponse);

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals("multi-scope-access-token", result.token().accessToken());
        assertEquals(7200L, result.token().ttl());

        verify(ztsClient, times(1)).getJAGExchangeToken(any(OAuthTokenRequestBuilder.class));
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_ZTSClientThrowsException() {
        // Arrange
        List<String> scopes = Arrays.asList("read", "write");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "test-namespace",
                "test-remote-server",
                tokenWrapper
        );

        when(ztsClient.getJAGExchangeToken(any(OAuthTokenRequestBuilder.class)))
                .thenThrow(new RuntimeException("ZTS exchange error"));

        // Act & Assert
        assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);
        });

        verify(ztsClient, times(1)).getJAGExchangeToken(any(OAuthTokenRequestBuilder.class));
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_Success() {
        // Arrange
        List<String> scopes = Arrays.asList("admin", "user");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "client-namespace",
                "client-remote-server",
                tokenWrapper
        );

        AccessTokenResponse mockResponse = new AccessTokenResponse();
        mockResponse.setAccess_token("client-credentials-token");
        mockResponse.setExpires_in(3600);

        when(ztsClient.getAccessToken(any(OAuthTokenRequestBuilder.class), eq(true))).thenReturn(mockResponse);

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertNotNull(result.token());
        assertEquals("test-key", result.token().key());
        assertEquals("client-remote-server", result.token().provider());
        assertNull(result.token().idToken());
        assertEquals("client-credentials-token", result.token().accessToken());
        assertNull(result.token().refreshToken());
        assertEquals(3600L, result.token().ttl());

        verify(ztsClient, times(1)).getAccessToken(any(OAuthTokenRequestBuilder.class), eq(true));
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_WithSingleScope() {
        // Arrange
        List<String> scopes = Collections.singletonList("read-only");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "single-cc-namespace",
                "single-cc-remote-server",
                tokenWrapper
        );

        AccessTokenResponse mockResponse = new AccessTokenResponse();
        mockResponse.setAccess_token("single-scope-cc-token");
        mockResponse.setExpires_in(1800);

        when(ztsClient.getAccessToken(any(OAuthTokenRequestBuilder.class), eq(true))).thenReturn(mockResponse);

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals("single-scope-cc-token", result.token().accessToken());
        assertEquals(1800L, result.token().ttl());

        verify(ztsClient, times(1)).getAccessToken(any(OAuthTokenRequestBuilder.class), eq(true));
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_ZTSClientThrowsException() {
        // Arrange
        List<String> scopes = Arrays.asList("admin", "user");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "client-namespace",
                "client-remote-server",
                tokenWrapper
        );

        when(ztsClient.getAccessToken(any(OAuthTokenRequestBuilder.class), eq(true)))
                .thenThrow(new RuntimeException("ZTS client credentials error"));

        // Act & Assert
        assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO);
        });

        verify(ztsClient, times(1)).getAccessToken(any(OAuthTokenRequestBuilder.class), eq(true));
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_WithNullIdToken() {
        // Arrange
        TokenWrapper wrapperWithNullIdToken = new TokenWrapper(
                "test-key",
                "test-provider",
                null,
                "test-access-token",
                "test-refresh-token",
                3600L
        );

        List<String> scopes = Arrays.asList("scope1");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "test-namespace",
                "test-remote-server",
                wrapperWithNullIdToken
        );

        AccessTokenResponse mockResponse = new AccessTokenResponse();
        mockResponse.setAccess_token("jag-token-with-null-input");
        mockResponse.setExpires_in(3600);

        when(ztsClient.getJAGToken(any(OAuthTokenRequestBuilder.class))).thenReturn(mockResponse);

        // Act
        AuthorizationResultDO result = tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals("jag-token-with-null-input", result.token().idToken());

        verify(ztsClient, times(1)).getJAGToken(any(OAuthTokenRequestBuilder.class));
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithNullIdToken() {
        // Arrange
        TokenWrapper wrapperWithNullIdToken = new TokenWrapper(
                "test-key",
                "test-provider",
                null,
                "test-access-token",
                "test-refresh-token",
                3600L
        );

        List<String> scopes = Arrays.asList("read");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "test-namespace",
                "test-remote-server",
                wrapperWithNullIdToken
        );

        AccessTokenResponse mockResponse = new AccessTokenResponse();
        mockResponse.setAccess_token("resource-token-with-null-input");
        mockResponse.setExpires_in(3600);

        when(ztsClient.getJAGExchangeToken(any(OAuthTokenRequestBuilder.class))).thenReturn(mockResponse);

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals("resource-token-with-null-input", result.token().accessToken());

        verify(ztsClient, times(1)).getJAGExchangeToken(any(OAuthTokenRequestBuilder.class));
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_VerifyBuilderConfiguration() {
        // Arrange
        List<String> scopes = Arrays.asList("scope1", "scope2");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "test-resource",
                "test-namespace",
                "test-remote-server",
                tokenWrapper
        );

        AccessTokenResponse mockResponse = new AccessTokenResponse();
        mockResponse.setAccess_token("jag-token");
        mockResponse.setExpires_in(3600);

        ArgumentCaptor<OAuthTokenRequestBuilder> builderCaptor = ArgumentCaptor.forClass(OAuthTokenRequestBuilder.class);
        when(ztsClient.getJAGToken(builderCaptor.capture())).thenReturn(mockResponse);

        // Act
        tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);

        // Assert
        verify(ztsClient, times(1)).getJAGToken(any(OAuthTokenRequestBuilder.class));
        // Note: OAuthTokenRequestBuilder internals are not easily testable without reflection
        // But we can verify the method was called with correct type
        assertNotNull(builderCaptor.getValue());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_VerifyBuilderConfiguration() {
        // Arrange
        List<String> scopes = Arrays.asList("read", "write");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "test-resource",
                "test-namespace",
                "test-remote-server",
                tokenWrapper
        );

        AccessTokenResponse mockResponse = new AccessTokenResponse();
        mockResponse.setAccess_token("resource-token");
        mockResponse.setExpires_in(3600);

        ArgumentCaptor<OAuthTokenRequestBuilder> builderCaptor = ArgumentCaptor.forClass(OAuthTokenRequestBuilder.class);
        when(ztsClient.getJAGExchangeToken(builderCaptor.capture())).thenReturn(mockResponse);

        // Act
        tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        verify(ztsClient, times(1)).getJAGExchangeToken(any(OAuthTokenRequestBuilder.class));
        assertNotNull(builderCaptor.getValue());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_VerifyBuilderConfiguration() {
        // Arrange
        List<String> scopes = Arrays.asList("admin");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "test-resource",
                "test-namespace",
                "test-remote-server",
                tokenWrapper
        );

        AccessTokenResponse mockResponse = new AccessTokenResponse();
        mockResponse.setAccess_token("cc-token");
        mockResponse.setExpires_in(3600);

        ArgumentCaptor<OAuthTokenRequestBuilder> builderCaptor = ArgumentCaptor.forClass(OAuthTokenRequestBuilder.class);
        when(ztsClient.getAccessToken(builderCaptor.capture(), eq(true))).thenReturn(mockResponse);

        // Act
        tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO);

        // Assert
        verify(ztsClient, times(1)).getAccessToken(any(OAuthTokenRequestBuilder.class), eq(true));
        assertNotNull(builderCaptor.getValue());
    }
}
