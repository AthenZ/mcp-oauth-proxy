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

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import io.athenz.mop.config.OktaTokenExchangeConfig;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.secret.K8SSecretsProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class TokenExchangeServiceOktaImplTest {

    @Mock
    private K8SSecretsProvider k8SSecretsProvider;

    @Mock
    private OktaTokenExchangeConfig oktaTokenExchangeConfig;

    @Mock
    private TokenClient tokenClient;

    @InjectMocks
    private TokenExchangeServiceOktaImpl tokenExchangeService;

    private TokenWrapper tokenWrapper;
    private TokenExchangeDO tokenExchangeDO;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        // Setup common test data
        tokenWrapper = new TokenWrapper(
                "okta-key",
                "okta-provider",
                "okta-id-token",
                "okta-access-token",
                "okta-refresh-token",
                3600L
        );
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_ThrowsRuntimeException() {
        // Arrange
        List<String> scopes = Arrays.asList("openid", "profile");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "okta-namespace",
                "okta-remote-server",
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
                "okta-namespace",
                "okta-remote-server",
                tokenWrapper
        );

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);
        });

        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_WithNullScopes() {
        // Arrange
        tokenExchangeDO = new TokenExchangeDO(
                null,
                "resource",
                "okta-namespace",
                "okta-remote-server",
                tokenWrapper
        );

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);
        });

        assertEquals("Not implemented yet", exception.getMessage());
    }

    
    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_ThrowsRuntimeException() {
        // Arrange
        List<String> scopes = Arrays.asList("client", "credentials");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "okta-namespace",
                "okta-remote-server",
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
                "okta-namespace",
                "okta-remote-server",
                tokenWrapper
        );

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO);
        });

        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_WithNullTokenWrapper() {
        // Arrange
        List<String> scopes = Arrays.asList("scope1");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "okta-namespace",
                "okta-remote-server",
                null
        );

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO);
        });

        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_WithDifferentRemoteServers() {
        // Arrange
        List<String> scopes = Arrays.asList("openid");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "okta-namespace",
                "different-remote-server",
                tokenWrapper
        );

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);
        });

        assertEquals("Not implemented yet", exception.getMessage());
    }


    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_WithNullResource() {
        // Arrange
        List<String> scopes = Arrays.asList("scope1");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                null,
                "okta-namespace",
                "okta-remote-server",
                tokenWrapper
        );

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO);
        });

        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testAllMethods_ConsistentExceptionMessage() {
        // Arrange
        List<String> scopes = Arrays.asList("scope");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "namespace",
                "remote-server",
                tokenWrapper
        );

        // Act & Assert - Test all three methods throw the same exception message
        RuntimeException exception1 = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);
        });

        // RuntimeException exception2 = assertThrows(RuntimeException.class, () -> {
        //     tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);
        // });

        RuntimeException exception3 = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO);
        });

        assertEquals("Not implemented yet", exception1.getMessage());
        // assertEquals("Not implemented yet", exception2.getMessage());
        assertEquals("Not implemented yet", exception3.getMessage());
    }

    @Test
    void testK8SSecretsProviderInjection() {
        // This test verifies that the K8SSecretsProvider is properly injected
        // Even though it's not used in the current implementation
        assertNotNull(k8SSecretsProvider);
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_ForGlean_SuccessfulTokenExchange() throws ParseException, IOException {
        // Arrange - Glean-specific configuration with test endpoints
        List<String> scopes = Arrays.asList("test.scope");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "test-resource",
                "test-namespace",
                "test-remote-server",
                tokenWrapper
        );

        // Mock Glean Okta configuration with test values
        when(oktaTokenExchangeConfig.authServerUrl()).thenReturn("https://test-okta.example.com/oauth2/test-auth-server");
        when(oktaTokenExchangeConfig.clientId()).thenReturn("test-client-id");
        when(oktaTokenExchangeConfig.clientSecretKey()).thenReturn("test-client-secret-key");
        when(oktaTokenExchangeConfig.audience()).thenReturn("https://test-audience.example.com");

        // Mock K8S secrets provider to return valid client secret
        Map<String, String> credentials = new HashMap<>();
        credentials.put("test-client-secret-key", "test-client-secret-value");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        // Mock successful token exchange response
        // Create a mock HTTP response and parse it to get AccessTokenResponse
        String jsonResponse = "{\"access_token\":\"test-exchanged-access-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}";
        HTTPResponse mockHttpResponse = new HTTPResponse(200);
        mockHttpResponse.setContentType("application/json");
        mockHttpResponse.setBody(jsonResponse);
        TokenResponse mockTokenResponse = TokenResponse.parse(mockHttpResponse);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(mockTokenResponse);

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertNotNull(result.token());
        assertEquals("test-exchanged-access-token", result.token().accessToken());
        assertEquals(3600L, result.token().ttl());
        
        // Verify that tokenClient.execute was called
        verify(tokenClient, times(1)).execute(any(TokenRequest.class));
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_ForGlean_WithMissingClientSecret() {
        // Arrange - Glean-specific configuration with test endpoints
        List<String> scopes = Arrays.asList("test.scope");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "test-resource",
                "test-namespace",
                "test-remote-server",
                tokenWrapper
        );

        // Mock Glean Okta configuration with test values
        when(oktaTokenExchangeConfig.clientId()).thenReturn("test-client-id");
        when(oktaTokenExchangeConfig.clientSecretKey()).thenReturn("test-client-secret-key");

        // Mock K8S secrets provider to return empty credentials (secret not found)
        Map<String, String> credentials = new HashMap<>();
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        assertNull(result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_ForGlean_WithNullClientSecret() {
        // Arrange - Glean-specific configuration with test endpoints
        List<String> scopes = Arrays.asList("test.scope");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "test-resource",
                "test-namespace",
                "test-remote-server",
                tokenWrapper
        );

        // Mock Glean Okta configuration with test values
        when(oktaTokenExchangeConfig.clientId()).thenReturn("test-client-id");
        when(oktaTokenExchangeConfig.clientSecretKey()).thenReturn("test-client-secret-key");

        // Mock K8S secrets provider to return null client secret
        Map<String, String> credentials = new HashMap<>();
        credentials.put("test-client-secret-key", null);
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        assertNull(result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_ForGlean_WithException() {
        // Arrange - Glean-specific configuration with test endpoints
        List<String> scopes = Arrays.asList("test.scope");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "test-resource",
                "test-namespace",
                "test-remote-server",
                tokenWrapper
        );

        // Mock Glean Okta configuration with test values
        when(oktaTokenExchangeConfig.clientId()).thenReturn("test-client-id");
        when(oktaTokenExchangeConfig.clientSecretKey()).thenReturn("test-client-secret-key");

        // Mock K8S secrets provider to throw exception
        when(k8SSecretsProvider.getCredentials(null)).thenThrow(new RuntimeException("K8S secrets provider error"));

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert - Exception should be caught and return UNAUTHORIZED
        assertNotNull(result);
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        assertNull(result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_ForGlean_ConfigurationRetrieval() {
        // Arrange - Glean-specific configuration with test endpoints
        List<String> scopes = Arrays.asList("test.scope");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "test-resource",
                "test-namespace",
                "test-remote-server",
                tokenWrapper
        );

        // Mock Glean Okta configuration values with test data
        String expectedAuthServerUrl = "https://test-okta.example.com/oauth2/test-auth-server";
        String expectedClientId = "test-client-id";
        String expectedClientSecretKey = "test-client-secret-key";
        String expectedAudience = "https://test-audience.example.com";

        when(oktaTokenExchangeConfig.authServerUrl()).thenReturn(expectedAuthServerUrl);
        when(oktaTokenExchangeConfig.clientId()).thenReturn(expectedClientId);
        when(oktaTokenExchangeConfig.clientSecretKey()).thenReturn(expectedClientSecretKey);
        when(oktaTokenExchangeConfig.audience()).thenReturn(expectedAudience);

        // Mock K8S secrets provider to return valid client secret
        Map<String, String> credentials = new HashMap<>();
        credentials.put(expectedClientSecretKey, "test-client-secret-value");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert - Verify configuration methods were called
        verify(oktaTokenExchangeConfig, times(1)).clientId();
        verify(oktaTokenExchangeConfig, times(1)).clientSecretKey();
        verify(oktaTokenExchangeConfig, atLeastOnce()).audience();
        verify(k8SSecretsProvider, times(1)).getCredentials(null);

        // Result will be UNAUTHORIZED because we can't mock the HTTP call, but we verified the config was retrieved
        assertNotNull(result);
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
    }
}
