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
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class TokenExchangeServiceGithubImplTest {

    @Mock
    private K8SSecretsProvider k8SSecretsProvider;

    @Mock
    private TokenClient tokenClient;

    @InjectMocks
    private TokenExchangeServiceGithubImpl tokenExchangeService;

    private TokenWrapper tokenWrapper;
    private TokenExchangeDO tokenExchangeDO;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        setField(tokenExchangeService, "clientId", "test-client-id");
        setField(tokenExchangeService, "clientSecretKey", "github-client-secret");

        // Setup common test data
        tokenWrapper = new TokenWrapper(
                "github-key",
                "github-provider",
                "github-id-token",
                "github-access-token",
                "github-refresh-token",
                3600L
        );
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_ThrowsRuntimeException() {
        // Arrange
        List<String> scopes = Arrays.asList("repo", "user");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "github-namespace",
                "github-remote-server",
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
                "github-namespace",
                "github-remote-server",
                tokenWrapper
        );

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);
        });

        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_WithPublicRepoScope() {
        // Arrange
        List<String> scopes = Collections.singletonList("public_repo");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "github-namespace",
                "github-remote-server",
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
        List<String> scopes = Arrays.asList("repo", "user");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "github-resource",
                "github-namespace",
                "github-remote-server",
                tokenWrapper
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertNotNull(result.token());
        assertEquals(tokenWrapper, result.token());
        assertEquals("github-key", result.token().key());
        assertEquals("github-provider", result.token().provider());
        assertEquals("github-id-token", result.token().idToken());
        assertEquals("github-access-token", result.token().accessToken());
        assertEquals("github-refresh-token", result.token().refreshToken());
        assertEquals(3600L, result.token().ttl());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithRepoScope() {
        // Arrange
        List<String> scopes = Collections.singletonList("repo");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "github-resource",
                "github-namespace",
                "github-remote-server",
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
    void testGetAccessTokenFromResourceAuthorizationServer_WithWorkflowScope() {
        // Arrange
        List<String> scopes = Collections.singletonList("workflow");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "github-resource",
                "github-namespace",
                "github-remote-server",
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
        List<String> scopes = Arrays.asList("repo", "workflow", "user", "read:org");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "multi-resource",
                "github-namespace",
                "github-remote-server",
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
                "github-namespace",
                "github-remote-server",
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
                "different-github-key",
                "different-github-provider",
                "different-github-id-token",
                "different-github-access-token",
                "different-github-refresh-token",
                7200L
        );

        List<String> scopes = Arrays.asList("repo");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "github-namespace",
                "github-remote-server",
                differentWrapper
        );

        // Act
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        // Assert
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(differentWrapper, result.token());
        assertEquals("different-github-key", result.token().key());
        assertEquals("different-github-provider", result.token().provider());
        assertEquals(7200L, result.token().ttl());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithNullTokens() {
        // Arrange
        TokenWrapper wrapperWithNulls = new TokenWrapper(
                "key",
                "github",
                null,
                null,
                null,
                1800L
        );

        List<String> scopes = Arrays.asList("repo");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "github-namespace",
                "github-remote-server",
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
        List<String> scopes = Arrays.asList("repo");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                null,
                "github-namespace",
                "github-remote-server",
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
        List<String> scopes = Arrays.asList("repo");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                null,
                "github-remote-server",
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
        List<String> scopes = Arrays.asList("repo");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "github-namespace",
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
        List<String> scopes = Arrays.asList("repo");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "github-namespace",
                "github-remote-server",
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
        List<String> scopes = Arrays.asList("repo", "user");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "github-namespace",
                "github-remote-server",
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
                "github-namespace",
                "github-remote-server",
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
        List<String> scopes = Arrays.asList("repo");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "github-namespace",
                "github-remote-server",
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
                "github",
                "id-token",
                "access-token",
                "refresh-token",
                0L
        );

        List<String> scopes = Arrays.asList("repo");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "github-namespace",
                "github-remote-server",
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
                "github",
                "id-token",
                "access-token",
                "refresh-token",
                -100L
        );

        List<String> scopes = Arrays.asList("repo");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "github-namespace",
                "github-remote-server",
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
        List<String> scopes = Arrays.asList("repo");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "github-namespace",
                "github-remote-server",
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
    void testRefreshWithUpstreamToken_returnsNullWhenTokenNull() {
        assertNull(tokenExchangeService.refreshWithUpstreamToken(null));
    }

    @Test
    void testRefreshWithUpstreamToken_returnsNullWhenTokenBlank() {
        assertNull(tokenExchangeService.refreshWithUpstreamToken(""));
        assertNull(tokenExchangeService.refreshWithUpstreamToken("   "));
    }

    @Test
    void testRefreshWithUpstreamToken_returnsNullWhenClientIdNotConfigured() throws Exception {
        setField(tokenExchangeService, "clientId", "");
        assertNull(tokenExchangeService.refreshWithUpstreamToken("valid-refresh-token"));
    }

    @Test
    void testRefreshWithUpstreamToken_returnsNullWhenClientSecretKeyNotConfigured() throws Exception {
        setField(tokenExchangeService, "clientSecretKey", "");
        assertNull(tokenExchangeService.refreshWithUpstreamToken("valid-refresh-token"));
    }

    private static void setField(Object target, String fieldName, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(target, value);
    }

    @Test
    void testRefreshWithUpstreamToken_returnsNullWhenCredentialsNull() {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(null);
        assertNull(tokenExchangeService.refreshWithUpstreamToken("valid-refresh-token"));
    }

    @Test
    void testRefreshWithUpstreamToken_returnsNullWhenSecretMissingForKey() {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Collections.emptyMap());
        assertNull(tokenExchangeService.refreshWithUpstreamToken("valid-refresh-token"));
    }

    @Test
    void testRefreshWithUpstreamToken_returnsNullWhenSecretBlank() {
        Map<String, String> creds = new HashMap<>();
        creds.put("github-client-secret", "");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(creds);
        assertNull(tokenExchangeService.refreshWithUpstreamToken("valid-refresh-token"));
    }

    @Test
    void testRefreshWithUpstreamToken_success_returnsTokenWrapper() throws ParseException, IOException {
        Map<String, String> credentials = new HashMap<>();
        credentials.put("github-client-secret", "secret-value");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        String jsonSuccess = "{\"access_token\":\"new-github-access\",\"token_type\":\"Bearer\",\"expires_in\":28800,\"refresh_token\":\"new-github-refresh\"}";
        HTTPResponse mockHttpResponse = new HTTPResponse(200);
        mockHttpResponse.setContentType("application/json");
        mockHttpResponse.setBody(jsonSuccess);
        TokenResponse mockTokenResponse = TokenResponse.parse(mockHttpResponse);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(mockTokenResponse);

        TokenWrapper result = tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token");

        assertNotNull(result);
        assertEquals("new-github-access", result.accessToken());
        assertEquals("new-github-refresh", result.refreshToken());
        assertEquals(28800L, result.ttl());
        verify(tokenClient, times(1)).execute(any(TokenRequest.class));
    }

    @Test
    void testRefreshWithUpstreamToken_errorResponse_returnsNull() throws ParseException, IOException {
        Map<String, String> credentials = new HashMap<>();
        credentials.put("github-client-secret", "secret-value");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        String jsonError = "{\"error\":\"bad_verification_code\",\"error_description\":\"The code passed is incorrect\"}";
        HTTPResponse mockHttpResponse = new HTTPResponse(400);
        mockHttpResponse.setContentType("application/json");
        mockHttpResponse.setBody(jsonError);
        TokenResponse mockTokenResponse = TokenResponse.parse(mockHttpResponse);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(mockTokenResponse);

        TokenWrapper result = tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token");

        assertNull(result);
        verify(tokenClient, times(1)).execute(any(TokenRequest.class));
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithAdminScopes() {
        // Arrange
        List<String> scopes = Arrays.asList("admin:org", "admin:repo_hook", "admin:public_key");
        tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "github-namespace",
                "github-remote-server",
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
