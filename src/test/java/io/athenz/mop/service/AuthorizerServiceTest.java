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

import com.yahoo.athenz.zms.Access;
import com.yahoo.athenz.zms.ZMSClient;
import io.athenz.mop.model.*;
import io.athenz.mop.service.AuthorizerService;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.TokenExchangeService;
import io.athenz.mop.service.TokenExchangeServiceProducer;
import io.athenz.mop.store.TokenStore;
import io.quarkus.oidc.RefreshToken;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthorizerServiceTest {

    @Mock
    private ZMSClient zmsClient;

    @Mock
    private TokenStore tokenStore;

    @Mock
    private TokenExchangeServiceProducer tokenExchangeServiceProducer;

    @Mock
    private ConfigService configService;

    @Mock
    private JsonWebToken idToken;

    @Mock
    private JsonWebToken accessToken;

    @Mock
    private RefreshToken refreshToken;

    @Mock
    private TokenExchangeService tokenExchangeService;

    @InjectMocks
    private AuthorizerService authorizerService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        authorizerService.userPrefix = "user.";
        authorizerService.ttl = 300L;
        authorizerService.authorizationDomain = "athenz.examples.agentic-ai";
        authorizerService.authorizationAction = "mcp.access";
        authorizerService.zmsResourceAuthorization = false;
    }

    @Test
    void testStoreTokens_WithAllTokens() {
        // Given
        String lookupKey = "test-lookup-key";
        String provider = "okta";
        String username = "testuser";
        String idTokenRaw = "id-token-raw";
        String accessTokenRaw = "access-token-raw";
        String refreshTokenRaw = "refresh-token-raw";

        when(accessToken.getName()).thenReturn(username);
        when(idToken.getRawToken()).thenReturn(idTokenRaw);
        when(accessToken.getRawToken()).thenReturn(accessTokenRaw);
        when(refreshToken.getToken()).thenReturn(refreshTokenRaw);

        // When
        authorizerService.storeTokens(lookupKey, idToken, accessToken, refreshToken, provider);

        // Then
        ArgumentCaptor<TokenWrapper> tokenCaptor = ArgumentCaptor.forClass(TokenWrapper.class);
        verify(tokenStore).storeUserToken(eq(lookupKey), eq(provider), tokenCaptor.capture());

        TokenWrapper capturedToken = tokenCaptor.getValue();
        assertEquals("user." + username, capturedToken.key());
        assertEquals(provider, capturedToken.provider());
        assertEquals(idTokenRaw, capturedToken.idToken());
        assertEquals(accessTokenRaw, capturedToken.accessToken());
        assertEquals(refreshTokenRaw, capturedToken.refreshToken());
        assertTrue(capturedToken.ttl() > Instant.now().getEpochSecond());
    }

    @Test
    void testStoreTokens_WithoutIdToken() {
        // Given
        String lookupKey = "test-lookup-key";
        String provider = "github";
        String username = "testuser";
        String accessTokenRaw = "access-token-raw";
        String refreshTokenRaw = "refresh-token-raw";

        when(accessToken.getName()).thenReturn(username);
        when(accessToken.getRawToken()).thenReturn(accessTokenRaw);
        when(refreshToken.getToken()).thenReturn(refreshTokenRaw);

        // When
        authorizerService.storeTokens(lookupKey, null, accessToken, refreshToken, provider);

        // Then
        ArgumentCaptor<TokenWrapper> tokenCaptor = ArgumentCaptor.forClass(TokenWrapper.class);
        verify(tokenStore).storeUserToken(eq(lookupKey), eq(provider), tokenCaptor.capture());

        TokenWrapper capturedToken = tokenCaptor.getValue();
        assertNull(capturedToken.idToken());
        assertEquals(accessTokenRaw, capturedToken.accessToken());
    }

    @Test
    void testStoreTokens_WithoutRefreshToken() {
        // Given
        String lookupKey = "test-lookup-key";
        String provider = "google";
        String username = "testuser";
        String idTokenRaw = "id-token-raw";
        String accessTokenRaw = "access-token-raw";

        when(accessToken.getName()).thenReturn(username);
        when(idToken.getRawToken()).thenReturn(idTokenRaw);
        when(accessToken.getRawToken()).thenReturn(accessTokenRaw);

        // When
        authorizerService.storeTokens(lookupKey, idToken, accessToken, null, provider);

        // Then
        ArgumentCaptor<TokenWrapper> tokenCaptor = ArgumentCaptor.forClass(TokenWrapper.class);
        verify(tokenStore).storeUserToken(eq(lookupKey), eq(provider), tokenCaptor.capture());

        TokenWrapper capturedToken = tokenCaptor.getValue();
        assertEquals(idTokenRaw, capturedToken.idToken());
        assertNull(capturedToken.refreshToken());
    }

    @Test
    void testStoreTokens_DirectMethod() {
        // Given
        String user = "user.testuser";
        String lookupKey = "test-lookup-key";
        String idToken = "id-token";
        String accessToken = "access-token";
        String refreshToken = "refresh-token";
        String provider = "atlassian";

        // When
        authorizerService.storeTokens(user, lookupKey, idToken, accessToken, refreshToken, provider);

        // Then
        ArgumentCaptor<TokenWrapper> tokenCaptor = ArgumentCaptor.forClass(TokenWrapper.class);
        verify(tokenStore).storeUserToken(eq(lookupKey), eq(provider), tokenCaptor.capture());

        TokenWrapper capturedToken = tokenCaptor.getValue();
        assertEquals(user, capturedToken.key());
        assertEquals(provider, capturedToken.provider());
        assertEquals(idToken, capturedToken.idToken());
        assertEquals(accessToken, capturedToken.accessToken());
        assertEquals(refreshToken, capturedToken.refreshToken());
    }

    @Test
    void testGetUserToken() {
        // Given
        String lookupKey = "test-lookup-key";
        String provider = "okta";
        TokenWrapper expectedToken = new TokenWrapper(
                "user.testuser", provider, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        when(tokenStore.getUserToken(lookupKey, provider)).thenReturn(expectedToken);

        // When
        TokenWrapper result = authorizerService.getUserToken(lookupKey, provider);

        // Then
        assertNotNull(result);
        assertEquals(expectedToken, result);
        verify(tokenStore).getUserToken(lookupKey, provider);
    }

    @Test
    void testAuthorize_Success_NoZMSCheck() {
        // Given
        String subject = "test-subject";
        String scopes = "read write";
        String resource = "https://api.example.com";
        String provider = "okta";

        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read", "write"), "domain1", provider, "as1", false, null
        );

        TokenWrapper token = new TokenWrapper(
                "user.testuser", provider, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(tokenStore.getUserToken(subject, provider)).thenReturn(token);

        // When
        AuthorizationResultDO result = authorizerService.authorize(subject, scopes, resource);

        // Then
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(token, result.token());
        verify(zmsClient, never()).getAccessExt(anyString(), anyString(), any(), anyString());
    }

    @Test
    void testAuthorize_TokenNotFound() {
        // Given
        String subject = "test-subject";
        String scopes = "read write";
        String resource = "https://api.example.com";
        String provider = "okta";

        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read", "write"), "domain1", provider, "as1", false, null
        );

        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(tokenStore.getUserToken(subject, provider)).thenReturn(null);

        // When
        AuthorizationResultDO result = authorizerService.authorize(subject, scopes, resource);

        // Then
        assertNotNull(result);
        assertEquals(AuthResult.EXPIRED, result.authResult());
        assertNull(result.token());
    }

    @Test
    void testAuthorize_ResourceMetaNotFound_UsesDefaultIDP() {
        // Given
        String subject = "test-subject";
        String scopes = "read write";
        String resource = "https://api.example.com";
        String defaultProvider = "default-okta";

        TokenWrapper token = new TokenWrapper(
                "user.testuser", defaultProvider, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        when(configService.getResourceMeta(resource)).thenReturn(null);
        when(configService.getDefaultIDP()).thenReturn(defaultProvider);
        when(tokenStore.getUserToken(subject, defaultProvider)).thenReturn(token);

        // When
        AuthorizationResultDO result = authorizerService.authorize(subject, scopes, resource);

        // Then
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(token, result.token());
        verify(configService).getDefaultIDP();
    }

    @Test
    void testAuthorize_WithZMSCheck_Granted() {
        // Given
        authorizerService.zmsResourceAuthorization = true;

        String subject = "test-subject";
        String scopes = "read write";
        String resource = "api-resource";
        String provider = "okta";

        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read", "write"), "domain1", provider, "as1", false, null
        );

        TokenWrapper token = new TokenWrapper(
                "user.testuser", provider, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        Access access = mock(Access.class);
        when(access.getGranted()).thenReturn(true);

        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(tokenStore.getUserToken(subject, provider)).thenReturn(token);
        when(zmsClient.getAccessExt(
                eq("mcp.access"),
                eq("athenz.examples.agentic-ai:api-resource"),
                isNull(),
                eq("user.testuser")
        )).thenReturn(access);

        // When
        AuthorizationResultDO result = authorizerService.authorize(subject, scopes, resource);

        // Then
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(token, result.token());
        verify(zmsClient).getAccessExt(
                eq("mcp.access"),
                eq("athenz.examples.agentic-ai:api-resource"),
                isNull(),
                eq("user.testuser")
        );
    }

    @Test
    void testAuthorize_WithZMSCheck_Denied() {
        // Given
        authorizerService.zmsResourceAuthorization = true;

        String subject = "test-subject";
        String scopes = "read write";
        String resource = "api-resource";
        String provider = "okta";

        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read", "write"), "domain1", provider, "as1", false, null
        );

        TokenWrapper token = new TokenWrapper(
                "user.testuser", provider, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        Access access = mock(Access.class);
        when(access.getGranted()).thenReturn(false);

        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(tokenStore.getUserToken(subject, provider)).thenReturn(token);
        when(zmsClient.getAccessExt(
                eq("mcp.access"),
                eq("athenz.examples.agentic-ai:api-resource"),
                isNull(),
                eq("user.testuser")
        )).thenReturn(access);

        // When
        AuthorizationResultDO result = authorizerService.authorize(subject, scopes, resource);

        // Then
        assertNotNull(result);
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        assertNull(result.token());
    }

    @Test
    void testGetTokenFromAuthorizationServer_NoResourceMeta() {
        // Given
        String subject = "test-subject";
        String scopes = "read write";
        String resource = "https://api.example.com";
        TokenWrapper token = new TokenWrapper(
                "user.testuser", "okta", "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        when(configService.getResourceMeta(resource)).thenReturn(null);

        // When
        TokenResponse result = authorizerService.getTokenFromAuthorizationServer(subject, scopes, resource, token);

        // Then
        assertNull(result);
    }

    @Test
    void testGetTokenFromAuthorizationServer_WithoutJAG() {
        // Given
        String subject = "test-subject";
        String scopes = "read write";
        String resource = "https://api.example.com";
        String authServer = "auth-server";
        String remoteEndpoint = "https://auth.example.com/token";

        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read", "write"), "domain1", "okta", authServer, false, null
        );

        TokenWrapper inputToken = new TokenWrapper(
                "user.testuser", "okta", "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        long expectedTtl = Instant.now().getEpochSecond() + 600;
        TokenWrapper resultToken = new TokenWrapper(
                "user.testuser", "okta", null, "new-access-token", null,
                expectedTtl
        );

        AuthorizationResultDO authResultDO = new AuthorizationResultDO(AuthResult.AUTHORIZED, resultToken);

        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint(authServer)).thenReturn(remoteEndpoint);
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(authServer))
                .thenReturn(tokenExchangeService);
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class)))
                .thenReturn(authResultDO);

        // When
        TokenResponse result = authorizerService.getTokenFromAuthorizationServer(subject, scopes, resource, inputToken);

        // Then
        assertNotNull(result);
        assertEquals("new-access-token", result.accessToken());
        assertEquals("Bearer", result.tokenType());
        // The service returns TTL as absolute timestamp in expiresIn field
        assertEquals(expectedTtl, result.expiresIn());
        assertEquals("[read, write]", result.scope());

        verify(tokenExchangeService).getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class));
        verify(tokenExchangeService, never()).getJWTAuthorizationGrantFromIdentityProvider(any());
    }

    @Test
    void testGetTokenFromAuthorizationServer_WithJAG() {
        // Given
        String subject = "test-subject";
        String scopes = "read write";
        String resource = "https://api.example.com";
        String authServer = "auth-server";
        String jagIssuer = "jag-issuer";
        String authServerEndpoint = "https://auth.example.com/token";
        String jagEndpoint = "https://jag.example.com/token";

        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read", "write"), "domain1", "okta", authServer, true, jagIssuer
        );

        TokenWrapper inputToken = new TokenWrapper(
                "user.testuser", "okta", "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        long expectedJagTtl = Instant.now().getEpochSecond() + 400;
        TokenWrapper jagToken = new TokenWrapper(
                "user.testuser", "okta", null, "jag-token", null,
                expectedJagTtl
        );

        long expectedFinalTtl = Instant.now().getEpochSecond() + 500;
        TokenWrapper finalToken = new TokenWrapper(
                "user.testuser", "okta", null, "final-access-token", null,
                expectedFinalTtl
        );

        AuthorizationResultDO jagResult = new AuthorizationResultDO(AuthResult.AUTHORIZED, jagToken);
        AuthorizationResultDO finalResult = new AuthorizationResultDO(AuthResult.AUTHORIZED, finalToken);

        TokenExchangeService jagTokenExchangeService = mock(TokenExchangeService.class);

        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint(authServer)).thenReturn(authServerEndpoint);
        when(configService.getRemoteServerEndpoint(jagIssuer)).thenReturn(jagEndpoint);
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(authServer))
                .thenReturn(tokenExchangeService);
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(jagIssuer))
                .thenReturn(jagTokenExchangeService);
        when(jagTokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(any(TokenExchangeDO.class)))
                .thenReturn(jagResult);
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class)))
                .thenReturn(finalResult);

        // When
        TokenResponse result = authorizerService.getTokenFromAuthorizationServer(subject, scopes, resource, inputToken);

        // Then
        assertNotNull(result);
        assertEquals("final-access-token", result.accessToken());
        assertEquals("Bearer", result.tokenType());
        // The service returns TTL as absolute timestamp in expiresIn field
        assertEquals(expectedFinalTtl, result.expiresIn());
        assertEquals("[read, write]", result.scope());

        verify(jagTokenExchangeService).getJWTAuthorizationGrantFromIdentityProvider(any(TokenExchangeDO.class));
        verify(tokenExchangeService).getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class));
    }

    @Test
    void testGetTokenFromAuthorizationServer_WithJAG_VerifyTokenExchangeDOParameters() {
        // Given
        String subject = "test-subject";
        String scopes = "read write";
        String resource = "https://api.example.com";
        String authServer = "auth-server";
        String jagIssuer = "jag-issuer";
        String authServerEndpoint = "https://auth.example.com/token";
        String jagEndpoint = "https://jag.example.com/token";

        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("custom-scope-1", "custom-scope-2"), "test-domain", "okta", authServer, true, jagIssuer
        );

        TokenWrapper inputToken = new TokenWrapper(
                "user.testuser", "okta", "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        TokenWrapper jagToken = new TokenWrapper(
                "user.testuser", "okta", null, "jag-token", null,
                Instant.now().getEpochSecond() + 400
        );

        TokenWrapper finalToken = new TokenWrapper(
                "user.testuser", "okta", null, "final-access-token", null,
                Instant.now().getEpochSecond() + 500
        );

        AuthorizationResultDO jagResult = new AuthorizationResultDO(AuthResult.AUTHORIZED, jagToken);
        AuthorizationResultDO finalResult = new AuthorizationResultDO(AuthResult.AUTHORIZED, finalToken);

        TokenExchangeService jagTokenExchangeService = mock(TokenExchangeService.class);

        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint(authServer)).thenReturn(authServerEndpoint);
        when(configService.getRemoteServerEndpoint(jagIssuer)).thenReturn(jagEndpoint);
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(authServer))
                .thenReturn(tokenExchangeService);
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(jagIssuer))
                .thenReturn(jagTokenExchangeService);
        when(jagTokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(any(TokenExchangeDO.class)))
                .thenReturn(jagResult);
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class)))
                .thenReturn(finalResult);

        // When
        authorizerService.getTokenFromAuthorizationServer(subject, scopes, resource, inputToken);

        // Then - Verify JAG token request parameters
        ArgumentCaptor<TokenExchangeDO> jagCaptor = ArgumentCaptor.forClass(TokenExchangeDO.class);
        verify(jagTokenExchangeService).getJWTAuthorizationGrantFromIdentityProvider(jagCaptor.capture());

        TokenExchangeDO jagRequest = jagCaptor.getValue();
        assertEquals(Arrays.asList("custom-scope-1", "custom-scope-2"), jagRequest.scopes());
        assertEquals(resource, jagRequest.resource());
        assertEquals("test-domain", jagRequest.namespace());
        assertEquals(jagEndpoint, jagRequest.remoteServer());
        assertEquals(inputToken, jagRequest.tokenWrapper());

        // Then - Verify access token request parameters
        ArgumentCaptor<TokenExchangeDO> atCaptor = ArgumentCaptor.forClass(TokenExchangeDO.class);
        verify(tokenExchangeService).getAccessTokenFromResourceAuthorizationServer(atCaptor.capture());

        TokenExchangeDO atRequest = atCaptor.getValue();
        assertEquals(Arrays.asList("custom-scope-1", "custom-scope-2"), atRequest.scopes());
        assertEquals(resource, atRequest.resource());
        assertEquals("test-domain", atRequest.namespace());
        assertEquals(authServerEndpoint, atRequest.remoteServer());
        assertEquals(jagToken, atRequest.tokenWrapper());
    }

    @Test
    void testGetTokenFromAuthorizationServer_WithoutJAG_VerifyTokenExchangeDOParameters() {
        // Given
        String subject = "test-subject";
        String scopes = "read write";
        String resource = "https://api.example.com";
        String authServer = "auth-server";
        String remoteEndpoint = "https://auth.example.com/token";

        ResourceMeta resourceMeta = new ResourceMeta(
                Collections.singletonList("admin"), "admin-domain", "okta", authServer, false, null
        );

        TokenWrapper inputToken = new TokenWrapper(
                "user.admin", "okta", "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        TokenWrapper resultToken = new TokenWrapper(
                "user.admin", "okta", null, "new-access-token", null,
                Instant.now().getEpochSecond() + 600
        );

        AuthorizationResultDO authResultDO = new AuthorizationResultDO(AuthResult.AUTHORIZED, resultToken);

        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint(authServer)).thenReturn(remoteEndpoint);
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(authServer))
                .thenReturn(tokenExchangeService);
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class)))
                .thenReturn(authResultDO);

        // When
        authorizerService.getTokenFromAuthorizationServer(subject, scopes, resource, inputToken);

        // Then - Verify access token request parameters
        ArgumentCaptor<TokenExchangeDO> captor = ArgumentCaptor.forClass(TokenExchangeDO.class);
        verify(tokenExchangeService).getAccessTokenFromResourceAuthorizationServer(captor.capture());

        TokenExchangeDO request = captor.getValue();
        assertEquals(Collections.singletonList("admin"), request.scopes());
        assertEquals(resource, request.resource());
        assertEquals("admin-domain", request.namespace());
        assertEquals(remoteEndpoint, request.remoteServer());
        assertEquals(inputToken, request.tokenWrapper());
    }
}
