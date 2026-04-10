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
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
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
        String provider = AudienceConstants.PROVIDER_OKTA;
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
        String provider = AudienceConstants.PROVIDER_OKTA;
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
        String provider = AudienceConstants.PROVIDER_OKTA;

        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read", "write"), "domain1", provider, "as1", false, null,""
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
        String provider = AudienceConstants.PROVIDER_OKTA;

        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read", "write"), "domain1", provider, "as1", false, null, ""
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
        String provider = AudienceConstants.PROVIDER_OKTA;

        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read", "write"), "domain1", provider, "as1", false, null, ""
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
        String provider = AudienceConstants.PROVIDER_OKTA;

        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read", "write"), "domain1", provider, "as1", false, null, ""
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
                "user.testuser", AudienceConstants.PROVIDER_OKTA, "id-token", "access-token", "refresh-token",
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
                Arrays.asList("read", "write"), "domain1", AudienceConstants.PROVIDER_OKTA, authServer, false, null, ""
        );

        TokenWrapper inputToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        long expectedTtl = Instant.now().getEpochSecond() + 600;
        TokenWrapper resultToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, null, "new-access-token", null,
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
    void testGetTokenFromAuthorizationServer_SplunkAudience_storesExchangedTokenForUserinfo() {
        String subject = "test-subject";
        String scopes = "read";
        String resource = "https://mcp-gateway.test/v1/splunk/mcp";
        String authServer = "splunk";
        String remoteEndpoint = "https://splunk-mgmt.test:8089";

        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read"), "domain1", AudienceConstants.PROVIDER_OKTA, authServer, false, null,
                AudienceConstants.PROVIDER_SPLUNK);

        TokenWrapper inputToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300);

        long tokenTtl = 3600L;
        TokenWrapper exchanged = new TokenWrapper(
                null, null, null, "splunk-exchanged-access-token", null, tokenTtl);
        AuthorizationResultDO authResultDO = new AuthorizationResultDO(AuthResult.AUTHORIZED, exchanged);

        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint(authServer)).thenReturn(remoteEndpoint);
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(authServer)).thenReturn(tokenExchangeService);
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class)))
                .thenReturn(authResultDO);

        TokenResponse result = authorizerService.getTokenFromAuthorizationServer(subject, scopes, resource, inputToken);

        assertNotNull(result);
        assertEquals("splunk-exchanged-access-token", result.accessToken());

        verify(tokenStore).storeUserToken(eq("user.testuser"), eq(AudienceConstants.PROVIDER_SPLUNK), argThat(w ->
                "splunk-exchanged-access-token".equals(w.accessToken())
                        && AudienceConstants.PROVIDER_SPLUNK.equals(w.provider())
                        && "user.testuser".equals(w.key())));
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
                Arrays.asList("read", "write"), "domain1", AudienceConstants.PROVIDER_OKTA, authServer, true, jagIssuer, ""
        );

        TokenWrapper inputToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        long expectedJagTtl = Instant.now().getEpochSecond() + 400;
        TokenWrapper jagToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, null, "jag-token", null,
                expectedJagTtl
        );

        long expectedFinalTtl = Instant.now().getEpochSecond() + 500;
        TokenWrapper finalToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, null, "final-access-token", null,
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
                Arrays.asList("custom-scope-1", "custom-scope-2"), "test-domain", AudienceConstants.PROVIDER_OKTA, authServer, true, jagIssuer, ""
        );

        TokenWrapper inputToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        TokenWrapper jagToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, null, "jag-token", null,
                Instant.now().getEpochSecond() + 400
        );

        TokenWrapper finalToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, null, "final-access-token", null,
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
                Collections.singletonList("admin"), "admin-domain", AudienceConstants.PROVIDER_OKTA, authServer, false, null, ""
        );

        TokenWrapper inputToken = new TokenWrapper(
                "user.admin", AudienceConstants.PROVIDER_OKTA, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        TokenWrapper resultToken = new TokenWrapper(
                "user.admin", AudienceConstants.PROVIDER_OKTA, null, "new-access-token", null,
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

    @Test
    void testRefreshUpstreamAndGetToken_returnsNullWhenUpstreamRefreshTokenNull() {
        RefreshAndTokenResult result = authorizerService.refreshUpstreamAndGetToken("user1", AudienceConstants.PROVIDER_OKTA, "https://resource.example.com", null);
        assertNull(result);
    }

    @Test
    void testRefreshUpstreamAndGetToken_returnsNullWhenUpstreamRefreshTokenEmpty() {
        RefreshAndTokenResult result = authorizerService.refreshUpstreamAndGetToken("user1", AudienceConstants.PROVIDER_OKTA, "https://resource.example.com", "");
        assertNull(result);
    }

    @Test
    void testRefreshUpstreamAndGetToken_returnsNullWhenExchangeReturnsNull() {
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_OKTA)).thenReturn(tokenExchangeService);
        when(tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token")).thenReturn(null);

        RefreshAndTokenResult result = authorizerService.refreshUpstreamAndGetToken("user1", AudienceConstants.PROVIDER_OKTA, "https://resource.example.com", "upstream-refresh-token");

        assertNull(result);
    }

    @Test
    void testRefreshUpstreamAndGetToken_success_returnsRefreshAndTokenResultWithNewUpstreamRefresh() {
        String resource = "https://resource.example.com";
        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read"), "domain1", AudienceConstants.PROVIDER_OKTA, AudienceConstants.PROVIDER_OKTA, false, null, ""
        );
        TokenWrapper newToken = new TokenWrapper(
                "user1", AudienceConstants.PROVIDER_OKTA, "new-id-token", "new-access-token", "new-upstream-refresh",
                Instant.now().getEpochSecond() + 3600
        );
        TokenWrapper exchangedToken = new TokenWrapper(
                null, null, null, "exchanged-access-token", null, 3600L
        );
        AuthorizationResultDO atDO = new AuthorizationResultDO(AuthResult.AUTHORIZED, exchangedToken);

        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_OKTA)).thenReturn(tokenExchangeService);
        when(tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token")).thenReturn(newToken);
        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint(AudienceConstants.PROVIDER_OKTA)).thenReturn("https://okta.example.com");
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_OKTA)).thenReturn(tokenExchangeService);
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class))).thenReturn(atDO);

        RefreshAndTokenResult result = authorizerService.refreshUpstreamAndGetToken("user1", AudienceConstants.PROVIDER_OKTA, resource, "upstream-refresh-token");

        assertNotNull(result);
        assertNotNull(result.tokenResponse());
        assertEquals("exchanged-access-token", result.tokenResponse().accessToken());
        assertEquals("new-upstream-refresh", result.newUpstreamRefreshToken());
        // Two stores: upstream token, then storeRefreshedAccessToken (non-Glean)
        verify(tokenStore, times(2)).storeUserToken(eq("user1"), eq(AudienceConstants.PROVIDER_OKTA), any(TokenWrapper.class));
    }

    @Test
    void testRefreshUpstreamAndGetToken_storeRefreshedAccessToken_Glean_storesExchangedTokenUnderGlean() {
        String resource = "https://glean.resource.example.com";
        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read"), "domain1", AudienceConstants.PROVIDER_OKTA, AudienceConstants.PROVIDER_OKTA, false, null, "glean"
        );
        long tokenTtl = 3600L;
        TokenWrapper newToken = new TokenWrapper(
                "user1", AudienceConstants.PROVIDER_OKTA, "new-id-token", "new-access-token", "new-upstream-refresh",
                Instant.now().getEpochSecond() + tokenTtl
        );
        TokenWrapper exchangedToken = new TokenWrapper(
                null, null, null, "glean-exchanged-access-token", null, tokenTtl
        );
        AuthorizationResultDO atDO = new AuthorizationResultDO(AuthResult.AUTHORIZED, exchangedToken);

        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_OKTA)).thenReturn(tokenExchangeService);
        when(tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token")).thenReturn(newToken);
        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint(AudienceConstants.PROVIDER_OKTA)).thenReturn("https://okta.example.com");
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class))).thenReturn(atDO);

        authorizerService.refreshUpstreamAndGetToken("user1", AudienceConstants.PROVIDER_OKTA, resource, "upstream-refresh-token");

        ArgumentCaptor<String> userCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> providerCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<TokenWrapper> tokenCaptor = ArgumentCaptor.forClass(TokenWrapper.class);
        verify(tokenStore, times(2)).storeUserToken(userCaptor.capture(), providerCaptor.capture(), tokenCaptor.capture());

        // Second call is from storeRefreshedAccessToken for Glean
        assertEquals("user1", userCaptor.getAllValues().get(1));
        assertEquals("glean", providerCaptor.getAllValues().get(1));
        TokenWrapper storedForUserinfo = tokenCaptor.getAllValues().get(1);
        assertEquals("user1", storedForUserinfo.key());
        assertEquals("glean", storedForUserinfo.provider());
        assertNull(storedForUserinfo.idToken());
        assertEquals("glean-exchanged-access-token", storedForUserinfo.accessToken());
        assertNull(storedForUserinfo.refreshToken());
        // TTL = now + tokenTtl + 300 (grace)
        long expectedMinTtl = Instant.now().getEpochSecond() + tokenTtl + 300L;
        assertTrue(storedForUserinfo.ttl() >= expectedMinTtl - 2, "stored TTL should be token expiry + 5 min grace");
    }

    @Test
    void testRefreshUpstreamAndGetToken_storeRefreshedAccessToken_Splunk_storesExchangedTokenUnderSplunk() {
        String resource = "https://mcp-gateway.test/v1/splunk/mcp";
        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read"), "domain1", AudienceConstants.PROVIDER_OKTA, "splunk", false, null,
                AudienceConstants.PROVIDER_SPLUNK
        );
        long tokenTtl = 3600L;
        TokenWrapper newToken = new TokenWrapper(
                "user1", AudienceConstants.PROVIDER_OKTA, "new-id-token", "new-access-token", "new-upstream-refresh",
                Instant.now().getEpochSecond() + tokenTtl
        );
        TokenWrapper exchangedToken = new TokenWrapper(
                null, null, null, "splunk-exchanged-access-token", null, tokenTtl
        );
        AuthorizationResultDO atDO = new AuthorizationResultDO(AuthResult.AUTHORIZED, exchangedToken);

        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_OKTA)).thenReturn(tokenExchangeService);
        when(tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token")).thenReturn(newToken);
        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint("splunk")).thenReturn("https://splunk-mgmt.test:8089");
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("splunk")).thenReturn(tokenExchangeService);
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class))).thenReturn(atDO);

        authorizerService.refreshUpstreamAndGetToken("user1", AudienceConstants.PROVIDER_OKTA, resource, "upstream-refresh-token");

        ArgumentCaptor<String> userCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> providerCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<TokenWrapper> tokenCaptor = ArgumentCaptor.forClass(TokenWrapper.class);
        verify(tokenStore, times(2)).storeUserToken(userCaptor.capture(), providerCaptor.capture(), tokenCaptor.capture());

        assertEquals("user1", userCaptor.getAllValues().get(1));
        assertEquals(AudienceConstants.PROVIDER_SPLUNK, providerCaptor.getAllValues().get(1));
        TokenWrapper storedForUserinfo = tokenCaptor.getAllValues().get(1);
        assertEquals("splunk-exchanged-access-token", storedForUserinfo.accessToken());
    }

    @Test
    void testRefreshUpstreamAndGetToken_storeRefreshedAccessToken_NonGlean_storesUnderUpstreamProvider() {
        String resource = "https://api.github.com";
        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read"), "domain1", "github", "github", false, null, ""
        );
        // Relative TTL (seconds) as returned by upstream; code converts to absolute and adds grace
        TokenWrapper newToken = new TokenWrapper(
                "user2", "github", "github-id-token", "github-access-token", "github-refresh",
                3600L
        );
        // For GitHub, exchange returns same token (request's tokenWrapper)
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("github")).thenReturn(tokenExchangeService);
        when(tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token")).thenReturn(newToken);
        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint("github")).thenReturn("https://github.com");
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class)))
                .thenAnswer(inv -> new AuthorizationResultDO(AuthResult.AUTHORIZED, inv.getArgument(0, TokenExchangeDO.class).tokenWrapper()));

        authorizerService.refreshUpstreamAndGetToken("user2", "github", resource, "upstream-refresh-token");

        ArgumentCaptor<String> userCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> providerCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<TokenWrapper> tokenCaptor = ArgumentCaptor.forClass(TokenWrapper.class);
        verify(tokenStore, times(2)).storeUserToken(userCaptor.capture(), providerCaptor.capture(), tokenCaptor.capture());

        // Second call is from storeRefreshedAccessToken (non-Glean): same provider, returned token stored for /userinfo
        assertEquals("user2", userCaptor.getAllValues().get(1));
        assertEquals("github", providerCaptor.getAllValues().get(1));
        TokenWrapper storedForUserinfo = tokenCaptor.getAllValues().get(1);
        assertEquals("user2", storedForUserinfo.key());
        assertEquals("github", storedForUserinfo.provider());
        assertEquals("github-id-token", storedForUserinfo.idToken());
        assertEquals("github-access-token", storedForUserinfo.accessToken());
        assertEquals("github-refresh", storedForUserinfo.refreshToken());
        // TTL is same as first stored token (absolute, with grace already applied in first store)
        assertEquals(tokenCaptor.getAllValues().get(0).ttl(), storedForUserinfo.ttl());
    }

    @Test
    void testRefreshUpstreamAndGetToken_returnsNullWhenTokenExchangeFails() {
        String resource = "https://resource.example.com";
        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read"), "domain1", AudienceConstants.PROVIDER_OKTA, AudienceConstants.PROVIDER_OKTA, false, null, ""
        );
        TokenWrapper newToken = new TokenWrapper(
                "user1", AudienceConstants.PROVIDER_OKTA, "id", "access", "refresh", Instant.now().getEpochSecond() + 3600
        );

        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_OKTA)).thenReturn(tokenExchangeService);
        when(tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token")).thenReturn(newToken);
        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint(AudienceConstants.PROVIDER_OKTA)).thenReturn("https://okta.example.com");
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class)))
                .thenReturn(new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null));

        RefreshAndTokenResult result = authorizerService.refreshUpstreamAndGetToken("user1", AudienceConstants.PROVIDER_OKTA, resource, "upstream-refresh-token");

        assertNull(result);
    }

    @Test
    void testCompleteRefreshWithOktaTokens_success_returnsResultWithNullNewUpstream() {
        String resource = "https://resource.example.com";
        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read"), "domain1", AudienceConstants.PROVIDER_OKTA, AudienceConstants.PROVIDER_OKTA, false, null, ""
        );
        TokenWrapper exchangedToken = new TokenWrapper(
                null, null, null, "exchanged-access-token", null, 3600L
        );
        AuthorizationResultDO atDO = new AuthorizationResultDO(AuthResult.AUTHORIZED, exchangedToken);
        OktaTokens oktaTokens = new OktaTokens("new-access", "new-refresh", "new-id", 3600);

        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint(AudienceConstants.PROVIDER_OKTA)).thenReturn("https://okta.example.com");
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_OKTA)).thenReturn(tokenExchangeService);
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class))).thenReturn(atDO);

        RefreshAndTokenResult result = authorizerService.completeRefreshWithOktaTokens("user1", AudienceConstants.PROVIDER_OKTA, resource, oktaTokens);

        assertNotNull(result);
        assertEquals("exchanged-access-token", result.tokenResponse().accessToken());
        assertNull(result.newUpstreamRefreshToken());
        verify(tokenStore, times(2)).storeUserToken(eq("user1"), eq(AudienceConstants.PROVIDER_OKTA), any(TokenWrapper.class));
    }
}
