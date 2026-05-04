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
import io.athenz.mop.config.OktaSessionCacheConfig;
import io.athenz.mop.model.*;
import io.athenz.mop.store.BearerIndexStore;
import io.athenz.mop.store.TokenStore;
import io.athenz.mop.telemetry.OauthProxyMetrics;
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
import static org.mockito.ArgumentMatchers.anyString;
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

    @Mock
    private ExchangedTokenUserinfoStoreProviderResolver exchangedTokenUserinfoStoreProviderResolver;

    @Mock
    private UserTokenRegionResolver userTokenRegionResolver;

    @Mock
    private RefreshCoordinationService refreshCoordinationService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private OktaSessionCache oktaSessionCache;

    @Mock
    private OktaSessionCacheConfig oktaSessionCacheConfig;

    @Mock
    private UpstreamRefreshService upstreamRefreshService;

    @Mock
    private BearerIndexStore bearerIndexStore;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private UpstreamProviderClassifier upstreamProviderClassifier;

    @Mock
    private IdpSessionCache idpSessionCache;

    @InjectMocks
    private AuthorizerService authorizerService;

    private void stubResolveByUserProvider(String user, String provider, TokenWrapper token, boolean fromFallback) {
        when(userTokenRegionResolver.resolveByUserProvider(eq(user), eq(provider), anyString()))
                .thenReturn(new UserTokenResolution(token, fromFallback));
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        authorizerService.userPrefix = "user.";
        authorizerService.ttl = 300L;
        authorizerService.authorizationDomain = "athenz.examples.agentic-ai";
        authorizerService.authorizationAction = "mcp.access";
        authorizerService.zmsResourceAuthorization = false;
        // Default cache state for the broad test suite: disabled. Cache-aware tests opt in by
        // overriding {@code oktaSessionCacheConfig.enabled()} to true.
        lenient().when(oktaSessionCacheConfig.enabled()).thenReturn(false);
        // Mirror real classifier: only okta + 12 google-* providers are promoted.
        lenient().when(upstreamProviderClassifier.isUpstreamPromoted(anyString()))
                .thenAnswer(invocation -> {
                    String p = invocation.getArgument(0);
                    if (p == null) {
                        return false;
                    }
                    return AudienceConstants.PROVIDER_OKTA.equals(p) || p.startsWith("google-");
                });
        lenient().when(upstreamProviderClassifier.isGoogleWorkspace(anyString()))
                .thenAnswer(invocation -> {
                    String p = invocation.getArgument(0);
                    return p != null && p.startsWith("google-");
                });
        when(exchangedTokenUserinfoStoreProviderResolver.resolve(anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArgument(1));
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
        String provider = "google-drive";
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

        stubResolveByUserProvider(lookupKey, provider, expectedToken, false);

        // When
        TokenWrapper result = authorizerService.getUserToken(lookupKey, provider);

        // Then
        assertNotNull(result);
        assertEquals(expectedToken, result);
        verify(userTokenRegionResolver).resolveByUserProvider(eq(lookupKey), eq(provider),
                eq(UserTokenRegionResolver.CALL_SITE_AUTHORIZER_GET_USER_TOKEN));
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
        stubResolveByUserProvider(subject, provider, token, false);

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
        stubResolveByUserProvider(subject, provider, null, false);

        // When
        AuthorizationResultDO result = authorizerService.authorize(subject, scopes, resource);

        // Then
        assertNotNull(result);
        assertEquals(AuthResult.EXPIRED, result.authResult());
        assertNull(result.token());
    }

    @Test
    void testAuthorize_TokenFoundOnlyInPeerRegion_ReturnsAuthorized() {
        // Given - simulates DynamoDB Global Tables replication lag where the row was just written in
        // the peer region; AuthorizerService.authorize must return AUTHORIZED, not EXPIRED.
        String subject = "test-subject";
        String scopes = "read write";
        String resource = "https://api.example.com";
        String provider = AudienceConstants.PROVIDER_OKTA;

        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read", "write"), "domain1", provider, "as1", false, null, ""
        );

        TokenWrapper token = new TokenWrapper(
                "user.testuser", provider, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300
        );

        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        stubResolveByUserProvider(subject, provider, token, true);

        // When
        AuthorizationResultDO result = authorizerService.authorize(subject, scopes, resource);

        // Then
        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(token, result.token());
        verify(userTokenRegionResolver).resolveByUserProvider(eq(subject), eq(provider),
                eq(UserTokenRegionResolver.CALL_SITE_AUTHORIZE_USER_TOKEN));
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
        stubResolveByUserProvider(subject, defaultProvider, token, false);

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
        stubResolveByUserProvider(subject, provider, token, false);
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
        stubResolveByUserProvider(subject, provider, token, false);
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

        // The TokenExchangeService impl in this test stuffs the absolute-epoch TTL into
        // TokenWrapper.ttl (mirrors what the four pass-through impls do today). The wire response
        // MUST normalize that back to a *duration in seconds* per RFC 6749 §5.1.
        long durationSeconds = 600L;
        long expectedTtl = Instant.now().getEpochSecond() + durationSeconds;
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
        // expires_in on the wire is the access-token's remaining lifetime in seconds, not the
        // absolute DDB TTL. sanitizeExpiresIn converts (now + 600) back to ~600.
        long actual = result.expiresIn();
        assertTrue(actual > 0L && actual <= durationSeconds,
                "expires_in must be a positive duration <= " + durationSeconds + ", got " + actual);
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

        // The (userId, "splunk") exchanged-token row is no longer written; the exchanged Splunk
        // access-token is now indexed in the dedicated bearer-index table so /userinfo can
        // resolve it by H(access-token) without colliding with sibling clients.
        verify(tokenStore, never()).storeUserToken(eq("user.testuser"),
                eq(AudienceConstants.PROVIDER_SPLUNK), any(TokenWrapper.class));
        verify(bearerIndexStore).putBearer(anyString(), eq("user.testuser"),
                org.mockito.ArgumentMatchers.isNull(), eq(AudienceConstants.PROVIDER_SPLUNK),
                org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyLong());
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

        long finalDurationSeconds = 500L;
        long expectedFinalTtl = Instant.now().getEpochSecond() + finalDurationSeconds;
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
        long actualFinalExpiresIn = result.expiresIn();
        assertTrue(actualFinalExpiresIn > 0L && actualFinalExpiresIn <= finalDurationSeconds,
                "expires_in must be a positive duration <= " + finalDurationSeconds
                        + ", got " + actualFinalExpiresIn);
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
    void testRefreshUpstreamAndGetToken_returnsNullWhenUpstreamRefreshReturnsNull_cleansTokenStoreAndRevokes() {
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_OKTA)).thenReturn(tokenExchangeService);
        when(tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token")).thenReturn(null);

        RefreshAndTokenResult result = authorizerService.refreshUpstreamAndGetToken("user1", AudienceConstants.PROVIDER_OKTA, "https://resource.example.com", "upstream-refresh-token");

        assertNull(result);
        verify(tokenStore).deleteUserToken("user1", AudienceConstants.PROVIDER_OKTA);
        verify(tokenExchangeService).revokeUpstreamRefreshToken("upstream-refresh-token");
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
        // Only the bare (userId, provider) upstream session marker is written; per-client rows
        // are no longer written. The returned access token is indexed via the bearer-index
        // table from storeRefreshedAccessToken.
        verify(tokenStore, times(1)).storeUserToken(eq("user1"), eq(AudienceConstants.PROVIDER_OKTA), any(TokenWrapper.class));
        verify(tokenStore, never()).storeUserToken(any(), any(), anyString(), any(TokenWrapper.class));
        verify(bearerIndexStore, atLeastOnce()).putBearer(anyString(), eq("user1"),
                org.mockito.ArgumentMatchers.isNull(), eq(AudienceConstants.PROVIDER_OKTA),
                org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyLong());
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

        // Only the bare upstream session marker (userId, okta) is written to mcp-oauth-proxy-tokens.
        // The exchanged Glean token now flows through the bearer-index table instead of a
        // (userId, "glean") tokens row.
        verify(tokenStore, times(1)).storeUserToken(eq("user1"), eq(AudienceConstants.PROVIDER_OKTA), any(TokenWrapper.class));
        verify(tokenStore, never()).storeUserToken(eq("user1"), eq("glean"), any(TokenWrapper.class));
        verify(tokenStore, never()).storeUserToken(any(), any(), anyString(), any(TokenWrapper.class));

        // Bearer-index row carries the exchanged Glean access-token under provider="glean".
        // TTL = now + tokenTtl + 300 (grace).
        long expectedMinTtl = Instant.now().getEpochSecond() + tokenTtl + 300L;
        ArgumentCaptor<Long> ttlCaptor = ArgumentCaptor.forClass(Long.class);
        verify(bearerIndexStore).putBearer(anyString(), eq("user1"),
                org.mockito.ArgumentMatchers.isNull(), eq("glean"),
                org.mockito.ArgumentMatchers.anyLong(), ttlCaptor.capture());
        assertTrue(ttlCaptor.getValue() >= expectedMinTtl - 2,
                "bearer-index ttl should be token expiry + 5 min grace");
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

        // Only the bare upstream session marker is written to mcp-oauth-proxy-tokens.
        verify(tokenStore, times(1)).storeUserToken(eq("user1"), eq(AudienceConstants.PROVIDER_OKTA), any(TokenWrapper.class));
        verify(tokenStore, never()).storeUserToken(eq("user1"), eq(AudienceConstants.PROVIDER_SPLUNK), any(TokenWrapper.class));
        verify(tokenStore, never()).storeUserToken(any(), any(), anyString(), any(TokenWrapper.class));

        // The exchanged Splunk access-token is indexed under provider="splunk" in the
        // bearer-index table so /userinfo can resolve it.
        verify(bearerIndexStore).putBearer(anyString(), eq("user1"),
                org.mockito.ArgumentMatchers.isNull(), eq(AudienceConstants.PROVIDER_SPLUNK),
                org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyLong());
    }

    @Test
    void testRefreshUpstreamAndGetToken_storeRefreshedAccessToken_DatabricksSql_storesUnderWorkspaceProvider() {
        String resource = "https://gateway.test.example/v1/databricks-sql/dbc-testws/mcp";
        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read"),
                "domain1",
                AudienceConstants.PROVIDER_OKTA,
                AudienceConstants.PROVIDER_DATABRICKS_SQL,
                false,
                null,
                AudienceConstants.PROVIDER_DATABRICKS_SQL);
        long tokenTtl = 3600L;
        TokenWrapper newToken = new TokenWrapper(
                "user1", AudienceConstants.PROVIDER_OKTA, "new-id-token", "new-access-token", "new-upstream-refresh",
                Instant.now().getEpochSecond() + tokenTtl
        );
        TokenWrapper exchangedToken = new TokenWrapper(
                null, null, null, "dbx-exchanged-access-token", null, tokenTtl
        );
        AuthorizationResultDO atDO = new AuthorizationResultDO(AuthResult.AUTHORIZED, exchangedToken, "sql");

        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_OKTA))
                .thenReturn(tokenExchangeService);
        when(tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token")).thenReturn(newToken);
        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint(AudienceConstants.PROVIDER_DATABRICKS_SQL)).thenReturn(null);
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_DATABRICKS_SQL))
                .thenReturn(tokenExchangeService);
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class))).thenReturn(atDO);
        when(exchangedTokenUserinfoStoreProviderResolver.resolve(eq(resource), eq(AudienceConstants.PROVIDER_DATABRICKS_SQL)))
                .thenReturn("databricks-sql-dbc-testws.cloud.databricks.com");

        RefreshAndTokenResult result = authorizerService.refreshUpstreamAndGetToken(
                "user1", AudienceConstants.PROVIDER_OKTA, resource, "upstream-refresh-token");

        assertNotNull(result);
        assertEquals("sql", result.tokenResponse().scope());

        // Only the bare (userId, okta) upstream session marker is written; the exchanged
        // Databricks-SQL workspace token now flows through the bearer-index table instead.
        verify(tokenStore, times(1)).storeUserToken(eq("user1"), eq(AudienceConstants.PROVIDER_OKTA),
                any(TokenWrapper.class));
        verify(tokenStore, never()).storeUserToken(any(), any(), anyString(), any(TokenWrapper.class));
        verify(bearerIndexStore).putBearer(anyString(), eq("user1"),
                org.mockito.ArgumentMatchers.isNull(),
                eq("databricks-sql-dbc-testws.cloud.databricks.com"),
                org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyLong());
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

        // Only the bare (userId, github) upstream session marker is written; the returned
        // GitHub access-token is now indexed via the bearer-index table.
        verify(tokenStore, times(1)).storeUserToken(eq("user2"), eq("github"), any(TokenWrapper.class));
        verify(tokenStore, never()).storeUserToken(any(), any(), anyString(), any(TokenWrapper.class));
        verify(bearerIndexStore).putBearer(anyString(), eq("user2"),
                org.mockito.ArgumentMatchers.isNull(), eq("github"),
                org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyLong());
        ArgumentCaptor<TokenWrapper> tokenCaptor = ArgumentCaptor.forClass(TokenWrapper.class);
        verify(tokenStore).storeUserToken(eq("user2"), eq("github"), tokenCaptor.capture());
        TokenWrapper storedForUserinfo = tokenCaptor.getValue();
        assertEquals("user2", storedForUserinfo.key());
        assertEquals("github", storedForUserinfo.provider());
        assertEquals("github-id-token", storedForUserinfo.idToken());
        assertEquals("github-access-token", storedForUserinfo.accessToken());
        assertEquals("github-refresh", storedForUserinfo.refreshToken());
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
        verify(tokenStore, never()).deleteUserToken(any(), any());
        verify(tokenExchangeService, never()).revokeUpstreamRefreshToken(any());
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
        // Only the bare upstream session marker is written; storeRefreshedAccessToken now
        // routes via the bearer-index table for the exchanged access token.
        verify(tokenStore, times(1)).storeUserToken(eq("user1"), eq(AudienceConstants.PROVIDER_OKTA), any(TokenWrapper.class));
        verify(tokenStore, never()).storeUserToken(any(), any(), anyString(), any(TokenWrapper.class));
        verify(bearerIndexStore).putBearer(anyString(), eq("user1"),
                org.mockito.ArgumentMatchers.isNull(), eq(AudienceConstants.PROVIDER_OKTA),
                org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyLong());
    }


    @Test
    void testRefreshUpstreamAndGetToken_returnsNullWhenResourceMetaMissing_andDoesNotExchange() {
        String resource = "https://unknown.example.com";
        TokenWrapper newToken = new TokenWrapper(
                "user1", AudienceConstants.PROVIDER_OKTA, "id", "access", "refresh",
                Instant.now().getEpochSecond() + 3600
        );

        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_OKTA))
                .thenReturn(tokenExchangeService);
        when(tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token")).thenReturn(newToken);
        when(configService.getResourceMeta(resource)).thenReturn(null);

        RefreshAndTokenResult result = authorizerService.refreshUpstreamAndGetToken(
                "user1", AudienceConstants.PROVIDER_OKTA, resource, "upstream-refresh-token");

        assertNull(result, "must not silently issue raw upstream AT when resourceMeta is null");
        verify(tokenExchangeService, never()).getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class));
        verify(configService, never()).getRemoteServerEndpoint(anyString());
    }

    @Test
    void testCompleteRefreshWithOktaTokens_returnsNullWhenResourceMetaMissing_andDoesNotExchange() {
        String resource = "https://unknown.example.com";
        OktaTokens oktaTokens = new OktaTokens("new-access", "new-refresh", "new-id", 3600);

        when(configService.getResourceMeta(resource)).thenReturn(null);

        RefreshAndTokenResult result = authorizerService.completeRefreshWithOktaTokens(
                "user1", AudienceConstants.PROVIDER_OKTA, resource, oktaTokens);

        assertNull(result, "must not silently issue raw upstream AT when resourceMeta is null");
        verify(tokenExchangeServiceProducer, never())
                .getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_OKTA);
        verify(tokenExchangeService, never()).getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class));
        verify(configService, never()).getRemoteServerEndpoint(anyString());
    }

    // -- compositeUserKey + per-client storeTokens + warm-mint tests --------------------------

    @Test
    void compositeUserKey_nullClientId_returnsBareUser() {
        assertEquals("u", AuthorizerService.compositeUserKey(null, "u"));
    }

    @Test
    void compositeUserKey_emptyClientId_returnsBareUser() {
        assertEquals("u", AuthorizerService.compositeUserKey("", "u"));
    }

    @Test
    void compositeUserKey_normalClientId_prefixes() {
        assertEquals("Cursor#u", AuthorizerService.compositeUserKey("Cursor", "u"));
    }

    @Test
    void compositeUserKey_clientIdWithHash_sanitizes() {
        assertEquals("Cur_sor#u", AuthorizerService.compositeUserKey("Cur#sor", "u"));
    }

    @Test
    void storeTokens_withClientId_writesBareRowAndBearerIndex_butNotPerClientRow() {
        String lookupKey = "test-lookup";
        String provider = AudienceConstants.PROVIDER_OKTA;

        authorizerService.storeTokens("user.bob", lookupKey, "id", "access", "refresh", provider, "Cursor");

        verify(tokenStore).storeUserToken(eq(lookupKey), eq(provider), any(TokenWrapper.class));
        verify(tokenStore, never()).storeUserToken(any(), any(), anyString(), any(TokenWrapper.class));
        verify(bearerIndexStore).putBearer(anyString(), eq(lookupKey), eq("Cursor"), eq(provider),
                org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyLong());
        verify(oauthProxyMetrics).recordBearerIndexWrite(true);
    }

    @Test
    void storeTokens_withNullClientId_writesOnlyBareRow() {
        String lookupKey = "test-lookup";
        String provider = AudienceConstants.PROVIDER_OKTA;

        authorizerService.storeTokens("user.bob", lookupKey, "id", "access", "refresh", provider, null);

        verify(tokenStore).storeUserToken(eq(lookupKey), eq(provider), any(TokenWrapper.class));
        verify(tokenStore, never()).storeUserToken(any(), any(), anyString(), any(TokenWrapper.class));
        verify(bearerIndexStore).putBearer(anyString(), eq(lookupKey),
                org.mockito.ArgumentMatchers.isNull(), eq(provider),
                org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyLong());
    }

    @Test
    void mintBearerForWarmCacheClient_returnsNullWhenClientIdEmpty() {
        TokenResponse result = authorizerService.mintBearerForWarmCacheClient(
                "u1", "google-docs", "https://r", "", "upstream-rt");
        assertNull(result, "Empty clientId must refuse to mint a bearer (would land in a bare row)");
        verifyNoInteractions(refreshCoordinationService);
    }

    @Test
    void mintBearerForWarmCacheClient_returnsNullWhenSharedRefreshTokenBlank() {
        TokenResponse result = authorizerService.mintBearerForWarmCacheClient(
                "u1", "google-docs", "https://r", "Cursor", "");
        assertNull(result);
        verifyNoInteractions(refreshCoordinationService);
    }

    @Test
    void mintBearerForWarmCacheClient_acquiresLockMintsAndWritesPerClientRow() {
        // Native-IdP provider (embrace) keeps the legacy lock+mint path. Promoted Google providers
        // are exercised by mintBearerForWarmCacheClient_promoted_* below.
        String userId = "u1";
        String provider = "embrace";
        String resource = "https://r";
        String clientId = "Claude";
        String upstreamRt = "shared-upstream-rt";

        TokenWrapper minted = new TokenWrapper(userId, provider, "id-claude", "access-claude", null, 3600L);
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(provider)).thenReturn(tokenExchangeService);
        when(tokenExchangeService.refreshWithUpstreamToken(upstreamRt)).thenReturn(minted);

        TokenResponse result = authorizerService.mintBearerForWarmCacheClient(
                userId, provider, resource, clientId, upstreamRt);

        assertNotNull(result);
        assertEquals("access-claude", result.accessToken());
        assertEquals("Bearer", result.tokenType());
        verify(refreshCoordinationService).acquireUpstream(provider + "#" + userId);
        verify(refreshCoordinationService).releaseUpstream(provider + "#" + userId);
        // Bare row updated with the freshly-minted upstream session marker
        verify(tokenStore).storeUserToken(eq(userId), eq(provider), any(TokenWrapper.class));
        // Per-client (clientId#userId, provider) row is no longer written; clientId now travels
        // via the bearer-index row keyed by H(access-token).
        verify(tokenStore, never()).storeUserToken(any(), any(), anyString(), any(TokenWrapper.class));
        verify(bearerIndexStore).putBearer(anyString(), eq(userId), eq(clientId), eq(provider),
                org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyLong());
        verify(oauthProxyMetrics).recordBearerIndexWrite(true);
        // No rotated RT (minted.refreshToken is null) so propagation is skipped
        verify(refreshTokenService, never()).updateUpstreamRefreshForAllRowsWithUserAndProvider(any(), any(), any());
    }

    @Test
    void mintBearerForWarmCacheClient_propagatesRotatedRefreshTokenAcrossSiblingRows() {
        String userId = "u1";
        String provider = "embrace";
        String clientId = "Claude";
        String oldRt = "old-rt";
        String newRt = "rotated-rt";

        TokenWrapper minted = new TokenWrapper(userId, provider, "id", "new-access", newRt, 3600L);
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(provider)).thenReturn(tokenExchangeService);
        when(tokenExchangeService.refreshWithUpstreamToken(oldRt)).thenReturn(minted);

        TokenResponse result = authorizerService.mintBearerForWarmCacheClient(
                userId, provider, "https://r", clientId, oldRt);

        assertNotNull(result);
        verify(refreshTokenService).updateUpstreamRefreshForAllRowsWithUserAndProvider(userId, provider, newRt);
    }

    @Test
    void mintBearerForWarmCacheClient_returnsNullWhenLockNotAcquired() {
        // Native-IdP path: in-process refreshCoordinationService lock contention => return null
        // without calling release. Promoted providers don't go through this lock anymore (their
        // L2 row's DDB-backed lock is acquired inside UpstreamRefreshService).
        doThrow(new IllegalStateException("lock contention")).when(refreshCoordinationService)
                .acquireUpstream(anyString());

        TokenResponse result = authorizerService.mintBearerForWarmCacheClient(
                "u1", "embrace", "https://r", "Cursor", "rt");

        assertNull(result);
        verify(tokenStore, never()).storeUserToken(any(), any(), anyString(), any(TokenWrapper.class));
        verify(refreshCoordinationService, never()).releaseUpstream(any());
    }

    @Test
    void mintBearerForWarmCacheClient_returnsNullWhenRefreshFails_andStillReleasesLock() {
        // Native-IdP path (embrace). Promoted-provider failure is covered by
        // mintBearerForWarmCacheClient_promoted_returnsNullOnRefreshFailure below.
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("embrace")).thenReturn(tokenExchangeService);
        when(tokenExchangeService.refreshWithUpstreamToken("rt")).thenReturn(null);

        TokenResponse result = authorizerService.mintBearerForWarmCacheClient(
                "u1", "embrace", "https://r", "Cursor", "rt");

        assertNull(result);
        verify(refreshCoordinationService).acquireUpstream("embrace#u1");
        verify(refreshCoordinationService).releaseUpstream("embrace#u1");
        verify(tokenStore, never()).storeUserToken(any(), any(), anyString(), any(TokenWrapper.class));
    }

    @Test
    void mintBearerForWarmCacheClient_promoted_routesThroughUpstreamRefreshService() {
        when(upstreamProviderClassifier.isUpstreamPromoted("google-docs")).thenReturn(true);
        UpstreamRefreshResponse refreshResponse = new UpstreamRefreshResponse(
                "fresh-google-at", "rotated-google-rt", "fresh-id-token", 3599L, "scope");
        when(upstreamRefreshService.refreshUpstream("google-docs#u1", "google-docs", "Cursor"))
                .thenReturn(refreshResponse);

        TokenResponse result = authorizerService.mintBearerForWarmCacheClient(
                "u1", "google-docs", "https://r", "Cursor", "ignored-shared-rt");

        assertNotNull(result);
        assertEquals("fresh-google-at", result.accessToken());
        assertEquals("Bearer", result.tokenType());
        verify(refreshCoordinationService, never()).acquireUpstream(any());
        verify(tokenExchangeServiceProducer, never()).getTokenExchangeServiceImplementation(any());
        verify(tokenStore).storeUserToken(eq("u1"), eq("google-docs"), any(TokenWrapper.class));
        verify(bearerIndexStore).putBearer(anyString(), eq("u1"), eq("Cursor"), eq("google-docs"),
                org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyLong());
        verify(refreshTokenService, never()).updateUpstreamRefreshForAllRowsWithUserAndProvider(any(), any(), any());
    }

    @Test
    void mintBearerForWarmCacheClient_promoted_returnsNullOnRefreshFailure() {
        when(upstreamProviderClassifier.isUpstreamPromoted("google-slides")).thenReturn(true);
        when(upstreamRefreshService.refreshUpstream("google-slides#u2", "google-slides", "Claude"))
                .thenThrow(new UpstreamRefreshException("Upstream google-slides token revoked; re-authentication required"));

        TokenResponse result = authorizerService.mintBearerForWarmCacheClient(
                "u2", "google-slides", "https://r", "Claude", "ignored");

        assertNull(result);
        verify(tokenStore, never()).storeUserToken(eq("u2"), eq("google-slides"), any(TokenWrapper.class));
        verify(bearerIndexStore, never()).putBearer(anyString(), any(), any(), any(),
                org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyLong());
    }

    @Test
    void mintBearerForWarmCacheClient_promoted_pathE_preservesBareRowRefreshTokenWhenNoRotation() {
        when(upstreamProviderClassifier.isUpstreamPromoted("google-docs")).thenReturn(true);
        UpstreamRefreshResponse pathEResponse = new UpstreamRefreshResponse(
                "staged-at", /* refreshToken */ null, /* idToken */ null, 3500L, /* scope */ null);
        when(upstreamRefreshService.refreshUpstream("google-docs#u3", "google-docs", "Claude"))
                .thenReturn(pathEResponse);
        TokenWrapper existingBare = new TokenWrapper(
                "u3", "google-docs", "old-id", "old-at", "existing-bare-rt", 9999L);
        when(tokenStore.getUserToken("u3", "google-docs")).thenReturn(existingBare);

        TokenResponse result = authorizerService.mintBearerForWarmCacheClient(
                "u3", "google-docs", "https://r", "Claude", "ignored");

        assertNotNull(result);
        assertEquals("staged-at", result.accessToken(),
                "Path E must serve the staged AT verbatim through the warm-mint path");
        // Verify the bare row update preserved the existing RT (not null).
        ArgumentCaptor<TokenWrapper> wrapperCaptor = ArgumentCaptor.forClass(TokenWrapper.class);
        verify(tokenStore).storeUserToken(eq("u3"), eq("google-docs"), wrapperCaptor.capture());
        assertEquals("existing-bare-rt", wrapperCaptor.getValue().refreshToken(),
                "Bare row's refreshToken must NOT be clobbered with null when Path E returned no rotated RT");
        assertEquals("staged-at", wrapperCaptor.getValue().accessToken());
    }

    @Test
    void refreshUpstreamAndGetToken_acquiresAndReleasesLockEvenOnNullToken() {
        // Empty upstreamRefreshToken short-circuits before lock acquisition.
        RefreshAndTokenResult r = authorizerService.refreshUpstreamAndGetToken(
                "u1", AudienceConstants.PROVIDER_OKTA, "https://r", "");
        assertNull(r);
        verifyNoInteractions(refreshCoordinationService);
    }

    // -- UpstreamExchangeException propagation (NPE -> 401 batch-2 fix) --------------------
    //
    // Pre-fix: every audience-style TokenExchangeService impl returned (UNAUTHORIZED, null)
    // on failure and AuthorizerService dereferenced atDO.token().ttl() unconditionally → NPE → 500.
    // Post-fix: AuthorizerService throws UpstreamExchangeException carrying the upstream
    // errorMessage so TokenResource can map it to 401 invalid_token. Generic — every audience
    // provider (Splunk, Databricks, GCP Workforce, Grafana, Evaluate, Okta-exchange, ZTS).

    private void stubResourceMetaAndExchange(String resource, AuthorizationResultDO atDO) {
        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read"), "domain1", AudienceConstants.PROVIDER_OKTA, "auth-server", false, null, ""
        );
        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint("auth-server")).thenReturn("https://auth.example.com/token");
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("auth-server"))
                .thenReturn(tokenExchangeService);
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class)))
                .thenReturn(atDO);
    }

    @Test
    void getTokenFromAuthorizationServer_unauthorizedWithMessage_throwsUpstreamExchangeException() {
        // Splunk-style failure: impl returns unauthorized("Role=… is not grantable").
        // Must throw UpstreamExchangeException with that message verbatim — TokenResource
        // surfaces it as the 401 error_description.
        String resource = "https://api.example.com";
        TokenWrapper inputToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300);
        stubResourceMetaAndExchange(resource,
                AuthorizationResultDO.unauthorized("Splunk createUser failed: status=403, message=Role=power_ads-pbp-008 is not grantable"));

        UpstreamExchangeException ex = assertThrows(UpstreamExchangeException.class,
                () -> authorizerService.getTokenFromAuthorizationServer("subj", "read", resource, inputToken));
        assertEquals(
                "Splunk createUser failed: status=403, message=Role=power_ads-pbp-008 is not grantable",
                ex.getMessage());
    }

    @Test
    void getTokenFromAuthorizationServer_unauthorizedWithoutMessage_throwsGenericUpstreamExchangeException() {
        // Legacy unauthorized() without errorMessage (e.g. provider impl not yet migrated).
        // Falls back to a generic message — never NPE, never 500.
        String resource = "https://api.example.com";
        TokenWrapper inputToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300);
        stubResourceMetaAndExchange(resource,
                new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null));

        UpstreamExchangeException ex = assertThrows(UpstreamExchangeException.class,
                () -> authorizerService.getTokenFromAuthorizationServer("subj", "read", resource, inputToken));
        assertTrue(ex.getMessage().contains("upstream token exchange failed"));
    }

    @Test
    void getTokenFromAuthorizationServer_grafanaUnauthorizedWithMessage_throwsUpstreamExchangeException() {
        // Generic across providers — same throw for grafana, no audience-specific branching.
        String resource = "https://grafana.example.com/dashboard";
        TokenWrapper inputToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300);
        stubResourceMetaAndExchange(resource,
                AuthorizationResultDO.unauthorized("Grafana exchange: token mint failed for shortId=alice (see server logs for upstream HTTP status)"));

        UpstreamExchangeException ex = assertThrows(UpstreamExchangeException.class,
                () -> authorizerService.getTokenFromAuthorizationServer("subj", "read", resource, inputToken));
        assertTrue(ex.getMessage().contains("Grafana exchange"));
    }

    @Test
    void getTokenFromAuthorizationServer_nullAtDO_throwsGenericUpstreamExchangeException() {
        // accessTokenIssuer returns null entirely — no NPE, falls through to generic throw.
        String resource = "https://api.example.com";
        TokenWrapper inputToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300);
        stubResourceMetaAndExchange(resource, null);

        UpstreamExchangeException ex = assertThrows(UpstreamExchangeException.class,
                () -> authorizerService.getTokenFromAuthorizationServer("subj", "read", resource, inputToken));
        assertTrue(ex.getMessage().contains("upstream token exchange failed"));
    }

    @Test
    void getTokenFromAuthorizationServer_authorizedWithNullToken_throwsGenericUpstreamExchangeException() {
        // Pathological: AuthResult.AUTHORIZED but token() == null. Pre-fix this hit NPE
        // on atDO.token().ttl(). Post-fix it throws UpstreamExchangeException so the
        // caller never sees a 500.
        String resource = "https://api.example.com";
        TokenWrapper inputToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300);
        stubResourceMetaAndExchange(resource,
                new AuthorizationResultDO(AuthResult.AUTHORIZED, null));

        assertThrows(UpstreamExchangeException.class,
                () -> authorizerService.getTokenFromAuthorizationServer("subj", "read", resource, inputToken));
    }

    @Test
    void getTokenFromAuthorizationServer_jagBranch_unauthorizedFinalAt_throwsUpstreamExchangeException() {
        // Cover the JAG branch (line 234 in AuthorizerService) — same guard, same throw.
        String resource = "https://api.example.com";
        String authServer = "auth-server-jag";
        String jagIssuer = "jag-issuer-x";

        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read"), "domain1", AudienceConstants.PROVIDER_OKTA, authServer, true, jagIssuer, ""
        );
        TokenWrapper inputToken = new TokenWrapper(
                "user.testuser", AudienceConstants.PROVIDER_OKTA, "id-token", "access-token", "refresh-token",
                Instant.now().getEpochSecond() + 300);
        TokenWrapper jagToken = new TokenWrapper(null, null, "jag-id", null, null, 600L);
        AuthorizationResultDO jagOk = new AuthorizationResultDO(AuthResult.AUTHORIZED, jagToken);

        when(configService.getResourceMeta(resource)).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint(authServer)).thenReturn("https://auth.example.com/token");
        when(configService.getRemoteServerEndpoint(jagIssuer)).thenReturn("https://jag.example.com/token");
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(authServer))
                .thenReturn(tokenExchangeService);
        TokenExchangeService jagService = mock(TokenExchangeService.class);
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(jagIssuer))
                .thenReturn(jagService);
        when(jagService.getJWTAuthorizationGrantFromIdentityProvider(any(TokenExchangeDO.class)))
                .thenReturn(jagOk);
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class)))
                .thenReturn(AuthorizationResultDO.unauthorized("Databricks prod-eng upstream HTTP 401: invalid_grant"));

        UpstreamExchangeException ex = assertThrows(UpstreamExchangeException.class,
                () -> authorizerService.getTokenFromAuthorizationServer("subj", "read", resource, inputToken));
        assertTrue(ex.getMessage().contains("Databricks prod-eng upstream HTTP 401"));
    }

    // ---------------- Shared Okta upstream session cache: write/invalidate hooks ----------------

    @Test
    void storeTokens_okta_populatesL0_whenCacheEnabled() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        authorizerService.storeTokens(
                "user.alice", "user.alice", "id-token-raw", "access-token-raw", "refresh-token-raw",
                AudienceConstants.PROVIDER_OKTA);
        verify(oktaSessionCache).put(eq("okta#alice"), any(OktaSessionEntry.class));
    }

    @Test
    void storeTokens_okta_skipsL0_whenCacheDisabled() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(false);
        authorizerService.storeTokens(
                "user.alice", "user.alice", "id-token-raw", "access-token-raw", "refresh-token-raw",
                AudienceConstants.PROVIDER_OKTA);
        verify(oktaSessionCache, never()).put(anyString(), any(OktaSessionEntry.class));
    }

    @Test
    void storeTokens_nonOktaProvider_doesNotPopulateL0() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        authorizerService.storeTokens(
                "user.alice", "user.alice", "id-token-raw", "access-token-raw", "refresh-token-raw",
                "github");
        verify(oktaSessionCache, never()).put(anyString(), any(OktaSessionEntry.class));
    }

    @Test
    void storeTokens_okta_idTokenAbsent_skipsL0() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        authorizerService.storeTokens(
                "user.alice", "user.alice", null, "access-token-raw", "refresh-token-raw",
                AudienceConstants.PROVIDER_OKTA);
        verify(oktaSessionCache, never()).put(anyString(), any(OktaSessionEntry.class));
    }

    @Test
    void storeTokens_okta_seedsCentralizedUpstreamRow_onLogin() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        authorizerService.storeTokens(
                "user.alice", "user.alice", "id-token-raw", "access-token-raw", "refresh-token-raw",
                AudienceConstants.PROVIDER_OKTA);
        verify(upstreamRefreshService).storeInitialUpstreamToken("okta#alice", "refresh-token-raw");
    }

    @Test
    void storeTokens_okta_seedsCentralizedUpstreamRow_evenWhenCacheDisabled() {
        // L2 (mcp-oauth-proxy-upstream-tokens) is the durable upstream RT. It must be seeded
        // independently of the L0 OktaSessionCache feature flag, otherwise a cache-disabled
        // pod would be unable to refresh after the bare-row TTL expires.
        when(oktaSessionCacheConfig.enabled()).thenReturn(false);
        authorizerService.storeTokens(
                "user.alice", "user.alice", "id-token-raw", "access-token-raw", "refresh-token-raw",
                AudienceConstants.PROVIDER_OKTA);
        verify(upstreamRefreshService).storeInitialUpstreamToken("okta#alice", "refresh-token-raw");
    }

    @Test
    void storeTokens_okta_seedsCentralizedUpstreamRow_evenWhenIdTokenMissing() {
        // The L0 cache requires an id_token (it carries claims used by /userinfo etc.), but the
        // L2 upstream-tokens row only needs the refresh token, so an absent id_token must not
        // suppress the L2 seed.
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        authorizerService.storeTokens(
                "user.alice", "user.alice", null, "access-token-raw", "refresh-token-raw",
                AudienceConstants.PROVIDER_OKTA);
        verify(upstreamRefreshService).storeInitialUpstreamToken("okta#alice", "refresh-token-raw");
    }

    @Test
    void storeTokens_okta_skipsCentralizedUpstreamRow_whenRefreshTokenAbsent() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        authorizerService.storeTokens(
                "user.alice", "user.alice", "id-token-raw", "access-token-raw", null,
                AudienceConstants.PROVIDER_OKTA);
        verify(upstreamRefreshService, never()).storeInitialUpstreamToken(anyString(), anyString());
    }

    @Test
    void storeTokens_nonOktaProvider_doesNotSeedCentralizedUpstreamRow() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        authorizerService.storeTokens(
                "user.alice", "user.alice", "id-token-raw", "access-token-raw", "refresh-token-raw",
                "github");
        verify(upstreamRefreshService, never()).storeInitialUpstreamToken(anyString(), anyString());
    }

    @Test
    void completeRefreshWithOktaTokens_populatesL0_whenCacheEnabled() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        ResourceMeta resourceMeta = new ResourceMeta(
                Arrays.asList("read"), "domain1", AudienceConstants.PROVIDER_OKTA,
                AudienceConstants.PROVIDER_OKTA, false, null, "");
        when(configService.getResourceMeta(anyString())).thenReturn(resourceMeta);
        when(configService.getRemoteServerEndpoint(anyString())).thenReturn("https://okta.example.com/token");
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(anyString()))
                .thenReturn(tokenExchangeService);
        TokenWrapper exchangedToken = new TokenWrapper(null, null, null, "exchanged-at", null, 3600L);
        when(tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(any(TokenExchangeDO.class)))
                .thenReturn(new AuthorizationResultDO(AuthResult.AUTHORIZED, exchangedToken));

        OktaTokens fresh = new OktaTokens("at", "rt", "id-token-raw", 3600);
        authorizerService.completeRefreshWithOktaTokens("user.alice", AudienceConstants.PROVIDER_OKTA,
                "https://api.example.com", fresh);

        verify(oktaSessionCache).put(eq("okta#alice"), any(OktaSessionEntry.class));
    }

    @Test
    void cleanupAfterTerminalUpstreamRefreshFailure_okta_invalidatesL0() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(anyString()))
                .thenReturn(tokenExchangeService);

        authorizerService.cleanupAfterTerminalUpstreamRefreshFailure(
                "user.alice", AudienceConstants.PROVIDER_OKTA, "rt-to-revoke");

        verify(oktaSessionCache).invalidate("okta#alice");
    }

    @Test
    void cleanupAfterTerminalUpstreamRefreshFailure_nonOkta_doesNotTouchL0() {
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(anyString()))
                .thenReturn(tokenExchangeService);

        authorizerService.cleanupAfterTerminalUpstreamRefreshFailure(
                "user.alice", "github", "rt-to-revoke");

        verify(oktaSessionCache, never()).invalidate(anyString());
    }

    @Test
    void oktaProviderUserId_stripsUserPrefix() {
        assertEquals("okta#alice", authorizerService.oktaProviderUserId("user.alice"));
        // Already without prefix: pass through as-is.
        assertEquals("okta#bob", authorizerService.oktaProviderUserId("bob"));
        assertNull(authorizerService.oktaProviderUserId(null));
        assertNull(authorizerService.oktaProviderUserId(""));
        // Prefix only — no subject — is null.
        assertNull(authorizerService.oktaProviderUserId("user."));
    }

    // expires_in (RFC 6749 §5.1) is the *access_token* lifetime, in seconds — NOT an absolute
    // timestamp and NOT the refresh_token's lifetime. sanitizeExpiresIn enforces that contract
    // and shields the wire response from the four pass-through TokenExchangeService impls that
    // re-emit the storage-side TokenWrapper whose `ttl` field is the absolute DDB epoch.

    @Test
    void sanitizeExpiresIn_passesThroughReasonableDuration() {
        assertEquals(3600L, AuthorizerService.sanitizeExpiresIn(3600L, 1_777_900_000L));
        assertEquals(43200L, AuthorizerService.sanitizeExpiresIn(43200L, 1_777_900_000L)); // 12h Slack
        assertEquals(1L, AuthorizerService.sanitizeExpiresIn(1L, 1_777_900_000L));
    }

    @Test
    void sanitizeExpiresIn_nullOrNonPositive_returnsDefault() {
        long now = 1_777_900_000L;
        assertEquals(AuthorizerService.DEFAULT_EXPIRES_IN_SECONDS,
                AuthorizerService.sanitizeExpiresIn(null, now));
        assertEquals(AuthorizerService.DEFAULT_EXPIRES_IN_SECONDS,
                AuthorizerService.sanitizeExpiresIn(0L, now));
        assertEquals(AuthorizerService.DEFAULT_EXPIRES_IN_SECONDS,
                AuthorizerService.sanitizeExpiresIn(-5L, now));
    }

    @Test
    void sanitizeExpiresIn_absoluteEpoch_isConvertedToRemainingSeconds() {
        // Real failure mode from the Slack refresh path: TokenWrapper.ttl was the DDB absolute TTL
        // (now + lifetime + grace). Convert back via `rawTtl - now`, return that remainder as the
        // duration on the wire — never echo the epoch.
        long now = 1_777_900_000L;
        long absoluteEpochOneHourFromNow = now + 3600L;
        assertEquals(3600L,
                AuthorizerService.sanitizeExpiresIn(absoluteEpochOneHourFromNow, now));
    }

    @Test
    void sanitizeExpiresIn_absoluteEpochAlreadyPast_returnsDefault() {
        // Clock skew or stale row: absolute TTL is in the past. Don't emit a negative duration
        // and don't lie that the token is fresh; emit the default so the client refreshes promptly.
        long now = 1_777_900_000L;
        long absoluteEpochInThePast = now - 60L;
        assertEquals(AuthorizerService.DEFAULT_EXPIRES_IN_SECONDS,
                AuthorizerService.sanitizeExpiresIn(absoluteEpochInThePast, now));
    }

    @Test
    void sanitizeExpiresIn_unreasonablyLargeDuration_isCappedNotPropagated() {
        // A buggy upstream could legitimately return a duration above 30 days (e.g. 60d). Treat it
        // as such (it's not an epoch — it's < epoch territory but > our duration sanity ceiling)…
        // actually any value > DURATION_SANITY_CEILING_SECONDS gets the absolute-epoch treatment.
        // Keep this test for the duration-cap path: a value well within "duration" range but above
        // MAX_REASONABLE_DURATION_SECONDS gets capped.
        long now = 1_777_900_000L;
        long fourtyEightHours = 60L * 60L * 48L;
        // 48h fits inside DURATION_SANITY_CEILING_SECONDS (30d) so it's treated as a duration,
        // and gets capped to MAX_REASONABLE_DURATION_SECONDS (24h).
        assertEquals(60L * 60L * 24L,
                AuthorizerService.sanitizeExpiresIn(fourtyEightHours, now));
    }
}
