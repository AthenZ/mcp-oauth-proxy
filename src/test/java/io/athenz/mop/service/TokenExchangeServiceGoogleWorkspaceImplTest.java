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
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryProviderResolver;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class TokenExchangeServiceGoogleWorkspaceImplTest {

    @Mock
    private K8SSecretsProvider k8SSecretsProvider;

    @Mock
    private TokenClient tokenClient;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private TelemetryProviderResolver telemetryProviderResolver;

    @Mock
    private TelemetryRequestContext telemetryRequestContext;

    @Mock
    private MetricsRegionProvider metricsRegionProvider;

    @InjectMocks
    private TokenExchangeServiceGoogleWorkspaceImpl tokenExchangeService;

    private TokenWrapper tokenWrapper;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(telemetryProviderResolver.fromResourceUri(any())).thenReturn("google-cloud-platform");
        when(telemetryRequestContext.oauthClient()).thenReturn("unknown");
        when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");
        tokenExchangeService.clientId = "test-client-id";
        tokenExchangeService.clientSecretKey = "google-client-secret";
        tokenExchangeService.setProviderLabel(OauthProviderLabel.GOOGLE_CLOUD_PLATFORM);

        tokenWrapper = new TokenWrapper(
                "google-workspace-key",
                "google-workspace-provider",
                "google-workspace-id-token",
                "google-workspace-access-token",
                "google-workspace-refresh-token",
                3600L
        );
    }

    @Test
    void testDefaultProviderLabelIsNull() {
        TokenExchangeServiceGoogleWorkspaceImpl fresh = new TokenExchangeServiceGoogleWorkspaceImpl();
        assertNull(fresh.getProviderLabel());
    }

    @Test
    void testSetProviderLabel() {
        tokenExchangeService.setProviderLabel("google-drive");
        assertEquals("google-drive", tokenExchangeService.getProviderLabel());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testProviderLabelCanBeSetToAnyGoogleWorkspaceProvider(String provider) {
        tokenExchangeService.setProviderLabel(provider);
        assertEquals(provider, tokenExchangeService.getProviderLabel());
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_ThrowsRuntimeException() {
        List<String> scopes = List.of("openid", "email", "profile");
        TokenExchangeDO tokenExchangeDO = new TokenExchangeDO(scopes, "resource", "ns", "rs", tokenWrapper);

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
            tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO));
        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testRefreshWithUpstreamToken_returnsNullWhenTokenNull() {
        assertNull(tokenExchangeService.refreshWithUpstreamToken(null));
    }

    @Test
    void testRefreshWithUpstreamToken_returnsNullWhenTokenEmpty() {
        assertNull(tokenExchangeService.refreshWithUpstreamToken(""));
        assertNull(tokenExchangeService.refreshWithUpstreamToken("   "));
    }

    @Test
    void testRefreshWithUpstreamToken_returnsNullWhenClientIdNotConfigured() {
        tokenExchangeService.clientId = "";
        assertNull(tokenExchangeService.refreshWithUpstreamToken("valid-refresh-token"));
    }

    @Test
    void testRefreshWithUpstreamToken_returnsNullWhenClientSecretKeyNotConfigured() {
        tokenExchangeService.clientSecretKey = "";
        assertNull(tokenExchangeService.refreshWithUpstreamToken("valid-refresh-token"));
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
    void testRefreshWithUpstreamToken_success_returnsTokenWrapper() throws ParseException, IOException {
        Map<String, String> credentials = new HashMap<>();
        credentials.put("google-client-secret", "secret-value");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        String jsonSuccess = "{\"access_token\":\"new-workspace-access\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"new-workspace-refresh\"}";
        HTTPResponse mockHttpResponse = new HTTPResponse(200);
        mockHttpResponse.setContentType("application/json");
        mockHttpResponse.setBody(jsonSuccess);
        TokenResponse mockTokenResponse = TokenResponse.parse(mockHttpResponse);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(mockTokenResponse);

        TokenWrapper result = tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token");

        assertNotNull(result);
        assertEquals("new-workspace-access", result.accessToken());
        assertEquals("new-workspace-refresh", result.refreshToken());
        assertEquals(3600L, result.ttl());
        verify(tokenClient, times(1)).execute(any(TokenRequest.class));
    }

    @Test
    void testRefreshWithUpstreamToken_errorResponse_returnsNull() throws ParseException, IOException {
        Map<String, String> credentials = new HashMap<>();
        credentials.put("google-client-secret", "secret-value");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        String jsonError = "{\"error\":\"invalid_grant\",\"error_description\":\"Token expired\"}";
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
    void testGetAccessTokenFromResourceAuthorizationServer_Success() {
        List<String> scopes = Collections.singletonList("https://www.googleapis.com/auth/cloud-platform");
        TokenExchangeDO tokenExchangeDO = new TokenExchangeDO(scopes, "workspace-resource", "ns", "rs", tokenWrapper);

        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(tokenWrapper, result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_ReturnsOriginalTokenWrapper() {
        List<String> scopes = List.of("openid");
        TokenExchangeDO tokenExchangeDO = new TokenExchangeDO(scopes, "resource", "ns", "rs", tokenWrapper);

        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        assertSame(tokenWrapper, result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_ThrowsRuntimeException() {
        List<String> scopes = List.of("openid", "email");
        TokenExchangeDO tokenExchangeDO = new TokenExchangeDO(scopes, "resource", "ns", "rs", tokenWrapper);

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
            tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO));
        assertEquals("Not implemented yet", exception.getMessage());
    }
}
