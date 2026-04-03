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
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryProviderResolver;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class TokenExchangeServiceEmbraceImplTest {

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
    private TokenExchangeServiceEmbraceImpl tokenExchangeService;

    private TokenWrapper tokenWrapper;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(telemetryProviderResolver.fromResourceUri(any())).thenReturn("embrace");
        when(telemetryRequestContext.oauthClient()).thenReturn("unknown");
        when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");
        tokenExchangeService.clientId = "test-client-id";
        tokenExchangeService.clientSecretKey = "embrace-client-secret";

        tokenWrapper = new TokenWrapper(
                "embrace-key",
                "embrace-provider",
                "embrace-id-token",
                "embrace-access-token",
                "embrace-refresh-token",
                3600L
        );
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_ThrowsRuntimeException() {
        List<String> scopes = Arrays.asList("mcp:read");
        TokenExchangeDO tokenExchangeDO = new TokenExchangeDO(
                scopes,
                "resource",
                "embrace-namespace",
                "embrace-remote-server",
                tokenWrapper
        );

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO);
        });

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
        credentials.put("embrace-client-secret", "secret-value");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        String jsonSuccess = "{\"access_token\":\"new-embrace-access\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"new-embrace-refresh\"}";
        HTTPResponse mockHttpResponse = new HTTPResponse(200);
        mockHttpResponse.setContentType("application/json");
        mockHttpResponse.setBody(jsonSuccess);
        TokenResponse mockTokenResponse = TokenResponse.parse(mockHttpResponse);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(mockTokenResponse);

        TokenWrapper result = tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token");

        assertNotNull(result);
        assertEquals("new-embrace-access", result.accessToken());
        assertEquals("new-embrace-refresh", result.refreshToken());
        assertEquals(3600L, result.ttl());
        verify(tokenClient, times(1)).execute(any(TokenRequest.class));
    }

    @Test
    void testRefreshWithUpstreamToken_errorResponse_returnsNull() throws ParseException, IOException {
        Map<String, String> credentials = new HashMap<>();
        credentials.put("embrace-client-secret", "secret-value");
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
    void testGetAccessTokenFromResourceAuthorizationServer_passThrough() {
        TokenExchangeDO tokenExchangeDO = new TokenExchangeDO(
                List.of("mcp:read"),
                "res",
                "ns",
                "srv",
                tokenWrapper
        );
        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertSame(tokenWrapper, result.token());
    }
}
