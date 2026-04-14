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

class TokenExchangeServiceSlackImplTest {

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
    private TokenExchangeServiceSlackImpl tokenExchangeService;

    private TokenWrapper tokenWrapper;
    private TokenExchangeDO tokenExchangeDO;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        when(telemetryProviderResolver.fromResourceUri(any())).thenReturn("slack");
        when(telemetryRequestContext.oauthClient()).thenReturn("unknown");
        when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");
        setField(tokenExchangeService, "clientId", "test-client-id");
        setField(tokenExchangeService, "clientSecretKey", "slack-client-secret");

        tokenWrapper = new TokenWrapper(
                "slack-key",
                "slack-provider",
                "slack-id-token",
                "slack-access-token",
                "slack-refresh-token",
                3600L
        );
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_ThrowsRuntimeException() {
        List<String> scopes = Arrays.asList("users:read", "search:read");
        tokenExchangeDO = new TokenExchangeDO(scopes, "resource", "slack-namespace", "slack-remote", tokenWrapper);

        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO));
        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_WithNull() {
        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(null));
        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_PassThrough() {
        List<String> scopes = Arrays.asList("users:read", "search:read");
        tokenExchangeDO = new TokenExchangeDO(scopes, "slack-resource", "slack-namespace", "slack-remote", tokenWrapper);

        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertSame(tokenWrapper, result.token());
        assertEquals("slack-access-token", result.token().accessToken());
        assertEquals("slack-refresh-token", result.token().refreshToken());
        assertEquals(3600L, result.token().ttl());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithEmptyScopes() {
        tokenExchangeDO = new TokenExchangeDO(Collections.emptyList(), "resource", "ns", "remote", tokenWrapper);

        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertSame(tokenWrapper, result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_WithNullTokenFields() {
        TokenWrapper nullFieldWrapper = new TokenWrapper("key", "slack", null, null, null, 1800L);
        tokenExchangeDO = new TokenExchangeDO(List.of("users:read"), "resource", "ns", "remote", nullFieldWrapper);

        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertNull(result.token().idToken());
        assertNull(result.token().accessToken());
        assertNull(result.token().refreshToken());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_NullInput_ThrowsNPE() {
        assertThrows(NullPointerException.class,
                () -> tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(null));
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_Throws() {
        tokenExchangeDO = new TokenExchangeDO(List.of("users:read"), "resource", "ns", "remote", tokenWrapper);

        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO));
        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_WithNull() {
        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(null));
        assertEquals("Not implemented yet", exception.getMessage());
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
    void testRefreshWithUpstreamToken_returnsNullWhenClientIdNull() throws Exception {
        setField(tokenExchangeService, "clientId", null);
        assertNull(tokenExchangeService.refreshWithUpstreamToken("valid-refresh-token"));
    }

    @Test
    void testRefreshWithUpstreamToken_returnsNullWhenClientSecretKeyNotConfigured() throws Exception {
        setField(tokenExchangeService, "clientSecretKey", "");
        assertNull(tokenExchangeService.refreshWithUpstreamToken("valid-refresh-token"));
    }

    @Test
    void testRefreshWithUpstreamToken_returnsNullWhenClientSecretKeyNull() throws Exception {
        setField(tokenExchangeService, "clientSecretKey", null);
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
    void testRefreshWithUpstreamToken_returnsNullWhenSecretBlank() {
        Map<String, String> creds = new HashMap<>();
        creds.put("slack-client-secret", "");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(creds);
        assertNull(tokenExchangeService.refreshWithUpstreamToken("valid-refresh-token"));
    }

    @Test
    void testRefreshWithUpstreamToken_success_returnsTokenWrapper() throws ParseException, IOException {
        Map<String, String> credentials = new HashMap<>();
        credentials.put("slack-client-secret", "secret-value");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        String jsonSuccess = "{\"access_token\":\"new-slack-access\",\"token_type\":\"Bearer\",\"expires_in\":43200,\"refresh_token\":\"new-slack-refresh\"}";
        HTTPResponse mockHttpResponse = new HTTPResponse(200);
        mockHttpResponse.setContentType("application/json");
        mockHttpResponse.setBody(jsonSuccess);
        TokenResponse mockTokenResponse = TokenResponse.parse(mockHttpResponse);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(mockTokenResponse);

        TokenWrapper result = tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token");

        assertNotNull(result);
        assertEquals("new-slack-access", result.accessToken());
        assertEquals("new-slack-refresh", result.refreshToken());
        assertEquals(43200L, result.ttl());
        verify(tokenClient, times(1)).execute(any(TokenRequest.class));
    }

    @Test
    void testRefreshWithUpstreamToken_successWithNoNewRefresh_returnsOriginalRefresh() throws ParseException, IOException {
        Map<String, String> credentials = new HashMap<>();
        credentials.put("slack-client-secret", "secret-value");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        String jsonSuccess = "{\"access_token\":\"new-slack-access\",\"token_type\":\"Bearer\",\"expires_in\":43200}";
        HTTPResponse mockHttpResponse = new HTTPResponse(200);
        mockHttpResponse.setContentType("application/json");
        mockHttpResponse.setBody(jsonSuccess);
        TokenResponse mockTokenResponse = TokenResponse.parse(mockHttpResponse);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(mockTokenResponse);

        TokenWrapper result = tokenExchangeService.refreshWithUpstreamToken("original-refresh");

        assertNotNull(result);
        assertEquals("new-slack-access", result.accessToken());
        assertEquals("original-refresh", result.refreshToken());
    }

    @Test
    void testRefreshWithUpstreamToken_successWithNoExpiresIn_usesDefaultTTL() throws ParseException, IOException {
        Map<String, String> credentials = new HashMap<>();
        credentials.put("slack-client-secret", "secret-value");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        String jsonSuccess = "{\"access_token\":\"new-slack-access\",\"token_type\":\"Bearer\",\"refresh_token\":\"new-refresh\"}";
        HTTPResponse mockHttpResponse = new HTTPResponse(200);
        mockHttpResponse.setContentType("application/json");
        mockHttpResponse.setBody(jsonSuccess);
        TokenResponse mockTokenResponse = TokenResponse.parse(mockHttpResponse);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(mockTokenResponse);

        TokenWrapper result = tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token");

        assertNotNull(result);
        assertEquals(43200L, result.ttl());
    }

    @Test
    void testRefreshWithUpstreamToken_errorResponse_returnsNull() throws ParseException, IOException {
        Map<String, String> credentials = new HashMap<>();
        credentials.put("slack-client-secret", "secret-value");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        String jsonError = "{\"error\":\"invalid_grant\",\"error_description\":\"Token has been revoked\"}";
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
    void testRefreshWithUpstreamToken_exceptionDuringRequest_returnsNull() throws ParseException, IOException {
        Map<String, String> credentials = new HashMap<>();
        credentials.put("slack-client-secret", "secret-value");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("Connection refused"));

        TokenWrapper result = tokenExchangeService.refreshWithUpstreamToken("upstream-refresh-token");

        assertNull(result);
    }

    @Test
    void testRefreshWithUpstreamToken_trimsWhitespace() throws ParseException, IOException {
        Map<String, String> credentials = new HashMap<>();
        credentials.put("slack-client-secret", "secret-value");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(credentials);

        String jsonSuccess = "{\"access_token\":\"trimmed-access\",\"token_type\":\"Bearer\",\"expires_in\":43200,\"refresh_token\":\"trimmed-refresh\"}";
        HTTPResponse mockHttpResponse = new HTTPResponse(200);
        mockHttpResponse.setContentType("application/json");
        mockHttpResponse.setBody(jsonSuccess);
        TokenResponse mockTokenResponse = TokenResponse.parse(mockHttpResponse);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(mockTokenResponse);

        TokenWrapper result = tokenExchangeService.refreshWithUpstreamToken("  refresh-with-whitespace  ");

        assertNotNull(result);
        assertEquals("trimmed-access", result.accessToken());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_RecordsMetrics() {
        tokenExchangeDO = new TokenExchangeDO(List.of("users:read"), "slack-resource", "ns", "remote", tokenWrapper);

        tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        verify(oauthProxyMetrics).recordExchangeStep(any(), eq("slack"), eq(true), eq(null), any(), any(), anyDouble());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_MultipleCallsSameResult() {
        tokenExchangeDO = new TokenExchangeDO(List.of("users:read"), "resource", "ns", "remote", tokenWrapper);

        AuthorizationResultDO result1 = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);
        AuthorizationResultDO result2 = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        assertNotNull(result1);
        assertNotNull(result2);
        assertEquals(result1.authResult(), result2.authResult());
        assertSame(result1.token(), result2.token());
    }

    private static void setField(Object target, String fieldName, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(target, value);
    }
}
