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

import io.athenz.mop.config.DatabricksSqlTokenExchangeConfig;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import java.net.URI;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.IOException;

class TokenExchangeServiceDatabricksSqlImplTest {

    @Mock
    DatabricksSqlTokenExchangeConfig config;

    @Mock
    OauthProxyMetrics oauthProxyMetrics;

    @Mock
    MetricsRegionProvider metricsRegionProvider;

    @Mock
    DatabricksSqlTokenClient tokenClient;

    TokenExchangeServiceDatabricksSqlImpl impl;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(config.workspaceHostTemplate()).thenReturn("https://%s.cloud.databricks.com");
        when(config.resourcePathPrefix()).thenReturn("/v1/databricks-sql/");
        when(config.workspaceSegmentPattern()).thenReturn("^dbc-[a-zA-Z0-9.-]+$");
        when(config.oauthScope()).thenReturn("sql");
        when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");

        impl = new TokenExchangeServiceDatabricksSqlImpl();
        impl.config = config;
        impl.oauthProxyMetrics = oauthProxyMetrics;
        impl.metricsRegionProvider = metricsRegionProvider;
        impl.databricksSqlTokenClient = tokenClient;
    }

    @Test
    void exchange_success_returnsOAuthScope() throws Exception {
        String json = "{\"access_token\":\"atok\",\"expires_in\":100,\"scope\":\"sql\"}";
        when(tokenClient.postForm(any(URI.class), anyString()))
                .thenReturn(new DatabricksSqlTokenClient.DatabricksTokenHttpResponse(200, json, Optional.of("req-1")));

        TokenWrapper tw = new TokenWrapper("u", "okta", "id.jwt", "acc", "rt", 3600L);
        TokenExchangeDO req = new TokenExchangeDO(
                null,
                "https://g.example/v1/databricks-sql/dbc-ws/mcp",
                null,
                null,
                tw);

        AuthorizationResultDO out = impl.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.AUTHORIZED, out.authResult());
        assertNotNull(out.token());
        assertEquals("atok", out.token().accessToken());
        assertEquals(100L, out.token().ttl());
        assertEquals("sql", out.oauthScope());
    }

    @Test
    void exchange_rejectsOfflineAccessInConfiguredScope() {
        when(config.oauthScope()).thenReturn("sql offline_access");
        TokenWrapper tw = new TokenWrapper("u", "okta", "id", "acc", null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(
                null,
                "https://g.example/v1/databricks-sql/dbc-ws/mcp",
                null,
                null,
                tw);

        AuthorizationResultDO out = impl.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, out.authResult());
        verifyNoInteractions(tokenClient);
    }

    @Test
    void exchange_httpError_unauthorized() throws Exception {
        when(tokenClient.postForm(any(URI.class), anyString()))
                .thenReturn(new DatabricksSqlTokenClient.DatabricksTokenHttpResponse(
                        400, "{\"error\":\"invalid_scope\"}", Optional.empty()));

        TokenWrapper tw = new TokenWrapper("u", "okta", "id", "acc", null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(
                null,
                "https://g.example/v1/databricks-sql/dbc-ws/mcp",
                null,
                null,
                tw);

        AuthorizationResultDO out = impl.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, out.authResult());
        assertNull(out.token());
    }

    @Test
    void getJwtGrant_unsupported() {
        assertThrows(UnsupportedOperationException.class,
                () -> impl.getJWTAuthorizationGrantFromIdentityProvider(mock(TokenExchangeDO.class)));
    }

    @Test
    void getAccessWithClientCredentials_unsupported() {
        assertThrows(UnsupportedOperationException.class,
                () -> impl.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(mock(TokenExchangeDO.class)));
    }

    @Test
    void refreshWithUpstreamToken_returnsNull() {
        assertNull(impl.refreshWithUpstreamToken("rt"));
    }

    @Test
    void exchange_nullRequest_unauthorized() {
        assertEquals(AuthResult.UNAUTHORIZED,
                impl.getAccessTokenFromResourceAuthorizationServer(null).authResult());
    }

    @Test
    void exchange_nullTokenWrapper_unauthorized() {
        TokenExchangeDO req = new TokenExchangeDO(null, "https://g.example/v1/databricks-sql/dbc-ws/mcp", null, null, null);
        assertEquals(AuthResult.UNAUTHORIZED,
                impl.getAccessTokenFromResourceAuthorizationServer(req).authResult());
        verifyNoInteractions(tokenClient);
    }

    @Test
    void exchange_missingIdToken_unauthorized() {
        TokenWrapper tw = new TokenWrapper("u", "okta", null, "acc", null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(null, "https://g.example/v1/databricks-sql/dbc-ws/mcp", null, null, tw);
        assertEquals(AuthResult.UNAUTHORIZED,
                impl.getAccessTokenFromResourceAuthorizationServer(req).authResult());
        verifyNoInteractions(tokenClient);
    }

    @Test
    void exchange_invalidResource_unauthorized() {
        TokenWrapper tw = new TokenWrapper("u", "okta", "id.jwt", "acc", null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(null, "https://g.example/wrong", null, null, tw);
        assertEquals(AuthResult.UNAUTHORIZED,
                impl.getAccessTokenFromResourceAuthorizationServer(req).authResult());
        verifyNoInteractions(tokenClient);
    }

    @Test
    void exchange_blankOauthScope_unauthorized() {
        when(config.oauthScope()).thenReturn("   ");
        TokenWrapper tw = new TokenWrapper("u", "okta", "id", "acc", null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(null, "https://g.example/v1/databricks-sql/dbc-ws/mcp", null, null, tw);
        assertEquals(AuthResult.UNAUTHORIZED,
                impl.getAccessTokenFromResourceAuthorizationServer(req).authResult());
        verifyNoInteractions(tokenClient);
    }

    @Test
    void exchange_rejectsOfflineAccess_caseInsensitive() {
        when(config.oauthScope()).thenReturn("openid Offline_Access");
        TokenWrapper tw = new TokenWrapper("u", "okta", "id", "acc", null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(null, "https://g.example/v1/databricks-sql/dbc-ws/mcp", null, null, tw);
        assertEquals(AuthResult.UNAUTHORIZED,
                impl.getAccessTokenFromResourceAuthorizationServer(req).authResult());
        verifyNoInteractions(tokenClient);
    }

    @Test
    void exchange_success_usesDefaultTtlWhenExpiresMissingOrNonPositive() throws Exception {
        String jsonNoExpiry = "{\"access_token\":\"at2\"}";
        when(tokenClient.postForm(any(URI.class), anyString()))
                .thenReturn(new DatabricksSqlTokenClient.DatabricksTokenHttpResponse(200, jsonNoExpiry, Optional.empty()));

        TokenWrapper tw = new TokenWrapper("u", "okta", "id.jwt", "acc", null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(
                null, "https://g.example/v1/databricks-sql/dbc-ws/mcp", null, null, tw);

        AuthorizationResultDO out = impl.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.AUTHORIZED, out.authResult());
        assertEquals(3600L, out.token().ttl());

        String jsonZeroExpiry = "{\"access_token\":\"at3\",\"expires_in\":0}";
        when(tokenClient.postForm(any(URI.class), anyString()))
                .thenReturn(new DatabricksSqlTokenClient.DatabricksTokenHttpResponse(200, jsonZeroExpiry, Optional.empty()));
        AuthorizationResultDO out2 = impl.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(3600L, out2.token().ttl());
    }

    @Test
    void exchange_success_usesConfiguredScopeWhenResponseOmitsScope() throws Exception {
        String json = "{\"access_token\":\"atok\",\"expires_in\":10}";
        when(tokenClient.postForm(any(URI.class), anyString()))
                .thenReturn(new DatabricksSqlTokenClient.DatabricksTokenHttpResponse(200, json, Optional.empty()));

        TokenWrapper tw = new TokenWrapper("u", "okta", "id.jwt", "acc", null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(
                null, "https://g.example/v1/databricks-sql/dbc-ws/mcp", null, null, tw);

        AuthorizationResultDO out = impl.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals("sql", out.oauthScope());
    }

    @Test
    void exchange_200MissingAccessToken_unauthorized() throws Exception {
        when(tokenClient.postForm(any(URI.class), anyString()))
                .thenReturn(new DatabricksSqlTokenClient.DatabricksTokenHttpResponse(200, "{}", Optional.empty()));

        TokenWrapper tw = new TokenWrapper("u", "okta", "id", "acc", null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(
                null, "https://g.example/v1/databricks-sql/dbc-ws/mcp", null, null, tw);

        assertEquals(AuthResult.UNAUTHORIZED,
                impl.getAccessTokenFromResourceAuthorizationServer(req).authResult());
    }

    @Test
    void exchange_200MalformedJson_unauthorized() throws Exception {
        when(tokenClient.postForm(any(URI.class), anyString()))
                .thenReturn(new DatabricksSqlTokenClient.DatabricksTokenHttpResponse(200, "not-json", Optional.empty()));

        TokenWrapper tw = new TokenWrapper("u", "okta", "id", "acc", null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(
                null, "https://g.example/v1/databricks-sql/dbc-ws/mcp", null, null, tw);

        assertEquals(AuthResult.UNAUTHORIZED,
                impl.getAccessTokenFromResourceAuthorizationServer(req).authResult());
        verify(oauthProxyMetrics).recordUpstreamRequest(
                eq("databricks-sql"), eq("oauth_token"), eq(200), eq("us-east-1"), anyDouble());
        verify(oauthProxyMetrics).recordUpstreamRequest(
                eq("databricks-sql"), eq("oauth_token"), eq(0), eq("us-east-1"), anyDouble());
    }

    @Test
    void exchange_postFormThrows_recordsFailureAndUnauthorized() throws Exception {
        when(tokenClient.postForm(any(URI.class), anyString())).thenThrow(new IOException("network"));

        TokenWrapper tw = new TokenWrapper("u", "okta", "id", "acc", null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(
                null, "https://g.example/v1/databricks-sql/dbc-ws/mcp", null, null, tw);

        AuthorizationResultDO out = impl.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, out.authResult());
        verify(oauthProxyMetrics).recordUpstreamRequest(
                eq("databricks-sql"), eq("oauth_token"), eq(0), eq("us-east-1"), anyDouble());
    }

    @Test
    void exchange_workspaceBaseUrlTrailingSlashes_strippedBeforeTokenPath() throws Exception {
        when(config.workspaceHostTemplate()).thenReturn("https://%s.cloud.databricks.com///");
        String json = "{\"access_token\":\"x\",\"expires_in\":1}";
        when(tokenClient.postForm(any(URI.class), anyString()))
                .thenAnswer(invocation -> {
                    URI u = invocation.getArgument(0);
                    assertTrue(u.toString().endsWith("/oidc/v1/token"), u::toString);
                    assertFalse(u.toString().contains("///oidc"), u::toString);
                    return new DatabricksSqlTokenClient.DatabricksTokenHttpResponse(200, json, Optional.empty());
                });

        TokenWrapper tw = new TokenWrapper("u", "okta", "id", "acc", null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(
                null, "https://g.example/v1/databricks-sql/dbc-ws/mcp", null, null, tw);

        assertEquals(AuthResult.AUTHORIZED,
                impl.getAccessTokenFromResourceAuthorizationServer(req).authResult());
    }
}
