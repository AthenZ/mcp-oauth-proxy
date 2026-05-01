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
package io.athenz.mop.resource;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.service.AudienceConstants;
import io.athenz.mop.service.OktaTokens;
import io.athenz.mop.service.UpstreamRefreshException;
import io.athenz.mop.service.UpstreamRefreshService;
import io.athenz.mop.service.UserTokenRegionResolver;
import io.athenz.mop.service.UserTokenResolution;
import io.athenz.mop.store.TokenStore;
import io.athenz.mop.telemetry.ExchangeStep;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for UserInfoResource, including cross-region fallback when token is not found locally.
 */
@ExtendWith(MockitoExtension.class)
class UserInfoResourceTest {

    private static final String ACCESS_TOKEN = "test_access_token";
    private static final String USER = "user.test";
    private static final String USER_PREFIX = "user.";
    private static final String SUBJECT = "test";
    private static final String PROVIDER = AudienceConstants.PROVIDER_OKTA;
    private static final String PROVIDER_USER_ID = PROVIDER + "#" + SUBJECT;

    @Mock
    private TokenStore tokenStore;

    @Mock
    private UserTokenRegionResolver userTokenRegionResolver;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private MetricsRegionProvider metricsRegionProvider;

    @Mock
    private TelemetryRequestContext telemetryRequestContext;

    @Mock
    private UpstreamRefreshService upstreamRefreshService;

    @InjectMocks
    private UserInfoResource userInfoResource;

    private TokenWrapper tokenWrapper;
    private TokenWrapper oktaTokenWrapper;
    private String idToken;

    @BeforeEach
    void setUp() throws Exception {
        lenient().when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");
        Field up = UserInfoResource.class.getDeclaredField("userPrefix");
        up.setAccessible(true);
        up.set(userInfoResource, USER_PREFIX);
        idToken = createIdToken(USER);
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        tokenWrapper = new TokenWrapper(USER, PROVIDER, idToken, ACCESS_TOKEN, "refresh", ttl);
        oktaTokenWrapper = new TokenWrapper(USER, PROVIDER, idToken, null, null, ttl);
    }

    private void stubResolveByHash(TokenWrapper token, boolean fromFallback) {
        lenient().when(userTokenRegionResolver.resolveByAccessTokenHash(anyString(), anyString()))
                .thenReturn(new UserTokenResolution(token, fromFallback));
    }

    private void stubResolveByUserProvider(String user, String provider, TokenWrapper token, boolean fromFallback) {
        lenient().when(userTokenRegionResolver.resolveByUserProvider(eq(user), eq(provider), anyString()))
                .thenReturn(new UserTokenResolution(token, fromFallback));
    }

    private static String createIdToken(String sub) throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(sub)
                .claim("name", "Test User")
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecKey.getKeyID()).build(),
                claims);
        jwt.sign(new ECDSASigner(ecKey));
        return jwt.serialize();
    }

    @Test
    void getUserInfo_missingAuthorization_returns401() {
        Response response = userInfoResource.getUserInfo(null);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertErrorBody(response, "invalid_token", "Missing or invalid Authorization header");
        verify(userTokenRegionResolver, never()).resolveByAccessTokenHash(anyString(), anyString());
    }

    @Test
    void getUserInfo_invalidAuthorizationPrefix_returns401() {
        Response response = userInfoResource.getUserInfo("Basic xyz");

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertErrorBody(response, "invalid_token", "Missing or invalid Authorization header");
        verify(userTokenRegionResolver, never()).resolveByAccessTokenHash(anyString(), anyString());
    }

    @Test
    void getUserInfo_tokenFoundInPrimary_returns200() {
        stubResolveByHash(tokenWrapper, false);
        stubResolveByUserProvider(USER, PROVIDER, oktaTokenWrapper, false);

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(userTokenRegionResolver, times(1)).resolveByAccessTokenHash(anyString(),
                eq(UserTokenRegionResolver.CALL_SITE_USERINFO_TOKEN_LOOKUP));
        verify(userTokenRegionResolver, times(1)).resolveByUserProvider(eq(USER), eq(PROVIDER),
                eq(UserTokenRegionResolver.CALL_SITE_USERINFO_OKTA_LOOKUP));
    }

    @Test
    void getUserInfo_tokenFoundInFallback_returns200() {
        stubResolveByHash(tokenWrapper, true);
        stubResolveByUserProvider(USER, PROVIDER, oktaTokenWrapper, true);

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(userTokenRegionResolver, times(1)).resolveByAccessTokenHash(anyString(),
                eq(UserTokenRegionResolver.CALL_SITE_USERINFO_TOKEN_LOOKUP));
        verify(userTokenRegionResolver, times(1)).resolveByUserProvider(eq(USER), eq(PROVIDER),
                eq(UserTokenRegionResolver.CALL_SITE_USERINFO_OKTA_LOOKUP));
    }

    @Test
    void getUserInfo_tokenNotFound_returns401() {
        stubResolveByHash(null, false);

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertErrorBody(response, "invalid_token", "Token not found");
        verify(userTokenRegionResolver, times(1)).resolveByAccessTokenHash(anyString(),
                eq(UserTokenRegionResolver.CALL_SITE_USERINFO_TOKEN_LOOKUP));
        // The exhausted-metric emission lives inside UserTokenRegionResolver and is covered by
        // UserTokenRegionResolverTest. UserInfoResource itself no longer records it.
        verify(oauthProxyMetrics, never()).recordCrossRegionFallbackExhausted(
                anyString(), anyString(), anyString(), anyString(), anyInt(), anyString());
    }

    @Test
    void getUserInfo_oktaRowMissing_upstreamRefreshSucceeds_returns200() throws Exception {
        String dbProvider = "databricks-sql-dbc-abc123.cloud.databricks.com";
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        TokenWrapper dbToken = new TokenWrapper(USER, dbProvider, null, ACCESS_TOKEN, null, ttl);
        stubResolveByHash(dbToken, false);
        stubResolveByUserProvider(USER, PROVIDER, null, false);
        when(upstreamRefreshService.refreshUpstream(PROVIDER_USER_ID))
                .thenReturn(new OktaTokens("new_at", "new_rt", idToken, 3600));

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(upstreamRefreshService, times(1)).refreshUpstream(PROVIDER_USER_ID);
        verify(tokenStore, times(1)).storeUserToken(eq(USER), eq(PROVIDER), any(TokenWrapper.class));
        verify(oauthProxyMetrics).recordExchangeStep(eq(ExchangeStep.UPSTREAM_REFRESH),
                eq(OauthProviderLabel.OKTA), eq(true), isNull(), eq(""), eq("us-east-1"), anyDouble());
    }

    @Test
    void getUserInfo_oktaRowMissing_upstreamRefreshFails_returns401() {
        String dbProvider = "databricks-sql-dbc-abc123.cloud.databricks.com";
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        TokenWrapper dbToken = new TokenWrapper(USER, dbProvider, null, ACCESS_TOKEN, null, ttl);
        stubResolveByHash(dbToken, false);
        stubResolveByUserProvider(USER, PROVIDER, null, false);
        when(upstreamRefreshService.refreshUpstream(PROVIDER_USER_ID))
                .thenThrow(new UpstreamRefreshException("token revoked"));

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertErrorBody(response, "server_error", "Okta token record not found");
        verify(upstreamRefreshService, times(1)).refreshUpstream(PROVIDER_USER_ID);
        verify(tokenStore, never()).storeUserToken(anyString(), anyString(), any(TokenWrapper.class));
        verify(oauthProxyMetrics).recordExchangeStep(eq(ExchangeStep.UPSTREAM_REFRESH),
                eq(OauthProviderLabel.OKTA), eq(false), eq("unauthorized"), eq(""), eq("us-east-1"), anyDouble());
    }

    @Test
    void getUserInfo_oktaRowMissing_upstreamLockFails_returns401() {
        String dbProvider = "databricks-sql-dbc-abc123.cloud.databricks.com";
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        TokenWrapper dbToken = new TokenWrapper(USER, dbProvider, null, ACCESS_TOKEN, null, ttl);
        stubResolveByHash(dbToken, false);
        stubResolveByUserProvider(USER, PROVIDER, null, false);
        when(upstreamRefreshService.refreshUpstream(PROVIDER_USER_ID))
                .thenThrow(new IllegalStateException("lock not acquired"));

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertErrorBody(response, "server_error", "Okta token record not found");
        verify(upstreamRefreshService, times(1)).refreshUpstream(PROVIDER_USER_ID);
        verify(tokenStore, never()).storeUserToken(anyString(), anyString(), any(TokenWrapper.class));
        verify(oauthProxyMetrics).recordExchangeStep(eq(ExchangeStep.UPSTREAM_REFRESH),
                eq(OauthProviderLabel.OKTA), eq(false), eq("unauthorized"), eq(""), eq("us-east-1"), anyDouble());
    }

    @Test
    void getUserInfo_oktaRowExistsButIdTokenNull_upstreamRefreshSucceeds_returns200() throws Exception {
        String dbProvider = "databricks-vector-search-dbc-xyz.cloud.databricks.com";
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        TokenWrapper dbToken = new TokenWrapper(USER, dbProvider, null, ACCESS_TOKEN, null, ttl);
        TokenWrapper oktaNoIdToken = new TokenWrapper(USER, PROVIDER, null, "old_at", null, ttl);
        stubResolveByHash(dbToken, false);
        stubResolveByUserProvider(USER, PROVIDER, oktaNoIdToken, false);
        when(upstreamRefreshService.refreshUpstream(PROVIDER_USER_ID))
                .thenReturn(new OktaTokens("new_at", "new_rt", idToken, 3600));

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(upstreamRefreshService, times(1)).refreshUpstream(PROVIDER_USER_ID);
        verify(tokenStore, times(1)).storeUserToken(eq(USER), eq(PROVIDER), any(TokenWrapper.class));
        verify(oauthProxyMetrics).recordExchangeStep(eq(ExchangeStep.UPSTREAM_REFRESH),
                eq(OauthProviderLabel.OKTA), eq(true), isNull(), eq(""), eq("us-east-1"), anyDouble());
    }

    @Test
    void getUserInfo_oktaRowExistsButIdTokenNull_upstreamRefreshFails_returns401() {
        String dbProvider = "databricks-vector-search-dbc-xyz.cloud.databricks.com";
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        TokenWrapper dbToken = new TokenWrapper(USER, dbProvider, null, ACCESS_TOKEN, null, ttl);
        TokenWrapper oktaNoIdToken = new TokenWrapper(USER, PROVIDER, null, "old_at", null, ttl);
        stubResolveByHash(dbToken, false);
        stubResolveByUserProvider(USER, PROVIDER, oktaNoIdToken, false);
        when(upstreamRefreshService.refreshUpstream(PROVIDER_USER_ID))
                .thenThrow(new UpstreamRefreshException("no upstream token"));

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertErrorBody(response, "server_error", "Okta token record not found");
        verify(upstreamRefreshService, times(1)).refreshUpstream(PROVIDER_USER_ID);
        verify(tokenStore, never()).storeUserToken(anyString(), anyString(), any(TokenWrapper.class));
        verify(oauthProxyMetrics).recordExchangeStep(eq(ExchangeStep.UPSTREAM_REFRESH),
                eq(OauthProviderLabel.OKTA), eq(false), eq("unauthorized"), eq(""), eq("us-east-1"), anyDouble());
    }

    @SuppressWarnings("unchecked")
    private static void assertErrorBody(Response response, String expectedError, String expectedDescription) {
        Object entity = response.getEntity();
        assertNotNull(entity);
        Map<String, Object> body = (Map<String, Object>) entity;
        assertEquals(expectedError, body.get("error"));
        assertEquals(expectedDescription, body.get("error_description"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void getUserInfo_perClientRow_publishesMcpClientIdClaim() {
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        // Per-client bearer row: TokenStore backends extract clientId from the partition-key
        // prefix into TokenWrapper.clientId on read.
        TokenWrapper perClient = new TokenWrapper(
                USER, PROVIDER, idToken, ACCESS_TOKEN, "refresh", ttl, "Cursor");
        stubResolveByHash(perClient, false);
        stubResolveByUserProvider(USER, PROVIDER, oktaTokenWrapper, false);

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        Map<String, Object> body = (Map<String, Object>) response.getEntity();
        assertEquals("Cursor", body.get("mcp_client_id"),
                "Per-client bearer rows must surface mcp_client_id from the partition-key prefix");
        assertEquals(PROVIDER, body.get("mcp_resource_idp"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void getUserInfo_legacyBareRow_omitsMcpClientIdClaim() {
        // Legacy bare row: TokenWrapper.clientId() == null.
        stubResolveByHash(tokenWrapper, false);
        stubResolveByUserProvider(USER, PROVIDER, oktaTokenWrapper, false);

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        Map<String, Object> body = (Map<String, Object>) response.getEntity();
        org.junit.jupiter.api.Assertions.assertFalse(body.containsKey("mcp_client_id"),
                "Legacy bare rows must omit the mcp_client_id claim entirely (no default, no placeholder)");
        assertEquals(PROVIDER, body.get("mcp_resource_idp"));
    }
}
