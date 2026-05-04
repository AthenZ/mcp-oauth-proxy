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
import io.athenz.mop.config.OktaSessionCacheConfig;
import io.athenz.mop.model.BearerIndexRecord;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.service.AudienceConstants;
import io.athenz.mop.service.BearerIndexRegionResolver;
import io.athenz.mop.service.BearerIndexResolution;
import io.athenz.mop.service.OktaTokens;
import io.athenz.mop.service.UpstreamRefreshException;
import io.athenz.mop.service.UpstreamRefreshService;
import io.athenz.mop.service.UserTokenRegionResolver;
import io.athenz.mop.service.UserTokenResolution;
import io.athenz.mop.store.BearerIndexStore;
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
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for UserInfoResource. Bearer resolution flows through the dedicated
 * mcp-oauth-proxy-bearer-index table via {@link BearerIndexRegionResolver}; per-client
 * mcp_client_id surfacing is read directly from the bearer-index row (no longer derived from
 * the legacy per-client tokens row).
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
    private BearerIndexStore bearerIndexStore;

    @Mock
    private BearerIndexRegionResolver bearerIndexRegionResolver;

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

    @Mock
    private OktaSessionCacheConfig oktaSessionCacheConfig;

    @InjectMocks
    private UserInfoResource userInfoResource;

    private TokenWrapper oktaTokenWrapper;
    private String idToken;

    @BeforeEach
    void setUp() throws Exception {
        lenient().when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");
        // Default: cache disabled — exercises today's behavior. Cache-aware tests opt-in.
        lenient().when(oktaSessionCacheConfig.enabled()).thenReturn(false);
        Field up = UserInfoResource.class.getDeclaredField("userPrefix");
        up.setAccessible(true);
        up.set(userInfoResource, USER_PREFIX);
        idToken = createIdToken(USER);
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        oktaTokenWrapper = new TokenWrapper(USER, PROVIDER, idToken, null, null, ttl);
    }

    private void stubBearerIndex(String user, String clientId, String provider, boolean fromFallback) {
        long now = System.currentTimeMillis() / 1000;
        BearerIndexRecord row = new BearerIndexRecord(
                "h", user, clientId == null ? "" : clientId, provider,
                now + 600, now + 3600);
        lenient().when(bearerIndexRegionResolver.resolveByHash(anyString()))
                .thenReturn(new BearerIndexResolution(row, fromFallback));
    }

    private void stubBearerIndexExpired(String user, String provider) {
        long now = System.currentTimeMillis() / 1000;
        BearerIndexRecord row = new BearerIndexRecord(
                "h", user, "", provider, now - 10, now - 5);
        lenient().when(bearerIndexRegionResolver.resolveByHash(anyString()))
                .thenReturn(new BearerIndexResolution(row, false));
    }

    private void stubBearerIndexMiss() {
        lenient().when(bearerIndexRegionResolver.resolveByHash(anyString()))
                .thenReturn(new BearerIndexResolution(null, false));
    }

    private void stubResolveByUserProvider(String user, String provider, TokenWrapper token, boolean fromFallback) {
        lenient().when(userTokenRegionResolver.resolveByUserProvider(eq(user), eq(provider), anyString()))
                .thenReturn(new UserTokenResolution(token, fromFallback));
    }

    private static String createIdToken(String sub) throws Exception {
        return createIdTokenWithExpEpoch(sub, System.currentTimeMillis() / 1000 + 3600);
    }

    private static String createIdTokenWithExpEpoch(String sub, long expEpochSeconds) throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(sub)
                .claim("name", "Test User")
                .expirationTime(new Date(expEpochSeconds * 1000L))
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
        verify(bearerIndexRegionResolver, never()).resolveByHash(anyString());
    }

    @Test
    void getUserInfo_invalidAuthorizationPrefix_returns401() {
        Response response = userInfoResource.getUserInfo("Basic xyz");

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertErrorBody(response, "invalid_token", "Missing or invalid Authorization header");
        verify(bearerIndexRegionResolver, never()).resolveByHash(anyString());
    }

    @Test
    void getUserInfo_bearerIndexLocalHit_returns200() {
        stubBearerIndex(USER, "", PROVIDER, false);
        stubResolveByUserProvider(USER, PROVIDER, oktaTokenWrapper, false);

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(bearerIndexRegionResolver, times(1)).resolveByHash(anyString());
        verify(userTokenRegionResolver, times(1)).resolveByUserProvider(eq(USER), eq(PROVIDER),
                eq(UserTokenRegionResolver.CALL_SITE_USERINFO_OKTA_LOOKUP));
    }

    @Test
    void getUserInfo_bearerIndexFromFallback_returns200() {
        stubBearerIndex(USER, "", PROVIDER, true);
        stubResolveByUserProvider(USER, PROVIDER, oktaTokenWrapper, true);

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(bearerIndexRegionResolver, times(1)).resolveByHash(anyString());
        verify(userTokenRegionResolver, times(1)).resolveByUserProvider(eq(USER), eq(PROVIDER),
                eq(UserTokenRegionResolver.CALL_SITE_USERINFO_OKTA_LOOKUP));
    }

    @Test
    void getUserInfo_bearerIndexMiss_returns401() {
        stubBearerIndexMiss();

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertErrorBody(response, "invalid_token", "Token not found");
        verify(bearerIndexRegionResolver, times(1)).resolveByHash(anyString());
        // Exhausted-metric emission lives inside BearerIndexRegionResolver and is covered by
        // BearerIndexRegionResolverTest. UserInfoResource itself no longer records it.
        verify(oauthProxyMetrics, never()).recordCrossRegionFallbackExhausted(
                anyString(), anyString(), anyString(), anyString(), anyInt(), anyString());
    }

    @Test
    void getUserInfo_bearerIndexExpired_returns401() {
        stubBearerIndexExpired(USER, "github");

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertErrorBody(response, "invalid_token", "Token has expired");
        verify(userTokenRegionResolver, never()).resolveByUserProvider(anyString(), anyString(), anyString());
        verify(upstreamRefreshService, never()).refreshUpstream(anyString());
    }

    @Test
    void getUserInfo_oktaRowMissing_upstreamRefreshSucceeds_returns200() throws Exception {
        stubBearerIndex(USER, "", "databricks-sql-dbc-abc123.cloud.databricks.com", false);
        stubResolveByUserProvider(USER, PROVIDER, null, false);
        when(upstreamRefreshService.refreshUpstream(PROVIDER_USER_ID))
                .thenReturn(new OktaTokens("new_at", "new_rt", idToken, 3600));

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(upstreamRefreshService, times(1)).refreshUpstream(PROVIDER_USER_ID);
        verify(tokenStore, times(1)).storeUserToken(eq(USER), eq(PROVIDER), any(TokenWrapper.class));
        // The freshly-rotated Okta bearer must be indexed so the next /userinfo resolves via the
        // bearer-index table without a miss.
        verify(bearerIndexStore, times(1)).putBearer(anyString(), eq(USER), eq(""), eq(PROVIDER),
                anyLong(), anyLong());
        verify(oauthProxyMetrics).recordBearerIndexWrite(true);
        verify(oauthProxyMetrics).recordExchangeStep(eq(ExchangeStep.UPSTREAM_REFRESH),
                eq(OauthProviderLabel.OKTA), eq(true), isNull(), eq(""), eq("us-east-1"), anyDouble());
    }

    @Test
    void getUserInfo_oktaRowMissing_upstreamRefreshFails_returns401() {
        stubBearerIndex(USER, "", "databricks-sql-dbc-abc123.cloud.databricks.com", false);
        stubResolveByUserProvider(USER, PROVIDER, null, false);
        when(upstreamRefreshService.refreshUpstream(PROVIDER_USER_ID))
                .thenThrow(new UpstreamRefreshException("token revoked"));

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertErrorBody(response, "server_error", "Okta token record not found");
        verify(upstreamRefreshService, times(1)).refreshUpstream(PROVIDER_USER_ID);
        verify(tokenStore, never()).storeUserToken(anyString(), anyString(), any(TokenWrapper.class));
        verify(bearerIndexStore, never()).putBearer(anyString(), anyString(), anyString(), anyString(),
                anyLong(), anyLong());
        verify(oauthProxyMetrics).recordExchangeStep(eq(ExchangeStep.UPSTREAM_REFRESH),
                eq(OauthProviderLabel.OKTA), eq(false), eq("unauthorized"), eq(""), eq("us-east-1"), anyDouble());
    }

    @Test
    void getUserInfo_oktaRowMissing_upstreamLockFails_returns401() {
        stubBearerIndex(USER, "", "databricks-sql-dbc-abc123.cloud.databricks.com", false);
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
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        TokenWrapper oktaNoIdToken = new TokenWrapper(USER, PROVIDER, null, "old_at", null, ttl);
        stubBearerIndex(USER, "", "databricks-vector-search-dbc-xyz.cloud.databricks.com", false);
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
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        TokenWrapper oktaNoIdToken = new TokenWrapper(USER, PROVIDER, null, "old_at", null, ttl);
        stubBearerIndex(USER, "", "databricks-vector-search-dbc-xyz.cloud.databricks.com", false);
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
    void getUserInfo_bearerIndexCarriesClientId_publishesMcpClientIdClaim() {
        // Bearer-index row carries clientId; /userinfo surfaces mcp_client_id verbatim from it.
        stubBearerIndex(USER, "Cursor", PROVIDER, false);
        stubResolveByUserProvider(USER, PROVIDER, oktaTokenWrapper, false);

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        Map<String, Object> body = (Map<String, Object>) response.getEntity();
        assertEquals("Cursor", body.get("mcp_client_id"),
                "mcp_client_id must come straight from the bearer-index row");
        assertEquals(PROVIDER, body.get("mcp_resource_idp"));
    }

    @Test
    void userinfo_idTokenSecondsFromExpiry_servesFromCache_noUpstreamRefresh() throws Exception {
        // 0s skew on /userinfo: an id_token whose exp is just a few seconds in the future is
        // still strictly fresh and must not trigger an upstream refresh.
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        String soonExpIdToken = createIdTokenWithExpEpoch(USER, System.currentTimeMillis() / 1000 + 5);
        TokenWrapper soonExpRow = new TokenWrapper(USER, PROVIDER, soonExpIdToken, null, null, ttl);
        stubBearerIndex(USER, "", PROVIDER, false);
        stubResolveByUserProvider(USER, PROVIDER, soonExpRow, false);
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(upstreamRefreshService, never()).refreshUpstream(anyString());
        verify(oauthProxyMetrics).recordUserinfoOktaCacheOutcome("fresh_hit");
    }

    @Test
    void userinfo_idTokenExpired_refreshSucceeds_servesFreshClaims_emitsExpiredRefreshed() throws Exception {
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        String expiredIdToken = createIdTokenWithExpEpoch(USER, System.currentTimeMillis() / 1000 - 60);
        TokenWrapper staleRow = new TokenWrapper(USER, PROVIDER, expiredIdToken, "old_at", "old_rt", ttl);
        stubBearerIndex(USER, "", PROVIDER, false);
        stubResolveByUserProvider(USER, PROVIDER, staleRow, false);
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        when(upstreamRefreshService.refreshUpstream(PROVIDER_USER_ID))
                .thenReturn(new OktaTokens("new_at", "new_rt", idToken, 3600));

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(upstreamRefreshService, times(1)).refreshUpstream(PROVIDER_USER_ID);
        verify(oauthProxyMetrics).recordUserinfoOktaCacheOutcome("expired_refreshed");
    }

    @Test
    @SuppressWarnings("unchecked")
    void userinfo_idTokenExpired_refreshFails_servesStaleClaims_emitsStaleClaimsServed() throws Exception {
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        String staleIdToken = createIdTokenWithExpEpoch(USER, System.currentTimeMillis() / 1000 - 60);
        TokenWrapper staleRow = new TokenWrapper(USER, PROVIDER, staleIdToken, "old_at", "old_rt", ttl);
        stubBearerIndex(USER, "", PROVIDER, false);
        stubResolveByUserProvider(USER, PROVIDER, staleRow, false);
        when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        when(upstreamRefreshService.refreshUpstream(PROVIDER_USER_ID))
                .thenThrow(new UpstreamRefreshException("transient"));

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus(),
                "Stale-claims fallback must keep /userinfo at 200 when the upstream-provider bearer is still valid");
        verify(oauthProxyMetrics).recordUserinfoOktaCacheOutcome("stale_claims_served");
        Map<String, Object> body = (Map<String, Object>) response.getEntity();
        assertEquals(USER, body.get("sub"),
                "Identity claims (sub/email/short_id) are stable across refreshes; serve from stale cache");
        org.junit.jupiter.api.Assertions.assertFalse(body.containsKey("exp"),
                "buildUserInfo strips exp/iat regardless of staleness");
    }

    @Test
    void userinfo_idTokenAbsent_refreshFails_returns401_unchanged() {
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        TokenWrapper rowNoIdToken = new TokenWrapper(USER, PROVIDER, null, "old_at", null, ttl);
        stubBearerIndex(USER, "", PROVIDER, false);
        stubResolveByUserProvider(USER, PROVIDER, rowNoIdToken, false);
        // Cache flag isn't consulted on this path (no parseable id_token to even consider as
        // "fresh" or "stale-served"), so we use a lenient stub for parity with the other
        // cache-aware tests in this class.
        lenient().when(oktaSessionCacheConfig.enabled()).thenReturn(true);
        when(upstreamRefreshService.refreshUpstream(PROVIDER_USER_ID))
                .thenThrow(new UpstreamRefreshException("no upstream RT"));

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertErrorBody(response, "server_error", "Okta token record not found");
        // No stale-claims fallback because there is no parseable id_token to serve from.
        verify(oauthProxyMetrics, never()).recordUserinfoOktaCacheOutcome("stale_claims_served");
    }

    @Test
    @SuppressWarnings("unchecked")
    void getUserInfo_bearerIndexClientIdEmpty_omitsMcpClientIdClaim() {
        // Bearer-index row with empty clientId (e.g. /userinfo upstream-refresh write site, or a
        // legacy bearer that never carried a clientId): /userinfo must omit the claim entirely.
        stubBearerIndex(USER, "", PROVIDER, false);
        stubResolveByUserProvider(USER, PROVIDER, oktaTokenWrapper, false);

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        Map<String, Object> body = (Map<String, Object>) response.getEntity();
        org.junit.jupiter.api.Assertions.assertFalse(body.containsKey("mcp_client_id"),
                "Bearer-index rows with empty clientId must omit mcp_client_id (no default, no placeholder)");
        assertEquals(PROVIDER, body.get("mcp_resource_idp"));
    }
}
