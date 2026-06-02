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

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.secret.K8SSecretsProvider;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryProviderResolver;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TokenExchangeServiceAirtableImpl#refreshWithUpstreamToken(String)}
 * (the legacy/native fallback path used by {@code AuthorizerService.refreshUpstreamAndGetToken}).
 * The canonical L2 refresh path lives in {@link AirtableUpstreamRefreshClient} and is covered
 * by {@link AirtableUpstreamRefreshClientTest} — including the {@code client_secret_basic}
 * wire-shape regression guard.
 */
@ExtendWith(MockitoExtension.class)
class TokenExchangeServiceAirtableImplTest {

    private static final String TEST_CLIENT_ID = "23800f05-6b1d-4907-a11d-3f5cde4e4830";
    private static final String TEST_CLIENT_SECRET_KEY = "airtable-client-secret";
    private static final String TEST_CLIENT_SECRET = "test-airtable-client-secret";

    @Mock
    K8SSecretsProvider k8SSecretsProvider;

    @Mock
    TokenClient tokenClient;

    @Mock
    OauthProxyMetrics oauthProxyMetrics;

    @Mock
    TelemetryProviderResolver telemetryProviderResolver;

    @Mock
    TelemetryRequestContext telemetryRequestContext;

    @Mock
    MetricsRegionProvider metricsRegionProvider;

    @InjectMocks
    TokenExchangeServiceAirtableImpl impl;

    @BeforeEach
    void setUp() {
        impl.clientId = TEST_CLIENT_ID;
        impl.clientSecretKey = TEST_CLIENT_SECRET_KEY;
        lenient().when(telemetryRequestContext.oauthClient()).thenReturn("test-client");
        lenient().when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");
    }

    @Test
    void refreshWithUpstreamToken_nullOrBlank_returnsNull() {
        assertNull(impl.refreshWithUpstreamToken(null));
        assertNull(impl.refreshWithUpstreamToken("   "));
    }

    @Test
    void refreshWithUpstreamToken_missingClientId_returnsNull() {
        impl.clientId = "";
        assertNull(impl.refreshWithUpstreamToken("rt"));
    }

    @Test
    void refreshWithUpstreamToken_missingClientSecretKey_returnsNull() {
        impl.clientSecretKey = "";
        assertNull(impl.refreshWithUpstreamToken("rt"));
    }

    @Test
    void refreshWithUpstreamToken_clientSecretMissing_returnsNull() {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("other-key", "value"));
        assertNull(impl.refreshWithUpstreamToken("rt"));
    }

    @Test
    void refreshWithUpstreamToken_success_returnsRotatedRtAnd1hTtl() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        AccessToken at = new BearerAccessToken("airtable_new_at", 3600L, null);
        AccessTokenResponse success = new AccessTokenResponse(
                new Tokens(at, new RefreshToken("airtable_rt_new")));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        TokenWrapper wrapper = impl.refreshWithUpstreamToken("airtable_rt_old");

        assertNotNull(wrapper);
        assertEquals("airtable_new_at", wrapper.accessToken());
        assertEquals("airtable_rt_new", wrapper.refreshToken(),
                "Airtable rotates the RT — response RT must replace prior RT");
        assertEquals(3_600L, wrapper.ttl());
    }

    @Test
    void refreshWithUpstreamToken_success_carryForwardWhenResponseOmitsRt() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        AccessToken at = new BearerAccessToken("airtable_new_at", 3600L, null);
        AccessTokenResponse success = new AccessTokenResponse(new Tokens(at, /* refreshToken */ null));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        TokenWrapper wrapper = impl.refreshWithUpstreamToken("airtable_rt_original");

        assertNotNull(wrapper);
        assertEquals("airtable_rt_original", wrapper.refreshToken(),
                "defensive carry-forward — when Airtable omits a rotated RT, prior RT must persist");
    }

    @Test
    void refreshWithUpstreamToken_success_defaultsTo1hWhenExpiresInMissing() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        AccessToken at = new BearerAccessToken("airtable_new_at"); // no lifetime
        AccessTokenResponse success = new AccessTokenResponse(
                new Tokens(at, new RefreshToken("airtable_rt_new")));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        TokenWrapper wrapper = impl.refreshWithUpstreamToken("airtable_rt_old");

        assertNotNull(wrapper);
        assertEquals(TokenExchangeServiceAirtableImpl.AIRTABLE_DEFAULT_TOKEN_TTL, wrapper.ttl());
        assertEquals(3_600L, TokenExchangeServiceAirtableImpl.AIRTABLE_DEFAULT_TOKEN_TTL,
                "default lifetime constant must equal Airtable's documented expires_in (3600 = 1h)");
    }

    @Test
    void refreshWithUpstreamToken_invalidGrant_returnsNull() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "revoked", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        // Legacy passthrough impl does NOT throw OktaTokenRevokedException — that's the
        // canonical L2 client's contract. Here we just return null so the caller falls through.
        assertNull(impl.refreshWithUpstreamToken("rt"));
    }

    @Test
    void refreshWithUpstreamToken_serverError_returnsNull() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("server_error", "internal", 500));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        assertNull(impl.refreshWithUpstreamToken("rt"));
    }

    @Test
    void refreshWithUpstreamToken_ioException_returnsNull() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        assertNull(impl.refreshWithUpstreamToken("rt"));
    }
}
