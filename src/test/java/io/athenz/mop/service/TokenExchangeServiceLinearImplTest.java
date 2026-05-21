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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TokenExchangeServiceLinearImpl#refreshWithUpstreamToken(String)} (the
 * legacy/native fallback path used by {@code AuthorizerService.refreshUpstreamAndGetToken}).
 * The canonical L2 refresh path lives in {@link LinearUpstreamRefreshClient} and is covered by
 * {@link LinearUpstreamRefreshClientTest}.
 */
@ExtendWith(MockitoExtension.class)
class TokenExchangeServiceLinearImplTest {

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
    TokenExchangeServiceLinearImpl impl;

    private static final String TEST_CLIENT_ID = "test-linear-client-id";

    @BeforeEach
    void setUp() {
        impl.clientId = TEST_CLIENT_ID;
        // Telemetry mocks are exercised on every refresh; lenient stubs keep the failure tests
        // simple (we don't assert on telemetry shape — that's covered by metric-bean tests).
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
    void refreshWithUpstreamToken_success_returnsRotatedRtAnd24hTtl() throws Exception {
        AccessToken at = new BearerAccessToken("li_new_at", 86399L, null);
        AccessTokenResponse success = new AccessTokenResponse(
                new Tokens(at, new RefreshToken("li_rt_new")));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        TokenWrapper wrapper = impl.refreshWithUpstreamToken("li_rt_old");

        assertNotNull(wrapper);
        assertEquals("li_new_at", wrapper.accessToken());
        assertEquals("li_rt_new", wrapper.refreshToken(),
                "Linear rotates the RT — response RT must replace prior RT");
        assertEquals(86_399L, wrapper.ttl());
    }

    @Test
    void refreshWithUpstreamToken_success_carryForwardWhenResponseOmitsRt() throws Exception {
        AccessToken at = new BearerAccessToken("li_new_at", 86399L, null);
        AccessTokenResponse success = new AccessTokenResponse(new Tokens(at, /* refreshToken */ null));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        TokenWrapper wrapper = impl.refreshWithUpstreamToken("li_rt_original");

        assertNotNull(wrapper);
        assertEquals("li_rt_original", wrapper.refreshToken(),
                "defensive carry-forward — when Linear omits a rotated RT, prior RT must persist");
    }

    @Test
    void refreshWithUpstreamToken_success_defaultsTo24hWhenExpiresInMissing() throws Exception {
        AccessToken at = new BearerAccessToken("li_new_at"); // no lifetime
        AccessTokenResponse success = new AccessTokenResponse(
                new Tokens(at, new RefreshToken("li_rt_new")));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        TokenWrapper wrapper = impl.refreshWithUpstreamToken("li_rt_old");

        assertNotNull(wrapper);
        assertEquals(TokenExchangeServiceLinearImpl.LINEAR_DEFAULT_TOKEN_TTL, wrapper.ttl());
        assertEquals(86_399L, TokenExchangeServiceLinearImpl.LINEAR_DEFAULT_TOKEN_TTL,
                "default lifetime constant must equal Linear's documented expires_in (86399 ~24h)");
    }

    @Test
    void refreshWithUpstreamToken_invalidGrant_returnsNull() throws Exception {
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "revoked", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        // Legacy passthrough impl does NOT throw OktaTokenRevokedException — that's the canonical
        // L2 client's contract. Here we just return null so the caller falls through.
        assertNull(impl.refreshWithUpstreamToken("rt"));
    }

    @Test
    void refreshWithUpstreamToken_serverError_returnsNull() throws Exception {
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("server_error", "internal", 500));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        assertNull(impl.refreshWithUpstreamToken("rt"));
    }

    @Test
    void refreshWithUpstreamToken_ioException_returnsNull() throws Exception {
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        assertNull(impl.refreshWithUpstreamToken("rt"));
    }
}
