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
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
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
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TokenExchangeServiceWisdomAiImpl#refreshWithUpstreamToken(String)} (the
 * legacy/native fallback path used by {@code AuthorizerService.refreshUpstreamAndGetToken}). The
 * canonical L2 refresh path lives in {@link WisdomAiUpstreamRefreshClient} and is covered by
 * {@link WisdomAiUpstreamRefreshClientTest}.
 *
 * <p>WisdomAI is a Descope-backed confidential client: client_secret_post first, with one-shot
 * fallback to client_secret_basic on invalid_client. These tests pin both the wire shape and the
 * fallback contract.
 */
@ExtendWith(MockitoExtension.class)
class TokenExchangeServiceWisdomAiImplTest {

    private static final String TEST_CLIENT_ID = "test-wisdomai-client-id";
    private static final String TEST_CLIENT_SECRET_KEY = "wisdomai-client-secret";
    private static final String TEST_CLIENT_SECRET = "test-wisdomai-secret-value";

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
    TokenExchangeServiceWisdomAiImpl impl;

    @BeforeEach
    void setUp() {
        impl.clientId = TEST_CLIENT_ID;
        impl.clientSecretKey = TEST_CLIENT_SECRET_KEY;
        lenient().when(telemetryRequestContext.oauthClient()).thenReturn("test-client");
        lenient().when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");
    }

    private void stubSecret() {
        when(k8SSecretsProvider.getCredentials(null))
                .thenReturn(Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
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
    void refreshWithUpstreamToken_missingClientSecretValue_returnsNull() {
        // K8s store has no entry for the configured key — fall back to null without NPE.
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of());
        assertNull(impl.refreshWithUpstreamToken("rt"));
    }

    @Test
    void refreshWithUpstreamToken_success_returnsRotatedRtAnd7dTtl() throws Exception {
        stubSecret();
        AccessToken at = new BearerAccessToken("wai_new_at", 604_800L, null);
        AccessTokenResponse success = new AccessTokenResponse(
                new Tokens(at, new RefreshToken("wai_rt_new")));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        TokenWrapper wrapper = impl.refreshWithUpstreamToken("wai_rt_old");

        assertNotNull(wrapper);
        assertEquals("wai_new_at", wrapper.accessToken());
        assertEquals("wai_rt_new", wrapper.refreshToken(),
                "response RT must replace the prior RT when present");
        assertEquals(604_800L, wrapper.ttl());
    }

    @Test
    void refreshWithUpstreamToken_success_carryForwardWhenResponseOmitsRt() throws Exception {
        stubSecret();
        AccessToken at = new BearerAccessToken("wai_new_at", 604_800L, null);
        AccessTokenResponse success = new AccessTokenResponse(new Tokens(at, /* refreshToken */ null));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        TokenWrapper wrapper = impl.refreshWithUpstreamToken("wai_rt_original");

        assertNotNull(wrapper);
        assertEquals("wai_rt_original", wrapper.refreshToken(),
                "defensive carry-forward -- when WisdomAI omits a rotated RT, prior RT must persist");
    }

    @Test
    void refreshWithUpstreamToken_success_defaultsTo7dWhenExpiresInMissing() throws Exception {
        stubSecret();
        AccessToken at = new BearerAccessToken("wai_new_at"); // no lifetime
        AccessTokenResponse success = new AccessTokenResponse(
                new Tokens(at, new RefreshToken("wai_rt_new")));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        TokenWrapper wrapper = impl.refreshWithUpstreamToken("wai_rt_old");

        assertNotNull(wrapper);
        assertEquals(TokenExchangeServiceWisdomAiImpl.WISDOMAI_DEFAULT_TOKEN_TTL, wrapper.ttl());
        assertEquals(604_800L, TokenExchangeServiceWisdomAiImpl.WISDOMAI_DEFAULT_TOKEN_TTL,
                "default lifetime constant must equal WisdomAI's documented expires_in (604800 ~7d)");
    }

    @Test
    void refreshWithUpstreamToken_invalidGrant_returnsNull_singleAttempt() throws Exception {
        stubSecret();
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "revoked", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        // Legacy passthrough impl does NOT throw OktaTokenRevokedException -- that's the canonical
        // L2 client's contract. Here we just return null so the caller falls through.
        assertNull(impl.refreshWithUpstreamToken("rt"));

        // invalid_grant must NOT trigger the basic-auth retry.
        verify(tokenClient, times(1)).execute(any(TokenRequest.class));
    }

    @Test
    void refreshWithUpstreamToken_serverError_returnsNull_singleAttempt() throws Exception {
        stubSecret();
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("server_error", "internal", 500));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        assertNull(impl.refreshWithUpstreamToken("rt"));
        verify(tokenClient, times(1)).execute(any(TokenRequest.class));
    }

    @Test
    void refreshWithUpstreamToken_ioException_returnsNull() throws Exception {
        stubSecret();
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        assertNull(impl.refreshWithUpstreamToken("rt"));
    }

    @Test
    void refreshWithUpstreamToken_firstAttemptUsesClientSecretPost() throws Exception {
        stubSecret();
        AccessToken at = new BearerAccessToken("wai_new_at", 604_800L, null);
        AccessTokenResponse success = new AccessTokenResponse(
                new Tokens(at, new RefreshToken("wai_rt_new")));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        impl.refreshWithUpstreamToken("wai_rt_old");

        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);
        verify(tokenClient).execute(captor.capture());
        assertInstanceOf(ClientSecretPost.class, captor.getValue().getClientAuthentication(),
                "first attempt must use client_secret_post");
    }

    @Test
    void refreshWithUpstreamToken_invalidClientOnPost_retriesOnceWithBasic_andSucceeds() throws Exception {
        stubSecret();
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_client", "Bad client auth method", 401));
        AccessToken at = new BearerAccessToken("wai_new_at", 604_800L, null);
        AccessTokenResponse success = new AccessTokenResponse(
                new Tokens(at, new RefreshToken("wai_rt_new")));
        when(tokenClient.execute(any(TokenRequest.class)))
                .thenReturn(err)
                .thenReturn(success);

        TokenWrapper wrapper = impl.refreshWithUpstreamToken("wai_rt_old");

        assertNotNull(wrapper);
        assertEquals("wai_new_at", wrapper.accessToken());

        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);
        verify(tokenClient, times(2)).execute(captor.capture());
        assertInstanceOf(ClientSecretPost.class, captor.getAllValues().get(0).getClientAuthentication(),
                "first attempt must use client_secret_post");
        assertInstanceOf(ClientSecretBasic.class, captor.getAllValues().get(1).getClientAuthentication(),
                "second attempt (after invalid_client) must fall back to client_secret_basic");
    }

    @Test
    void refreshWithUpstreamToken_invalidClientOnBoth_returnsNull_andDoesNotLoop() throws Exception {
        stubSecret();
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_client", "still bad", 401));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        assertNull(impl.refreshWithUpstreamToken("rt"));
        verify(tokenClient, times(2)).execute(any(TokenRequest.class));
    }
}
