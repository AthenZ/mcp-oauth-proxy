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
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
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
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TokenExchangeServiceDatahubImpl}: PASS_THROUGH exchange leg plus the
 * legacy {@code refreshWithUpstreamToken} fallback (client_secret_basic + RFC 8707 resource
 * indicator). The canonical L2 refresh path lives in {@link DatahubUpstreamRefreshClient}
 * (covered by {@link DatahubUpstreamRefreshClientTest}).
 */
@ExtendWith(MockitoExtension.class)
class TokenExchangeServiceDatahubImplTest {

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
    TokenExchangeServiceDatahubImpl impl;

    @BeforeEach
    void setUp() {
        impl.clientId = "test-datahub-client-id";
        impl.clientSecretKey = "datahub-client-secret";
        lenient().when(telemetryRequestContext.oauthClient()).thenReturn("test-client");
        lenient().when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");
        lenient().when(telemetryProviderResolver.fromResourceUri(org.mockito.ArgumentMatchers.anyString()))
                .thenReturn("datahub");
    }

    @Test
    void getAccessTokenFromResourceAuthorizationServer_passThrough_returnsAuthorizedWrapper() {
        TokenWrapper wrapper = new TokenWrapper(null, "datahub", null, "dh_at", "dh_rt", 3599L);
        TokenExchangeDO exchangeDO = new TokenExchangeDO(
                List.of(), "https://gateway.example.test/v1/datahub/mcp", "ns", "datahub", wrapper);

        AuthorizationResultDO result = impl.getAccessTokenFromResourceAuthorizationServer(exchangeDO);

        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertSame(wrapper, result.token(),
                "pass-through must return the same upstream token wrapper stored at consent");
    }

    @Test
    void refreshWithUpstreamToken_blankOrMissingConfig_returnsNull() {
        assertNull(impl.refreshWithUpstreamToken(null));
        assertNull(impl.refreshWithUpstreamToken("  "));

        impl.clientId = "";
        assertNull(impl.refreshWithUpstreamToken("rt"));

        impl.clientId = "test-datahub-client-id";
        impl.clientSecretKey = "";
        assertNull(impl.refreshWithUpstreamToken("rt"));
    }

    @Test
    void refreshWithUpstreamToken_secretMissing_returnsNull() {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("other-key", "value"));
        assertNull(impl.refreshWithUpstreamToken("rt"));
    }

    @Test
    void refreshWithUpstreamToken_success_returnsWrapperWithRotatedRt() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("datahub-client-secret", "secret"));
        AccessToken at = new BearerAccessToken("dh_at_new", 3599L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("dh_rt_new"));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(new AccessTokenResponse(tokens));

        TokenWrapper wrapper = impl.refreshWithUpstreamToken("dh_rt_old");

        assertNotNull(wrapper);
        assertEquals("dh_at_new", wrapper.accessToken());
        assertEquals("dh_rt_new", wrapper.refreshToken());
        assertEquals(3599L, wrapper.ttl(),
            "expires_in must reflect DataHub's reported value, never a pinned constant");
    }

    @Test
    void refreshWithUpstreamToken_sendsBasicAuthAndResourceIndicator() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("datahub-client-secret", "secret"));
        AccessToken at = new BearerAccessToken("dh_at_new", 3599L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("dh_rt_new"));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(new AccessTokenResponse(tokens));

        impl.refreshWithUpstreamToken("dh_rt_old");

        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);
        verify(tokenClient).execute(captor.capture());
        TokenRequest sent = captor.getValue();
        assertInstanceOf(ClientSecretBasic.class, sent.getClientAuthentication(),
                "DataHub token auth must be HTTP Basic (client_secret_basic)");
        assertEquals(List.of(TokenExchangeServiceDatahubImpl.DATAHUB_RESOURCE), sent.getResources(),
                "the RFC 8707 resource indicator must ride along on the refresh grant");
    }

    @Test
    void refreshWithUpstreamToken_keepsOriginalRtWhenResponseOmitsRotation() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("datahub-client-secret", "secret"));
        AccessToken at = new BearerAccessToken("dh_at_new");
        Tokens tokens = new Tokens(at, /* refreshToken */ null);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(new AccessTokenResponse(tokens));

        TokenWrapper wrapper = impl.refreshWithUpstreamToken("  dh_rt_original  ");

        assertEquals("dh_rt_original", wrapper.refreshToken(),
                "must trim whitespace and carry the original RT forward when upstream omits a rotated one");
    }

    @Test
    void refreshWithUpstreamToken_upstreamError_returnsNull() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("datahub-client-secret", "secret"));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "Refresh token has been revoked.", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        assertNull(impl.refreshWithUpstreamToken("rt"));
    }

    @Test
    void refreshWithUpstreamToken_ioException_returnsNull() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("datahub-client-secret", "secret"));
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        assertNull(impl.refreshWithUpstreamToken("rt"));
    }

    @Test
    void getJWTAuthorizationGrantFromIdentityProvider_notImplemented() {
        assertThrows(RuntimeException.class,
                () -> impl.getJWTAuthorizationGrantFromIdentityProvider(null));
    }

    @Test
    void getAccessTokenFromResourceAuthorizationServerWithClientCredentials_notImplemented() {
        assertThrows(RuntimeException.class,
                () -> impl.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(null));
    }
}
