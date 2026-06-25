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

import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryProviderResolver;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link TokenExchangeServiceGeminiEnterpriseImpl}, which reuses the Google Workspace
 * pass-through base. The Gemini upstream-refresh HTTP call lives in
 * {@link GeminiEnterpriseUpstreamRefreshClient}; the legacy {@code refreshWithUpstreamToken} on
 * this class is an unreachable safety stub (promoted providers route through
 * {@link UpstreamRefreshService}).
 */
class TokenExchangeServiceGeminiEnterpriseImplTest {

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private TelemetryProviderResolver telemetryProviderResolver;

    @Mock
    private TelemetryRequestContext telemetryRequestContext;

    @Mock
    private MetricsRegionProvider metricsRegionProvider;

    @InjectMocks
    private TokenExchangeServiceGeminiEnterpriseImpl tokenExchangeService;

    private TokenWrapper tokenWrapper;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(telemetryProviderResolver.fromResourceUri(any())).thenReturn(OauthProviderLabel.GEMINI_ENTERPRISE);
        when(telemetryRequestContext.oauthClient()).thenReturn("unknown");
        when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");
        tokenExchangeService.setProviderLabel(OauthProviderLabel.GEMINI_ENTERPRISE);

        tokenWrapper = new TokenWrapper(
                "gemini-enterprise-key",
                "gemini-enterprise-provider",
                "gemini-enterprise-id-token",
                "gemini-enterprise-access-token",
                "gemini-enterprise-refresh-token",
                3600L
        );
    }

    @Test
    void testSetProviderLabel() {
        tokenExchangeService.setProviderLabel(OauthProviderLabel.GEMINI_ENTERPRISE);
        assertEquals(OauthProviderLabel.GEMINI_ENTERPRISE, tokenExchangeService.getProviderLabel());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_PassThrough() {
        List<String> scopes = Collections.singletonList("https://www.googleapis.com/auth/cloud-platform");
        TokenExchangeDO tokenExchangeDO = new TokenExchangeDO(scopes, "gemini-resource", "ns", "rs", tokenWrapper);

        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertSame(tokenWrapper, result.token());
    }

    @Test
    void testRefreshWithUpstreamToken_alwaysReturnsNullPostL2Promotion() {
        assertNull(tokenExchangeService.refreshWithUpstreamToken(null));
        assertNull(tokenExchangeService.refreshWithUpstreamToken(""));
        assertNull(tokenExchangeService.refreshWithUpstreamToken("any-non-empty-rt"));
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_ThrowsRuntimeException() {
        TokenExchangeDO tokenExchangeDO = new TokenExchangeDO(List.of("openid"), "resource", "ns", "rs", tokenWrapper);
        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO));
        assertEquals("Not implemented yet", exception.getMessage());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_ThrowsRuntimeException() {
        TokenExchangeDO tokenExchangeDO = new TokenExchangeDO(List.of("openid"), "resource", "ns", "rs", tokenWrapper);
        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO));
        assertEquals("Not implemented yet", exception.getMessage());
    }
}
