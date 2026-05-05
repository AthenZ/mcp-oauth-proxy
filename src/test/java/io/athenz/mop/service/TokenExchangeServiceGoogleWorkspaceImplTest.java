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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Tests for the slimmed-down {@link TokenExchangeServiceGoogleWorkspaceImpl}.
 *
 * <p>The Google upstream-refresh HTTP call has moved to
 * {@link GoogleWorkspaceUpstreamRefreshClient}; the legacy
 * {@code refreshWithUpstreamToken} on this class is now an unreachable safety stub that logs an
 * error and returns null. The remaining responsibilities — provider-label management,
 * resource-authorization-server pass-through, and unsupported-grant guards — are exercised here.
 */
class TokenExchangeServiceGoogleWorkspaceImplTest {

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private TelemetryProviderResolver telemetryProviderResolver;

    @Mock
    private TelemetryRequestContext telemetryRequestContext;

    @Mock
    private MetricsRegionProvider metricsRegionProvider;

    @InjectMocks
    private TokenExchangeServiceGoogleWorkspaceImpl tokenExchangeService;

    private TokenWrapper tokenWrapper;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(telemetryProviderResolver.fromResourceUri(any())).thenReturn("google-cloud-platform");
        when(telemetryRequestContext.oauthClient()).thenReturn("unknown");
        when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");
        tokenExchangeService.setProviderLabel(OauthProviderLabel.GOOGLE_CLOUD_PLATFORM);

        tokenWrapper = new TokenWrapper(
                "google-workspace-key",
                "google-workspace-provider",
                "google-workspace-id-token",
                "google-workspace-access-token",
                "google-workspace-refresh-token",
                3600L
        );
    }

    @Test
    void testDefaultProviderLabelIsNull() {
        TokenExchangeServiceGoogleWorkspaceImpl fresh = new TokenExchangeServiceGoogleWorkspaceImpl();
        assertNull(fresh.getProviderLabel());
    }

    @Test
    void testSetProviderLabel() {
        tokenExchangeService.setProviderLabel("google-drive");
        assertEquals("google-drive", tokenExchangeService.getProviderLabel());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testProviderLabelCanBeSetToAnyGoogleWorkspaceProvider(String provider) {
        tokenExchangeService.setProviderLabel(provider);
        assertEquals(provider, tokenExchangeService.getProviderLabel());
    }

    @Test
    void testGetJWTAuthorizationGrantFromIdentityProvider_ThrowsRuntimeException() {
        List<String> scopes = List.of("openid", "email", "profile");
        TokenExchangeDO tokenExchangeDO = new TokenExchangeDO(scopes, "resource", "ns", "rs", tokenWrapper);

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
            tokenExchangeService.getJWTAuthorizationGrantFromIdentityProvider(tokenExchangeDO));
        assertEquals("Not implemented yet", exception.getMessage());
    }

    /**
     * After the L2 promotion, the legacy direct refresh path is unreachable for promoted Google
     * providers and exists only as a safety stub. It must always return null and never call out
     * to Google. The test asserts the contract for both null and non-null inputs so any future
     * change that re-introduces a direct call will fail this test.
     */
    @Test
    void testRefreshWithUpstreamToken_alwaysReturnsNullPostL2Promotion() {
        assertNull(tokenExchangeService.refreshWithUpstreamToken(null));
        assertNull(tokenExchangeService.refreshWithUpstreamToken(""));
        assertNull(tokenExchangeService.refreshWithUpstreamToken("any-non-empty-rt"));
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_Success() {
        List<String> scopes = Collections.singletonList("https://www.googleapis.com/auth/cloud-platform");
        TokenExchangeDO tokenExchangeDO = new TokenExchangeDO(scopes, "workspace-resource", "ns", "rs", tokenWrapper);

        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(tokenWrapper, result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServer_ReturnsOriginalTokenWrapper() {
        List<String> scopes = List.of("openid");
        TokenExchangeDO tokenExchangeDO = new TokenExchangeDO(scopes, "resource", "ns", "rs", tokenWrapper);

        AuthorizationResultDO result = tokenExchangeService.getAccessTokenFromResourceAuthorizationServer(tokenExchangeDO);

        assertSame(tokenWrapper, result.token());
    }

    @Test
    void testGetAccessTokenFromResourceAuthorizationServerWithClientCredentials_ThrowsRuntimeException() {
        List<String> scopes = List.of("openid", "email");
        TokenExchangeDO tokenExchangeDO = new TokenExchangeDO(scopes, "resource", "ns", "rs", tokenWrapper);

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
            tokenExchangeService.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(tokenExchangeDO));
        assertEquals("Not implemented yet", exception.getMessage());
    }
}
