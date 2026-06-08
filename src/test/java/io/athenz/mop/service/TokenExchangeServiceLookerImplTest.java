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
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryProviderResolver;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.lenient;

/**
 * Unit tests for {@link TokenExchangeServiceLookerImpl}. Looker is L2-promoted, so the exchange
 * leg is a no-op pass-through and the legacy {@code refreshWithUpstreamToken} path is unreachable
 * (it returns null loudly). The canonical refresh path lives in {@link LookerUpstreamRefreshClient}
 * (covered by {@link LookerUpstreamRefreshClientTest}).
 */
@ExtendWith(MockitoExtension.class)
class TokenExchangeServiceLookerImplTest {

    @Mock
    OauthProxyMetrics oauthProxyMetrics;

    @Mock
    TelemetryProviderResolver telemetryProviderResolver;

    @Mock
    TelemetryRequestContext telemetryRequestContext;

    @Mock
    MetricsRegionProvider metricsRegionProvider;

    @InjectMocks
    TokenExchangeServiceLookerImpl impl;

    @BeforeEach
    void setUp() {
        impl.setProviderLabel("looker-ouryahoo");
        lenient().when(telemetryRequestContext.oauthClient()).thenReturn("test-client");
        lenient().when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");
        lenient().when(telemetryProviderResolver.fromResourceUri(org.mockito.ArgumentMatchers.anyString()))
                .thenReturn("looker-ouryahoo");
    }

    @Test
    void getAccessTokenFromResourceAuthorizationServer_passThrough_returnsAuthorizedWrapper() {
        TokenWrapper wrapper = new TokenWrapper(null, "looker-ouryahoo", null, "lk_at", "lk_rt", 3600L);
        TokenExchangeDO exchangeDO = new TokenExchangeDO(
                List.of(), "https://looker.example.test/mcp", "ns", "looker-ouryahoo", wrapper);

        AuthorizationResultDO result = impl.getAccessTokenFromResourceAuthorizationServer(exchangeDO);

        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertSame(wrapper, result.token(),
                "pass-through must return the same upstream token wrapper stored at consent");
    }

    @Test
    void refreshWithUpstreamToken_alwaysReturnsNull_forPromotedProvider() {
        // Looker is L2-promoted; the legacy single-arg refresh path must not issue an upstream
        // call (it cannot resolve the per-instance host/client_id and would bypass the L2 lock).
        assertNull(impl.refreshWithUpstreamToken("any-rt"));
        assertNull(impl.refreshWithUpstreamToken(null));
    }

    @Test
    void setProviderLabel_isReadBack() {
        impl.setProviderLabel("looker-enterprise");
        assertEquals("looker-enterprise", impl.getProviderLabel());
    }

    @Test
    void getJWTAuthorizationGrantFromIdentityProvider_notImplemented() {
        org.junit.jupiter.api.Assertions.assertThrows(RuntimeException.class,
                () -> impl.getJWTAuthorizationGrantFromIdentityProvider(null));
    }
}
