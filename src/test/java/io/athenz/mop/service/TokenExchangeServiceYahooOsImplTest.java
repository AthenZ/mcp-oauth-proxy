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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.telemetry.ExchangeStep;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class TokenExchangeServiceYahooOsImplTest {

    private static final String RESOURCE = "https://mcp-gateway.ouryahoo.com/v1/yahoo-os/mcp";
    private static final String REMOTE_SERVER = "https://yahoo-os.example.com";
    // 32-byte secret for HS256 signing in tests.
    private static final byte[] HS256_SECRET = "0123456789abcdef0123456789abcdef".getBytes();

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private TelemetryRequestContext telemetryRequestContext;

    @Mock
    private MetricsRegionProvider metricsRegionProvider;

    @InjectMocks
    private TokenExchangeServiceYahooOsImpl service;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(telemetryRequestContext.oauthClient()).thenReturn("mcp-client");
        when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");
    }

    private TokenExchangeDO newRequest(TokenWrapper wrapper) {
        return new TokenExchangeDO(
                Collections.emptyList(),
                RESOURCE,
                "ignored-namespace",
                REMOTE_SERVER,
                wrapper,
                null);
    }

    private static String signedIdTokenExpiringIn(long secondsFromNow) {
        try {
            Date exp = Date.from(Instant.now().plusSeconds(secondsFromNow));
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("00uoqmkz1ru90YPep696")
                    .expirationTime(exp)
                    .build();
            SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
            jwt.sign(new MACSigner(HS256_SECRET));
            return jwt.serialize();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // --- Success ---

    @Test
    void getAccessToken_success_returnsOktaIdTokenAsAccessToken() {
        String idToken = signedIdTokenExpiringIn(1800);
        TokenWrapper oktaToken = new TokenWrapper("user-key", "okta", idToken, null, "okta-refresh", 3600L);

        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(oktaToken));

        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertNotNull(result.token());
        assertEquals("user-key", result.token().key());
        assertEquals(REMOTE_SERVER, result.token().provider());
        assertNull(result.token().idToken());
        assertEquals(idToken, result.token().accessToken());
        assertNull(result.token().refreshToken());
        // ttl derived from exp (~1800s), allow slack for clock/test execution time.
        long ttl = result.token().ttl();
        assertTrue(ttl > 1700 && ttl <= 1800, "ttl should be derived from id_token exp, was " + ttl);

        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.YAHOO_OS_ID_TOKEN),
                eq(OauthProviderLabel.YAHOO_OS),
                eq(true),
                eq(null),
                eq("mcp-client"),
                eq("us-east-1"),
                anyDouble());
    }

    @Test
    void getAccessToken_nonJwtIdToken_usesDefaultTtl() {
        TokenWrapper oktaToken = new TokenWrapper("user-key", "okta", "not-a-jwt", null, null, 3600L);

        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(oktaToken));

        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals("not-a-jwt", result.token().accessToken());
        assertEquals(TokenExchangeServiceYahooOsImpl.DEFAULT_TTL_SECONDS, result.token().ttl());
    }

    @Test
    void getAccessToken_expiredIdToken_ttlFlooredAtZero() {
        String idToken = signedIdTokenExpiringIn(-100);
        TokenWrapper oktaToken = new TokenWrapper("user-key", "okta", idToken, null, null, 3600L);

        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(oktaToken));

        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertEquals(0L, result.token().ttl());
    }

    // --- Validation failures ---

    @Test
    void getAccessToken_nullRequest_returnsUnauthorizedAndRecordsFailure() {
        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(null);
        assertNotNull(result);
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        assertNull(result.token());
        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.YAHOO_OS_ID_TOKEN),
                eq(OauthProviderLabel.YAHOO_OS),
                eq(false),
                eq("unauthorized"),
                eq("mcp-client"),
                eq("us-east-1"),
                anyDouble());
    }

    @Test
    void getAccessToken_nullTokenWrapper_returnsUnauthorized() {
        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(null));
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        assertNull(result.token());
    }

    @Test
    void getAccessToken_blankIdToken_returnsUnauthorized() {
        TokenWrapper blank = new TokenWrapper("k", "okta", "  ", null, null, 3600L);
        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(blank));
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        assertNull(result.token());
    }

    @Test
    void getAccessToken_nullIdToken_returnsUnauthorized() {
        TokenWrapper blank = new TokenWrapper("k", "okta", null, null, null, 3600L);
        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(blank));
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
    }

    // --- Unsupported operations ---

    @Test
    void getJWTAuthorizationGrant_throws() {
        assertThrows(UnsupportedOperationException.class,
                () -> service.getJWTAuthorizationGrantFromIdentityProvider(newRequest(null)));
    }

    @Test
    void getAccessTokenWithClientCredentials_throws() {
        assertThrows(UnsupportedOperationException.class,
                () -> service.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(newRequest(null)));
    }

    @Test
    void refreshWithUpstreamToken_returnsNull() {
        assertNull(service.refreshWithUpstreamToken("any"));
        verify(oauthProxyMetrics, never()).recordExchangeStep(
                any(), anyString(), anyBoolean(), any(), anyString(), anyString(), anyDouble());
    }
}
