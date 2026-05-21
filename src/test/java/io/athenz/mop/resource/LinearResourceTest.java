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

import io.athenz.mop.model.AuthorizationCode;
import io.athenz.mop.service.AuthCodeRegionResolver;
import io.athenz.mop.service.AuthCodeResolution;
import io.athenz.mop.service.AuthorizerService;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.RefreshTokenService;
import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.oidc.OidcSession;
import io.quarkus.oidc.RefreshToken;
import io.quarkus.oidc.UserInfo;
import io.smallrye.mutiny.Uni;
import jakarta.ws.rs.core.Response;

import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link LinearResource}. Modeled on {@link DatadogResourceTest}; pins the
 * Linear-specific contract:
 *
 * <ul>
 *   <li>Username claim is {@code email}, and {@code BaseResource.getUsername} strips the
 *       {@code @domain} suffix so the stored {@code lookupKey} is the short id (e.g.
 *       {@code yosrixp} for {@code yosrixp@yahooinc.com}).</li>
 *   <li>The 8-arg {@code AuthorizerService.storeTokens} overload is used with
 *       {@link LinearResource#LINEAR_ACCESS_TOKEN_LIFETIME_SECONDS} (~24 h) so the bare L1 row
 *       outlives the global ~8h {@code server.token-store.expiry} cap. Without this the row
 *       would evict 8h after consent and force re-consent while the upstream Linear AT is still
 *       valid.</li>
 *   <li>Borrow-RT path exercises {@code refreshTokenService.getUpstreamRefreshToken(lookupKey,
 *       "linear")} when the OIDC session has no fresh RT.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class LinearResourceTest {

    private static final String STATE = "test-state-linear";
    private static final String SUBJECT = "linear-subject-uuid";
    private static final String REDIRECT_URI = "https://client.example.com/callback";
    private static final String AUTH_CODE_STATE = "auth-code-state";
    private static final String ACCESS_TOKEN = "lin_oat_access_token";
    private static final String REFRESH_TOKEN = "lin_oar_refresh_token";
    private static final String EMAIL = "yosrixp@yahooinc.com";
    private static final String LOOKUP_KEY = "yosrixp";
    private static final String CLIENT_ID = "mcp-client-1";
    private static final String RESOURCE = "https://local.sample-mcp.experiments.athenz.ouryahoo.com:8443/v1/linear/mcp";
    private static final long EXPECTED_LIFETIME = 86_399L;

    @Mock
    private AuthorizerService authorizerService;

    @Mock
    private AccessTokenCredential accessTokenCredential;

    @Mock
    private AuthCodeRegionResolver authCodeRegionResolver;

    @Mock
    private UserInfo userInfo;

    @Mock
    private OidcSession oidcSession;

    @Mock
    private ConfigService configService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private LinearResource linearResource;

    private AuthorizationCode authorizationCode;

    @BeforeEach
    void setUp() {
        linearResource.providerDefault = "okta";
        authorizationCode = new AuthorizationCode(
                "code-1",
                CLIENT_ID,
                SUBJECT,
                REDIRECT_URI,
                "default",
                RESOURCE,
                "challenge",
                "S256",
                Instant.now().plusSeconds(600),
                AUTH_CODE_STATE);
    }

    @Test
    void authorize_nullState_returnsBadRequest() {
        Response response = linearResource.authorize(null);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        @SuppressWarnings("unchecked")
        Map<String, String> entity = (Map<String, String>) response.getEntity();
        assertEquals("invalid_request", entity.get("error"));
        assertEquals("Missing state parameter", entity.get("error_description"));
    }

    @Test
    void authorize_emptyState_returnsBadRequest() {
        Response response = linearResource.authorize("");

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        @SuppressWarnings("unchecked")
        Map<String, String> entity = (Map<String, String>) response.getEntity();
        assertEquals("invalid_request", entity.get("error"));
    }

    @Test
    void authorize_authCodeNotFound_returnsBadRequest() {
        lenient().when(userInfo.get("email")).thenReturn(EMAIL);
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(null, false));

        Response response = linearResource.authorize(STATE);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        @SuppressWarnings("unchecked")
        Map<String, String> entity = (Map<String, String>) response.getEntity();
        assertEquals("invalid_grant", entity.get("error"));
        assertEquals("Authorization code not found or expired", entity.get("error_description"));
    }

    @Test
    void authorize_withNewRefreshToken_storesAndRedirectsWith24hLifetime() {
        when(userInfo.get("email")).thenReturn(EMAIL);
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim("linear")).thenReturn("email");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        RefreshToken refreshToken = new RefreshToken(REFRESH_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(refreshToken);
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        Response response = linearResource.authorize(STATE);

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        // Pins the 8-arg storeTokens overload: idToken == accessToken, AT lifetime = 86399s
        // (Linear's documented expires_in). The bare L1 row TTL must outlive the global
        // ~8h server.token-store.expiry, otherwise the row evicts before the upstream Linear
        // AT actually expires.
        verify(authorizerService).storeTokens(
                eq(LOOKUP_KEY), eq(SUBJECT), eq(ACCESS_TOKEN), eq(ACCESS_TOKEN),
                eq(REFRESH_TOKEN), eq("linear"), eq(CLIENT_ID), eq(EXPECTED_LIFETIME));
        verify(oidcSession).logout();
    }

    @Test
    void authorize_emailClaim_isStrippedToShortId() {
        when(userInfo.get("email")).thenReturn("alice@yahooinc.com");
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim("linear")).thenReturn("email");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(new RefreshToken(REFRESH_TOKEN));
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        linearResource.authorize(STATE);

        verify(authorizerService).storeTokens(
                eq("alice"), eq(SUBJECT), eq(ACCESS_TOKEN), eq(ACCESS_TOKEN),
                eq(REFRESH_TOKEN), eq("linear"), eq(CLIENT_ID), eq(EXPECTED_LIFETIME));
    }

    @Test
    void authorize_noNewRefreshToken_borrowsCanonicalUpstream() {
        // Second/third MCP-client window relogin: no fresh RT in the OIDC session, but the L2
        // row already has a canonical upstream RT. With Linear's RT rotating on every refresh,
        // the borrowed RT is the freshest known good value to seed the next AT exchange.
        when(userInfo.get("email")).thenReturn(EMAIL);
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim("linear")).thenReturn("email");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(null);
        when(refreshTokenService.getUpstreamRefreshToken(LOOKUP_KEY, "linear"))
                .thenReturn("existing-canonical-rt");
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        Response response = linearResource.authorize(STATE);

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        verify(authorizerService).storeTokens(
                eq(LOOKUP_KEY), eq(SUBJECT), eq(ACCESS_TOKEN), eq(ACCESS_TOKEN),
                eq("existing-canonical-rt"), eq("linear"), eq(CLIENT_ID), eq(EXPECTED_LIFETIME));
    }

    @Test
    void authorize_noRefreshTokenAnywhere_storesNullRtAndRedirects() {
        when(userInfo.get("email")).thenReturn(EMAIL);
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim("linear")).thenReturn("email");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(null);
        when(refreshTokenService.getUpstreamRefreshToken(LOOKUP_KEY, "linear")).thenReturn(null);
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        Response response = linearResource.authorize(STATE);

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        verify(authorizerService).storeTokens(
                eq(LOOKUP_KEY), eq(SUBJECT), eq(ACCESS_TOKEN), eq(ACCESS_TOKEN),
                eq((String) null), eq("linear"), eq(CLIENT_ID), eq(EXPECTED_LIFETIME));
    }

    @Test
    void authorize_newRefreshTokenPreferred_overExistingUpstream() {
        when(userInfo.get("email")).thenReturn(EMAIL);
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim("linear")).thenReturn("email");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        RefreshToken refreshToken = new RefreshToken("brand-new-refresh");
        when(accessTokenCredential.getRefreshToken()).thenReturn(refreshToken);
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        Response response = linearResource.authorize(STATE);

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        verify(authorizerService).storeTokens(
                eq(LOOKUP_KEY), eq(SUBJECT), eq(ACCESS_TOKEN), eq(ACCESS_TOKEN),
                eq("brand-new-refresh"), eq("linear"), eq(CLIENT_ID), eq(EXPECTED_LIFETIME));
        verify(refreshTokenService, never()).getUpstreamRefreshToken(anyString(), any());
    }

    @Test
    void authorize_callsLogoutFromProvider() {
        when(userInfo.get("email")).thenReturn(EMAIL);
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim("linear")).thenReturn("email");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(new RefreshToken(REFRESH_TOKEN));
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        linearResource.authorize(STATE);

        verify(oidcSession).logout();
    }

    @Test
    void authorize_redirectContainsCorrectUri() {
        when(userInfo.get("email")).thenReturn(EMAIL);
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim("linear")).thenReturn("email");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(new RefreshToken(REFRESH_TOKEN));
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        Response response = linearResource.authorize(STATE);

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        assertNotNull(response.getLocation());
        String location = response.getLocation().toString();
        assert location.startsWith(REDIRECT_URI);
    }
}
