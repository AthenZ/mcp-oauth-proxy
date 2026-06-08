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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link LookerResource}. One resource serves all Looker instances via a
 * regex-constrained {@code {provider}} path; these tests pin:
 * <ul>
 *   <li>unknown / non-Looker provider -&gt; 404,</li>
 *   <li>missing state / auth-code-not-found error contracts,</li>
 *   <li>username claim {@code email} stripped to short id,</li>
 *   <li>the 8-arg {@code storeTokens} overload with Looker's ~1h AT lifetime, keyed by the
 *       per-instance provider id,</li>
 *   <li>borrow-canonical-upstream RT when the OIDC session has no fresh RT (Looker only returns
 *       the RT on the initial code exchange).</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class LookerResourceTest {

    private static final String PROVIDER = "looker-ouryahoo";
    private static final String STATE = "test-state-looker";
    private static final String SUBJECT = "looker-subject-5792";
    private static final String REDIRECT_URI = "https://client.example.com/callback";
    private static final String AUTH_CODE_STATE = "auth-code-state";
    private static final String ACCESS_TOKEN = "lk_access_token";
    private static final String REFRESH_TOKEN = "lk_refresh_token";
    private static final String EMAIL = "testuser@example.com";
    private static final String LOOKUP_KEY = "testuser";
    private static final String CLIENT_ID = "mcp-client-1";
    private static final String RESOURCE = "https://looker.example.test/mcp";
    private static final long EXPECTED_LIFETIME = 3_600L;

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
    private LookerResource lookerResource;

    private AuthorizationCode authorizationCode;

    @BeforeEach
    void setUp() {
        lookerResource.providerDefault = "okta";
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
    void authorize_unknownProvider_returnsNotFound() {
        Response response = lookerResource.authorize("looker-bogus", STATE);

        assertEquals(Response.Status.NOT_FOUND.getStatusCode(), response.getStatus());
        @SuppressWarnings("unchecked")
        Map<String, String> entity = (Map<String, String>) response.getEntity();
        assertEquals("invalid_request", entity.get("error"));
    }

    @Test
    void authorize_nullState_returnsBadRequest() {
        Response response = lookerResource.authorize(PROVIDER, null);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        @SuppressWarnings("unchecked")
        Map<String, String> entity = (Map<String, String>) response.getEntity();
        assertEquals("invalid_request", entity.get("error"));
        assertEquals("Missing state parameter", entity.get("error_description"));
    }

    @Test
    void authorize_authCodeNotFound_returnsBadRequest() {
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(null, false));

        Response response = lookerResource.authorize(PROVIDER, STATE);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        @SuppressWarnings("unchecked")
        Map<String, String> entity = (Map<String, String>) response.getEntity();
        assertEquals("invalid_grant", entity.get("error"));
        assertEquals("Authorization code not found or expired", entity.get("error_description"));
    }

    @Test
    void authorize_withNewRefreshToken_storesAndRedirectsWith1hLifetime() {
        when(userInfo.get("email")).thenReturn(EMAIL);
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim(PROVIDER)).thenReturn("email");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(new RefreshToken(REFRESH_TOKEN));
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        Response response = lookerResource.authorize(PROVIDER, STATE);

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        verify(authorizerService).storeTokens(
                eq(LOOKUP_KEY), eq(SUBJECT), eq(ACCESS_TOKEN), eq(ACCESS_TOKEN),
                eq(REFRESH_TOKEN), eq(PROVIDER), eq(CLIENT_ID), eq(EXPECTED_LIFETIME));
        verify(oidcSession).logout();
    }

    @Test
    void authorize_emailClaim_isStrippedToShortId() {
        when(userInfo.get("email")).thenReturn("alice@example.com");
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim(PROVIDER)).thenReturn("email");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(new RefreshToken(REFRESH_TOKEN));
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        lookerResource.authorize(PROVIDER, STATE);

        verify(authorizerService).storeTokens(
                eq("alice"), eq(SUBJECT), eq(ACCESS_TOKEN), eq(ACCESS_TOKEN),
                eq(REFRESH_TOKEN), eq(PROVIDER), eq(CLIENT_ID), eq(EXPECTED_LIFETIME));
    }

    @Test
    void authorize_noNewRefreshToken_borrowsCanonicalUpstream() {
        // Looker only returns the RT on the initial code exchange; a second MCP-client window
        // relogin has no fresh RT in the OIDC session, so we borrow the canonical L2 RT.
        when(userInfo.get("email")).thenReturn(EMAIL);
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim(PROVIDER)).thenReturn("email");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(null);
        when(refreshTokenService.getUpstreamRefreshToken(LOOKUP_KEY, PROVIDER))
                .thenReturn("existing-canonical-rt");
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        Response response = lookerResource.authorize(PROVIDER, STATE);

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        verify(authorizerService).storeTokens(
                eq(LOOKUP_KEY), eq(SUBJECT), eq(ACCESS_TOKEN), eq(ACCESS_TOKEN),
                eq("existing-canonical-rt"), eq(PROVIDER), eq(CLIENT_ID), eq(EXPECTED_LIFETIME));
    }

    @Test
    void authorize_enterpriseInstance_keysTokensByProvider() {
        // A different Looker instance keys the bare row + L2 row off its own provider id so the
        // two instances never collide for the same user.
        String enterprise = "looker-enterprise";
        when(userInfo.get("email")).thenReturn(EMAIL);
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim(enterprise)).thenReturn("email");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(new RefreshToken(REFRESH_TOKEN));
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        lookerResource.authorize(enterprise, STATE);

        verify(authorizerService).storeTokens(
                eq(LOOKUP_KEY), eq(SUBJECT), eq(ACCESS_TOKEN), eq(ACCESS_TOKEN),
                eq(REFRESH_TOKEN), eq(enterprise), eq(CLIENT_ID), eq(EXPECTED_LIFETIME));
    }

    @Test
    void authorize_redirectContainsClientRedirectUri() {
        lenient().when(userInfo.get("email")).thenReturn(EMAIL);
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim(PROVIDER)).thenReturn("email");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(new RefreshToken(REFRESH_TOKEN));
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        Response response = lookerResource.authorize(PROVIDER, STATE);

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        assertNotNull(response.getLocation());
        assert response.getLocation().toString().startsWith(REDIRECT_URI);
    }
}
