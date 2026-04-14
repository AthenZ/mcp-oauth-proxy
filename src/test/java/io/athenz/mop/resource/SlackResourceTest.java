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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SlackResourceTest {

    private static final String STATE = "test-state-123";
    private static final String SUBJECT = "slack-subject";
    private static final String REDIRECT_URI = "https://client.example.com/callback";
    private static final String AUTH_CODE_STATE = "auth-code-state";
    private static final String ACCESS_TOKEN = "xoxp-slack-access-token";
    private static final String REFRESH_TOKEN = "xoxr-slack-refresh-token";
    private static final String LOOKUP_KEY = "U12345";
    private static final String RESOURCE = "https://local.sample-mcp.experiments.athenz.ouryahoo.com:8443/v1/slack/mcp";

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
    private SlackResource slackResource;

    private AuthorizationCode authorizationCode;

    @BeforeEach
    void setUp() {
        slackResource.providerDefault = "okta";
        authorizationCode = new AuthorizationCode(
                "code-1",
                "client-1",
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
        Response response = slackResource.authorize(null);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        @SuppressWarnings("unchecked")
        Map<String, String> entity = (Map<String, String>) response.getEntity();
        assertEquals("invalid_request", entity.get("error"));
        assertEquals("Missing state parameter", entity.get("error_description"));
    }

    @Test
    void authorize_emptyState_returnsBadRequest() {
        Response response = slackResource.authorize("");

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        @SuppressWarnings("unchecked")
        Map<String, String> entity = (Map<String, String>) response.getEntity();
        assertEquals("invalid_request", entity.get("error"));
    }

    @Test
    void authorize_authCodeNotFound_returnsBadRequest() {
        lenient().when(userInfo.get("user_id")).thenReturn("U12345");
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(null, false));

        Response response = slackResource.authorize(STATE);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        @SuppressWarnings("unchecked")
        Map<String, String> entity = (Map<String, String>) response.getEntity();
        assertEquals("invalid_grant", entity.get("error"));
        assertEquals("Authorization code not found or expired", entity.get("error_description"));
    }

    @Test
    void authorize_withNewRefreshToken_storesAndRedirects() {
        when(userInfo.get("user_id")).thenReturn("U12345");
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim("slack")).thenReturn("user_id");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        RefreshToken refreshToken = new RefreshToken(REFRESH_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(refreshToken);
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        Response response = slackResource.authorize(STATE);

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        verify(authorizerService).storeTokens(
                eq(LOOKUP_KEY), eq(SUBJECT), eq(ACCESS_TOKEN), eq(ACCESS_TOKEN), eq(REFRESH_TOKEN), eq("slack"));
        verify(oidcSession).logout();
    }

    @Test
    void authorize_noNewRefreshToken_usesExistingUpstream() {
        when(userInfo.get("user_id")).thenReturn("U12345");
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim("slack")).thenReturn("user_id");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(null);
        when(refreshTokenService.getUpstreamRefreshToken(SUBJECT, "slack"))
                .thenReturn("existing-upstream-refresh");
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        Response response = slackResource.authorize(STATE);

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        verify(authorizerService).storeTokens(
                eq(LOOKUP_KEY), eq(SUBJECT), eq(ACCESS_TOKEN), eq(ACCESS_TOKEN), eq("existing-upstream-refresh"), eq("slack"));
    }

    @Test
    void authorize_noRefreshTokenAnywhere_returnsServerError() {
        when(userInfo.get("user_id")).thenReturn("U12345");
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim("slack")).thenReturn("user_id");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(null);
        when(refreshTokenService.getUpstreamRefreshToken(SUBJECT, "slack")).thenReturn(null);
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        Response response = slackResource.authorize(STATE);

        assertEquals(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
        verify(authorizerService, never()).storeTokens(any(), any(), any(), any(), any(), any());
        verify(oidcSession).logout();
    }

    @Test
    void authorize_newRefreshTokenPreferred_overExistingUpstream() {
        when(userInfo.get("user_id")).thenReturn("U12345");
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim("slack")).thenReturn("user_id");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        RefreshToken refreshToken = new RefreshToken("brand-new-refresh");
        when(accessTokenCredential.getRefreshToken()).thenReturn(refreshToken);
        when(refreshTokenService.getUpstreamRefreshToken(SUBJECT, "slack"))
                .thenReturn("old-upstream-refresh");
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        Response response = slackResource.authorize(STATE);

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        verify(authorizerService).storeTokens(
                eq(LOOKUP_KEY), eq(SUBJECT), eq(ACCESS_TOKEN), eq(ACCESS_TOKEN), eq("brand-new-refresh"), eq("slack"));
    }

    @Test
    void authorize_callsLogoutFromProvider() {
        when(userInfo.get("user_id")).thenReturn("U12345");
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim("slack")).thenReturn("user_id");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        RefreshToken refreshToken = new RefreshToken(REFRESH_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(refreshToken);
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        slackResource.authorize(STATE);

        verify(oidcSession).logout();
    }

    @Test
    void authorize_redirectContainsCorrectUri() {
        when(userInfo.get("user_id")).thenReturn("U12345");
        when(authCodeRegionResolver.resolve(STATE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(configService.getRemoteServerUsernameClaim("slack")).thenReturn("user_id");
        when(accessTokenCredential.getToken()).thenReturn(ACCESS_TOKEN);
        RefreshToken refreshToken = new RefreshToken(REFRESH_TOKEN);
        when(accessTokenCredential.getRefreshToken()).thenReturn(refreshToken);
        when(oidcSession.logout()).thenReturn(Uni.createFrom().voidItem());

        Response response = slackResource.authorize(STATE);

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        assertNotNull(response.getLocation());
        String location = response.getLocation().toString();
        assert location.startsWith(REDIRECT_URI);
    }
}
