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

import io.athenz.mop.model.OAuth2AuthorizationRequest;
import io.athenz.mop.model.ResourceMeta;
import io.athenz.mop.service.AudienceConstants;
import io.athenz.mop.service.AuthorizationCodeService;
import io.athenz.mop.service.AuthorizerService;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.RedirectUriValidator;
import io.athenz.mop.service.UpstreamRefreshService;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.oidc.UserInfo;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AuthorizeResource} covering the opaque access-token fix:
 * when Okta issues an opaque (non-JWT) access token, the authorize handler must
 * not throw {@code OIDCException} and must forward the raw access token string to
 * {@link AuthorizerService#storeTokens(String, String, String, String, String, String)}
 * unchanged.
 */
@ExtendWith(MockitoExtension.class)
class AuthorizeResourceUnitTest {

    private static final String CLIENT_ID = "test-client";
    private static final String REDIRECT_URI = "https://app.example.com/callback";
    private static final String SCOPE = "openid";
    private static final String STATE = "state-xyz";
    private static final String CODE_CHALLENGE = "challenge";
    private static final String CODE_CHALLENGE_METHOD = "S256";
    private static final String KNOWN_RESOURCE = "https://api.example.com";
    private static final String USERNAME_CLAIM = "email";
    private static final String SUBJECT = "okta-subject-1";
    private static final String USERNAME = "user@example.com";
    // Intentionally NOT a JWT: three-part JWTs have two dots and base64-encoded segments;
    // an opaque Okta reference token is typically a short random string.
    private static final String OPAQUE_ACCESS_TOKEN = "AT.opaqueReferenceToken.abc123XYZ";

    @Mock
    private AuthorizerService authorizerService;

    @Mock
    private AuthorizationCodeService authorizationCodeService;

    @Mock
    private RedirectUriValidator redirectUriValidator;

    @Mock
    private ConfigService configService;

    @Mock
    private UpstreamRefreshService upstreamRefreshService;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private UserInfo userInfo;

    private AuthorizeResource authorizeResource;

    @BeforeEach
    void setUp() {
        authorizeResource = new AuthorizeResource();
        authorizeResource.authorizerService = authorizerService;
        authorizeResource.authorizationCodeService = authorizationCodeService;
        authorizeResource.redirectUriValidator = redirectUriValidator;
        authorizeResource.configService = configService;
        authorizeResource.upstreamRefreshService = upstreamRefreshService;
        authorizeResource.oauthProxyMetrics = oauthProxyMetrics;
        authorizeResource.userInfo = userInfo;
        authorizeResource.host = "mop.example.com";
        authorizeResource.providerDefault = AudienceConstants.PROVIDER_OKTA;
        // idToken intentionally left null to exercise the userInfo fallback path used when
        // an opaque access token is issued and no JWT id-token is available.
        authorizeResource.idToken = null;
        authorizeResource.refreshToken = null;
    }

    private OAuth2AuthorizationRequest newRequest(String resource) {
        OAuth2AuthorizationRequest req = new OAuth2AuthorizationRequest();
        req.setResponseType("code");
        req.setClientId(CLIENT_ID);
        req.setRedirectUri(REDIRECT_URI);
        req.setScope(SCOPE);
        req.setState(STATE);
        req.setCodeChallenge(CODE_CHALLENGE);
        req.setCodeChallengeMethod(CODE_CHALLENGE_METHOD);
        req.setResource(resource);
        return req;
    }

    @Test
    void authorize_withOpaqueAccessToken_forwardsRawTokenToStoreTokens() {
        when(redirectUriValidator.isValidRedirectUri(eq(REDIRECT_URI), eq(CLIENT_ID))).thenReturn(true);
        when(configService.getResourceMeta(eq(KNOWN_RESOURCE))).thenReturn(
                new ResourceMeta(Collections.singletonList("openid"), "example-domain",
                        AudienceConstants.PROVIDER_OKTA, "authzServer", false, "jagIssuer", "audience"));
        when(configService.getRemoteServerUsernameClaim(eq(AudienceConstants.PROVIDER_OKTA)))
                .thenReturn(USERNAME_CLAIM);
        when(userInfo.getSubject()).thenReturn(SUBJECT);
        when(userInfo.get(eq(USERNAME_CLAIM))).thenReturn(USERNAME);
        when(upstreamRefreshService.getCurrentUpstream(anyString())).thenReturn(Optional.empty());
        when(authorizerService.getUserToken(anyString(), anyString())).thenReturn(null);
        when(authorizationCodeService.generateCode(anyString(), anyString(), anyString(), any(),
                anyString(), anyString(), anyString(), any())).thenReturn("auth-code-123");

        // Inject a real AccessTokenCredential carrying an opaque (non-JWT) token. This is the
        // shape Okta issues for some users; injecting @Inject JsonWebToken would throw here.
        authorizeResource.accessTokenCredential = new AccessTokenCredential(OPAQUE_ACCESS_TOKEN);

        Response response = authorizeResource.authorize(newRequest(KNOWN_RESOURCE));

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus(),
                "Happy path should redirect with the authorization code");

        // The opaque access token must be forwarded verbatim to storeTokens; we should NOT
        // attempt to JWT-parse it. Signature: (user, lookupKey, idToken, accessToken, refreshToken, provider).
        ArgumentCaptor<String> accessTokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(authorizerService).storeTokens(
                anyString(),
                anyString(),
                any(),
                accessTokenCaptor.capture(),
                any(),
                eq(AudienceConstants.PROVIDER_OKTA),
                eq(CLIENT_ID));
        assertEquals(OPAQUE_ACCESS_TOKEN, accessTokenCaptor.getValue(),
                "Opaque access token must be forwarded to storeTokens unchanged");
    }

    @Test
    void authorize_withNullAccessTokenCredential_doesNotThrow() {
        // Edge case: when AccessTokenCredential is not injected, we must still not throw and
        // the stored access token should simply be null.
        when(redirectUriValidator.isValidRedirectUri(eq(REDIRECT_URI), eq(CLIENT_ID))).thenReturn(true);
        when(configService.getResourceMeta(eq(KNOWN_RESOURCE))).thenReturn(
                new ResourceMeta(Collections.singletonList("openid"), "example-domain",
                        AudienceConstants.PROVIDER_OKTA, "authzServer", false, "jagIssuer", "audience"));
        when(configService.getRemoteServerUsernameClaim(eq(AudienceConstants.PROVIDER_OKTA)))
                .thenReturn(USERNAME_CLAIM);
        when(userInfo.getSubject()).thenReturn(SUBJECT);
        when(userInfo.get(eq(USERNAME_CLAIM))).thenReturn(USERNAME);
        when(upstreamRefreshService.getCurrentUpstream(anyString())).thenReturn(Optional.empty());
        when(authorizerService.getUserToken(anyString(), anyString())).thenReturn(null);
        when(authorizationCodeService.generateCode(anyString(), anyString(), anyString(), any(),
                anyString(), anyString(), anyString(), any())).thenReturn("auth-code-null");

        authorizeResource.accessTokenCredential = null;

        Response response = authorizeResource.authorize(newRequest(KNOWN_RESOURCE));

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        ArgumentCaptor<String> accessTokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(authorizerService).storeTokens(
                anyString(), anyString(), any(), accessTokenCaptor.capture(), any(),
                eq(AudienceConstants.PROVIDER_OKTA), eq(CLIENT_ID));
        assertEquals(null, accessTokenCaptor.getValue(),
                "Null AccessTokenCredential must translate to a null raw access token, not a crash");
    }
}
