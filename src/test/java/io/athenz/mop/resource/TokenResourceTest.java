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

import io.athenz.mop.model.*;
import io.athenz.mop.service.AudienceConstants;
import io.athenz.mop.service.AuthorizationCodeService;
import io.athenz.mop.service.AuthorizerService;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.RefreshTokenService;
import io.athenz.mop.service.UpstreamRefreshService;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryProviderResolver;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
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

/**
 * Unit tests for TokenResource, including refresh_token grant behavior when upstream fails.
 */
@ExtendWith(MockitoExtension.class)
class TokenResourceTest {

    private static final String TOKEN_FAMILY_ID = "family-1";
    private static final String USER_ID = "user-1";
    private static final String OKTA_SUBJECT = "okta-subject-auth-code";
    private static final String PROVIDER = AudienceConstants.PROVIDER_OKTA;
    private static final String CLIENT_ID = "client-1";
    private static final String RESOURCE = "https://resource.example.com";
    private static final String REDIRECT_URI = "https://client.example.com/cb";

    @Mock
    private AuthorizerService authorizerService;

    @Mock
    private AuthorizationCodeService authorizationCodeService;

    @Mock
    private ConfigService configService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private UpstreamRefreshService upstreamRefreshService;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private TelemetryRequestContext telemetryRequestContext;

    @Mock
    private TelemetryProviderResolver telemetryProviderResolver;

    @Mock
    private MetricsRegionProvider metricsRegionProvider;

    @InjectMocks
    private TokenResource tokenResource;

    @BeforeEach
    void setUp() {
        tokenResource.refreshExpirySeconds = 7776000L;
        lenient().when(telemetryRequestContext.oauthClient()).thenReturn("unknown");
        lenient().when(telemetryProviderResolver.fromResourceUri(any())).thenReturn("unknown");
        lenient().when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");
    }

    @Test
    void refreshTokenGrant_whenUpstreamReturnsNull_revokesFamilyAndReturnsInvalidGrant() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("refresh_token");
        request.setRefreshToken("rt_validToken");
        request.setClientId(CLIENT_ID);
        request.setResource(RESOURCE);

        RefreshTokenRecord record = new RefreshTokenRecord(
                "refresh-id-1",
                "provider-user-1",
                USER_ID,
                CLIENT_ID,
                PROVIDER,
                "sub-1",
                "encrypted-upstream",
                "ACTIVE",
                TOKEN_FAMILY_ID,
                null,
                null,
                0L,
                System.currentTimeMillis() / 1000,
                System.currentTimeMillis() / 1000 + 7776000L,
                System.currentTimeMillis() / 1000 + 7776000L + 604800L
        );

        when(refreshTokenService.lookupUserIdAndProviderForLock(eq("rt_validToken"), eq(CLIENT_ID)))
                .thenReturn(Optional.of(new RefreshTokenLockKey(USER_ID, PROVIDER)));
        when(refreshTokenService.validate(eq("rt_validToken"), eq(CLIENT_ID)))
                .thenReturn(RefreshTokenValidationResult.active(record));
        when(refreshTokenService.rotate(eq("rt_validToken"), eq(CLIENT_ID)))
                .thenReturn(new RefreshTokenRotateResult("rt_newToken", "refresh-id-2", "provider-user-1"));
        when(authorizerService.refreshUpstreamAndGetToken(
                eq(USER_ID),
                eq(PROVIDER),
                eq(RESOURCE),
                eq("encrypted-upstream")))
                .thenReturn(null);

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        OAuth2ErrorResponse body = (OAuth2ErrorResponse) response.getEntity();
        assertNotNull(body);
        assertEquals(OAuth2ErrorResponse.ErrorCode.INVALID_GRANT, body.error());

        ArgumentCaptor<String> familyIdCaptor = ArgumentCaptor.forClass(String.class);
        verify(refreshTokenService).revokeFamily(familyIdCaptor.capture());
        assertEquals(TOKEN_FAMILY_ID, familyIdCaptor.getValue());
    }

    @Test
    void authorizationCodeGrant_whenCentralizedOktaUpstreamPresent_usesCentralAndSkipsUserTokenLookup() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("authorization_code");
        request.setCode("the-auth-code");
        request.setRedirectUri(REDIRECT_URI);
        request.setCodeVerifier("verifier");
        request.setClientId(CLIENT_ID);
        request.setResource(RESOURCE);

        AuthorizationCode authCode = new AuthorizationCode(
                "the-auth-code",
                CLIENT_ID,
                OKTA_SUBJECT,
                REDIRECT_URI,
                "default",
                RESOURCE,
                "challenge",
                "S256",
                Instant.now().plusSeconds(600),
                "state");
        when(authorizationCodeService.validateAndConsume(
                eq("the-auth-code"), eq(CLIENT_ID), eq(REDIRECT_URI), eq("verifier"), eq(RESOURCE)))
                .thenReturn(authCode);

        ResourceMeta meta = new ResourceMeta(List.of(), "dom", PROVIDER, PROVIDER, false, null, null);
        when(configService.getResourceMeta(RESOURCE)).thenReturn(meta);

        TokenWrapper authToken = new TokenWrapper("k", PROVIDER, null, "access", null, 9999999999L);
        when(authorizerService.authorize(eq(OKTA_SUBJECT), any(), eq(RESOURCE)))
                .thenReturn(new AuthorizationResultDO(AuthResult.AUTHORIZED, authToken));
        when(authorizerService.getTokenFromAuthorizationServer(eq(OKTA_SUBJECT), any(), eq(RESOURCE), eq(authToken)))
                .thenReturn(new TokenResponse("access", "Bearer", 3600L, "scope"));

        UpstreamTokenRecord central = new UpstreamTokenRecord(
                AudienceConstants.PROVIDER_OKTA + "#" + OKTA_SUBJECT, "central-upstream-rt", "", 2L, 0L, "", "");
        when(upstreamRefreshService.getCurrentUpstream(AudienceConstants.PROVIDER_OKTA + "#" + OKTA_SUBJECT)).thenReturn(Optional.of(central));
        when(refreshTokenService.store(eq(OKTA_SUBJECT), eq(CLIENT_ID), eq(PROVIDER), eq(OKTA_SUBJECT), eq(null)))
                .thenReturn("mop-refresh");

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(authorizerService, never()).getUserToken(any(), any());
        verify(upstreamRefreshService).storeInitialUpstreamToken(AudienceConstants.PROVIDER_OKTA + "#" + OKTA_SUBJECT, "central-upstream-rt");
    }

    @Test
    void authorizationCodeGrant_whenNoCentralizedUpstream_fallsBackToTokenWrapper() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("authorization_code");
        request.setCode("the-auth-code");
        request.setRedirectUri(REDIRECT_URI);
        request.setCodeVerifier("verifier");
        request.setClientId(CLIENT_ID);
        request.setResource(RESOURCE);

        AuthorizationCode authCode = new AuthorizationCode(
                "the-auth-code",
                CLIENT_ID,
                OKTA_SUBJECT,
                REDIRECT_URI,
                "default",
                RESOURCE,
                "challenge",
                "S256",
                Instant.now().plusSeconds(600),
                "state");
        when(authorizationCodeService.validateAndConsume(
                eq("the-auth-code"), eq(CLIENT_ID), eq(REDIRECT_URI), eq("verifier"), eq(RESOURCE)))
                .thenReturn(authCode);

        ResourceMeta meta = new ResourceMeta(List.of(), "dom", PROVIDER, PROVIDER, false, null, null);
        when(configService.getResourceMeta(RESOURCE)).thenReturn(meta);

        TokenWrapper authToken = new TokenWrapper("k", PROVIDER, null, "access", null, 9999999999L);
        when(authorizerService.authorize(eq(OKTA_SUBJECT), any(), eq(RESOURCE)))
                .thenReturn(new AuthorizationResultDO(AuthResult.AUTHORIZED, authToken));
        when(authorizerService.getTokenFromAuthorizationServer(eq(OKTA_SUBJECT), any(), eq(RESOURCE), eq(authToken)))
                .thenReturn(new TokenResponse("access", "Bearer", 3600L, "scope"));

        when(upstreamRefreshService.getCurrentUpstream(AudienceConstants.PROVIDER_OKTA + "#" + OKTA_SUBJECT)).thenReturn(Optional.empty());
        long ttlFuture = System.currentTimeMillis() / 1000 + 3600;
        TokenWrapper userRow = new TokenWrapper(
                OKTA_SUBJECT, PROVIDER, "id", "access", "wrapper-upstream-rt", ttlFuture);
        when(authorizerService.getUserToken(OKTA_SUBJECT, PROVIDER)).thenReturn(userRow);
        when(refreshTokenService.store(eq(OKTA_SUBJECT), eq(CLIENT_ID), eq(PROVIDER), eq(OKTA_SUBJECT), eq(null)))
                .thenReturn("mop-refresh");

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(authorizerService).getUserToken(OKTA_SUBJECT, PROVIDER);
        verify(upstreamRefreshService).storeInitialUpstreamToken(AudienceConstants.PROVIDER_OKTA + "#" + OKTA_SUBJECT, "wrapper-upstream-rt");
    }
}
