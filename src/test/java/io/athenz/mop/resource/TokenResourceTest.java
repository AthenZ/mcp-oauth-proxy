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
import io.athenz.mop.service.UpstreamExchangeException;
import io.athenz.mop.service.UpstreamRefreshException;
import io.athenz.mop.service.UpstreamProviderClassifier;
import io.athenz.mop.service.UpstreamRefreshResponse;
import io.athenz.mop.service.UpstreamRefreshService;
import io.athenz.mop.service.UpstreamRefreshTransientException;
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
    private UpstreamProviderClassifier upstreamProviderClassifier;

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
        // Mirror real classifier semantics: okta + google-* are promoted to L2.
        lenient().when(upstreamProviderClassifier.isUpstreamPromoted(any()))
                .thenAnswer(invocation -> {
                    String p = invocation.getArgument(0);
                    if (p == null) {
                        return false;
                    }
                    return AudienceConstants.PROVIDER_OKTA.equals(p) || p.startsWith("google-");
                });
        // Default-allow the canonical RESOURCE so tests that don't care about the new
        // validateResourceMappedIfPresent (RFC 8707) gate don't trip the early 400 invalid_target
        // branch added in TokenResource.generateTokenOAuth2. Tests that want to exercise the
        // "unknown resource" path override this stub explicitly.
        lenient().when(configService.getResourceMeta(RESOURCE))
                .thenReturn(new ResourceMeta(List.of(), "dom", PROVIDER, PROVIDER, false, null, null));
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
                null,
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
        // Promoted Okta path: UpstreamRefreshService returns a fresh upstream tuple, but the
        // downstream authorizerService.completeRefreshWithOktaTokens returns null (e.g. resource
        // exchange failed). The grant must revoke the family and return invalid_grant — this
        // is the contract for any null RefreshAndTokenResult on the promoted code path.
        // The rotated row's providerUserId is "provider-user-1" (no "#"), so handleRefreshTokenGrant
        // defensively reconstructs the L2 key as "okta#user-1".
        when(upstreamRefreshService.refreshUpstream(eq("okta#" + USER_ID), eq(PROVIDER), eq(CLIENT_ID)))
                .thenReturn(new UpstreamRefreshResponse("upstream-at", "upstream-rt", "upstream-id", 3600L, "scope"));
        when(authorizerService.completeRefreshWithOktaTokens(
                eq(USER_ID), eq(PROVIDER), eq(RESOURCE), any(), eq(CLIENT_ID)))
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
        when(authorizerService.getTokenFromAuthorizationServer(eq(OKTA_SUBJECT), any(), eq(RESOURCE), eq(authToken), eq(CLIENT_ID)))
                .thenReturn(new TokenResponse("access", "Bearer", 3600L, "scope"));

        UpstreamTokenRecord central = new UpstreamTokenRecord(
                AudienceConstants.PROVIDER_OKTA + "#" + OKTA_SUBJECT, "central-upstream-rt", "", 2L, 0L, "", "");
        when(upstreamRefreshService.getCurrentUpstream(AudienceConstants.PROVIDER_OKTA + "#" + OKTA_SUBJECT)).thenReturn(Optional.of(central));
        when(refreshTokenService.store(eq(OKTA_SUBJECT), eq(CLIENT_ID), eq(PROVIDER), eq(OKTA_SUBJECT), eq(null), eq(null)))
                .thenReturn("mop-refresh");

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(authorizerService, never()).getUserToken(any(), any());
        verify(refreshTokenService, never()).getUpstreamRefreshToken(any(), any());
        verify(upstreamRefreshService).storeInitialUpstreamToken(AudienceConstants.PROVIDER_OKTA + "#" + OKTA_SUBJECT, "central-upstream-rt");
    }

    @Test
    void authorizationCodeGrant_whenNoCentralizedUpstream_fallsBackToRefreshTokensTable() {
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
        when(authorizerService.getTokenFromAuthorizationServer(eq(OKTA_SUBJECT), any(), eq(RESOURCE), eq(authToken), eq(CLIENT_ID)))
                .thenReturn(new TokenResponse("access", "Bearer", 3600L, "scope"));

        when(upstreamRefreshService.getCurrentUpstream(AudienceConstants.PROVIDER_OKTA + "#" + OKTA_SUBJECT)).thenReturn(Optional.empty());
        when(refreshTokenService.getUpstreamRefreshToken(OKTA_SUBJECT, PROVIDER))
                .thenReturn("refreshtable-upstream-rt");
        when(refreshTokenService.store(eq(OKTA_SUBJECT), eq(CLIENT_ID), eq(PROVIDER), eq(OKTA_SUBJECT), eq(null), eq(null)))
                .thenReturn("mop-refresh");

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(authorizerService, never()).getUserToken(any(), any());
        verify(refreshTokenService).getUpstreamRefreshToken(OKTA_SUBJECT, PROVIDER);
        verify(upstreamRefreshService).storeInitialUpstreamToken(
                AudienceConstants.PROVIDER_OKTA + "#" + OKTA_SUBJECT, "refreshtable-upstream-rt");
    }

    @Test
    void refreshTokenGrant_whenUpstreamTransientCrossRegion_returns503AndDoesNotRevokeFamily() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("refresh_token");
        request.setRefreshToken("rt_validToken");
        request.setClientId(CLIENT_ID);
        request.setResource(RESOURCE);

        String oktaProviderUserId = AudienceConstants.PROVIDER_OKTA + "#" + OKTA_SUBJECT;
        RefreshTokenRecord record = new RefreshTokenRecord(
                "refresh-id-1",
                oktaProviderUserId,
                USER_ID,
                CLIENT_ID,
                PROVIDER,
                null,
                OKTA_SUBJECT,
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
                .thenReturn(new RefreshTokenRotateResult("rt_newToken", "refresh-id-2", oktaProviderUserId));
        when(upstreamRefreshService.refreshUpstream(eq(oktaProviderUserId), eq(PROVIDER), eq(CLIENT_ID)))
                .thenThrow(new UpstreamRefreshTransientException("peer ahead; replication pending"));

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        OAuth2ErrorResponse body = (OAuth2ErrorResponse) response.getEntity();
        assertNotNull(body);
        assertEquals(OAuth2ErrorResponse.ErrorCode.INVALID_GRANT, body.error());
        // CRITICAL: a transient cross-region replication lag must NOT revoke the user's refresh-token family.
        verify(refreshTokenService, never()).revokeFamily(any());
        verify(authorizerService, never()).cleanupAfterTerminalUpstreamRefreshFailure(any(), any(), any());
    }

    @Test
    void refreshTokenGrant_whenUpstreamTerminalFailure_returns400AndRevokesFamily() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("refresh_token");
        request.setRefreshToken("rt_validToken");
        request.setClientId(CLIENT_ID);
        request.setResource(RESOURCE);

        String oktaProviderUserId = AudienceConstants.PROVIDER_OKTA + "#" + OKTA_SUBJECT;
        RefreshTokenRecord record = new RefreshTokenRecord(
                "refresh-id-1",
                oktaProviderUserId,
                USER_ID,
                CLIENT_ID,
                PROVIDER,
                null,
                OKTA_SUBJECT,
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
                .thenReturn(new RefreshTokenRotateResult("rt_newToken", "refresh-id-2", oktaProviderUserId));
        when(upstreamRefreshService.refreshUpstream(eq(oktaProviderUserId), eq(PROVIDER), eq(CLIENT_ID)))
                .thenThrow(new UpstreamRefreshException("Upstream Okta token revoked"));

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        OAuth2ErrorResponse body = (OAuth2ErrorResponse) response.getEntity();
        assertNotNull(body);
        assertEquals(OAuth2ErrorResponse.ErrorCode.INVALID_GRANT, body.error());
        // Terminal upstream failure: family is revoked and cleanup is invoked.
        verify(refreshTokenService).revokeFamily(TOKEN_FAMILY_ID);
        verify(authorizerService).cleanupAfterTerminalUpstreamRefreshFailure(USER_ID, PROVIDER, "encrypted-upstream");
    }

    @Test
    void authorizationCodeGrant_upstreamExchangeException_returns401InvalidTokenWithUpstreamMessage() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("authorization_code");
        request.setCode("the-auth-code");
        request.setRedirectUri(REDIRECT_URI);
        request.setCodeVerifier("verifier");
        request.setClientId(CLIENT_ID);
        request.setResource(RESOURCE);

        AuthorizationCode authCode = new AuthorizationCode(
                "the-auth-code", CLIENT_ID, OKTA_SUBJECT, REDIRECT_URI, "default", RESOURCE,
                "challenge", "S256", Instant.now().plusSeconds(600), "state");
        when(authorizationCodeService.validateAndConsume(
                eq("the-auth-code"), eq(CLIENT_ID), eq(REDIRECT_URI), eq("verifier"), eq(RESOURCE)))
                .thenReturn(authCode);

        ResourceMeta meta = new ResourceMeta(List.of(), "dom", PROVIDER, PROVIDER, false, null, null);
        when(configService.getResourceMeta(RESOURCE)).thenReturn(meta);

        TokenWrapper authToken = new TokenWrapper("k", PROVIDER, null, "access", null, 9999999999L);
        when(authorizerService.authorize(eq(OKTA_SUBJECT), any(), eq(RESOURCE)))
                .thenReturn(new AuthorizationResultDO(AuthResult.AUTHORIZED, authToken));
        String upstream = "Splunk createUser failed: status=403, message=Role=power_ads-pbp-008 is not grantable";
        when(authorizerService.getTokenFromAuthorizationServer(
                eq(OKTA_SUBJECT), any(), eq(RESOURCE), eq(authToken), eq(CLIENT_ID)))
                .thenThrow(new UpstreamExchangeException(upstream));

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        OAuth2ErrorResponse body = (OAuth2ErrorResponse) response.getEntity();
        assertNotNull(body);
        assertEquals(OAuth2ErrorResponse.ErrorCode.INVALID_TOKEN, body.error());
        // The upstream Splunk message must reach the client verbatim — no wrapping, no truncation.
        assertEquals(upstream, body.errorDescription());
    }

    @Test
    void authorizationCodeGrant_passesResourceMetaAudienceToRefreshTokenStore() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("authorization_code");
        request.setCode("the-auth-code");
        request.setRedirectUri(REDIRECT_URI);
        request.setCodeVerifier("verifier");
        request.setClientId(CLIENT_ID);
        request.setResource(RESOURCE);

        AuthorizationCode authCode = new AuthorizationCode(
                "the-auth-code", CLIENT_ID, OKTA_SUBJECT, REDIRECT_URI, "default", RESOURCE,
                "challenge", "S256", Instant.now().plusSeconds(600), "state");
        when(authorizationCodeService.validateAndConsume(
                eq("the-auth-code"), eq(CLIENT_ID), eq(REDIRECT_URI), eq("verifier"), eq(RESOURCE)))
                .thenReturn(authCode);

        // Splunk-style resource meta: idpServer=okta, audience=splunk. Audience must reach
        // refreshTokenService.store so the row is self-describing for ops queries.
        ResourceMeta meta = new ResourceMeta(List.of(), "dom", PROVIDER, "splunk", false, null, "splunk");
        when(configService.getResourceMeta(RESOURCE)).thenReturn(meta);

        TokenWrapper authToken = new TokenWrapper("k", PROVIDER, null, "access", null, 9999999999L);
        when(authorizerService.authorize(eq(OKTA_SUBJECT), any(), eq(RESOURCE)))
                .thenReturn(new AuthorizationResultDO(AuthResult.AUTHORIZED, authToken));
        when(authorizerService.getTokenFromAuthorizationServer(eq(OKTA_SUBJECT), any(), eq(RESOURCE), eq(authToken), eq(CLIENT_ID)))
                .thenReturn(new TokenResponse("access", "Bearer", 3600L, "scope"));
        when(upstreamRefreshService.getCurrentUpstream(AudienceConstants.PROVIDER_OKTA + "#" + OKTA_SUBJECT))
                .thenReturn(Optional.empty());
        when(refreshTokenService.getUpstreamRefreshToken(OKTA_SUBJECT, PROVIDER)).thenReturn(null);
        when(refreshTokenService.store(eq(OKTA_SUBJECT), eq(CLIENT_ID), eq(PROVIDER), eq(OKTA_SUBJECT), eq(null), eq("splunk")))
                .thenReturn("mop-refresh");

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        // Capture the actual call to confirm the audience argument made the round trip.
        ArgumentCaptor<String> audienceCaptor = ArgumentCaptor.forClass(String.class);
        verify(refreshTokenService).store(
                eq(OKTA_SUBJECT), eq(CLIENT_ID), eq(PROVIDER), eq(OKTA_SUBJECT),
                eq(null), audienceCaptor.capture());
        assertEquals("splunk", audienceCaptor.getValue());
    }

    @Test
    void authorizationCodeGrant_whenResourceMetaAudienceAbsent_passesNullAudience() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("authorization_code");
        request.setCode("the-auth-code");
        request.setRedirectUri(REDIRECT_URI);
        request.setCodeVerifier("verifier");
        request.setClientId(CLIENT_ID);
        request.setResource(RESOURCE);

        AuthorizationCode authCode = new AuthorizationCode(
                "the-auth-code", CLIENT_ID, OKTA_SUBJECT, REDIRECT_URI, "default", RESOURCE,
                "challenge", "S256", Instant.now().plusSeconds(600), "state");
        when(authorizationCodeService.validateAndConsume(
                eq("the-auth-code"), eq(CLIENT_ID), eq(REDIRECT_URI), eq("verifier"), eq(RESOURCE)))
                .thenReturn(authCode);

        // Legacy / unconfigured-audience resource meta. Audience field is null.
        ResourceMeta meta = new ResourceMeta(List.of(), "dom", PROVIDER, PROVIDER, false, null, null);
        when(configService.getResourceMeta(RESOURCE)).thenReturn(meta);

        TokenWrapper authToken = new TokenWrapper("k", PROVIDER, null, "access", null, 9999999999L);
        when(authorizerService.authorize(eq(OKTA_SUBJECT), any(), eq(RESOURCE)))
                .thenReturn(new AuthorizationResultDO(AuthResult.AUTHORIZED, authToken));
        when(authorizerService.getTokenFromAuthorizationServer(eq(OKTA_SUBJECT), any(), eq(RESOURCE), eq(authToken), eq(CLIENT_ID)))
                .thenReturn(new TokenResponse("access", "Bearer", 3600L, "scope"));
        when(upstreamRefreshService.getCurrentUpstream(AudienceConstants.PROVIDER_OKTA + "#" + OKTA_SUBJECT))
                .thenReturn(Optional.empty());
        when(refreshTokenService.getUpstreamRefreshToken(OKTA_SUBJECT, PROVIDER)).thenReturn(null);
        when(refreshTokenService.store(eq(OKTA_SUBJECT), eq(CLIENT_ID), eq(PROVIDER), eq(OKTA_SUBJECT), eq(null), eq(null)))
                .thenReturn("mop-refresh");

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(refreshTokenService).store(
                eq(OKTA_SUBJECT), eq(CLIENT_ID), eq(PROVIDER), eq(OKTA_SUBJECT),
                eq(null), eq(null));
    }

    /**
     * RFC 8707 §2: when the wire {@code resource} parameter does not map to any
     * ResourceMeta, the token endpoint must reject with 400 invalid_target before
     * doing any DB lookup, RT validation, or upstream call. This guards against the
     * silent-degrade path in AuthorizerService.completeRefreshWithOktaTokens /
     * refreshUpstreamAndGetTokenLocked where {@code resourceMeta == null} causes the
     * code to fall back to {@code provider} (i.e. raw Okta) and emit a wrong-issuer
     * access token to the client (Databricks/Splunk/Glean/etc. would 401 every call).
     */
    @Test
    void refreshTokenGrant_whenResourceUnknown_returns400InvalidTargetAndDoesNotTouchUpstream() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("refresh_token");
        request.setRefreshToken("rt_validToken");
        request.setClientId(CLIENT_ID);
        request.setResource("https://unknown.example.com/v1/typo/mcp");

        // configService default-stub from setUp covers RESOURCE; this URI is intentionally
        // unmapped (returns null) to trigger the new validation gate.
        when(configService.getResourceMeta("https://unknown.example.com/v1/typo/mcp"))
                .thenReturn(null);

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        OAuth2ErrorResponse body = (OAuth2ErrorResponse) response.getEntity();
        assertNotNull(body);
        assertEquals(OAuth2ErrorResponse.ErrorCode.INVALID_TARGET, body.error());
        // Critical: short-circuit must happen before any DB / upstream lookup.
        verify(refreshTokenService, never()).lookupUserIdAndProviderForLock(any(), any());
        verify(refreshTokenService, never()).validate(any(), any());
        verify(upstreamRefreshService, never()).refreshUpstream(any());
        verify(authorizerService, never()).completeRefreshWithOktaTokens(any(), any(), any(), any(), any());
        verify(authorizerService, never()).refreshUpstreamAndGetToken(any(), any(), any(), any(), any());
        // Gate metric: rejected/unknown_resource on refresh_token grant.
        verify(oauthProxyMetrics).recordTokenResourceValidation(
                eq(false), eq("unknown_resource"), eq("refresh_token"), any());
    }

    @Test
    void authorizationCodeGrant_whenResourceUnknown_returns400InvalidTargetAndDoesNotConsumeCode() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("authorization_code");
        request.setCode("the-auth-code");
        request.setRedirectUri(REDIRECT_URI);
        request.setCodeVerifier("verifier");
        request.setClientId(CLIENT_ID);
        request.setResource("https://unknown.example.com/v1/typo/mcp");

        when(configService.getResourceMeta("https://unknown.example.com/v1/typo/mcp"))
                .thenReturn(null);

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        OAuth2ErrorResponse body = (OAuth2ErrorResponse) response.getEntity();
        assertNotNull(body);
        assertEquals(OAuth2ErrorResponse.ErrorCode.INVALID_TARGET, body.error());
        // Authorization code MUST NOT be consumed when the resource is invalid.
        verify(authorizationCodeService, never())
                .validateAndConsume(any(), any(), any(), any(), any());
        // Gate metric: rejected/unknown_resource on authorization_code grant.
        verify(oauthProxyMetrics).recordTokenResourceValidation(
                eq(false), eq("unknown_resource"), eq("authorization_code"), any());
    }

    @Test
    void clientCredentialsGrant_whenResourceUnknown_returns400InvalidTarget() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("client_credentials");
        request.setResource("https://unknown.example.com/v1/typo/mcp");

        when(configService.getResourceMeta("https://unknown.example.com/v1/typo/mcp"))
                .thenReturn(null);

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        OAuth2ErrorResponse body = (OAuth2ErrorResponse) response.getEntity();
        assertNotNull(body);
        assertEquals(OAuth2ErrorResponse.ErrorCode.INVALID_TARGET, body.error());
        // Gate metric: rejected/unknown_resource on client_credentials grant.
        verify(oauthProxyMetrics).recordTokenResourceValidation(
                eq(false), eq("unknown_resource"), eq("client_credentials"), any());
    }

    /**
     * The accepted-path counterpart: when the wire {@code resource} resolves to a known
     * {@code ResourceMeta}, the gate emits {@code (accepted, known_mapped)} and lets the
     * request through to the per-grant handler. We deliberately pick a refresh_token request
     * with an early downstream failure (lookup returns empty) so we can assert the gate
     * fired without having to stub the full happy-path chain.
     */
    @Test
    void generateTokenOAuth2_whenResourceKnown_recordsAcceptedKnownMappedMetric() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("refresh_token");
        request.setRefreshToken("rt_validToken");
        request.setClientId(CLIENT_ID);
        request.setResource(RESOURCE); // configService.getResourceMeta(RESOURCE) returns non-null per setUp()
        when(refreshTokenService.lookupUserIdAndProviderForLock(eq("rt_validToken"), eq(CLIENT_ID)))
                .thenReturn(java.util.Optional.empty());

        tokenResource.generateTokenOAuth2(request);

        verify(oauthProxyMetrics).recordTokenResourceValidation(
                eq(true), eq("known_mapped"), eq("refresh_token"), any());
        // And of course, no rejected sample for this request.
        verify(oauthProxyMetrics, never()).recordTokenResourceValidation(
                eq(false), any(), any(), any());
    }

    /**
     * Absent {@code resource} must NOT be rejected by the new validation gate — the
     * per-grant handlers downstream still enforce their own presence rules
     * (refresh_token requires it, client_credentials requires it, authorization_code
     * uses the resource bound at /authorize time). This test confirms the gate is
     * "validate-if-present", not "always-required".
     */
    @Test
    void generateTokenOAuth2_whenResourceAbsent_doesNotRejectWithInvalidTarget() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("refresh_token");
        request.setRefreshToken("rt_validToken");
        request.setClientId(CLIENT_ID);
        // resource intentionally not set

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        OAuth2ErrorResponse body = (OAuth2ErrorResponse) response.getEntity();
        assertNotNull(body);
        // The refresh-token handler enforces "resource is required" with invalid_grant
        // (line 393-395 of TokenResource); the new RFC 8707 gate does NOT short-circuit
        // for absent resource.
        assertEquals(OAuth2ErrorResponse.ErrorCode.INVALID_GRANT, body.error());
        // Gate metric is intentionally NOT emitted for absent resource (the gate only
        // observes resources it actually inspected; absent/blank is not inspected).
        verify(oauthProxyMetrics, never()).recordTokenResourceValidation(
                any(Boolean.class), any(), any(), any());
    }

    @Test
    void generateTokenOAuth2_whenResourceBlank_doesNotRejectWithInvalidTarget() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("refresh_token");
        request.setRefreshToken("rt_validToken");
        request.setClientId(CLIENT_ID);
        request.setResource("   "); // whitespace-only

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        OAuth2ErrorResponse body = (OAuth2ErrorResponse) response.getEntity();
        assertNotNull(body);
        assertEquals(OAuth2ErrorResponse.ErrorCode.INVALID_GRANT, body.error());
        // Same contract as absent: blank/whitespace-only resource is not observed.
        verify(oauthProxyMetrics, never()).recordTokenResourceValidation(
                any(Boolean.class), any(), any(), any());
    }

    /**
     * Read-side legacy migration must fire on the refresh_token grant for ANY promoted provider,
     * not just Okta. The original wiring only invoked
     * {@link UpstreamRefreshService#ensureMigratedFromLegacyIfNeeded(String, RefreshTokenRecord)}
     * inside an {@code if (provider == "okta")} branch, which left google-* families that were
     * minted before L2 promotion stranded — their first /token refresh after deployment found
     * no L2 row and threw "no upstream RT", revoking the family.
     *
     * <p>This test pins the fix: a refresh_token grant for {@code google-slides} where the
     * rotated row carries a legacy {@code encrypted_upstream_refresh_token} must call the
     * provider-aware migration overload before invoking
     * {@link UpstreamRefreshService#refreshUpstream(String, String, String)}.
     */
    @Test
    void refreshTokenGrant_whenGoogleSlidesPromoted_invokesLegacyMigrationBeforeUpstreamRefresh() {
        final String googleProvider = "google-slides";
        final String googleSub = "alice-google-sub";
        final String googleResource = "https://google-slides-mcp.example.com";
        final String googleClientId = "gslidestrial6";

        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("refresh_token");
        request.setRefreshToken("rt_googleValid");
        request.setClientId(googleClientId);
        request.setResource(googleResource);

        // Resource meta must resolve so the RFC 8707 gate doesn't short-circuit. This stub is
        // local to the test (the setUp default only stubs RESOURCE).
        when(configService.getResourceMeta(googleResource))
                .thenReturn(new ResourceMeta(List.of(), "dom", googleProvider, googleProvider, false, null, null));

        // The rotated source row is a Google family with a legacy upstream RT in the legacy
        // column — exactly the shape an in-flight family minted before L2 promotion would have.
        RefreshTokenRecord legacyRow = new RefreshTokenRecord(
                "refresh-id-gs-1",
                /* providerUserId is intentionally NOT prefixed with "google-slides#" to exercise
                 * the defensive prefix-reconstruction in handleRefreshTokenGrant (this is the
                 * exact shape of pre-promotion rows). */
                googleSub,
                googleSub,
                googleClientId,
                googleProvider,
                null,
                googleSub,
                "encrypted-google-legacy-rt",
                "ACTIVE",
                "fam-gs-1",
                null,
                null,
                0L,
                System.currentTimeMillis() / 1000,
                System.currentTimeMillis() / 1000 + 7776000L,
                System.currentTimeMillis() / 1000 + 7776000L + 604800L
        );

        when(refreshTokenService.lookupUserIdAndProviderForLock(eq("rt_googleValid"), eq(googleClientId)))
                .thenReturn(Optional.of(new RefreshTokenLockKey(googleSub, googleProvider)));
        when(refreshTokenService.validate(eq("rt_googleValid"), eq(googleClientId)))
                .thenReturn(RefreshTokenValidationResult.active(legacyRow));
        when(refreshTokenService.rotate(eq("rt_googleValid"), eq(googleClientId)))
                .thenReturn(new RefreshTokenRotateResult("rt_newGoogleToken", "refresh-id-gs-2", googleSub));

        // refreshUpstream returns a rotated tuple (we don't care about its contents here — the
        // assertion is just that it was called AFTER the migration ran). The key is constructed
        // by handleRefreshTokenGrant as "google-slides#alice-google-sub".
        String expectedPuid = googleProvider + "#" + googleSub;
        when(upstreamRefreshService.refreshUpstream(eq(expectedPuid), eq(googleProvider), eq(googleClientId)))
                .thenReturn(new UpstreamRefreshResponse("g-at", "g-rt", null, 3599L, "scope"));
        // Force the downstream completion path to short-circuit so we don't have to wire up a
        // full TokenResponse — the migration assertion runs purely off the verify() at the end.
        when(authorizerService.completeRefreshWithOktaTokens(
                eq(googleSub), eq(googleProvider), eq(googleResource), any(), eq(googleClientId)))
                .thenReturn(null);

        tokenResource.generateTokenOAuth2(request);

        // The critical assertion: the provider-aware migration overload (3-arg) was called with
        // (puid, "google-slides", legacyRow) — pre-bug the code only called the 2-arg overload
        // when provider==okta, so for google-slides this verify() would have failed.
        verify(upstreamRefreshService).ensureMigratedFromLegacyIfNeeded(
                eq(expectedPuid), eq(googleProvider), eq(legacyRow));
        // And the migration ran BEFORE the upstream refresh (Mockito doesn't enforce order by
        // default; we use InOrder to make this explicit).
        org.mockito.InOrder inOrder = org.mockito.Mockito.inOrder(upstreamRefreshService);
        inOrder.verify(upstreamRefreshService).ensureMigratedFromLegacyIfNeeded(
                eq(expectedPuid), eq(googleProvider), eq(legacyRow));
        inOrder.verify(upstreamRefreshService).refreshUpstream(
                eq(expectedPuid), eq(googleProvider), eq(googleClientId));
    }

    /**
     * Companion to the test above: the Okta path must continue to invoke the migration too,
     * even though the call site no longer has its provider-specific guard. Locks in the
     * generalization without regressing the original Okta wiring.
     */
    @Test
    void refreshTokenGrant_whenOktaPromoted_stillInvokesLegacyMigration() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("refresh_token");
        request.setRefreshToken("rt_oktaValid");
        request.setClientId(CLIENT_ID);
        request.setResource(RESOURCE);

        RefreshTokenRecord legacyOktaRow = new RefreshTokenRecord(
                "refresh-id-okta-1", "provider-user-1", USER_ID, CLIENT_ID, PROVIDER, null,
                "sub-1", "encrypted-okta-legacy-rt", "ACTIVE", TOKEN_FAMILY_ID,
                null, null, 0L,
                System.currentTimeMillis() / 1000,
                System.currentTimeMillis() / 1000 + 7776000L,
                System.currentTimeMillis() / 1000 + 7776000L + 604800L);

        when(refreshTokenService.lookupUserIdAndProviderForLock(eq("rt_oktaValid"), eq(CLIENT_ID)))
                .thenReturn(Optional.of(new RefreshTokenLockKey(USER_ID, PROVIDER)));
        when(refreshTokenService.validate(eq("rt_oktaValid"), eq(CLIENT_ID)))
                .thenReturn(RefreshTokenValidationResult.active(legacyOktaRow));
        when(refreshTokenService.rotate(eq("rt_oktaValid"), eq(CLIENT_ID)))
                .thenReturn(new RefreshTokenRotateResult("rt_newOkta", "refresh-id-okta-2", "provider-user-1"));
        String expectedPuid = AudienceConstants.PROVIDER_OKTA + "#" + USER_ID;
        when(upstreamRefreshService.refreshUpstream(eq(expectedPuid), eq(PROVIDER), eq(CLIENT_ID)))
                .thenReturn(new UpstreamRefreshResponse("at", "rt", "id", 3600L, "scope"));
        when(authorizerService.completeRefreshWithOktaTokens(
                eq(USER_ID), eq(PROVIDER), eq(RESOURCE), any(), eq(CLIENT_ID)))
                .thenReturn(null);

        tokenResource.generateTokenOAuth2(request);

        verify(upstreamRefreshService).ensureMigratedFromLegacyIfNeeded(
                eq(expectedPuid), eq(PROVIDER), eq(legacyOktaRow));
    }
}
