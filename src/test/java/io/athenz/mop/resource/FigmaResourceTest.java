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
import io.athenz.mop.service.FigmaCodeExchangeClient;
import io.athenz.mop.service.FigmaPkceStateCache;
import io.athenz.mop.service.FigmaUserInfoClient;
import io.athenz.mop.telemetry.AuthCodeValidationReason;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import jakarta.ws.rs.core.Response;

import java.time.Instant;
import java.util.Map;
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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link FigmaResource}, the custom (non-Quarkus-OIDC) Figma callback resource.
 *
 * <p>The test surface covers the two endpoints introduced by Option B (replacing the stock
 * Quarkus tenant for Figma): {@code GET /figma/authorize} (PKCE/state mint + 302 to Figma) and
 * {@code GET /figma/authorize/callback} (state pop + code exchange + /v1/me + storeTokens with
 * the 90-day lifetime).
 */
@ExtendWith(MockitoExtension.class)
class FigmaResourceTest {

    private static final String MOP_AUTH_CODE = "mop-auth-code-123";
    private static final String SUBJECT = "figma-subject";
    private static final String REDIRECT_URI = "https://client.example.com/callback";
    private static final String AUTH_CODE_STATE = "auth-code-state";
    private static final String CLIENT_ID = "ya3TXRUOYz3n5mypao2BSz";
    private static final String CALLBACK_URI = "https://test.example.com/figma/authorize/callback";
    private static final String FIGMA_CODE = "figma-code-xyz";
    private static final String UPSTREAM_STATE = "upstream-state-abc";
    private static final String CODE_VERIFIER = "test-code-verifier-1234567890ABCDEFGH";
    private static final String ACCESS_TOKEN = "figu_test-access-token";
    private static final String REFRESH_TOKEN = "figur_test-refresh-token";
    private static final String EMAIL = "alice@example.com";
    private static final String EXPECTED_LOOKUP_KEY = "alice";
    private static final String RESOURCE = "https://test.example.com/v1/figma/mcp";

    @Mock
    private AuthorizerService authorizerService;

    @Mock
    private AuthCodeRegionResolver authCodeRegionResolver;

    @Mock
    private ConfigService configService;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private TelemetryRequestContext telemetryRequestContext;

    @Mock
    private FigmaPkceStateCache pkceStateCache;

    @Mock
    private FigmaCodeExchangeClient codeExchangeClient;

    @Mock
    private FigmaUserInfoClient userInfoClient;

    @InjectMocks
    private FigmaResource figmaResource;

    private AuthorizationCode authorizationCode;

    @BeforeEach
    void setUp() {
        figmaResource.providerDefault = "okta";
        figmaResource.clientId = CLIENT_ID;
        figmaResource.callbackRedirectUri = CALLBACK_URI;
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

    // -------- /figma/authorize (Step 1: outbound redirect to Figma) --------

    @Test
    void authorize_nullState_returnsBadRequest() {
        Response resp = figmaResource.authorize(null);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), resp.getStatus());
        @SuppressWarnings("unchecked")
        Map<String, String> entity = (Map<String, String>) resp.getEntity();
        assertEquals("invalid_request", entity.get("error"));
        assertEquals("Missing state parameter", entity.get("error_description"));
        verify(telemetryRequestContext).setOauthProvider(OauthProviderLabel.FIGMA);
        verify(pkceStateCache, never()).put(anyString(), anyString(), anyString());
    }

    @Test
    void authorize_emptyState_returnsBadRequest() {
        Response resp = figmaResource.authorize("");

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), resp.getStatus());
    }

    @Test
    void authorize_missingClientId_returnsServerError() {
        figmaResource.clientId = "";
        Response resp = figmaResource.authorize(MOP_AUTH_CODE);

        assertEquals(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), resp.getStatus());
        verify(pkceStateCache, never()).put(anyString(), anyString(), anyString());
    }

    @Test
    void authorize_missingCallbackRedirectUri_returnsServerError() {
        // Intentional fail-loud: misconfigured deployment must not 302 to a URL Figma will reject.
        figmaResource.callbackRedirectUri = "";
        Response resp = figmaResource.authorize(MOP_AUTH_CODE);

        assertEquals(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), resp.getStatus());
        verify(pkceStateCache, never()).put(anyString(), anyString(), anyString());
    }

    @Test
    void authorize_happyPath_storesPkceStateAndRedirectsToFigma() {
        Response resp = figmaResource.authorize(MOP_AUTH_CODE);

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), resp.getStatus());
        assertNotNull(resp.getLocation());
        String url = resp.getLocation().toString();
        assertTrue(url.startsWith("https://www.figma.com/oauth/mcp?"),
                "must redirect to Figma authorize endpoint, got: " + url);
        assertTrue(url.contains("response_type=code"));
        assertTrue(url.contains("client_id=" + CLIENT_ID));
        // redirect_uri is URL-encoded — assert the encoded scheme is present and the host survives.
        assertTrue(url.contains("redirect_uri=https%3A%2F%2Ftest.example.com%2Ffigma%2Fauthorize%2Fcallback"),
                "redirect_uri must be URL-encoded and match the configured Figma callback");
        assertTrue(url.contains("scope=mcp%3Aconnect+current_user%3Aread"));
        assertTrue(url.contains("code_challenge=") && url.contains("code_challenge_method=S256"));
        assertTrue(url.contains("state="));
        // PKCE state cache populated with (upstreamState, codeVerifier, mopAuthCode) — assert
        // the latter two were forwarded verbatim; upstreamState is random per-call so we just
        // capture it and confirm non-empty.
        ArgumentCaptor<String> upstreamStateCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> verifierCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> mopCodeCaptor = ArgumentCaptor.forClass(String.class);
        verify(pkceStateCache).put(upstreamStateCaptor.capture(),
                verifierCaptor.capture(), mopCodeCaptor.capture());
        assertNotNull(upstreamStateCaptor.getValue());
        assertTrue(upstreamStateCaptor.getValue().length() >= 32, "upstream state must be unguessable");
        assertNotNull(verifierCaptor.getValue());
        assertTrue(verifierCaptor.getValue().length() >= 43,
                "PKCE code_verifier must be RFC 7636 length (43-128 chars)");
        assertEquals(MOP_AUTH_CODE, mopCodeCaptor.getValue());
    }

    // -------- /figma/authorize/callback (Step 2: code exchange + storeTokens) --------

    @Test
    void callback_upstreamErrorParam_returnsBadRequest() {
        Response resp = figmaResource.callback(null, null, "access_denied", "User denied");

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), resp.getStatus());
        @SuppressWarnings("unchecked")
        Map<String, String> entity = (Map<String, String>) resp.getEntity();
        assertEquals("access_denied", entity.get("error"));
        verify(authorizerService, never()).storeTokens(
                anyString(), anyString(), anyString(), anyString(), anyString(),
                anyString(), anyString(), any());
    }

    @Test
    void callback_missingCode_returnsBadRequest() {
        Response resp = figmaResource.callback(null, UPSTREAM_STATE, null, null);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), resp.getStatus());
    }

    @Test
    void callback_missingState_returnsBadRequest() {
        Response resp = figmaResource.callback(FIGMA_CODE, null, null, null);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), resp.getStatus());
    }

    @Test
    void callback_pkceStateNotFound_returnsBadRequestAndRecordsMetric() {
        when(pkceStateCache.pop(UPSTREAM_STATE)).thenReturn(Optional.empty());

        Response resp = figmaResource.callback(FIGMA_CODE, UPSTREAM_STATE, null, null);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), resp.getStatus());
        @SuppressWarnings("unchecked")
        Map<String, String> entity = (Map<String, String>) resp.getEntity();
        assertEquals("invalid_grant", entity.get("error"));
        verify(oauthProxyMetrics).recordAuthCodeValidationFailure(
                OauthProviderLabel.FIGMA, AuthCodeValidationReason.NOT_FOUND);
    }

    @Test
    void callback_mopAuthCodeNotFound_returnsBadRequestAndRecordsMetric() {
        FigmaPkceStateCache.Entry entry = new FigmaPkceStateCache.Entry(
                CODE_VERIFIER, MOP_AUTH_CODE, Instant.now().getEpochSecond());
        when(pkceStateCache.pop(UPSTREAM_STATE)).thenReturn(Optional.of(entry));
        when(authCodeRegionResolver.resolve(MOP_AUTH_CODE, "okta"))
                .thenReturn(new AuthCodeResolution(null, false));

        Response resp = figmaResource.callback(FIGMA_CODE, UPSTREAM_STATE, null, null);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), resp.getStatus());
        verify(oauthProxyMetrics).recordAuthCodeValidationFailure(
                OauthProviderLabel.FIGMA, AuthCodeValidationReason.NOT_FOUND);
        verify(codeExchangeClient, never()).exchange(anyString(), anyString(), anyString());
    }

    @Test
    void callback_codeExchangeFailure_returnsServerError() {
        FigmaPkceStateCache.Entry entry = new FigmaPkceStateCache.Entry(
                CODE_VERIFIER, MOP_AUTH_CODE, Instant.now().getEpochSecond());
        when(pkceStateCache.pop(UPSTREAM_STATE)).thenReturn(Optional.of(entry));
        when(authCodeRegionResolver.resolve(MOP_AUTH_CODE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(codeExchangeClient.exchange(FIGMA_CODE, CALLBACK_URI, CODE_VERIFIER))
                .thenThrow(new FigmaCodeExchangeClient.FigmaCodeExchangeException("upstream invalid_grant"));

        Response resp = figmaResource.callback(FIGMA_CODE, UPSTREAM_STATE, null, null);

        assertEquals(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), resp.getStatus());
        verify(authorizerService, never()).storeTokens(
                anyString(), anyString(), anyString(), anyString(), anyString(),
                anyString(), anyString(), any());
    }

    @Test
    void callback_userInfoFailure_returnsServerError() {
        FigmaPkceStateCache.Entry entry = new FigmaPkceStateCache.Entry(
                CODE_VERIFIER, MOP_AUTH_CODE, Instant.now().getEpochSecond());
        when(pkceStateCache.pop(UPSTREAM_STATE)).thenReturn(Optional.of(entry));
        when(authCodeRegionResolver.resolve(MOP_AUTH_CODE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(codeExchangeClient.exchange(FIGMA_CODE, CALLBACK_URI, CODE_VERIFIER))
                .thenReturn(new FigmaCodeExchangeClient.FigmaTokens(ACCESS_TOKEN, REFRESH_TOKEN, 7_776_000L));
        when(userInfoClient.fetchMe(ACCESS_TOKEN))
                .thenThrow(new FigmaUserInfoClient.FigmaUserInfoException("transport"));

        Response resp = figmaResource.callback(FIGMA_CODE, UPSTREAM_STATE, null, null);

        assertEquals(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), resp.getStatus());
        verify(authorizerService, never()).storeTokens(
                anyString(), anyString(), anyString(), anyString(), anyString(),
                anyString(), anyString(), any());
    }

    @Test
    void callback_happyPath_storesTokensAndRedirects() {
        FigmaPkceStateCache.Entry entry = new FigmaPkceStateCache.Entry(
                CODE_VERIFIER, MOP_AUTH_CODE, Instant.now().getEpochSecond());
        when(pkceStateCache.pop(UPSTREAM_STATE)).thenReturn(Optional.of(entry));
        when(authCodeRegionResolver.resolve(MOP_AUTH_CODE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(codeExchangeClient.exchange(FIGMA_CODE, CALLBACK_URI, CODE_VERIFIER))
                .thenReturn(new FigmaCodeExchangeClient.FigmaTokens(ACCESS_TOKEN, REFRESH_TOKEN, 7_776_000L));
        FigmaUserInfoClient.FigmaUser figmaUser =
                new FigmaUserInfoClient.FigmaUser("test-user-id-12345", EMAIL, "alice");
        when(userInfoClient.fetchMe(ACCESS_TOKEN)).thenReturn(figmaUser);
        when(configService.getRemoteServerUsernameClaim("figma")).thenReturn("email");

        Response resp = figmaResource.callback(FIGMA_CODE, UPSTREAM_STATE, null, null);

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), resp.getStatus());
        assertNotNull(resp.getLocation());
        String location = resp.getLocation().toString();
        assertTrue(location.startsWith(REDIRECT_URI));
        verify(authorizerService).storeTokens(
                eq(EXPECTED_LOOKUP_KEY),
                eq(SUBJECT),
                eq(ACCESS_TOKEN),
                eq(ACCESS_TOKEN),
                eq(REFRESH_TOKEN),
                eq("figma"),
                eq("client-1"),
                eq(FigmaResource.FIGMA_ACCESS_TOKEN_LIFETIME_SECONDS));
    }

    @Test
    void callback_userWithoutEmail_returnsServerError() {
        FigmaPkceStateCache.Entry entry = new FigmaPkceStateCache.Entry(
                CODE_VERIFIER, MOP_AUTH_CODE, Instant.now().getEpochSecond());
        when(pkceStateCache.pop(UPSTREAM_STATE)).thenReturn(Optional.of(entry));
        when(authCodeRegionResolver.resolve(MOP_AUTH_CODE, "okta"))
                .thenReturn(new AuthCodeResolution(authorizationCode, false));
        when(codeExchangeClient.exchange(FIGMA_CODE, CALLBACK_URI, CODE_VERIFIER))
                .thenReturn(new FigmaCodeExchangeClient.FigmaTokens(ACCESS_TOKEN, REFRESH_TOKEN, 7_776_000L));
        when(userInfoClient.fetchMe(ACCESS_TOKEN))
                .thenReturn(new FigmaUserInfoClient.FigmaUser("123", null, "noemail"));
        when(configService.getRemoteServerUsernameClaim("figma")).thenReturn("email");

        Response resp = figmaResource.callback(FIGMA_CODE, UPSTREAM_STATE, null, null);

        assertEquals(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), resp.getStatus());
        verify(authorizerService, never()).storeTokens(
                anyString(), anyString(), anyString(), anyString(), anyString(),
                anyString(), anyString(), any());
    }

    // -------- lookupKeyFor: claim mapping --------

    @Test
    void lookupKeyFor_emailClaim_stripsAtDomain() {
        assertEquals(EXPECTED_LOOKUP_KEY,
                FigmaResource.lookupKeyFor(
                        new FigmaUserInfoClient.FigmaUser("123", EMAIL, "h"), "email"));
    }

    @Test
    void lookupKeyFor_handleClaim_returnsHandleVerbatim() {
        assertEquals("the-handle",
                FigmaResource.lookupKeyFor(
                        new FigmaUserInfoClient.FigmaUser("123", "x@y", "the-handle"), "handle"));
    }

    @Test
    void lookupKeyFor_idClaimDefault_returnsId() {
        assertEquals("123",
                FigmaResource.lookupKeyFor(
                        new FigmaUserInfoClient.FigmaUser("123", "x@y", "h"), "id"));
    }

    @Test
    void lookupKeyFor_nullUser_returnsNull() {
        assertEquals(null, FigmaResource.lookupKeyFor(null, "email"));
    }

    @Test
    void figmaAccessTokenLifetimeConstant_pinnedAt90Days() {
        assertEquals(7_776_000L, FigmaResource.FIGMA_ACCESS_TOKEN_LIFETIME_SECONDS,
                "must equal exactly 90 days; drift would either evict the bare row prematurely "
                        + "or extend it past the real Figma AT lifetime");
    }
}
