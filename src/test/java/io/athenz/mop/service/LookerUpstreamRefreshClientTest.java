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

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import io.athenz.mop.config.LookerConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link LookerUpstreamRefreshClient}. Looker instances are public PKCE clients
 * ({@code token_endpoint_auth_method=none}) with a <strong>non-rotating</strong> refresh token
 * (the refresh response returns {@code refresh_token:null}). These tests pin:
 * <ul>
 *   <li>the public-client wire shape (no {@code Authorization} header, no {@code client_secret}),</li>
 *   <li>carry-forward of the prior RT when the response omits a new one (the steady-state case),</li>
 *   <li>per-instance token-endpoint + client_id resolution from the {@code provider#sub} key,</li>
 *   <li>the {@code invalid_grant} -&gt; revoked / everything-else -&gt; refresh error contract.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class LookerUpstreamRefreshClientTest {

    @Mock
    TokenClient tokenClient;

    @Mock
    ConfigService configService;

    @Mock
    LookerConfig lookerConfig;

    @InjectMocks
    LookerUpstreamRefreshClient client;

    // Use a valid Looker instance id (so LookerInstances.isLooker() passes) but a synthetic host
    // and client_id — never a real Looker deployment URL.
    private static final String PROVIDER = "looker-ouryahoo";
    private static final String PROVIDER_USER_ID = PROVIDER + "#test-user";
    private static final String TEST_CLIENT_ID = "test-looker-client-id";
    private static final String HOST_BASE = "https://looker.example.test";

    @BeforeEach
    void setUp() {
        lenient().when(lookerConfig.clientId(PROVIDER)).thenReturn(TEST_CLIENT_ID);
        lenient().when(configService.getRemoteServerEndpoint(PROVIDER)).thenReturn(HOST_BASE);
    }

    @Test
    void refresh_emptyRefreshToken_throwsRefreshException() {
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh(PROVIDER_USER_ID, null));
        assertTrue(e.getMessage().contains("empty"));

        OktaTokenRefreshException e2 = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh(PROVIDER_USER_ID, "  "));
        assertTrue(e2.getMessage().contains("empty"));
    }

    @Test
    void refresh_nonLookerProvider_throwsRefreshException() {
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("datadog#u", "rt"));
        assertTrue(e.getMessage().contains("non-Looker"));
    }

    @Test
    void refresh_missingClientId_throwsRefreshException() {
        when(lookerConfig.clientId(PROVIDER)).thenReturn("");
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh(PROVIDER_USER_ID, "rt"));
        assertTrue(e.getMessage().contains("client_id"));
    }

    @Test
    void refresh_missingTokenEndpoint_throwsRefreshException() {
        when(configService.getRemoteServerEndpoint(PROVIDER)).thenReturn(null);
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh(PROVIDER_USER_ID, "rt"));
        assertTrue(e.getMessage().contains("token endpoint"));
    }

    @Test
    void refresh_success_carryForwardWhenResponseOmitsRt() throws Exception {
        // Looker does NOT rotate the RT (refresh response returns refresh_token:null). The client
        // must echo the original RT back so the L2 row's encrypted_upstream_refresh_token is not
        // nulled out. This is the steady-state case for Looker, not a defensive edge.
        AccessToken at = new BearerAccessToken("lk_new_at", 3600L, null);
        Tokens tokens = new Tokens(at, /* refreshToken */ null);
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh(PROVIDER_USER_ID, "  lk_rt_original  ");

        assertNotNull(resp);
        assertEquals("lk_new_at", resp.accessToken());
        assertEquals("lk_rt_original", resp.refreshToken(),
                "Looker does not rotate the RT; client must trim and reuse the original RT when the response omits one");
        assertEquals(3600L, resp.expiresInSeconds());
        assertNull(resp.idToken(), "Looker token endpoint does not return an id_token");
    }

    @Test
    void refresh_success_propagatesRotatedRtWhenPresent() throws Exception {
        // Defensive: if Looker ever does return a rotated RT, persist it verbatim.
        AccessToken at = new BearerAccessToken("lk_new_at", 3599L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("lk_rt_rotated"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh(PROVIDER_USER_ID, "lk_rt_old");

        assertEquals("lk_rt_rotated", resp.refreshToken());
        assertEquals(3599L, resp.expiresInSeconds());
    }

    @Test
    void refresh_success_defaultsTo1HourWhenExpiresInMissing() throws Exception {
        AccessToken at = new BearerAccessToken("lk_new_at"); // no lifetime
        Tokens tokens = new Tokens(at, null);
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh(PROVIDER_USER_ID, "lk_rt_old");

        assertEquals(LookerUpstreamRefreshClient.DEFAULT_EXPIRES_IN_SECONDS, resp.expiresInSeconds());
        assertEquals(3_600L, LookerUpstreamRefreshClient.DEFAULT_EXPIRES_IN_SECONDS,
                "Looker default lifetime constant must equal Looker's documented expires_in (~1h)");
    }

    @Test
    void refresh_invalidGrant_throwsRevokedException() throws Exception {
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "Refresh token has been revoked.", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRevokedException e = assertThrows(OktaTokenRevokedException.class,
                () -> client.refresh(PROVIDER_USER_ID, "rt"));
        assertTrue(e.getMessage().toLowerCase().contains("invalid"),
                "invalid_grant must map to revoked-RT semantics so UpstreamRefreshService marks the L2 row");
    }

    @Test
    void refresh_serverError_throwsRefreshException() throws Exception {
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("server_error", "internal", 500));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh(PROVIDER_USER_ID, "rt"));
        assertTrue(e.getMessage().contains("server_error"));
    }

    @Test
    void refresh_ioException_wrappedAsRefreshException() throws Exception {
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh(PROVIDER_USER_ID, "rt"));
        assertTrue(e.getMessage().contains("boom"));
    }

    /**
     * Pins the public-client wire shape: the serialized HTTP request must carry {@code client_id}
     * in the form body and must NOT carry an {@code Authorization} header or {@code client_secret}.
     * Also asserts the per-instance token endpoint is {@code <host>/api/token}.
     */
    @Test
    void refresh_serializedRequest_publicClientShape_andPerInstanceEndpoint() throws Exception {
        AccessToken at = new BearerAccessToken("lk_new_at", 3600L, null);
        AccessTokenResponse success = new AccessTokenResponse(new Tokens(at, null));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        client.refresh(PROVIDER_USER_ID, "lk_rt_old");

        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);
        org.mockito.Mockito.verify(tokenClient).execute(captor.capture());
        TokenRequest sent = captor.getValue();

        assertNull(sent.getClientAuthentication(),
                "Looker is a public PKCE client; clientAuthentication must be null");
        assertNotNull(sent.getClientID());
        assertEquals(TEST_CLIENT_ID, sent.getClientID().getValue());
        assertEquals(HOST_BASE + "/api/token", sent.getEndpointURI().toString(),
                "Looker token endpoint must be resolved per instance as <host>/api/token");

        HTTPRequest http = sent.toHTTPRequest();
        String body = http.getBody();
        assertNotNull(body);
        assertTrue(body.contains("client_id=" + TEST_CLIENT_ID), "form body must include client_id; was: " + body);
        assertTrue(body.contains("grant_type=refresh_token"), "form body must include grant_type=refresh_token");
        assertFalse(body.contains("client_secret"),
                "form body must NOT contain client_secret (Looker is a public client); was: " + body);
        assertNull(http.getAuthorization(),
                "request must NOT carry an Authorization header");
    }
}
