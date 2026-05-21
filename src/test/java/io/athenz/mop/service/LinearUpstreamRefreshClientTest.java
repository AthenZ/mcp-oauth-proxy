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
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link LinearUpstreamRefreshClient}. Linear is a public PKCE client today (DCR
 * registers public clients); these tests pin the public-client request shape so a future
 * regression that injects {@code ClientSecretBasic} / {@code ClientSecretPost} (or a stray
 * {@code Authorization} header) fails loudly.
 *
 * <p>Differences vs {@link DatadogUpstreamRefreshClientTest}:
 * <ul>
 *   <li>Default {@code expires_in} is ~24 h (Linear's documented {@code expires_in=86399}), not 1 h.</li>
 *   <li>Linear <strong>rotates</strong> the RT on every refresh — the rotated-RT branch is the
 *       common case; the carry-forward branch is the safety net for the (anomalous) HTTP 200
 *       response that omits {@code refresh_token}.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class LinearUpstreamRefreshClientTest {

    @Mock
    TokenClient tokenClient;

    @InjectMocks
    LinearUpstreamRefreshClient client;

    private static final String TEST_CLIENT_ID = "test-linear-client-id";

    @BeforeEach
    void setUp() {
        client.clientId = TEST_CLIENT_ID;
        // Production sets a non-empty placeholder for the secret-key so SmallRye Config can
        // resolve a String at startup. The Linear refresh path must STILL ignore it on the wire
        // (no client_secret in the form body, no Authorization header). This setup pins that
        // contract so a future change that wires up ClientSecretBasic without flipping the
        // documented confidential-mode plan would break the public-client assertion below.
        client.clientSecretKey = "linear-client-secret";
    }

    @Test
    void refresh_emptyRefreshToken_throwsRefreshException() {
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("linear#u", null));
        assertTrue(e.getMessage().contains("empty"));

        OktaTokenRefreshException e2 = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("linear#u", "  "));
        assertTrue(e2.getMessage().contains("empty"));
    }

    @Test
    void refresh_missingClientId_throwsRefreshException() {
        client.clientId = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("linear#u", "rt"));
        assertTrue(e.getMessage().contains("client_id"));
    }

    @Test
    void refresh_success_propagatesRotatedRt() throws Exception {
        // Linear rotates the RT on every refresh — the response's new refresh_token must replace
        // the prior one in UpstreamRefreshResponse so callers persist the rotated value.
        AccessToken at = new BearerAccessToken("li_new_at", 86399L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("li_rt_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("linear#user-uuid", "  li_rt_old  ");

        assertNotNull(resp);
        assertEquals("li_new_at", resp.accessToken());
        assertEquals("li_rt_new", resp.refreshToken(),
                "Linear rotates the RT every refresh; the response RT must replace the prior one");
        assertEquals(86399L, resp.expiresInSeconds());
        assertNull(resp.idToken(),
                "Linear token endpoint does not return an id_token");
    }

    @Test
    void refresh_success_carryForwardWhenResponseOmitsRt() throws Exception {
        // Defensive: in the (anomalous) case where Linear returns HTTP 200 with no rotated
        // refresh_token, the client must echo the original RT back so the L2 row's
        // encrypted_upstream_refresh_token is not nulled out.
        AccessToken at = new BearerAccessToken("li_new_at", 86399L, null);
        Tokens tokens = new Tokens(at, /* refreshToken */ null);
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("linear#u", "  li_rt_original  ");

        assertEquals("li_rt_original", resp.refreshToken(),
                "client must trim whitespace and reuse the original RT when Linear's response omits a rotated one");
    }

    @Test
    void refresh_success_defaultsTo24HoursWhenExpiresInMissing() throws Exception {
        AccessToken at = new BearerAccessToken("li_new_at"); // no lifetime
        Tokens tokens = new Tokens(at, new RefreshToken("li_rt_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("linear#u", "li_rt_old");

        assertEquals(LinearUpstreamRefreshClient.DEFAULT_EXPIRES_IN_SECONDS, resp.expiresInSeconds());
        assertEquals(86_399L, LinearUpstreamRefreshClient.DEFAULT_EXPIRES_IN_SECONDS,
                "Linear default lifetime constant must equal Linear's documented expires_in (86399 ~24h)");
    }

    @Test
    void refresh_invalidGrant_throwsRevokedException() throws Exception {
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "Refresh token has been revoked.", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRevokedException e = assertThrows(OktaTokenRevokedException.class,
                () -> client.refresh("linear#u", "rt"));
        assertTrue(e.getMessage().toLowerCase().contains("invalid"),
                "invalid_grant must map to revoked-RT semantics so UpstreamRefreshService marks the L2 row");
    }

    @Test
    void refresh_serverError_throwsRefreshException() throws Exception {
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("server_error", "internal", 500));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("linear#u", "rt"));
        assertTrue(e.getMessage().contains("server_error"));
    }

    @Test
    void refresh_ioException_wrappedAsRefreshException() throws Exception {
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("linear#u", "rt"));
        assertTrue(e.getMessage().contains("boom"));
    }

    /**
     * Pins the public-client wire shape: the serialized HTTP request must carry {@code client_id}
     * in the form body and must NOT carry an {@code Authorization} header or {@code client_secret}
     * field. This is the regression guard for the {@code TODO(linear-confidential)} hook —
     * accidentally enabling client-secret machinery before Linear DCR returns one would silently
     * break refresh.
     */
    @Test
    void refresh_serializedRequest_hasNoClientSecretAndNoAuthorizationHeader() throws Exception {
        AccessToken at = new BearerAccessToken("li_new_at", 86399L, null);
        AccessTokenResponse success = new AccessTokenResponse(new Tokens(at, new RefreshToken("li_rt_new")));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        client.refresh("linear#u", "li_rt_old");

        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);
        org.mockito.Mockito.verify(tokenClient).execute(captor.capture());
        TokenRequest sent = captor.getValue();

        // Public-client overload sets clientAuthentication to null. The grant itself authenticates
        // the client (PKCE on /authorize was the only required proof; refresh_token grants only
        // need client_id when the client is public).
        assertNull(sent.getClientAuthentication(),
                "Linear is a public PKCE client; clientAuthentication must be null");
        assertNotNull(sent.getClientID(),
                "client_id must still be passed via the public-client TokenRequest overload so it lands in the form body");
        assertEquals(TEST_CLIENT_ID, sent.getClientID().getValue());

        // Serialize and confirm the wire shape: form body has client_id but no client_secret;
        // headers carry no Authorization.
        HTTPRequest http = sent.toHTTPRequest();
        String body = http.getBody();
        assertNotNull(body, "request body should not be null");
        assertTrue(body.contains("client_id=" + TEST_CLIENT_ID),
                "form body must include client_id; was: " + body);
        assertTrue(body.contains("grant_type=refresh_token"), "form body must include grant_type=refresh_token");
        assertFalse(body.contains("client_secret"),
                "form body must NOT contain client_secret (Linear is a public client); was: " + body);
        assertNull(http.getAuthorization(),
                "request must NOT carry an Authorization header; if present, the upstream call would silently break with bogus credentials");
    }
}
