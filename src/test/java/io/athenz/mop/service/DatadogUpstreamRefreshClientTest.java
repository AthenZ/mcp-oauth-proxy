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
 * Unit tests for {@link DatadogUpstreamRefreshClient}. Datadog is a public PKCE client (DCR
 * returns no client_secret); these tests pin the public-client request shape so a future
 * regression that injects {@code ClientSecretBasic} / {@code ClientSecretPost} (or a stray
 * {@code Authorization} header) fails loudly.
 *
 * <p>Differences vs {@link FigmaUpstreamRefreshClientTest}:
 * <ul>
 *   <li>Default {@code expires_in} is 1 h (Datadog's documented AT lifetime), not 90 d.</li>
 *   <li>No {@link io.athenz.mop.secret.K8SSecretsProvider} dependency; the client must not
 *       require any client-secret machinery.</li>
 *   <li>Datadog's RT does not rotate, so the "no new RT" branch is the common case rather than
 *       a defensive corner.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class DatadogUpstreamRefreshClientTest {

    @Mock
    TokenClient tokenClient;

    @InjectMocks
    DatadogUpstreamRefreshClient client;

    @BeforeEach
    void setUp() {
        client.clientId = "mcp_test_datadog_client";
    }

    @Test
    void refresh_emptyRefreshToken_throwsRefreshException() {
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("datadog#u", null));
        assertTrue(e.getMessage().contains("empty"));

        OktaTokenRefreshException e2 = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("datadog#u", "  "));
        assertTrue(e2.getMessage().contains("empty"));
    }

    @Test
    void refresh_missingClientId_throwsRefreshException() {
        client.clientId = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("datadog#u", "rt"));
        assertTrue(e.getMessage().contains("client_id"));
    }

    @Test
    void refresh_success_returnsAtAndCarriesForwardRtWhenNotRotated() throws Exception {
        // Datadog does not rotate the RT; the common case is success with no new RT in the
        // response. The client must echo the original RT back into UpstreamRefreshResponse so the
        // L2 row's encrypted_upstream_refresh_token is not nulled out.
        AccessToken at = new BearerAccessToken("dd_new_at", 3600L, null);
        Tokens tokens = new Tokens(at, /* refreshToken */ null);
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("datadog#user-uuid", "  ddoar_original  ");

        assertNotNull(resp);
        assertEquals("dd_new_at", resp.accessToken());
        assertEquals("ddoar_original", resp.refreshToken(),
                "client must trim whitespace and reuse the original RT when Datadog omits a rotated one");
        assertEquals(3600L, resp.expiresInSeconds());
        assertNull(resp.idToken(),
                "Datadog token endpoint does not return an id_token");
    }

    @Test
    void refresh_success_propagatesRotatedRtIfDatadogEverStartsRotating() throws Exception {
        // Defensive: if a future Datadog response does include a rotated refresh_token, the
        // client must propagate it verbatim rather than reusing the stale one.
        AccessToken at = new BearerAccessToken("dd_new_at", 3600L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("ddoar_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("datadog#u", "ddoar_old");

        assertEquals("ddoar_new", resp.refreshToken());
    }

    @Test
    void refresh_success_defaultsTo1HourWhenExpiresInMissing() throws Exception {
        AccessToken at = new BearerAccessToken("dd_new_at"); // no lifetime
        Tokens tokens = new Tokens(at, /* refreshToken */ null);
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("datadog#u", "ddoar_x");

        assertEquals(DatadogUpstreamRefreshClient.DEFAULT_EXPIRES_IN_SECONDS, resp.expiresInSeconds());
        assertEquals(3600L, DatadogUpstreamRefreshClient.DEFAULT_EXPIRES_IN_SECONDS,
                "Datadog default lifetime constant must equal 1 hour");
    }

    @Test
    void refresh_invalidGrant_throwsRevokedException() throws Exception {
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "Refresh token has been revoked.", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRevokedException e = assertThrows(OktaTokenRevokedException.class,
                () -> client.refresh("datadog#u", "rt"));
        assertTrue(e.getMessage().toLowerCase().contains("invalid"),
                "invalid_grant must map to revoked-RT semantics so UpstreamRefreshService marks the L2 row");
    }

    @Test
    void refresh_serverError_throwsRefreshException() throws Exception {
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("server_error", "internal", 500));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("datadog#u", "rt"));
        assertTrue(e.getMessage().contains("server_error"));
    }

    @Test
    void refresh_ioException_wrappedAsRefreshException() throws Exception {
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("datadog#u", "rt"));
        assertTrue(e.getMessage().contains("boom"));
    }

    /**
     * Pins the public-client wire shape: the serialized HTTP request must carry {@code client_id}
     * in the form body and must NOT carry an {@code Authorization} header or {@code client_secret}
     * field. This is the regression guard for the "someone wires K8SSecretsProvider for
     * consistency" risk called out in the implementation plan — wiring any auth mechanism that
     * requires a secret would silently break Datadog refresh.
     */
    @Test
    void refresh_serializedRequest_hasNoClientSecretAndNoAuthorizationHeader() throws Exception {
        AccessToken at = new BearerAccessToken("dd_new_at", 3600L, null);
        AccessTokenResponse success = new AccessTokenResponse(new Tokens(at, null));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        client.refresh("datadog#u", "ddoar_x");

        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);
        org.mockito.Mockito.verify(tokenClient).execute(captor.capture());
        TokenRequest sent = captor.getValue();

        // Public-client overload sets clientAuthentication to null. The grant itself authenticates
        // the client (PKCE on /authorize was the only required proof; refresh_token grants only
        // need client_id when the client is public).
        assertNull(sent.getClientAuthentication(),
                "Datadog is a public PKCE client; clientAuthentication must be null");
        assertNotNull(sent.getClientID(),
                "client_id must still be passed via the public-client TokenRequest overload so it lands in the form body");
        assertEquals("mcp_test_datadog_client", sent.getClientID().getValue());

        // Serialize and confirm the wire shape: form body has client_id but no client_secret;
        // headers carry no Authorization.
        HTTPRequest http = sent.toHTTPRequest();
        String body = http.getBody();
        assertNotNull(body, "request body should not be null");
        assertTrue(body.contains("client_id=mcp_test_datadog_client"),
                "form body must include client_id; was: " + body);
        assertTrue(body.contains("grant_type=refresh_token"), "form body must include grant_type=refresh_token");
        assertFalse(body.contains("client_secret"),
                "form body must NOT contain client_secret (Datadog is a public client); was: " + body);
        assertNull(http.getAuthorization(),
                "request must NOT carry an Authorization header; if present, the upstream call would silently break with bogus credentials");
    }
}
