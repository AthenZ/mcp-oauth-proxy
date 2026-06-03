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
import io.athenz.mop.secret.K8SSecretsProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AirtableUpstreamRefreshClient}. Airtable is a confidential client using
 * {@code client_secret_basic} (HTTP Basic on the {@code Authorization} header), matching
 * Airtable's documented curl examples ({@code curl -u client_id:client_secret}). The tests pin
 * the on-the-wire shape so a future regression that switches to {@code ClientSecretPost} (form
 * body) — silently breaking compatibility with Airtable's documented examples — fails loudly.
 *
 * <p>Differences vs {@link OracleEpmUpstreamRefreshClientTest}:
 * <ul>
 *   <li>Airtable uses {@code ClientSecretBasic}, Oracle uses {@code ClientSecretPost}.</li>
 *   <li>Both have {@code expires_in=3600} (1 h) defaults.</li>
 *   <li>Both rotate the RT on every refresh.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class AirtableUpstreamRefreshClientTest {

    private static final String TEST_CLIENT_ID = "23800f05-6b1d-4907-a11d-3f5cde4e4830";
    private static final String TEST_CLIENT_SECRET_KEY = "airtable-client-secret";
    private static final String TEST_CLIENT_SECRET = "test-airtable-client-secret";

    @Mock
    K8SSecretsProvider k8SSecretsProvider;

    @Mock
    TokenClient tokenClient;

    @InjectMocks
    AirtableUpstreamRefreshClient client;

    @BeforeEach
    void setUp() {
        client.clientId = TEST_CLIENT_ID;
        client.clientSecretKey = TEST_CLIENT_SECRET_KEY;
    }

    @Test
    void refresh_emptyRefreshToken_throwsRefreshException() {
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("airtable#u", null));
        assertTrue(e.getMessage().contains("empty"));

        OktaTokenRefreshException e2 = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("airtable#u", "  "));
        assertTrue(e2.getMessage().contains("empty"));
    }

    @Test
    void refresh_missingClientId_throwsRefreshException() {
        client.clientId = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("airtable#u", "rt"));
        assertTrue(e.getMessage().contains("client_id"));
    }

    @Test
    void refresh_missingClientSecretKey_throwsRefreshException() {
        client.clientSecretKey = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("airtable#u", "rt"));
        assertTrue(e.getMessage().contains("secret key"));
    }

    @Test
    void refresh_clientSecretNotFoundInSecrets_throwsRefreshException() {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("other-key", "value"));
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("airtable#u", "rt"));
        assertTrue(e.getMessage().contains("not found"));
    }

    @Test
    void refresh_success_propagatesRotatedRt() throws Exception {
        // Airtable rotates the RT on every refresh (60d RT lifetime) — the response's new
        // refresh_token must replace the prior one so callers persist the rotated value.
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        AccessToken at = new BearerAccessToken("airtable_new_at", 3600L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("airtable_rt_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("airtable#user-uuid", "  airtable_rt_old  ");

        assertNotNull(resp);
        assertEquals("airtable_new_at", resp.accessToken());
        assertEquals("airtable_rt_new", resp.refreshToken(),
                "Airtable rotates the RT every refresh; the response RT must replace the prior one");
        assertEquals(3600L, resp.expiresInSeconds());
        assertNull(resp.idToken(),
                "Airtable's /token endpoint does not return an id_token; the refresh response is bound to UpstreamRefreshResponse without an id_token field");
    }

    @Test
    void refresh_success_carryForwardWhenResponseOmitsRt() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        AccessToken at = new BearerAccessToken("airtable_new_at", 3600L, null);
        Tokens tokens = new Tokens(at, /* refreshToken */ null);
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("airtable#u", "  airtable_rt_original  ");

        assertEquals("airtable_rt_original", resp.refreshToken(),
                "client must trim whitespace and reuse the original RT when Airtable's response omits a rotated one");
    }

    @Test
    void refresh_success_defaultsTo1HourWhenExpiresInMissing() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        AccessToken at = new BearerAccessToken("airtable_new_at"); // no lifetime
        Tokens tokens = new Tokens(at, new RefreshToken("airtable_rt_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("airtable#u", "airtable_rt_old");

        assertEquals(AirtableUpstreamRefreshClient.DEFAULT_EXPIRES_IN_SECONDS, resp.expiresInSeconds());
        assertEquals(3_600L, AirtableUpstreamRefreshClient.DEFAULT_EXPIRES_IN_SECONDS,
                "Airtable default lifetime constant must equal Airtable's documented expires_in (3600 = 1h)");
    }

    @Test
    void refresh_invalidGrant_throwsRevokedException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "Refresh token has been revoked.", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRevokedException e = assertThrows(OktaTokenRevokedException.class,
                () -> client.refresh("airtable#u", "rt"));
        assertTrue(e.getMessage().toLowerCase().contains("invalid"),
                "invalid_grant must map to revoked-RT semantics so UpstreamRefreshService marks the L2 row");
    }

    @Test
    void refresh_serverError_throwsRefreshException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("server_error", "internal", 500));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("airtable#u", "rt"));
        assertTrue(e.getMessage().contains("server_error"));
    }

    @Test
    void refresh_ioException_wrappedAsRefreshException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("airtable#u", "rt"));
        assertTrue(e.getMessage().contains("boom"));
    }

    /**
     * Pins the confidential-client wire shape: the serialized HTTP request must carry
     * {@code Authorization: Basic <base64(id:secret)>} and must NOT carry {@code client_id} or
     * {@code client_secret} in the form body. This is the regression guard against accidentally
     * switching to {@code ClientSecretPost} (form body) which would silently break compatibility
     * with Airtable's documented and verified curl examples ({@code curl -u id:secret}).
     */
    @Test
    void refresh_serializedRequest_usesBasicAuthHeaderAndNoBodyCredentials() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        AccessToken at = new BearerAccessToken("airtable_new_at", 3600L, null);
        AccessTokenResponse success = new AccessTokenResponse(new Tokens(at, new RefreshToken("airtable_rt_new")));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        client.refresh("airtable#u", "airtable_rt_old");

        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);
        org.mockito.Mockito.verify(tokenClient).execute(captor.capture());
        TokenRequest sent = captor.getValue();

        // ClientSecretBasic, not ClientSecretPost or the public-client overload.
        assertNotNull(sent.getClientAuthentication(),
                "Airtable is a confidential client; clientAuthentication must NOT be null");
        assertEquals("client_secret_basic", sent.getClientAuthentication().getMethod().getValue(),
                "Airtable's verified curl uses HTTP Basic (`-u id:secret`), not client_secret_post");

        // Serialize and confirm the wire shape: Authorization header carries Basic credentials;
        // form body must NOT contain client_id or client_secret (that would indicate
        // ClientSecretPost was misused).
        HTTPRequest http = sent.toHTTPRequest();
        String body = http.getBody();
        assertNotNull(body, "request body should not be null");
        assertTrue(body.contains("grant_type=refresh_token"), "form body must include grant_type=refresh_token");
        assertFalse(body.contains("client_id="),
                "form body must NOT include client_id; that would indicate client_secret_post was used. body=" + body);
        assertFalse(body.contains("client_secret="),
                "form body must NOT include client_secret; that would indicate client_secret_post was used. body=" + body);

        String expectedAuth = "Basic " + Base64.getEncoder().encodeToString(
                (TEST_CLIENT_ID + ":" + TEST_CLIENT_SECRET).getBytes());
        assertEquals(expectedAuth, http.getAuthorization(),
                "Authorization header must be `Basic base64(client_id:client_secret)` per Airtable's documented curl");
    }
}
