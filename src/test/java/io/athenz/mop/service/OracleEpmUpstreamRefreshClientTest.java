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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OracleEpmUpstreamRefreshClient}. Oracle EPM is a confidential client
 * using {@code client_secret_post} (form body), matching Oracle's verified curl examples. The
 * tests pin the on-the-wire shape so a future regression that switches to
 * {@code ClientSecretBasic} (Authorization header) — silently breaking compatibility with
 * Oracle's documented examples — fails loudly.
 *
 * <p>Differences vs {@link FigmaUpstreamRefreshClientTest}:
 * <ul>
 *   <li>Default {@code expires_in} is 1 h (Oracle IDCS), not 90 d.</li>
 *   <li>Oracle <strong>rotates</strong> the RT on every refresh; the rotated-RT branch is the
 *       common case (the carry-forward branch is the safety net for anomalous responses).</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class OracleEpmUpstreamRefreshClientTest {

    private static final String TEST_CLIENT_ID = "test-oracle-epm-client-id";
    private static final String TEST_CLIENT_SECRET_KEY = "test-oracle-epm-client-secret-key";
    private static final String TEST_CLIENT_SECRET = "test-oracle-epm-client-secret";

    @Mock
    K8SSecretsProvider k8SSecretsProvider;

    @Mock
    TokenClient tokenClient;

    @InjectMocks
    OracleEpmUpstreamRefreshClient client;

    @BeforeEach
    void setUp() {
        client.clientId = TEST_CLIENT_ID;
        client.clientSecretKey = TEST_CLIENT_SECRET_KEY;
    }

    @Test
    void refresh_emptyRefreshToken_throwsRefreshException() {
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("oracle-epm#u", null));
        assertTrue(e.getMessage().contains("empty"));

        OktaTokenRefreshException e2 = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("oracle-epm#u", "  "));
        assertTrue(e2.getMessage().contains("empty"));
    }

    @Test
    void refresh_missingClientId_throwsRefreshException() {
        client.clientId = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("oracle-epm#u", "rt"));
        assertTrue(e.getMessage().contains("client_id"));
    }

    @Test
    void refresh_missingClientSecretKey_throwsRefreshException() {
        client.clientSecretKey = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("oracle-epm#u", "rt"));
        assertTrue(e.getMessage().contains("secret key"));
    }

    @Test
    void refresh_clientSecretNotFoundInSecrets_throwsRefreshException() {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("other-key", "value"));
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("oracle-epm#u", "rt"));
        assertTrue(e.getMessage().contains("not found"));
    }

    @Test
    void refresh_success_propagatesRotatedRt() throws Exception {
        // Oracle IDCS rotates the RT on every refresh — the response's new refresh_token must
        // replace the prior one in UpstreamRefreshResponse so callers persist the rotated value.
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        AccessToken at = new BearerAccessToken("oepm_new_at", 3600L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("oepm_rt_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("oracle-epm#user-uuid", "  oepm_rt_old  ");

        assertNotNull(resp);
        assertEquals("oepm_new_at", resp.accessToken());
        assertEquals("oepm_rt_new", resp.refreshToken(),
                "Oracle rotates the RT every refresh; the response RT must replace the prior one");
        assertEquals(3600L, resp.expiresInSeconds());
        assertNull(resp.idToken(),
                "Oracle's /token endpoint may return an id_token in the auth-code flow but the refresh response is bound to UpstreamRefreshResponse without an id_token field");
    }

    @Test
    void refresh_success_carryForwardWhenResponseOmitsRt() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        AccessToken at = new BearerAccessToken("oepm_new_at", 3600L, null);
        Tokens tokens = new Tokens(at, /* refreshToken */ null);
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("oracle-epm#u", "  oepm_rt_original  ");

        assertEquals("oepm_rt_original", resp.refreshToken(),
                "client must trim whitespace and reuse the original RT when Oracle's response omits a rotated one");
    }

    @Test
    void refresh_success_defaultsTo1HourWhenExpiresInMissing() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        AccessToken at = new BearerAccessToken("oepm_new_at"); // no lifetime
        Tokens tokens = new Tokens(at, new RefreshToken("oepm_rt_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("oracle-epm#u", "oepm_rt_old");

        assertEquals(OracleEpmUpstreamRefreshClient.DEFAULT_EXPIRES_IN_SECONDS, resp.expiresInSeconds());
        assertEquals(3_600L, OracleEpmUpstreamRefreshClient.DEFAULT_EXPIRES_IN_SECONDS,
                "Oracle default lifetime constant must equal Oracle's documented expires_in (3600 = 1h)");
    }

    @Test
    void refresh_invalidGrant_throwsRevokedException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "Refresh token has been revoked.", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRevokedException e = assertThrows(OktaTokenRevokedException.class,
                () -> client.refresh("oracle-epm#u", "rt"));
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
                () -> client.refresh("oracle-epm#u", "rt"));
        assertTrue(e.getMessage().contains("server_error"));
    }

    @Test
    void refresh_ioException_wrappedAsRefreshException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("oracle-epm#u", "rt"));
        assertTrue(e.getMessage().contains("boom"));
    }

    /**
     * Pins the confidential-client wire shape: the serialized HTTP request must carry
     * {@code client_id} AND {@code client_secret} in the form body and must NOT carry an
     * {@code Authorization} header. This is the regression guard against accidentally switching
     * to {@code ClientSecretBasic} (HTTP Basic auth) which would silently break compatibility
     * with Oracle's documented and verified curl examples.
     */
    @Test
    void refresh_serializedRequest_hasClientSecretInBodyAndNoAuthorizationHeader() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(
                Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        AccessToken at = new BearerAccessToken("oepm_new_at", 3600L, null);
        AccessTokenResponse success = new AccessTokenResponse(new Tokens(at, new RefreshToken("oepm_rt_new")));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        client.refresh("oracle-epm#u", "oepm_rt_old");

        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);
        org.mockito.Mockito.verify(tokenClient).execute(captor.capture());
        TokenRequest sent = captor.getValue();

        // ClientSecretPost, not the public-client overload.
        assertNotNull(sent.getClientAuthentication(),
                "Oracle EPM is a confidential client; clientAuthentication must NOT be null");
        assertEquals("client_secret_post", sent.getClientAuthentication().getMethod().getValue(),
                "Oracle's verified curl uses client_secret_post (form body), not client_secret_basic");

        // Serialize and confirm the wire shape: form body has BOTH client_id and client_secret;
        // headers carry no Authorization (which would indicate ClientSecretBasic was misused).
        HTTPRequest http = sent.toHTTPRequest();
        String body = http.getBody();
        assertNotNull(body, "request body should not be null");
        assertTrue(body.contains("client_id=" + TEST_CLIENT_ID),
                "form body must include client_id; was: " + body);
        assertTrue(body.contains("client_secret=" + TEST_CLIENT_SECRET),
                "form body must include client_secret (client_secret_post); was: " + body);
        assertTrue(body.contains("grant_type=refresh_token"), "form body must include grant_type=refresh_token");
        assertNull(http.getAuthorization(),
                "request must NOT carry an Authorization header; if present, the upstream call would be using ClientSecretBasic instead of ClientSecretPost");
    }
}
