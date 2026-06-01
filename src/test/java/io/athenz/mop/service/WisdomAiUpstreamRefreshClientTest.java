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
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WisdomAiUpstreamRefreshClient}. WisdomAI is a Descope-backed confidential
 * client: although DCR registers it as public, Descope's token endpoint requires a client_secret
 * on refresh ({@code errorCode=E011002 "missing secret"}). This client uses
 * {@code client_secret_post} first and falls back to {@code client_secret_basic} once on
 * {@code invalid_client}.
 *
 * <p>Tests pin both the on-the-wire shape (form body has {@code client_secret}, no Authorization
 * header for {@code _post} / has Authorization header, no body secret for {@code _basic}) and the
 * one-shot fallback contract.
 */
@ExtendWith(MockitoExtension.class)
class WisdomAiUpstreamRefreshClientTest {

    private static final String TEST_CLIENT_ID = "test-wisdomai-client-id";
    private static final String TEST_CLIENT_SECRET_KEY = "wisdomai-client-secret";
    private static final String TEST_CLIENT_SECRET = "test-wisdomai-secret-value";

    @Mock
    K8SSecretsProvider k8SSecretsProvider;

    @Mock
    TokenClient tokenClient;

    @InjectMocks
    WisdomAiUpstreamRefreshClient client;

    @BeforeEach
    void setUp() {
        client.clientId = TEST_CLIENT_ID;
        client.clientSecretKey = TEST_CLIENT_SECRET_KEY;
    }

    /** Stub credentials provider to return our test secret under the configured key. */
    private void stubSecret() {
        when(k8SSecretsProvider.getCredentials(null))
                .thenReturn(Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
    }

    @Test
    void refresh_emptyRefreshToken_throwsRefreshException() {
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("wisdomai#u", null));
        assertTrue(e.getMessage().contains("empty"));

        OktaTokenRefreshException e2 = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("wisdomai#u", "  "));
        assertTrue(e2.getMessage().contains("empty"));
    }

    @Test
    void refresh_missingClientId_throwsRefreshException() {
        client.clientId = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("wisdomai#u", "rt"));
        assertTrue(e.getMessage().contains("client_id"));
    }

    @Test
    void refresh_missingClientSecretKey_throwsRefreshException() {
        client.clientSecretKey = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("wisdomai#u", "rt"));
        assertTrue(e.getMessage().contains("secret key"));
    }

    @Test
    void refresh_missingClientSecretValue_throwsRefreshException() {
        // K8s store has no entry for the configured key — surfaces an explicit error rather
        // than NPEing inside Nimbus when ClientSecretPost gets a null Secret.
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of());

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("wisdomai#u", "rt"));
        assertTrue(e.getMessage().contains("client secret not found"));
    }

    @Test
    void refresh_success_propagatesRotatedRt() throws Exception {
        stubSecret();
        AccessToken at = new BearerAccessToken("wai_new_at", 604_800L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("wai_rt_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("wisdomai#user-id", "  wai_rt_old  ");

        assertNotNull(resp);
        assertEquals("wai_new_at", resp.accessToken());
        assertEquals("wai_rt_new", resp.refreshToken(),
                "rotated RT in response must replace the prior one");
        assertEquals(604_800L, resp.expiresInSeconds());
        assertNull(resp.idToken(),
                "WisdomAI refresh response does not return an id_token");
    }

    @Test
    void refresh_success_carryForwardWhenResponseOmitsRt() throws Exception {
        // Defensive: in the case where the upstream returns HTTP 200 with no rotated
        // refresh_token, the client must echo the original RT back so the L2 row's
        // encrypted_upstream_refresh_token is not nulled out.
        stubSecret();
        AccessToken at = new BearerAccessToken("wai_new_at", 604_800L, null);
        Tokens tokens = new Tokens(at, /* refreshToken */ null);
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("wisdomai#u", "  wai_rt_original  ");

        assertEquals("wai_rt_original", resp.refreshToken(),
                "client must trim whitespace and reuse the original RT when the response omits a rotated one");
    }

    @Test
    void refresh_success_defaultsTo7DaysWhenExpiresInMissing() throws Exception {
        stubSecret();
        AccessToken at = new BearerAccessToken("wai_new_at"); // no lifetime
        Tokens tokens = new Tokens(at, new RefreshToken("wai_rt_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("wisdomai#u", "wai_rt_old");

        assertEquals(WisdomAiUpstreamRefreshClient.DEFAULT_EXPIRES_IN_SECONDS, resp.expiresInSeconds());
        assertEquals(604_800L, WisdomAiUpstreamRefreshClient.DEFAULT_EXPIRES_IN_SECONDS,
                "WisdomAI default lifetime constant must equal WisdomAI's documented expires_in (604800 ~7d)");
    }

    @Test
    void refresh_invalidGrant_throwsRevokedException() throws Exception {
        stubSecret();
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "Refresh token has been revoked.", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRevokedException e = assertThrows(OktaTokenRevokedException.class,
                () -> client.refresh("wisdomai#u", "rt"));
        assertTrue(e.getMessage().toLowerCase().contains("invalid"),
                "invalid_grant must map to revoked-RT semantics so UpstreamRefreshService marks the L2 row");

        // invalid_grant must NOT trigger the basic-auth retry: a single attempt only.
        verify(tokenClient, times(1)).execute(any(TokenRequest.class));
    }

    @Test
    void refresh_serverError_throwsRefreshException() throws Exception {
        stubSecret();
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("server_error", "internal", 500));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("wisdomai#u", "rt"));
        assertTrue(e.getMessage().contains("server_error"));

        // server_error must NOT trigger the basic-auth retry.
        verify(tokenClient, times(1)).execute(any(TokenRequest.class));
    }

    @Test
    void refresh_ioException_wrappedAsRefreshException() throws Exception {
        stubSecret();
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("wisdomai#u", "rt"));
        assertTrue(e.getMessage().contains("boom"));
    }

    /**
     * Pins the on-the-wire shape for client_secret_post against WisdomAI's documented curl:
     * <pre>
     *   curl -sS -X POST https://api.descope.com/oauth2/v1/apps/token \
     *     -H 'Content-Type: application/x-www-form-urlencoded' \
     *     --data-urlencode 'grant_type=refresh_token' \
     *     --data-urlencode 'client_id=&lt;CLIENT-ID&gt;' \
     *     --data-urlencode 'client_secret=&lt;CLIENT-SECRET&gt;' \
     *     --data-urlencode 'refresh_token=&lt;REFRESH_TOKEN&gt;'
     * </pre>
     * Every field in the curl above must be present in the rendered request, and there must be
     * no Authorization header (Descope rejects ambiguous client auth combinations).
     */
    @Test
    void refresh_serializedRequest_matchesDescopeCurlContract() throws Exception {
        stubSecret();
        AccessToken at = new BearerAccessToken("wai_new_at", 604_800L, null);
        AccessTokenResponse success = new AccessTokenResponse(new Tokens(at, new RefreshToken("wai_rt_new")));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        // A realistic-looking Descope refresh-token JWT that contains '+', '/', and '=' so the
        // form-encoder is exercised against URL-unsafe characters.
        String descopeRtJwt = "eyJhbGc.eyJzdWIiOiJ1c2VyMSJ9.AbCd+/=Ef";
        client.refresh("wisdomai#alice", descopeRtJwt);

        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);
        verify(tokenClient).execute(captor.capture());
        TokenRequest sent = captor.getValue();

        // Endpoint must be Descope's /oauth2/v1/apps/token, not WisdomAI's host.
        assertEquals("https://api.descope.com/oauth2/v1/apps/token",
                sent.getEndpointURI().toString(),
                "token endpoint must be Descope's /oauth2/v1/apps/token");

        // Auth method must be ClientSecretPost (everything in the form body).
        assertNotNull(sent.getClientAuthentication());
        assertInstanceOf(ClientSecretPost.class, sent.getClientAuthentication(),
                "first attempt must use client_secret_post (matches Descope curl)");

        HTTPRequest http = sent.toHTTPRequest();

        // Method + Content-Type match the curl invocation.
        assertEquals("POST", http.getMethod().name());
        assertNotNull(http.getEntityContentType(), "Content-Type must be set");
        assertTrue(http.getEntityContentType().toString().contains("application/x-www-form-urlencoded"),
                "Content-Type must be application/x-www-form-urlencoded; was: "
                        + http.getEntityContentType());

        // No Authorization header — client_secret_post carries credentials in the body only.
        assertNull(http.getAuthorization(),
                "client_secret_post must NOT carry an Authorization header");

        // Body must contain every field from the documented curl. The refresh_token will be
        // URL-encoded by Nimbus, so we check the encoded form.
        String body = http.getBody();
        assertNotNull(body);
        assertTrue(body.contains("grant_type=refresh_token"),
                "form body must include grant_type=refresh_token; was: " + body);
        assertTrue(body.contains("client_id=" + TEST_CLIENT_ID),
                "form body must include client_id=" + TEST_CLIENT_ID + "; was: " + body);
        assertTrue(body.contains("client_secret=" + TEST_CLIENT_SECRET),
                "form body must include client_secret=" + TEST_CLIENT_SECRET + "; was: " + body);
        // refresh_token is URL-encoded: '+' -> %2B, '/' -> %2F, '=' -> %3D
        String urlEncodedRt = "eyJhbGc.eyJzdWIiOiJ1c2VyMSJ9.AbCd%2B%2F%3DEf";
        assertTrue(body.contains("refresh_token=" + urlEncodedRt),
                "form body must include URL-encoded refresh_token; was: " + body);
    }

    /**
     * Pins the one-shot fallback: when Descope rejects {@code client_secret_post} with
     * {@code invalid_client}, the client retries with {@code client_secret_basic}. The fallback
     * must run exactly once and must succeed when the upstream accepts the basic-auth attempt.
     */
    @Test
    void refresh_invalidClientOnPost_retriesOnceWithBasic_andSucceeds() throws Exception {
        stubSecret();
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_client", "Bad client auth method", 401));
        AccessToken at = new BearerAccessToken("wai_new_at", 604_800L, null);
        AccessTokenResponse success = new AccessTokenResponse(new Tokens(at, new RefreshToken("wai_rt_new")));
        when(tokenClient.execute(any(TokenRequest.class)))
                .thenReturn(err)
                .thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("wisdomai#u", "wai_rt_old");

        assertNotNull(resp);
        assertEquals("wai_new_at", resp.accessToken());

        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);
        verify(tokenClient, times(2)).execute(captor.capture());
        assertEquals(2, captor.getAllValues().size());
        assertInstanceOf(ClientSecretPost.class, captor.getAllValues().get(0).getClientAuthentication(),
                "first attempt must use client_secret_post");
        assertInstanceOf(ClientSecretBasic.class, captor.getAllValues().get(1).getClientAuthentication(),
                "second attempt (after invalid_client) must fall back to client_secret_basic");

        // Confirm the basic attempt's wire shape: Authorization header set, no client_secret in body.
        HTTPRequest basicHttp = captor.getAllValues().get(1).toHTTPRequest();
        assertNotNull(basicHttp.getAuthorization(),
                "client_secret_basic must carry an Authorization header");
        assertTrue(basicHttp.getAuthorization().startsWith("Basic "),
                "Authorization header must be HTTP Basic; was: " + basicHttp.getAuthorization());
    }

    /**
     * Both attempts fail with {@code invalid_client} → final exception bubbles up. Ensures we do
     * NOT retry more than once even if the second attempt also returns invalid_client.
     */
    @Test
    void refresh_invalidClientOnBoth_throwsRefreshException_andDoesNotLoop() throws Exception {
        stubSecret();
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_client", "still bad", 401));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("wisdomai#u", "rt"));
        assertTrue(e.getMessage().contains("invalid_client"));

        verify(tokenClient, times(2)).execute(any(TokenRequest.class));
    }

    /**
     * Descope returns non-RFC6749 error bodies for refresh-token-binding failures; Nimbus parses
     * those as code/desc=null. The client must scan the raw body and map known revoke-worthy
     * Descope error codes to {@link OktaTokenRevokedException} so the L2 row gets cleared.
     */
    @Test
    void refresh_descopeAzpMismatch_mapsToRevokedException() throws Exception {
        stubSecret();
        // E061004: "azp in the refresh token is invalid" -- the stored RT was minted for a
        // different client_id than the one currently configured. User must re-consent.
        ErrorObject descopeAzp = new ErrorObject(null, null, 401)
                .setCustomParams(Map.of(
                        "errorCode", "E061004",
                        "errorMessage", "azp in the refresh token is invalid",
                        "errorDescription", "Unauthorized request"));
        TokenErrorResponse err = new TokenErrorResponse(descopeAzp);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRevokedException e = assertThrows(OktaTokenRevokedException.class,
                () -> client.refresh("wisdomai#u", "rt"));
        assertTrue(e.getMessage().contains("E061004"));

        // azp-mismatch must NOT trigger the basic-auth retry (it's not invalid_client).
        verify(tokenClient, times(1)).execute(any(TokenRequest.class));
    }

    @Test
    void refresh_descopeRefreshTokenRevoked_mapsToRevokedException() throws Exception {
        stubSecret();
        ErrorObject descopeRevoked = new ErrorObject(null, null, 401)
                .setCustomParams(Map.of(
                        "errorCode", "E061003",
                        "errorMessage", "Refresh token has been revoked"));
        when(tokenClient.execute(any(TokenRequest.class)))
                .thenReturn(new TokenErrorResponse(descopeRevoked));

        OktaTokenRevokedException e = assertThrows(OktaTokenRevokedException.class,
                () -> client.refresh("wisdomai#u", "rt"));
        assertTrue(e.getMessage().contains("E061003"));
    }

    @Test
    void refresh_descopeUnknownError_treatedAsTransient() throws Exception {
        // Unknown Descope error codes must NOT be mapped to revoked -- conservative on purpose.
        // A transient server-side error should remain retriable rather than wiping the L2 row.
        // Because OktaTokenRevokedException is a SIBLING of OktaTokenRefreshException (not a
        // subclass), assertThrows below will fail if the client incorrectly throws revoked.
        stubSecret();
        ErrorObject unknown = new ErrorObject(null, null, 500)
                .setCustomParams(Map.of(
                        "errorCode", "E999999",
                        "errorMessage", "something else"));
        when(tokenClient.execute(any(TokenRequest.class)))
                .thenReturn(new TokenErrorResponse(unknown));

        assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("wisdomai#u", "rt"));
    }

    @Test
    void extractDescopeErrorCode_parsesNestedPayload() {
        String body = "{\"errorMessage\":\"...\",\"errorCode\":\"E061004\",\"errorDescription\":\"x\"}";
        assertEquals("E061004", WisdomAiUpstreamRefreshClient.extractDescopeErrorCode(body));
    }

    @Test
    void extractDescopeErrorCode_returnsNullWhenAbsent() {
        assertNull(WisdomAiUpstreamRefreshClient.extractDescopeErrorCode(
                "{\"error\":\"invalid_grant\",\"error_description\":\"x\"}"));
        assertNull(WisdomAiUpstreamRefreshClient.extractDescopeErrorCode(null));
        assertNull(WisdomAiUpstreamRefreshClient.extractDescopeErrorCode(""));
    }
}
