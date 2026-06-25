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
 * Unit tests for {@link GeminiEnterpriseUpstreamRefreshClient}. Gemini Enterprise refreshes
 * against Google's token endpoint exactly like {@link GoogleWorkspaceUpstreamRefreshClient}, but
 * with its own dedicated client_id + {@code gemini-enterprise-client-secret} (confidential
 * {@code client_secret_post}).
 *
 * <p>The tests pin the protocol contract (success body, RT rotation passthrough + carry-forward),
 * config / secret guards, the confidential-client wire shape (client_id + client_secret in the
 * form body, no Authorization header), and the error-mapping rule: {@code invalid_grant} →
 * {@link OktaTokenRevokedException}, other upstream errors → {@link OktaTokenRefreshException}.
 */
@ExtendWith(MockitoExtension.class)
class GeminiEnterpriseUpstreamRefreshClientTest {

    private static final String TEST_CLIENT_ID = "test-gemini-enterprise-client-id";
    private static final String TEST_CLIENT_SECRET_KEY = "gemini-enterprise-client-secret";
    private static final String TEST_CLIENT_SECRET = "test-gemini-enterprise-client-secret";

    @Mock
    K8SSecretsProvider k8SSecretsProvider;

    @Mock
    TokenClient tokenClient;

    @InjectMocks
    GeminiEnterpriseUpstreamRefreshClient client;

    @BeforeEach
    void setUp() {
        client.clientId = TEST_CLIENT_ID;
        client.clientSecretKey = TEST_CLIENT_SECRET_KEY;
    }

    @Test
    void refresh_emptyRefreshToken_throwsRefreshException() {
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("gemini-enterprise#alice", null));
        assertTrue(e.getMessage().contains("empty"));

        OktaTokenRefreshException e2 = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("gemini-enterprise#alice", "  "));
        assertTrue(e2.getMessage().contains("empty"));
    }

    @Test
    void refresh_missingClientId_throwsRefreshException() {
        client.clientId = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("gemini-enterprise#alice", "rt"));
        assertTrue(e.getMessage().contains("client_id"));
    }

    @Test
    void refresh_missingClientSecretKey_throwsRefreshException() {
        client.clientSecretKey = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("gemini-enterprise#alice", "rt"));
        assertTrue(e.getMessage().contains("secret key"));
    }

    @Test
    void refresh_clientSecretNotFoundInSecrets_throwsRefreshException() {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("other-key", "value"));
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("gemini-enterprise#alice", "rt"));
        assertTrue(e.getMessage().contains("not found"));
    }

    @Test
    void refresh_success_returnsRotatedRtAndExpiresIn() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        AccessToken at = new BearerAccessToken("new-at", 1799L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("new-rt"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("gemini-enterprise#alice", "old-rt");

        assertNotNull(resp);
        assertEquals("new-at", resp.accessToken());
        assertEquals("new-rt", resp.refreshToken(),
                "Google rotates RT on every refresh; the client must propagate the rotated value verbatim");
        assertEquals(1799L, resp.expiresInSeconds());
        assertNull(resp.idToken(),
                "Google /token does not return an id_token on refresh by default");
    }

    @Test
    void refresh_success_keepsOriginalRtWhenGoogleOmitsRotation() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        AccessToken at = new BearerAccessToken("new-at");
        Tokens tokens = new Tokens(at, /* refreshToken */ null);
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("gemini-enterprise#alice", "  original-rt  ");

        assertEquals("original-rt", resp.refreshToken(),
                "client must trim whitespace and reuse the original RT when upstream omits a rotated one");
    }

    @Test
    void refresh_serializedRequest_hasClientSecretInBodyAndNoAuthorizationHeader() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        AccessToken at = new BearerAccessToken("new-at", 1799L, null);
        AccessTokenResponse success = new AccessTokenResponse(new Tokens(at, new RefreshToken("new-rt")));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        client.refresh("gemini-enterprise#alice", "old-rt");

        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);
        org.mockito.Mockito.verify(tokenClient).execute(captor.capture());
        TokenRequest sent = captor.getValue();

        assertNotNull(sent.getClientAuthentication(),
                "Gemini Enterprise is a confidential Google client; clientAuthentication must NOT be null");
        assertEquals("client_secret_post", sent.getClientAuthentication().getMethod().getValue(),
                "Gemini Enterprise uses client_secret_post (form body), not client_secret_basic");

        HTTPRequest http = sent.toHTTPRequest();
        String body = http.getBody();
        assertNotNull(body, "request body should not be null");
        assertTrue(body.contains("client_id=" + TEST_CLIENT_ID),
                "form body must include client_id; was: " + body);
        assertTrue(body.contains("client_secret=" + TEST_CLIENT_SECRET),
                "form body must include client_secret (client_secret_post); was: " + body);
        assertTrue(body.contains("grant_type=refresh_token"), "form body must include grant_type=refresh_token");
        assertNull(http.getAuthorization(),
                "request must NOT carry an Authorization header (that would indicate client_secret_basic)");
    }

    @Test
    void refresh_invalidGrant_throwsRevokedException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "Token has been expired or revoked.", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRevokedException e = assertThrows(OktaTokenRevokedException.class,
                () -> client.refresh("gemini-enterprise#alice", "rt"));
        assertTrue(e.getMessage().toLowerCase().contains("invalid"),
                "invalid_grant must map to revoked-RT semantics so UpstreamRefreshService marks the L2 row");
    }

    @Test
    void refresh_serverError_throwsRefreshException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("server_error", "internal", 500));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("gemini-enterprise#alice", "rt"));
        assertTrue(e.getMessage().contains("server_error"));
    }

    @Test
    void refresh_ioException_wrappedAsRefreshException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of(TEST_CLIENT_SECRET_KEY, TEST_CLIENT_SECRET));
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("gemini-enterprise#alice", "rt"));
        assertTrue(e.getMessage().contains("boom"));
    }
}
