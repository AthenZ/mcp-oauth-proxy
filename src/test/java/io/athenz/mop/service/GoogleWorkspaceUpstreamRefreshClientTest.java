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
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import io.athenz.mop.secret.K8SSecretsProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
 * Unit tests for {@link GoogleWorkspaceUpstreamRefreshClient}. This is the L2-layer Google
 * refresh-token client; the {@link UpstreamRefreshService} owns the lock/CAS/staged-AT
 * concerns and delegates only the HTTP refresh call to this class.
 *
 * <p>The tests cover the protocol contract (success body shape, RT rotation passthrough),
 * config / secret guards (missing client_id, missing secret), and the error-mapping rule:
 * {@code invalid_grant} → {@link OktaTokenRevokedException} (so {@code UpstreamRefreshService}'s
 * existing revoke-on-invalid-grant path stays provider-agnostic), other upstream errors →
 * {@link OktaTokenRefreshException} (which the service maps to a non-revoking transient
 * failure).
 */
@ExtendWith(MockitoExtension.class)
class GoogleWorkspaceUpstreamRefreshClientTest {

    @Mock
    K8SSecretsProvider k8SSecretsProvider;

    @Mock
    TokenClient tokenClient;

    @InjectMocks
    GoogleWorkspaceUpstreamRefreshClient client;

    @BeforeEach
    void setUp() {
        client.clientId = "google-client-id";
        client.clientSecretKey = "google_client_secret";
    }

    @Test
    void refresh_emptyRefreshToken_throwsRefreshException() {
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("google-drive#alice", null));
        assertTrue(e.getMessage().contains("empty"));

        OktaTokenRefreshException e2 = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("google-drive#alice", "  "));
        assertTrue(e2.getMessage().contains("empty"));
    }

    @Test
    void refresh_missingClientId_throwsRefreshException() {
        client.clientId = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("google-drive#alice", "rt"));
        assertTrue(e.getMessage().contains("client_id"));
    }

    @Test
    void refresh_missingClientSecretKey_throwsRefreshException() {
        client.clientSecretKey = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("google-drive#alice", "rt"));
        assertTrue(e.getMessage().contains("secret key"));
    }

    @Test
    void refresh_clientSecretNotFoundInSecrets_throwsRefreshException() {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("other-key", "value"));
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("google-drive#alice", "rt"));
        assertTrue(e.getMessage().contains("not found"));
    }

    @Test
    void refresh_success_returnsRotatedRtAndExpiresIn() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("google_client_secret", "secret"));
        AccessToken at = new BearerAccessToken("new-at", 1799L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("new-rt"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("google-drive#alice", "old-rt");

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
        // In rare cases (re-prompted scopes, hourly limit hit) Google may not return a fresh RT.
        // The contract is to fall back to the original value so the L2 row's RT is not nulled out.
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("google_client_secret", "secret"));
        AccessToken at = new BearerAccessToken("new-at");
        Tokens tokens = new Tokens(at, /* refreshToken */ null);
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("google-drive#alice", "  original-rt  ");

        assertEquals("original-rt", resp.refreshToken(),
                "client must trim whitespace and reuse the original RT when upstream omits a rotated one");
    }

    @Test
    void refresh_invalidGrant_throwsRevokedException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("google_client_secret", "secret"));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "Token has been expired or revoked.", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRevokedException e = assertThrows(OktaTokenRevokedException.class,
                () -> client.refresh("google-drive#alice", "rt"));
        assertTrue(e.getMessage().toLowerCase().contains("invalid"),
                "invalid_grant must map to revoked-RT semantics so UpstreamRefreshService marks the L2 row");
    }

    @Test
    void refresh_serverError_throwsRefreshException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("google_client_secret", "secret"));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("server_error", "internal", 500));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("google-drive#alice", "rt"));
        assertTrue(e.getMessage().contains("server_error"));
    }

    @Test
    void refresh_ioException_wrappedAsRefreshException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("google_client_secret", "secret"));
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("google-drive#alice", "rt"));
        assertTrue(e.getMessage().contains("boom"));
    }
}
