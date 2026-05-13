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
 * Unit tests for {@link FigmaUpstreamRefreshClient}. Mirrors the shape of
 * {@link GoogleWorkspaceUpstreamRefreshClientTest} since the two implement the same
 * {@link UpstreamRefreshClient} contract; differences are protocol-specific:
 *
 * <ul>
 *   <li>Default {@code expires_in} is 90 d (Figma's documented AT lifetime), not 1h.</li>
 *   <li>Figma is not in {@code GOOGLE_WORKSPACE_PROVIDERS}, so the floor in
 *       {@code UpstreamTokenConfig} does not apply — the L2 row TTL is governed entirely by
 *       the configured per-provider override.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class FigmaUpstreamRefreshClientTest {

    @Mock
    K8SSecretsProvider k8SSecretsProvider;

    @Mock
    TokenClient tokenClient;

    @InjectMocks
    FigmaUpstreamRefreshClient client;

    @BeforeEach
    void setUp() {
        client.clientId = "test-figma-client-id";
        client.clientSecretKey = "figma-client-secret";
    }

    @Test
    void refresh_emptyRefreshToken_throwsRefreshException() {
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("figma#1234", null));
        assertTrue(e.getMessage().contains("empty"));

        OktaTokenRefreshException e2 = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("figma#1234", "  "));
        assertTrue(e2.getMessage().contains("empty"));
    }

    @Test
    void refresh_missingClientId_throwsRefreshException() {
        client.clientId = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("figma#1234", "rt"));
        assertTrue(e.getMessage().contains("client_id"));
    }

    @Test
    void refresh_missingClientSecretKey_throwsRefreshException() {
        client.clientSecretKey = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("figma#1234", "rt"));
        assertTrue(e.getMessage().contains("secret key"));
    }

    @Test
    void refresh_clientSecretNotFoundInSecrets_throwsRefreshException() {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("other-key", "value"));
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("figma#1234", "rt"));
        assertTrue(e.getMessage().contains("not found"));
    }

    @Test
    void refresh_success_returnsRotatedRtAndExpiresIn() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("figma-client-secret", "secret"));
        AccessToken at = new BearerAccessToken("figu_new", 7_776_000L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("figur_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("figma#test-user-id-12345", "figur_old");

        assertNotNull(resp);
        assertEquals("figu_new", resp.accessToken());
        assertEquals("figur_new", resp.refreshToken(),
                "Figma may rotate RT on refresh; the client must propagate the rotated value verbatim");
        assertEquals(7_776_000L, resp.expiresInSeconds(),
                "expires_in must reflect the upstream value (90 d in this case)");
        assertNull(resp.idToken(),
                "Figma /v1/oauth/token does not return an id_token");
    }

    @Test
    void refresh_success_keepsOriginalRtWhenFigmaOmitsRotation() throws Exception {
        // Defensive: if a future Figma response omits a rotated refresh_token, the client must
        // carry the prior RT forward so the L2 row's encrypted_upstream_refresh_token is not
        // nulled out.
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("figma-client-secret", "secret"));
        AccessToken at = new BearerAccessToken("figu_new");
        Tokens tokens = new Tokens(at, /* refreshToken */ null);
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("figma#1234", "  figur_original  ");

        assertEquals("figur_original", resp.refreshToken(),
                "client must trim whitespace and reuse the original RT when upstream omits a rotated one");
    }

    @Test
    void refresh_success_defaultsTo90DaysWhenExpiresInMissing() throws Exception {
        // Figma documents 90-day ATs; if the upstream response somehow omits expires_in (it
        // shouldn't), the client falls back to the documented constant rather than 0/3600.
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("figma-client-secret", "secret"));
        AccessToken at = new BearerAccessToken("figu_new"); // no lifetime
        Tokens tokens = new Tokens(at, new RefreshToken("figur_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("figma#1234", "rt");

        assertEquals(FigmaUpstreamRefreshClient.DEFAULT_EXPIRES_IN_SECONDS, resp.expiresInSeconds());
        assertEquals(7_776_000L, FigmaUpstreamRefreshClient.DEFAULT_EXPIRES_IN_SECONDS,
                "Figma default lifetime constant must equal 90 days");
    }

    @Test
    void refresh_invalidGrant_throwsRevokedException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("figma-client-secret", "secret"));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "Refresh token has been revoked.", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRevokedException e = assertThrows(OktaTokenRevokedException.class,
                () -> client.refresh("figma#1234", "rt"));
        assertTrue(e.getMessage().toLowerCase().contains("invalid"),
                "invalid_grant must map to revoked-RT semantics so UpstreamRefreshService marks the L2 row");
    }

    @Test
    void refresh_serverError_throwsRefreshException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("figma-client-secret", "secret"));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("server_error", "internal", 500));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("figma#1234", "rt"));
        assertTrue(e.getMessage().contains("server_error"));
    }

    @Test
    void refresh_ioException_wrappedAsRefreshException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("figma-client-secret", "secret"));
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("figma#1234", "rt"));
        assertTrue(e.getMessage().contains("boom"));
    }
}
