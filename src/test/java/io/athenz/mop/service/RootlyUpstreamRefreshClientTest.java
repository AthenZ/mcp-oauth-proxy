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
 * Unit tests for {@link RootlyUpstreamRefreshClient}. Mirrors the shape of
 * {@link FigmaUpstreamRefreshClientTest} since the two implement the same
 * {@link UpstreamRefreshClient} contract with the same {@code client_secret_post} auth;
 * differences are protocol-specific (token endpoint and default {@code expires_in} fallback).
 */
@ExtendWith(MockitoExtension.class)
class RootlyUpstreamRefreshClientTest {

    @Mock
    K8SSecretsProvider k8SSecretsProvider;

    @Mock
    TokenClient tokenClient;

    @InjectMocks
    RootlyUpstreamRefreshClient client;

    @BeforeEach
    void setUp() {
        client.clientId = "test-rootly-client-id";
        client.clientSecretKey = "rootly-client-secret";
    }

    @Test
    void refresh_emptyRefreshToken_throwsRefreshException() {
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("rootly#1234", null));
        assertTrue(e.getMessage().contains("empty"));

        OktaTokenRefreshException e2 = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("rootly#1234", "  "));
        assertTrue(e2.getMessage().contains("empty"));
    }

    @Test
    void refresh_missingClientId_throwsRefreshException() {
        client.clientId = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("rootly#1234", "rt"));
        assertTrue(e.getMessage().contains("client_id"));
    }

    @Test
    void refresh_missingClientSecretKey_throwsRefreshException() {
        client.clientSecretKey = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("rootly#1234", "rt"));
        assertTrue(e.getMessage().contains("secret key"));
    }

    @Test
    void refresh_clientSecretNotFoundInSecrets_throwsRefreshException() {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("other-key", "value"));
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("rootly#1234", "rt"));
        assertTrue(e.getMessage().contains("not found"));
    }

    @Test
    void refresh_success_returnsRotatedRtAndExpiresIn() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("rootly-client-secret", "secret"));
        AccessToken at = new BearerAccessToken("rootly_at_new", 3600L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("rootly_rt_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("rootly#test-user-id-12345", "rootly_rt_old");

        assertNotNull(resp);
        assertEquals("rootly_at_new", resp.accessToken());
        assertEquals("rootly_rt_new", resp.refreshToken(),
                "Rootly rotates RT on refresh; the client must propagate the rotated value verbatim");
        assertEquals(3600L, resp.expiresInSeconds(),
                "expires_in must reflect the upstream value");
        assertNull(resp.idToken(),
                "Rootly /oauth/token does not return an id_token on refresh");
    }

    @Test
    void refresh_success_keepsOriginalRtWhenRootlyOmitsRotation() throws Exception {
        // Defensive: if a Rootly response omits a rotated refresh_token, the client must carry
        // the prior RT forward so the L2 row's encrypted_upstream_refresh_token is not nulled out.
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("rootly-client-secret", "secret"));
        AccessToken at = new BearerAccessToken("rootly_at_new");
        Tokens tokens = new Tokens(at, /* refreshToken */ null);
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("rootly#1234", "  rootly_rt_original  ");

        assertEquals("rootly_rt_original", resp.refreshToken(),
                "client must trim whitespace and reuse the original RT when upstream omits a rotated one");
    }

    @Test
    void refresh_success_usesUpstreamExpiresInVerbatim() throws Exception {
        // Rootly access tokens are ~1h. MoP must echo Rootly's reported expires_in verbatim and
        // never substitute a pinned/fabricated lifetime.
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("rootly-client-secret", "secret"));
        AccessToken at = new BearerAccessToken("rootly_at_new", 3600L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("rootly_rt_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("rootly#1234", "rt");

        assertEquals(3600L, resp.expiresInSeconds(),
                "must reflect Rootly's real ~1h access-token lifetime, not a pinned constant");
    }

    @Test
    void refresh_success_expiresInZeroWhenUpstreamOmitsIt() throws Exception {
        // Defensive: if Rootly omits expires_in (it does not in practice), we return 0 rather than
        // fabricating a lifetime, so the staged AT is treated as immediately stale.
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("rootly-client-secret", "secret"));
        AccessToken at = new BearerAccessToken("rootly_at_new"); // no lifetime
        Tokens tokens = new Tokens(at, new RefreshToken("rootly_rt_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("rootly#1234", "rt");

        assertEquals(0L, resp.expiresInSeconds(),
                "no fixed AT lifetime is pinned for Rootly; absent expires_in maps to 0");
    }

    @Test
    void refresh_invalidGrant_throwsRevokedException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("rootly-client-secret", "secret"));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "Refresh token has been revoked.", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRevokedException e = assertThrows(OktaTokenRevokedException.class,
                () -> client.refresh("rootly#1234", "rt"));
        assertTrue(e.getMessage().toLowerCase().contains("invalid"),
                "invalid_grant must map to revoked-RT semantics so UpstreamRefreshService marks the L2 row");
    }

    @Test
    void refresh_serverError_throwsRefreshException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("rootly-client-secret", "secret"));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("server_error", "internal", 500));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("rootly#1234", "rt"));
        assertTrue(e.getMessage().contains("server_error"));
    }

    @Test
    void refresh_ioException_wrappedAsRefreshException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("rootly-client-secret", "secret"));
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("rootly#1234", "rt"));
        assertTrue(e.getMessage().contains("boom"));
    }
}
