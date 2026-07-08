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
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DatahubUpstreamRefreshClient}. Mirrors the shape of
 * {@link RootlyUpstreamRefreshClientTest} since the two implement the same
 * {@link UpstreamRefreshClient} contract; DataHub differs in client auth
 * ({@code client_secret_basic} instead of {@code client_secret_post}) and in sending the
 * RFC 8707 resource indicator on the refresh grant.
 */
@ExtendWith(MockitoExtension.class)
class DatahubUpstreamRefreshClientTest {

    @Mock
    K8SSecretsProvider k8SSecretsProvider;

    @Mock
    TokenClient tokenClient;

    @InjectMocks
    DatahubUpstreamRefreshClient client;

    @BeforeEach
    void setUp() {
        client.clientId = "test-datahub-client-id";
        client.clientSecretKey = "datahub-client-secret";
    }

    @Test
    void refresh_emptyRefreshToken_throwsRefreshException() {
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("datahub#1234", null));
        assertTrue(e.getMessage().contains("empty"));

        OktaTokenRefreshException e2 = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("datahub#1234", "  "));
        assertTrue(e2.getMessage().contains("empty"));
    }

    @Test
    void refresh_missingClientId_throwsRefreshException() {
        client.clientId = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("datahub#1234", "rt"));
        assertTrue(e.getMessage().contains("client_id"));
    }

    @Test
    void refresh_missingClientSecretKey_throwsRefreshException() {
        client.clientSecretKey = "";
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("datahub#1234", "rt"));
        assertTrue(e.getMessage().contains("secret key"));
    }

    @Test
    void refresh_clientSecretNotFoundInSecrets_throwsRefreshException() {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("other-key", "value"));
        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("datahub#1234", "rt"));
        assertTrue(e.getMessage().contains("not found"));
    }

    @Test
    void refresh_success_returnsRotatedRtAndExpiresIn() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("datahub-client-secret", "secret"));
        AccessToken at = new BearerAccessToken("datahub_at_new", 3599L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("datahub_rt_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("datahub#test-user-id-12345", "datahub_rt_old");

        assertNotNull(resp);
        assertEquals("datahub_at_new", resp.accessToken());
        assertEquals("datahub_rt_new", resp.refreshToken(),
                "a rotated RT in the response must be propagated verbatim");
        assertEquals(3599L, resp.expiresInSeconds(),
                "expires_in must reflect the upstream value");
        assertNull(resp.idToken(),
                "id_token is not carried through the refresh response");
    }

    @Test
    void refresh_sendsBasicAuthAndResourceIndicator() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("datahub-client-secret", "secret"));
        AccessToken at = new BearerAccessToken("datahub_at_new", 3599L, null);
        Tokens tokens = new Tokens(at, new RefreshToken("datahub_rt_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        client.refresh("datahub#1234", "rt");

        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);
        verify(tokenClient).execute(captor.capture());
        TokenRequest sent = captor.getValue();
        assertInstanceOf(ClientSecretBasic.class, sent.getClientAuthentication(),
                "DataHub token auth must be HTTP Basic (client_secret_basic), matching the verified curl flow");
        assertEquals(List.of(DatahubUpstreamRefreshClient.DATAHUB_RESOURCE), sent.getResources(),
                "the RFC 8707 resource indicator must ride along on the refresh grant");
        assertEquals("refresh_token", sent.getAuthorizationGrant().getType().getValue());
    }

    @Test
    void refresh_success_keepsOriginalRtWhenDatahubOmitsRotation() throws Exception {
        // Defensive: if a DataHub response omits a rotated refresh_token, the client must carry
        // the prior RT forward so the L2 row's encrypted_upstream_refresh_token is not nulled out.
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("datahub-client-secret", "secret"));
        AccessToken at = new BearerAccessToken("datahub_at_new");
        Tokens tokens = new Tokens(at, /* refreshToken */ null);
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("datahub#1234", "  datahub_rt_original  ");

        assertEquals("datahub_rt_original", resp.refreshToken(),
                "client must trim whitespace and reuse the original RT when upstream omits a rotated one");
    }

    @Test
    void refresh_success_expiresInZeroWhenUpstreamOmitsIt() throws Exception {
        // Defensive: if DataHub omits expires_in, we return 0 rather than fabricating a lifetime,
        // so the staged AT is treated as immediately stale.
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("datahub-client-secret", "secret"));
        AccessToken at = new BearerAccessToken("datahub_at_new"); // no lifetime
        Tokens tokens = new Tokens(at, new RefreshToken("datahub_rt_new"));
        AccessTokenResponse success = new AccessTokenResponse(tokens);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(success);

        UpstreamRefreshResponse resp = client.refresh("datahub#1234", "rt");

        assertEquals(0L, resp.expiresInSeconds(),
                "no fixed AT lifetime is pinned for DataHub; absent expires_in maps to 0");
    }

    @Test
    void refresh_invalidGrant_throwsRevokedException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("datahub-client-secret", "secret"));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("invalid_grant", "Refresh token has been revoked.", 400));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRevokedException e = assertThrows(OktaTokenRevokedException.class,
                () -> client.refresh("datahub#1234", "rt"));
        assertTrue(e.getMessage().toLowerCase().contains("invalid"),
                "invalid_grant must map to revoked-RT semantics so UpstreamRefreshService marks the L2 row");
    }

    @Test
    void refresh_serverError_throwsRefreshException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("datahub-client-secret", "secret"));
        TokenErrorResponse err = new TokenErrorResponse(
                new ErrorObject("server_error", "internal", 500));
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(err);

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("datahub#1234", "rt"));
        assertTrue(e.getMessage().contains("server_error"));
    }

    @Test
    void refresh_ioException_wrappedAsRefreshException() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of("datahub-client-secret", "secret"));
        when(tokenClient.execute(any(TokenRequest.class))).thenThrow(new IOException("boom"));

        OktaTokenRefreshException e = assertThrows(OktaTokenRefreshException.class,
                () -> client.refresh("datahub#1234", "rt"));
        assertTrue(e.getMessage().contains("boom"));
    }
}
