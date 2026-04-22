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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.athenz.mop.config.GrafanaTokenExchangeConfig;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.secret.K8SSecretsProvider;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TokenExchangeServiceGrafanaImplTest {

    private static final String BASE = "https://yahooinc.grafana.net";
    private static final String SA = "cfja56rp4ix34e";
    private static final String SECRET_KEY = "grafana-api-prod";
    private static final String BEARER = "admin-bearer";

    @Mock
    GrafanaTokenExchangeConfig grafanaConfig;

    @Mock
    GrafanaManagementClient grafanaClient;

    @Mock
    K8SSecretsProvider k8SSecretsProvider;

    @Mock
    ConfigService configService;

    @InjectMocks
    TokenExchangeServiceGrafanaImpl service;

    @BeforeEach
    void baseConfig() {
        when(grafanaConfig.adminTokenSecretKey()).thenReturn(SECRET_KEY);
        when(grafanaConfig.tokenNamePrefix()).thenReturn("mcp.");
        when(grafanaConfig.secondsToLive()).thenReturn(3600L);
        when(configService.getRemoteServerUsernameClaim("grafana")).thenReturn("short_id");
        when(configService.getRemoteServerEndpoint("grafana")).thenReturn(BASE);
        when(configService.getRemoteServerServiceAccountId("grafana")).thenReturn(SA);
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of(SECRET_KEY, BEARER));
    }

    private static String idTokenWithShortId(String shortId) throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(shortId)
                .expirationTime(new Date(new Date().getTime() + 600_000))
                .claim("short_id", shortId)
                .build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecKey.getKeyID()).build(), claims);
        jwt.sign(new ECDSASigner(ecKey));
        return jwt.serialize();
    }

    private static String idTokenWithClaim(String claimName, String value) throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("sub")
                .expirationTime(new Date(new Date().getTime() + 600_000))
                .claim(claimName, value)
                .build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecKey.getKeyID()).build(), claims);
        jwt.sign(new ECDSASigner(ecKey));
        return jwt.serialize();
    }

    private static TokenExchangeDO requestWith(String idToken, String remoteServer) {
        return new TokenExchangeDO(List.of("s"), "r", "d", remoteServer,
                new TokenWrapper("u", "okta", idToken, "a", "rt", Instant.now().getEpochSecond() + 300));
    }

    @Test
    void getAccessToken_nullDO_unauthorized() {
        assertEquals(AuthResult.UNAUTHORIZED,
                service.getAccessTokenFromResourceAuthorizationServer(null).authResult());
    }

    @Test
    void getAccessToken_missingIdToken_unauthorized() {
        TokenExchangeDO req = requestWith(null, BASE);
        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        assertNull(r.token());
    }

    @Test
    void getAccessToken_blankIdToken_unauthorized() {
        assertEquals(AuthResult.UNAUTHORIZED,
                service.getAccessTokenFromResourceAuthorizationServer(requestWith("  ", BASE)).authResult());
    }

    @Test
    void getAccessToken_missingRemoteServer_fallsBackToConfigService() throws Exception {
        String shortId = "alice";
        TokenExchangeDO req = requestWith(idTokenWithShortId(shortId), null);
        when(grafanaClient.mintToken(eq(BASE), eq(SA), eq(BEARER), anyString(), eq(3600L)))
                .thenReturn("glsa_xyz");

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.AUTHORIZED, r.authResult());
        assertNotNull(r.token());
        assertEquals("glsa_xyz", r.token().accessToken());
    }

    @Test
    void getAccessToken_missingEndpointEverywhere_unauthorized() throws Exception {
        when(configService.getRemoteServerEndpoint("grafana")).thenReturn(null);
        TokenExchangeDO req = requestWith(idTokenWithShortId("a"), "");
        assertEquals(AuthResult.UNAUTHORIZED,
                service.getAccessTokenFromResourceAuthorizationServer(req).authResult());
    }

    @Test
    void getAccessToken_missingServiceAccountId_unauthorized() throws Exception {
        when(configService.getRemoteServerServiceAccountId("grafana")).thenReturn(null);
        TokenExchangeDO req = requestWith(idTokenWithShortId("a"), BASE);
        assertEquals(AuthResult.UNAUTHORIZED,
                service.getAccessTokenFromResourceAuthorizationServer(req).authResult());
    }

    @Test
    void getAccessToken_missingShortIdClaim_unauthorized() throws Exception {
        TokenExchangeDO req = requestWith(idTokenWithClaim("email", "a@b.c"), BASE);
        assertEquals(AuthResult.UNAUTHORIZED,
                service.getAccessTokenFromResourceAuthorizationServer(req).authResult());
    }

    @Test
    void getAccessToken_blankUsernameClaim_fallsBackToShortId() throws Exception {
        when(configService.getRemoteServerUsernameClaim("grafana")).thenReturn("  ");
        TokenExchangeDO req = requestWith(idTokenWithShortId("bob"), BASE);
        when(grafanaClient.mintToken(eq(BASE), eq(SA), eq(BEARER), anyString(), eq(3600L)))
                .thenReturn("glsa_bob");
        assertEquals(AuthResult.AUTHORIZED,
                service.getAccessTokenFromResourceAuthorizationServer(req).authResult());
    }

    @Test
    void getAccessToken_missingAdminBearer_unauthorized() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of());
        TokenExchangeDO req = requestWith(idTokenWithShortId("a"), BASE);
        assertEquals(AuthResult.UNAUTHORIZED,
                service.getAccessTokenFromResourceAuthorizationServer(req).authResult());
    }

    @Test
    void getAccessToken_mintFails_unauthorized() throws Exception {
        TokenExchangeDO req = requestWith(idTokenWithShortId("carol"), BASE);
        when(grafanaClient.mintToken(anyString(), anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(null);
        assertEquals(AuthResult.UNAUTHORIZED,
                service.getAccessTokenFromResourceAuthorizationServer(req).authResult());
    }

    @Test
    void getAccessToken_ok_tokenNameHasPrefixAndTimestampSuffix() throws Exception {
        String shortId = "dave";
        TokenExchangeDO req = requestWith(idTokenWithShortId(shortId), BASE);
        when(grafanaClient.mintToken(eq(BASE), eq(SA), eq(BEARER), anyString(), eq(3600L)))
                .thenReturn("glsa_ok");

        long before = Instant.now().getEpochSecond();
        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        long after = Instant.now().getEpochSecond();

        assertEquals(AuthResult.AUTHORIZED, r.authResult());
        assertEquals("glsa_ok", r.token().accessToken());
        assertEquals(3600L, r.token().ttl());

        ArgumentCaptor<String> name = ArgumentCaptor.forClass(String.class);
        verify(grafanaClient).mintToken(eq(BASE), eq(SA), eq(BEARER), name.capture(), eq(3600L));
        String captured = name.getValue();
        assertTrue(captured.startsWith("mcp." + shortId + "."),
                "Expected prefix mcp.<shortId>. but got " + captured);
        long ts = Long.parseLong(captured.substring(("mcp." + shortId + ".").length()));
        assertTrue(ts >= before && ts <= after,
                "Expected timestamp in [" + before + "," + after + "] but got " + ts);
    }

    @Test
    void getAccessToken_nullTokenNamePrefix_usesDefaultMcpDot() throws Exception {
        when(grafanaConfig.tokenNamePrefix()).thenReturn(null);
        TokenExchangeDO req = requestWith(idTokenWithShortId("eve"), BASE);
        when(grafanaClient.mintToken(eq(BASE), eq(SA), eq(BEARER), anyString(), eq(3600L)))
                .thenReturn("glsa_eve");

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.AUTHORIZED, r.authResult());
        ArgumentCaptor<String> name = ArgumentCaptor.forClass(String.class);
        verify(grafanaClient).mintToken(eq(BASE), eq(SA), eq(BEARER), name.capture(), eq(3600L));
        assertTrue(name.getValue().startsWith("mcp.eve."));
    }

    @Test
    void getJWTAuthorizationGrant_unsupported() throws Exception {
        assertThrows(UnsupportedOperationException.class, () ->
                service.getJWTAuthorizationGrantFromIdentityProvider(
                        requestWith(idTokenWithShortId("a"), BASE)));
    }

    @Test
    void getAccessTokenWithClientCredentials_unsupported() throws Exception {
        assertThrows(UnsupportedOperationException.class, () ->
                service.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(
                        requestWith(idTokenWithShortId("a"), BASE)));
    }

    @Test
    void refreshWithUpstreamToken_returnsNull() {
        assertNull(service.refreshWithUpstreamToken("rt"));
    }

    @Test
    void storesExchangedTokenForUserinfo_includesGrafana() {
        assertEquals(true, AudienceConstants.storesExchangedTokenForUserinfo(AudienceConstants.PROVIDER_GRAFANA));
    }
}
