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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.athenz.mop.config.SplunkTokenExchangeConfig;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.secret.K8SSecretsProvider;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TokenExchangeServiceSplunkImplTest {

    private static final String MGMT = "https://splunk-mgmt.test:8089";

    @Mock
    SplunkTokenExchangeConfig splunkConfig;

    @Mock
    SplunkManagementClient splunkClient;

    @Mock
    K8SSecretsProvider k8SSecretsProvider;

    @Mock
    ConfigService configService;

    @InjectMocks
    TokenExchangeServiceSplunkImpl service;

    @BeforeEach
    void baseConfig() {
        when(splunkConfig.mirrorUserPrefix()).thenReturn("mcp.");
        when(splunkConfig.splunkTokenAudience()).thenReturn("mcp");
        when(splunkConfig.tokenExpiresOn()).thenReturn("+1h");
        when(splunkConfig.adminTokenSecretKey()).thenReturn(K8SSecretsProvider.SECRET_DATA_KEY_SPLUNK_API_STAGE);
        when(splunkConfig.allowedRoles()).thenReturn(List.of("yahoo_user", "mcp_user"));
        when(configService.getRemoteServerUsernameClaim("splunk")).thenReturn("short_id");
        when(k8SSecretsProvider.getCredentials(null))
                .thenReturn(Map.of(K8SSecretsProvider.SECRET_DATA_KEY_SPLUNK_API_STAGE, "admin-bearer"));
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
                .subject("subj")
                .expirationTime(new Date(new Date().getTime() + 600_000))
                .claim(claimName, value)
                .build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecKey.getKeyID()).build(), claims);
        jwt.sign(new ECDSASigner(ecKey));
        return jwt.serialize();
    }

    @Test
    void getAccessToken_missingIdToken_unauthorized() {
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", MGMT,
                new TokenWrapper("u", "okta", null, "a", "rt", Instant.now().getEpochSecond() + 300));
        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        assertNull(r.token());
    }

    @Test
    void getAccessToken_nullTokenExchangeDO_unauthorized() {
        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(null);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
    }

    @Test
    void getAccessToken_blankRemoteServer_unauthorized() throws Exception {
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", "  ",
                new TokenWrapper("u", "okta", idTokenWithShortId("x"), "a", "rt",
                        Instant.now().getEpochSecond() + 300));
        assertEquals(AuthResult.UNAUTHORIZED, service.getAccessTokenFromResourceAuthorizationServer(req).authResult());
    }

    @Test
    void getAccessToken_blankIdToken_unauthorized() {
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", MGMT,
                new TokenWrapper("u", "okta", "  ", "a", "rt", Instant.now().getEpochSecond() + 300));
        assertEquals(AuthResult.UNAUTHORIZED, service.getAccessTokenFromResourceAuthorizationServer(req).authResult());
    }

    @Test
    void getAccessToken_missingConfiguredClaim_unauthorized() throws Exception {
        when(configService.getRemoteServerUsernameClaim("splunk")).thenReturn("short_id");
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", MGMT,
                new TokenWrapper("u", "okta", idTokenWithClaim("email", "a@b.c"), "a", "rt",
                        Instant.now().getEpochSecond() + 300));
        assertEquals(AuthResult.UNAUTHORIZED, service.getAccessTokenFromResourceAuthorizationServer(req).authResult());
    }

    @Test
    void getAccessToken_customUsernameClaim_ok() throws Exception {
        when(configService.getRemoteServerUsernameClaim("splunk")).thenReturn("email");
        String human = "eve@example.com";
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", MGMT,
                new TokenWrapper("u", "okta", idTokenWithClaim("email", human), "a", "rt",
                        Instant.now().getEpochSecond() + 300));
        when(splunkClient.getUser(MGMT, "admin-bearer", human))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(false, List.of()));
        when(splunkClient.getUser(MGMT, "admin-bearer", "mcp." + human))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(false, List.of()));
        when(splunkClient.mintToken(MGMT, "admin-bearer", "mcp." + human, "mcp", "+1h"))
                .thenReturn("tok");

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.AUTHORIZED, r.authResult());
    }

    @Test
    void getAccessToken_blankUsernameClaim_fallsBackToShortId() throws Exception {
        when(configService.getRemoteServerUsernameClaim("splunk")).thenReturn(" ");
        String human = "frank";
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", MGMT,
                new TokenWrapper("u", "okta", idTokenWithShortId(human), "a", "rt",
                        Instant.now().getEpochSecond() + 300));
        when(splunkClient.getUser(MGMT, "admin-bearer", human))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(false, List.of()));
        when(splunkClient.getUser(MGMT, "admin-bearer", "mcp." + human))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(false, List.of()));
        when(splunkClient.mintToken(MGMT, "admin-bearer", "mcp." + human, "mcp", "+1h"))
                .thenReturn("tok");

        assertEquals(AuthResult.AUTHORIZED, service.getAccessTokenFromResourceAuthorizationServer(req).authResult());
    }

    @Test
    void getAccessToken_nullMirrorPrefix_usesDefault() throws Exception {
        when(splunkConfig.mirrorUserPrefix()).thenReturn(null);
        String human = "grace";
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", MGMT,
                new TokenWrapper("u", "okta", idTokenWithShortId(human), "a", "rt",
                        Instant.now().getEpochSecond() + 300));
        when(splunkClient.getUser(MGMT, "admin-bearer", human))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(false, List.of()));
        when(splunkClient.getUser(MGMT, "admin-bearer", "mcp." + human))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(false, List.of()));
        when(splunkClient.mintToken(MGMT, "admin-bearer", "mcp." + human, "mcp", "+1h"))
                .thenReturn("tok");

        assertEquals(AuthResult.AUTHORIZED, service.getAccessTokenFromResourceAuthorizationServer(req).authResult());
    }

    @Test
    void getAccessToken_emptyAllowedRolesList_usesDefaultRoleOnly() throws Exception {
        when(splunkConfig.allowedRoles()).thenReturn(List.of("  ", "", " "));
        String human = "heidi";
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", MGMT,
                new TokenWrapper("u", "okta", idTokenWithShortId(human), "a", "rt",
                        Instant.now().getEpochSecond() + 300));
        when(splunkClient.getUser(MGMT, "admin-bearer", human))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(true, List.of("power")));
        when(splunkClient.getUser(MGMT, "admin-bearer", "mcp." + human))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(false, List.of()));
        when(splunkClient.mintToken(MGMT, "admin-bearer", "mcp." + human, "mcp", "+1h"))
                .thenReturn("tok");

        service.getAccessTokenFromResourceAuthorizationServer(req);
        verify(splunkClient).createUser(eq(MGMT), eq("admin-bearer"), eq("mcp.heidi"), anyString(),
                eq(List.of("power", "yahoo_user")));
    }

    @Test
    void getAccessToken_mintReturnsBlank_unauthorized() throws Exception {
        String human = "ivy";
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", MGMT,
                new TokenWrapper("u", "okta", idTokenWithShortId(human), "a", "rt",
                        Instant.now().getEpochSecond() + 300));
        when(splunkClient.getUser(MGMT, "admin-bearer", human))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(false, List.of()));
        when(splunkClient.getUser(MGMT, "admin-bearer", "mcp.ivy"))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(false, List.of()));
        when(splunkClient.mintToken(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn("   ");

        assertEquals(AuthResult.UNAUTHORIZED, service.getAccessTokenFromResourceAuthorizationServer(req).authResult());
    }

    @Test
    void getAccessToken_realUser_unionsBaselineAndSplunkRoles_mirrorCreated() throws Exception {
        String human = "alice";
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", MGMT,
                new TokenWrapper("user.alice", "okta", idTokenWithShortId(human), "a", "rt",
                        Instant.now().getEpochSecond() + 300));

        when(splunkClient.getUser(MGMT, "admin-bearer", human))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(true,
                        List.of("power_other", "user_yamas-026", "yahoo_user")));
        when(splunkClient.getUser(MGMT, "admin-bearer", "mcp.alice"))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(false, List.of()));
        when(splunkClient.mintToken(MGMT, "admin-bearer", "mcp.alice", "mcp", "+1h"))
                .thenReturn("splunk-secret-token");

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.AUTHORIZED, r.authResult());
        assertNotNull(r.token());
        assertEquals("splunk-secret-token", r.token().accessToken());
        verify(splunkClient).createUser(eq(MGMT), eq("admin-bearer"), eq("mcp.alice"), anyString(),
                eq(List.of("mcp_user", "power_other", "user_yamas-026", "yahoo_user")));
        verify(splunkClient, never()).updateUserRoles(anyString(), anyString(), anyString(), any());
    }

    @Test
    void getAccessToken_noRealUser_appliesFullAllowedRoles() throws Exception {
        String human = "newbie";
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", MGMT,
                new TokenWrapper("u", "okta", idTokenWithShortId(human), "a", "rt",
                        Instant.now().getEpochSecond() + 300));

        when(splunkClient.getUser(MGMT, "admin-bearer", human))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(false, List.of()));
        when(splunkClient.getUser(MGMT, "admin-bearer", "mcp.newbie"))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(false, List.of()));
        when(splunkClient.mintToken(MGMT, "admin-bearer", "mcp.newbie", "mcp", "+1h"))
                .thenReturn("t1");

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.AUTHORIZED, r.authResult());
        verify(splunkClient).createUser(eq(MGMT), eq("admin-bearer"), eq("mcp.newbie"), anyString(),
                eq(List.of("mcp_user", "yahoo_user")));
    }

    @Test
    void getAccessToken_mirrorExists_rolesDrift_updateThenMint() throws Exception {
        String human = "bob";
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", MGMT,
                new TokenWrapper("u", "okta", idTokenWithShortId(human), "a", "rt",
                        Instant.now().getEpochSecond() + 300));

        when(splunkClient.getUser(MGMT, "admin-bearer", human))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(true, List.of("yahoo_user")));
        when(splunkClient.getUser(MGMT, "admin-bearer", "mcp.bob"))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(true, List.of("yahoo_user")));
        when(splunkClient.mintToken(MGMT, "admin-bearer", "mcp.bob", "mcp", "+1h"))
                .thenReturn("t2");

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.AUTHORIZED, r.authResult());
        verify(splunkClient, never()).createUser(anyString(), anyString(), anyString(), anyString(), any());
        verify(splunkClient).updateUserRoles(MGMT, "admin-bearer", "mcp.bob", List.of("mcp_user", "yahoo_user"));
    }

    @Test
    void getAccessToken_mirrorExists_rolesMatch_noUpdate() throws Exception {
        String human = "carol";
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", MGMT,
                new TokenWrapper("u", "okta", idTokenWithShortId(human), "a", "rt",
                        Instant.now().getEpochSecond() + 300));

        when(splunkClient.getUser(MGMT, "admin-bearer", human))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(true, List.of("yahoo_user")));
        when(splunkClient.getUser(MGMT, "admin-bearer", "mcp.carol"))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(true, List.of("mcp_user", "yahoo_user")));
        when(splunkClient.mintToken(MGMT, "admin-bearer", "mcp.carol", "mcp", "+1h"))
                .thenReturn("t3");

        service.getAccessTokenFromResourceAuthorizationServer(req);
        verify(splunkClient, never()).createUser(anyString(), anyString(), anyString(), anyString(), any());
        verify(splunkClient, never()).updateUserRoles(anyString(), anyString(), anyString(), any());
    }

    @Test
    void getAccessToken_missingAdminToken_unauthorized() throws Exception {
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(Map.of());
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", MGMT,
                new TokenWrapper("u", "okta", idTokenWithShortId("x"), "a", "rt",
                        Instant.now().getEpochSecond() + 300));
        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
    }

    @Test
    void getAccessToken_mintFails_unauthorized() throws Exception {
        String human = "dave";
        TokenExchangeDO req = new TokenExchangeDO(List.of("s"), "r", "d", MGMT,
                new TokenWrapper("u", "okta", idTokenWithShortId(human), "a", "rt",
                        Instant.now().getEpochSecond() + 300));
        when(splunkClient.getUser(MGMT, "admin-bearer", human))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(false, List.of()));
        when(splunkClient.getUser(MGMT, "admin-bearer", "mcp.dave"))
                .thenReturn(new SplunkManagementClient.SplunkUserLookup(false, List.of()));
        when(splunkClient.mintToken(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(null);
        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
    }

    @Test
    void toAllowedRoleSet_trimsAndDeduplicates() {
        java.util.ArrayList<String> in = new java.util.ArrayList<>();
        in.add(" yahoo_user ");
        in.add("mcp_user");
        in.add("yahoo_user");
        in.add(null);
        Set<String> s = TokenExchangeServiceSplunkImpl.toAllowedRoleSet(in);
        assertEquals(new TreeSet<>(List.of("mcp_user", "yahoo_user")), s);
    }

    @Test
    void toAllowedRoleSet_allBlank_fallsBackToYahooUser() {
        assertEquals(
                Set.of(TokenExchangeServiceSplunkImpl.ALLOWED_ROLES_FALLBACK),
                TokenExchangeServiceSplunkImpl.toAllowedRoleSet(null));
        assertEquals(
                Set.of(TokenExchangeServiceSplunkImpl.ALLOWED_ROLES_FALLBACK),
                TokenExchangeServiceSplunkImpl.toAllowedRoleSet(List.of()));
        assertEquals(
                Set.of(TokenExchangeServiceSplunkImpl.ALLOWED_ROLES_FALLBACK),
                TokenExchangeServiceSplunkImpl.toAllowedRoleSet(List.of("  ", "", " ")));
    }

    @Test
    void buildDesiredMirrorRoles_noRealUser_appliesBaselineOnly() {
        Set<String> baseline = new TreeSet<>(List.of("mcp_user", "yahoo_user"));
        List<String> out = TokenExchangeServiceSplunkImpl.buildDesiredMirrorRoles(false, List.of(), baseline);
        assertEquals(List.of("mcp_user", "yahoo_user"), out);
    }

    @Test
    void buildDesiredMirrorRoles_unionsAllRealRolesWithBaseline() {
        Set<String> baseline = new TreeSet<>(List.of("mcp_user", "yahoo_user"));
        List<String> out = TokenExchangeServiceSplunkImpl.buildDesiredMirrorRoles(
                true, List.of("yahoo_user", "power_other", "user_yamas-026"), baseline);
        assertEquals(List.of("mcp_user", "power_other", "user_yamas-026", "yahoo_user"), out);
    }

    @Test
    void buildDesiredMirrorRoles_skipsNullAndBlankRealRoles() {
        Set<String> baseline = new TreeSet<>(List.of("mcp_user", "yahoo_user"));
        List<String> real = new java.util.ArrayList<>();
        real.add("yahoo_user");
        real.add(null);
        real.add("   ");
        List<String> out = TokenExchangeServiceSplunkImpl.buildDesiredMirrorRoles(true, real, baseline);
        assertEquals(List.of("mcp_user", "yahoo_user"), out);
    }

    @Test
    void generateMirrorPassword_fixedLength() {
        String p = TokenExchangeServiceSplunkImpl.generateMirrorPassword();
        assertEquals(32, p.length());
        for (int i = 0; i < p.length(); i++) {
            assertTrue(
                    Character.isLetterOrDigit(p.charAt(i)) || "!@#$%^&*-_=+".indexOf(p.charAt(i)) >= 0);
        }
    }

    @Test
    void getJWTAuthorizationGrant_unsupported() {
        assertThrows(UnsupportedOperationException.class, () -> service.getJWTAuthorizationGrantFromIdentityProvider(
                new TokenExchangeDO(List.of(), "r", "d", MGMT, new TokenWrapper("u", "okta", "x", "a", "rt", 0L))));
    }

    @Test
    void getAccessTokenWithClientCredentials_unsupported() {
        assertThrows(UnsupportedOperationException.class, () -> service.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(
                new TokenExchangeDO(List.of(), "r", "d", MGMT, new TokenWrapper("u", "okta", "x", "a", "rt", 0L))));
    }

    @Test
    void refreshWithUpstreamToken_returnsNull() {
        assertNull(service.refreshWithUpstreamToken("rt"));
    }

    @Test
    void storesExchangedTokenForUserinfo_includesSplunk() {
        assertEquals(true, AudienceConstants.storesExchangedTokenForUserinfo(AudienceConstants.PROVIDER_SPLUNK));
        assertEquals(true, AudienceConstants.storesExchangedTokenForUserinfo(AudienceConstants.PROVIDER_DATABRICKS_SQL));
        assertEquals(false, AudienceConstants.storesExchangedTokenForUserinfo("unknown"));
    }
}
