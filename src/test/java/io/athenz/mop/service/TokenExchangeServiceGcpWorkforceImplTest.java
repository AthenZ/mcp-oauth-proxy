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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.athenz.mop.config.AthenzTokenExchangeConfig;
import io.athenz.mop.config.GoogleWorkforceTokenExchangeConfig;
import io.athenz.mop.config.GoogleWorkforceTokenExchangeConfig.ServiceConfig;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.GcpZmsPrincipalScope;
import io.athenz.mop.model.RequestedZtsTokenType;
import io.athenz.mop.model.ResourceMeta;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.telemetry.ExchangeStep;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class TokenExchangeServiceGcpWorkforceImplTest {

    private static final String ATHENZ_AUDIENCE = "sys.auth.gcp";
    private static final String SHORT_ID = "alice";
    private static final String MCP_CLIENT = "mcp-client";
    private static final String REGION = "us-east-1";
    private static final String BILLING_PROJECT = "core-monitoring-p";
    private static final String ATHENZ_ID_TOKEN = "athenz-id-token";
    private static final String STS_ACCESS_TOKEN = "sts-access-token";

    private static final String MONITORING_ROLE = "gcp.fed.mcp.user, gcp.fed.mcp.monitoring.user";
    private static final String BIGQUERY_ROLE = "gcp.fed.mcp.bigquery.user";

    @Mock
    private ZMSServiceImpl zmsServiceImpl;

    @Mock
    private TokenExchangeServiceProducer tokenExchangeServiceProducer;

    @Mock
    private AthenzTokenExchangeConfig athenzTokenExchangeConfig;

    @Mock
    private GoogleWorkforceTokenExchange googleWorkforceTokenExchange;

    @Mock
    private GoogleWorkforceTokenExchangeConfig googleWorkforceConfig;

    @Mock
    private ConfigService configService;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private TelemetryRequestContext telemetryRequestContext;

    @Mock
    private MetricsRegionProvider metricsRegionProvider;

    @Mock
    private TokenExchangeService athenzExchange;

    @InjectMocks
    private TokenExchangeServiceGcpWorkforceImpl service;

    private final Map<String, ServiceConfig> services = new HashMap<>();

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("athenz"))
                .thenReturn(athenzExchange);
        when(telemetryRequestContext.oauthClient()).thenReturn(MCP_CLIENT);
        when(metricsRegionProvider.primaryRegion()).thenReturn(REGION);
        when(athenzTokenExchangeConfig.audience()).thenReturn(ATHENZ_AUDIENCE);
        when(googleWorkforceConfig.services()).thenReturn(services);

        services.put(AudienceConstants.PROVIDER_GOOGLE_MONITORING,
                serviceConfig(List.of("https://www.googleapis.com/auth/monitoring.read"), MONITORING_ROLE));
        services.put(AudienceConstants.PROVIDER_GOOGLE_LOGGING,
                serviceConfig(List.of("https://www.googleapis.com/auth/logging.read"), MONITORING_ROLE));
        services.put(AudienceConstants.PROVIDER_GOOGLE_BIGQUERY,
                serviceConfig(
                        List.of("https://www.googleapis.com/auth/cloud-platform.read-only",
                                "https://www.googleapis.com/auth/devstorage.read_only"),
                        BIGQUERY_ROLE));
    }

    private static ServiceConfig serviceConfig(List<String> scopes, String roleName) {
        return new ServiceConfig() {
            @Override
            public List<String> scopes() {
                return scopes;
            }

            @Override
            public Optional<String> gcpRoleName() {
                return Optional.ofNullable(roleName);
            }
        };
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

    private static String idTokenWithoutShortId() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("sub")
                .expirationTime(new Date(new Date().getTime() + 600_000))
                .build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecKey.getKeyID()).build(), claims);
        jwt.sign(new ECDSASigner(ecKey));
        return jwt.serialize();
    }

    private TokenExchangeDO request(String audience, String idToken) {
        String resource = "https://mcp-gateway.ouryahoo.com/v1/gcp-" + audienceSuffix(audience) + "/mcp";
        ResourceMeta meta = new ResourceMeta(
                List.of("athenz.examples.agentic-ai:role.mcp.google-mcp-access"),
                "athenz.examples.agentic-ai",
                "okta",
                audience,
                false,
                "okta",
                audience);
        when(configService.getResourceMeta(resource)).thenReturn(meta);
        TokenWrapper wrapper = new TokenWrapper("user-key", "okta", idToken, null, "okta-refresh", 3600L);
        return new TokenExchangeDO(List.of(), resource, "", audience, wrapper, null);
    }

    private static String audienceSuffix(String audience) {
        return audience.replaceFirst("^google-", "");
    }

    private void mockAthenzReturnsIdToken(String idToken) {
        TokenWrapper athenzOut = new TokenWrapper(
                "user-key", "ztsserver", idToken, null, null, 3600L);
        when(athenzExchange.getAccessTokenFromResourceAuthorizationServer(any()))
                .thenReturn(new AuthorizationResultDO(AuthResult.AUTHORIZED, athenzOut));
    }

    // ---------- Unsupported operations ----------

    @Test
    void getJWTAuthorizationGrant_throws() {
        assertThrows(UnsupportedOperationException.class,
                () -> service.getJWTAuthorizationGrantFromIdentityProvider(null));
    }

    @Test
    void getAccessTokenWithClientCredentials_throws() {
        assertThrows(UnsupportedOperationException.class,
                () -> service.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(null));
    }

    @Test
    void refreshWithUpstreamToken_returnsNull() {
        assertNull(service.refreshWithUpstreamToken("any"));
    }

    // ---------- Input validation (no metrics, no downstream calls) ----------

    @Test
    void getAccessToken_nullRequest_returnsUnauthorized() {
        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(null);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        assertNull(r.token());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
        verify(googleWorkforceTokenExchange, never()).exchange(anyString(), anyString(), anyString());
    }

    @Test
    void getAccessToken_nullTokenWrapper_returnsUnauthorized() {
        TokenExchangeDO req = new TokenExchangeDO(List.of(), "https://x/mcp", "", "google-monitoring", null, null);
        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        assertNull(r.token());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
    }

    @Test
    void getAccessToken_blankIdToken_returnsUnauthorized() {
        TokenWrapper wrapper = new TokenWrapper("k", "okta", "  ", null, null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(List.of(), "https://x/mcp", "", "google-monitoring", wrapper, null);
        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
    }

    @Test
    void getAccessToken_nullIdToken_returnsUnauthorized() {
        TokenWrapper wrapper = new TokenWrapper("k", "okta", null, null, null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(List.of(), "https://x/mcp", "", "google-monitoring", wrapper, null);
        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
    }

    @Test
    void getAccessToken_nullResourceMeta_returnsUnauthorized() throws Exception {
        String idToken = idTokenWithShortId(SHORT_ID);
        TokenWrapper wrapper = new TokenWrapper("k", "okta", idToken, null, null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(List.of(), "https://unknown/mcp", "", "google-monitoring", wrapper, null);
        when(configService.getResourceMeta("https://unknown/mcp")).thenReturn(null);

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
    }

    @Test
    void getAccessToken_blankAudience_returnsUnauthorized() throws Exception {
        String idToken = idTokenWithShortId(SHORT_ID);
        TokenWrapper wrapper = new TokenWrapper("k", "okta", idToken, null, null, 3600L);
        TokenExchangeDO req = new TokenExchangeDO(List.of(), "https://x/mcp", "", "google-monitoring", wrapper, null);
        ResourceMeta meta = new ResourceMeta(List.of(), "d", "okta", "google-monitoring", false, "okta", null);
        when(configService.getResourceMeta("https://x/mcp")).thenReturn(meta);

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
    }

    @Test
    void getAccessToken_unknownAudience_returnsUnauthorized() throws Exception {
        String idToken = idTokenWithShortId(SHORT_ID);
        TokenExchangeDO req = request("unknown-gcp", idToken);

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
        verify(googleWorkforceTokenExchange, never()).exchange(anyString(), anyString(), anyString());
    }

    @Test
    void getAccessToken_missingShortIdClaim_returnsUnauthorized() throws Exception {
        String idToken = idTokenWithoutShortId();
        TokenExchangeDO req = request(AudienceConstants.PROVIDER_GOOGLE_MONITORING, idToken);

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
        verify(oauthProxyMetrics, never()).recordExchangeStep(
                any(), anyString(), anyBoolean(), any(), anyString(), anyString(), anyDouble());
    }

    @Test
    void getAccessToken_servicesMapIsNull_returnsUnauthorized() throws Exception {
        when(googleWorkforceConfig.services()).thenReturn(null);
        String idToken = idTokenWithShortId(SHORT_ID);
        TokenExchangeDO req = request(AudienceConstants.PROVIDER_GOOGLE_MONITORING, idToken);

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(req);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
    }

    // ---------- Athenz failure modes ----------

    @Test
    void getAccessToken_athenzReturnsNull_unauthorizedAndStepMetricFailure() throws Exception {
        String idToken = idTokenWithShortId(SHORT_ID);
        when(zmsServiceImpl.getScopeForPrincipal("user." + SHORT_ID, MONITORING_ROLE))
                .thenReturn(new GcpZmsPrincipalScope("dom:role.gcp.fed.mcp.monitoring.user openid", BILLING_PROJECT));
        when(athenzExchange.getAccessTokenFromResourceAuthorizationServer(any())).thenReturn(null);

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(
                request(AudienceConstants.PROVIDER_GOOGLE_MONITORING, idToken));

        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.GCP_ATHENZ_ID_TOKEN),
                eq(OauthProviderLabel.GOOGLE_MONITORING),
                eq(false),
                eq("unauthorized"),
                eq(MCP_CLIENT),
                eq(REGION),
                anyDouble());
        verify(googleWorkforceTokenExchange, never()).exchange(anyString(), anyString(), anyString());
    }

    @Test
    void getAccessToken_athenzUnauthorized_unauthorizedAndFailureRecorded() throws Exception {
        String idToken = idTokenWithShortId(SHORT_ID);
        when(zmsServiceImpl.getScopeForPrincipal("user." + SHORT_ID, MONITORING_ROLE))
                .thenReturn(new GcpZmsPrincipalScope("openid", null));
        when(athenzExchange.getAccessTokenFromResourceAuthorizationServer(any()))
                .thenReturn(new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null));

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(
                request(AudienceConstants.PROVIDER_GOOGLE_LOGGING, idToken));

        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.GCP_ATHENZ_ID_TOKEN),
                eq(OauthProviderLabel.GOOGLE_LOGGING),
                eq(false),
                eq("unauthorized"),
                eq(MCP_CLIENT),
                eq(REGION),
                anyDouble());
    }

    @Test
    void getAccessToken_athenzReturnsBlankIdToken_unauthorized() throws Exception {
        String idToken = idTokenWithShortId(SHORT_ID);
        when(zmsServiceImpl.getScopeForPrincipal("user." + SHORT_ID, MONITORING_ROLE))
                .thenReturn(new GcpZmsPrincipalScope("openid", null));
        TokenWrapper athenzOut = new TokenWrapper("k", "zts", "  ", null, null, 3600L);
        when(athenzExchange.getAccessTokenFromResourceAuthorizationServer(any()))
                .thenReturn(new AuthorizationResultDO(AuthResult.AUTHORIZED, athenzOut));

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(
                request(AudienceConstants.PROVIDER_GOOGLE_MONITORING, idToken));

        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        verify(googleWorkforceTokenExchange, never()).exchange(anyString(), anyString(), anyString());
    }

    // ---------- STS failure modes ----------

    @Test
    void getAccessToken_stsReturnsNull_unauthorizedAndStsFailureRecorded() throws Exception {
        String idToken = idTokenWithShortId(SHORT_ID);
        when(zmsServiceImpl.getScopeForPrincipal("user." + SHORT_ID, MONITORING_ROLE))
                .thenReturn(new GcpZmsPrincipalScope("openid", BILLING_PROJECT));
        mockAthenzReturnsIdToken(ATHENZ_ID_TOKEN);
        when(googleWorkforceTokenExchange.exchange(
                eq(ATHENZ_ID_TOKEN),
                eq(AudienceConstants.PROVIDER_GOOGLE_MONITORING),
                eq(BILLING_PROJECT))).thenReturn(null);

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(
                request(AudienceConstants.PROVIDER_GOOGLE_MONITORING, idToken));

        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.GCP_ATHENZ_ID_TOKEN),
                eq(OauthProviderLabel.GOOGLE_MONITORING),
                eq(true),
                eq(null),
                eq(MCP_CLIENT),
                eq(REGION),
                anyDouble());
        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.GCP_GOOGLE_STS),
                eq(OauthProviderLabel.GOOGLE_MONITORING),
                eq(false),
                eq("unauthorized"),
                eq(MCP_CLIENT),
                eq(REGION),
                anyDouble());
    }

    @Test
    void getAccessToken_stsReturnsBlank_unauthorized() throws Exception {
        String idToken = idTokenWithShortId(SHORT_ID);
        when(zmsServiceImpl.getScopeForPrincipal("user." + SHORT_ID, BIGQUERY_ROLE))
                .thenReturn(new GcpZmsPrincipalScope("openid", BILLING_PROJECT));
        mockAthenzReturnsIdToken(ATHENZ_ID_TOKEN);
        when(googleWorkforceTokenExchange.exchange(
                eq(ATHENZ_ID_TOKEN), eq(AudienceConstants.PROVIDER_GOOGLE_BIGQUERY), eq(BILLING_PROJECT)))
                .thenReturn("   ");

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(
                request(AudienceConstants.PROVIDER_GOOGLE_BIGQUERY, idToken));

        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.GCP_GOOGLE_STS),
                eq(OauthProviderLabel.GOOGLE_BIGQUERY),
                eq(false),
                eq("unauthorized"),
                eq(MCP_CLIENT),
                eq(REGION),
                anyDouble());
    }

    // ---------- Happy paths (per audience) ----------

    @Test
    void getAccessToken_googleMonitoring_success() throws Exception {
        String idToken = idTokenWithShortId(SHORT_ID);
        GcpZmsPrincipalScope zmsScope = new GcpZmsPrincipalScope(
                "dom:role.gcp.fed.mcp.user dom:role.gcp.fed.mcp.monitoring.user openid", BILLING_PROJECT);
        when(zmsServiceImpl.getScopeForPrincipal("user." + SHORT_ID, MONITORING_ROLE)).thenReturn(zmsScope);
        mockAthenzReturnsIdToken(ATHENZ_ID_TOKEN);
        when(googleWorkforceTokenExchange.exchange(
                eq(ATHENZ_ID_TOKEN),
                eq(AudienceConstants.PROVIDER_GOOGLE_MONITORING),
                eq(BILLING_PROJECT))).thenReturn(STS_ACCESS_TOKEN);

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(
                request(AudienceConstants.PROVIDER_GOOGLE_MONITORING, idToken));

        assertEquals(AuthResult.AUTHORIZED, r.authResult());
        assertNotNull(r.token());
        assertEquals(STS_ACCESS_TOKEN, r.token().accessToken());
        assertEquals(3600L, r.token().ttl());
        assertNull(r.token().idToken());
        assertNull(r.token().refreshToken());

        // Verify Athenz request was built with space-split scopes, empty namespace, and ID_TOKEN type.
        ArgumentCaptor<TokenExchangeDO> captor = ArgumentCaptor.forClass(TokenExchangeDO.class);
        verify(athenzExchange, times(1)).getAccessTokenFromResourceAuthorizationServer(captor.capture());
        TokenExchangeDO sent = captor.getValue();
        assertEquals(List.of("dom:role.gcp.fed.mcp.user", "dom:role.gcp.fed.mcp.monitoring.user", "openid"),
                sent.scopes());
        assertEquals(ATHENZ_AUDIENCE, sent.remoteServer());
        assertEquals(RequestedZtsTokenType.ID_TOKEN, sent.requestedZtsTokenType());

        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.GCP_ATHENZ_ID_TOKEN),
                eq(OauthProviderLabel.GOOGLE_MONITORING),
                eq(true),
                eq(null),
                eq(MCP_CLIENT),
                eq(REGION),
                anyDouble());
        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.GCP_GOOGLE_STS),
                eq(OauthProviderLabel.GOOGLE_MONITORING),
                eq(true),
                eq(null),
                eq(MCP_CLIENT),
                eq(REGION),
                anyDouble());
    }

    @Test
    void getAccessToken_googleLogging_success_usesLoggingRoleName() throws Exception {
        String idToken = idTokenWithShortId(SHORT_ID);
        when(zmsServiceImpl.getScopeForPrincipal("user." + SHORT_ID, MONITORING_ROLE))
                .thenReturn(new GcpZmsPrincipalScope("openid", null));
        mockAthenzReturnsIdToken(ATHENZ_ID_TOKEN);
        when(googleWorkforceTokenExchange.exchange(
                eq(ATHENZ_ID_TOKEN),
                eq(AudienceConstants.PROVIDER_GOOGLE_LOGGING),
                eq(null))).thenReturn(STS_ACCESS_TOKEN);

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(
                request(AudienceConstants.PROVIDER_GOOGLE_LOGGING, idToken));

        assertEquals(AuthResult.AUTHORIZED, r.authResult());
        assertEquals(STS_ACCESS_TOKEN, r.token().accessToken());
        verify(zmsServiceImpl, times(1)).getScopeForPrincipal("user." + SHORT_ID, MONITORING_ROLE);
    }

    @Test
    void getAccessToken_googleBigQuery_success_usesBigQueryRoleName() throws Exception {
        String idToken = idTokenWithShortId(SHORT_ID);
        when(zmsServiceImpl.getScopeForPrincipal("user." + SHORT_ID, BIGQUERY_ROLE))
                .thenReturn(new GcpZmsPrincipalScope("bq-domain:role.gcp.fed.mcp.bigquery.user openid", BILLING_PROJECT));
        mockAthenzReturnsIdToken(ATHENZ_ID_TOKEN);
        when(googleWorkforceTokenExchange.exchange(
                eq(ATHENZ_ID_TOKEN),
                eq(AudienceConstants.PROVIDER_GOOGLE_BIGQUERY),
                eq(BILLING_PROJECT))).thenReturn(STS_ACCESS_TOKEN);

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(
                request(AudienceConstants.PROVIDER_GOOGLE_BIGQUERY, idToken));

        assertEquals(AuthResult.AUTHORIZED, r.authResult());
        assertEquals(STS_ACCESS_TOKEN, r.token().accessToken());
        assertEquals(3600L, r.token().ttl());
        verify(zmsServiceImpl, times(1)).getScopeForPrincipal("user." + SHORT_ID, BIGQUERY_ROLE);
        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.GCP_ATHENZ_ID_TOKEN),
                eq(OauthProviderLabel.GOOGLE_BIGQUERY),
                eq(true),
                eq(null),
                eq(MCP_CLIENT),
                eq(REGION),
                anyDouble());
        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.GCP_GOOGLE_STS),
                eq(OauthProviderLabel.GOOGLE_BIGQUERY),
                eq(true),
                eq(null),
                eq(MCP_CLIENT),
                eq(REGION),
                anyDouble());
    }

    @Test
    void getAccessToken_serviceWithoutRoleName_fallsBackToDefault() throws Exception {
        // Replace the bigquery entry with one that omits gcp-role-name; the default
        // "gcp.fed.mcp.user" should be used instead of the configured override.
        services.put(AudienceConstants.PROVIDER_GOOGLE_BIGQUERY,
                serviceConfig(List.of("https://www.googleapis.com/auth/cloud-platform.read-only"), null));
        String idToken = idTokenWithShortId(SHORT_ID);
        when(zmsServiceImpl.getScopeForPrincipal("user." + SHORT_ID, "gcp.fed.mcp.user"))
                .thenReturn(new GcpZmsPrincipalScope("openid", null));
        mockAthenzReturnsIdToken(ATHENZ_ID_TOKEN);
        when(googleWorkforceTokenExchange.exchange(
                eq(ATHENZ_ID_TOKEN),
                eq(AudienceConstants.PROVIDER_GOOGLE_BIGQUERY),
                eq(null))).thenReturn(STS_ACCESS_TOKEN);

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(
                request(AudienceConstants.PROVIDER_GOOGLE_BIGQUERY, idToken));

        assertEquals(AuthResult.AUTHORIZED, r.authResult());
        verify(zmsServiceImpl, times(1)).getScopeForPrincipal("user." + SHORT_ID, "gcp.fed.mcp.user");
    }

    @Test
    void getAccessToken_emptyZmsScope_stillRunsAthenzWithEmptyScopes() throws Exception {
        String idToken = idTokenWithShortId(SHORT_ID);
        when(zmsServiceImpl.getScopeForPrincipal("user." + SHORT_ID, MONITORING_ROLE))
                .thenReturn(new GcpZmsPrincipalScope("   ", null));
        mockAthenzReturnsIdToken(ATHENZ_ID_TOKEN);
        when(googleWorkforceTokenExchange.exchange(
                eq(ATHENZ_ID_TOKEN), eq(AudienceConstants.PROVIDER_GOOGLE_MONITORING), eq(null)))
                .thenReturn(STS_ACCESS_TOKEN);

        AuthorizationResultDO r = service.getAccessTokenFromResourceAuthorizationServer(
                request(AudienceConstants.PROVIDER_GOOGLE_MONITORING, idToken));

        assertEquals(AuthResult.AUTHORIZED, r.authResult());
        ArgumentCaptor<TokenExchangeDO> captor = ArgumentCaptor.forClass(TokenExchangeDO.class);
        verify(athenzExchange, times(1)).getAccessTokenFromResourceAuthorizationServer(captor.capture());
        assertEquals(List.of(), captor.getValue().scopes());
    }
}
