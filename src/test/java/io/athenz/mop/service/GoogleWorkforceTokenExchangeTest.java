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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.athenz.mop.config.GoogleWorkforceTokenExchangeConfig;
import io.athenz.mop.config.GoogleWorkforceTokenExchangeConfig.ServiceConfig;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.UpstreamHttpCallLabels;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class GoogleWorkforceTokenExchangeTest {

    private static final String REGION = "us-east-1";
    private static final String WORKFORCE_AUDIENCE =
            "//iam.googleapis.com/locations/global/workforcePools/yahoo-athenz/providers/athenz-oidc";
    private static final String ATHENZ_ID_TOKEN = "athenz.id.token";

    @Mock
    private GoogleWorkforceTokenExchangeConfig config;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private MetricsRegionProvider metricsRegionProvider;

    @InjectMocks
    private GoogleWorkforceTokenExchange exchange;

    private HttpServer server;
    private final ConcurrentLinkedQueue<CapturedRequest> captured = new ConcurrentLinkedQueue<>();
    private volatile int responseStatus = 200;
    private volatile String responseBody = "{\"access_token\":\"sts-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}";

    private final Map<String, ServiceConfig> services = new HashMap<>();

    private record CapturedRequest(String method, Map<String, String> headers, String body) {}

    @BeforeEach
    void setUp() throws IOException {
        MockitoAnnotations.openMocks(this);
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newSingleThreadExecutor());
        server.createContext("/v1/token", (HttpExchange ex) -> {
            try (InputStream in = ex.getRequestBody()) {
                byte[] body = in.readAllBytes();
                Map<String, String> headers = new HashMap<>();
                ex.getRequestHeaders().forEach((k, v) -> {
                    if (!v.isEmpty()) {
                        headers.put(k, v.get(0));
                    }
                });
                captured.add(new CapturedRequest(ex.getRequestMethod(), headers, new String(body, StandardCharsets.UTF_8)));
            }
            byte[] payload = responseBody.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(responseStatus, payload.length);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(payload);
            }
        });
        server.start();

        String stsUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/token";
        when(config.stsTokenUrl()).thenReturn(stsUrl);
        when(config.audience()).thenReturn(WORKFORCE_AUDIENCE);
        when(config.services()).thenReturn(services);
        when(metricsRegionProvider.primaryRegion()).thenReturn(REGION);

        services.put(AudienceConstants.PROVIDER_GOOGLE_MONITORING,
                svc(List.of("https://www.googleapis.com/auth/cloud-platform",
                        "https://www.googleapis.com/auth/monitoring.read"), "role-monitoring"));
        services.put(AudienceConstants.PROVIDER_GOOGLE_LOGGING,
                svc(List.of("https://www.googleapis.com/auth/cloud-platform",
                        "https://www.googleapis.com/auth/logging.read"), "role-logging"));
        services.put(AudienceConstants.PROVIDER_GOOGLE_BIGQUERY,
                svc(List.of("https://www.googleapis.com/auth/cloud-platform.read-only",
                        "https://www.googleapis.com/auth/devstorage.read_only"), "role-bigquery"));
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    private static ServiceConfig svc(List<String> scopes, String roleName) {
        return new ServiceConfig() {
            @Override public List<String> scopes() { return scopes; }
            @Override public Optional<String> gcpRoleName() { return Optional.ofNullable(roleName); }
        };
    }

    // ---------- Input validation (no HTTP call) ----------

    @Test
    void exchange_nullIdToken_returnsNullNoHttp() {
        assertNull(exchange.exchange(null, AudienceConstants.PROVIDER_GOOGLE_MONITORING));
        assertTrue(captured.isEmpty());
        verify(oauthProxyMetrics, never()).recordUpstreamRequest(anyString(), anyString(), anyInt(), anyString(), anyDouble());
    }

    @Test
    void exchange_blankIdToken_returnsNullNoHttp() {
        assertNull(exchange.exchange("   ", AudienceConstants.PROVIDER_GOOGLE_MONITORING));
        assertTrue(captured.isEmpty());
    }

    @Test
    void exchange_nullAudience_returnsNullNoHttp() {
        assertNull(exchange.exchange(ATHENZ_ID_TOKEN, null));
        assertTrue(captured.isEmpty());
    }

    @Test
    void exchange_blankAudience_returnsNullNoHttp() {
        assertNull(exchange.exchange(ATHENZ_ID_TOKEN, "  "));
        assertTrue(captured.isEmpty());
    }

    @Test
    void exchange_unknownAudience_returnsNullNoHttp() {
        assertNull(exchange.exchange(ATHENZ_ID_TOKEN, "unknown-gcp"));
        assertTrue(captured.isEmpty());
        verify(oauthProxyMetrics, never()).recordUpstreamRequest(anyString(), anyString(), anyInt(), anyString(), anyDouble());
    }

    @Test
    void exchange_servicesMapIsNull_returnsNullNoHttp() {
        when(config.services()).thenReturn(null);
        assertNull(exchange.exchange(ATHENZ_ID_TOKEN, AudienceConstants.PROVIDER_GOOGLE_MONITORING));
        assertTrue(captured.isEmpty());
    }

    @Test
    void exchange_nullScopes_returnsNullNoHttp() {
        services.put(AudienceConstants.PROVIDER_GOOGLE_BIGQUERY, svc(null, "role"));
        assertNull(exchange.exchange(ATHENZ_ID_TOKEN, AudienceConstants.PROVIDER_GOOGLE_BIGQUERY));
        assertTrue(captured.isEmpty());
    }

    @Test
    void exchange_emptyScopes_returnsNullNoHttp() {
        services.put(AudienceConstants.PROVIDER_GOOGLE_BIGQUERY, svc(List.of(), "role"));
        assertNull(exchange.exchange(ATHENZ_ID_TOKEN, AudienceConstants.PROVIDER_GOOGLE_BIGQUERY));
        assertTrue(captured.isEmpty());
    }

    // ---------- HTTP / happy paths ----------

    @Test
    void exchange_monitoring_success_sendsExpectedRequestAndRecordsMetric() throws Exception {
        String token = exchange.exchange(ATHENZ_ID_TOKEN, AudienceConstants.PROVIDER_GOOGLE_MONITORING);

        assertEquals("sts-token", token);
        assertEquals(1, captured.size());
        CapturedRequest req = captured.poll();
        assertNotNull(req);
        assertEquals("POST", req.method());
        ObjectMapper om = new ObjectMapper();
        JsonNode body = om.readTree(req.body());
        assertEquals("urn:ietf:params:oauth:grant-type:token-exchange", body.get("grantType").asText());
        assertEquals(WORKFORCE_AUDIENCE, body.get("audience").asText());
        assertEquals("https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/monitoring.read",
                body.get("scope").asText());
        assertEquals("urn:ietf:params:oauth:token-type:access_token", body.get("requestedTokenType").asText());
        assertEquals(ATHENZ_ID_TOKEN, body.get("subjectToken").asText());
        assertEquals("urn:ietf:params:oauth:token-type:jwt", body.get("subjectTokenType").asText());
        JsonNode options = om.readTree(body.get("options").asText());
        assertEquals("core-mcpworkspace-p", options.get("userProject").asText());

        verify(oauthProxyMetrics, times(1)).recordUpstreamRequest(
                eq(OauthProviderLabel.GOOGLE_MONITORING),
                eq(UpstreamHttpCallLabels.ENDPOINT_GOOGLE_STS),
                eq(200),
                eq(REGION),
                anyDouble());
    }

    @Test
    void exchange_logging_success_sendsExpectedScopes() throws Exception {
        String token = exchange.exchange(ATHENZ_ID_TOKEN, AudienceConstants.PROVIDER_GOOGLE_LOGGING);

        assertEquals("sts-token", token);
        CapturedRequest req = captured.poll();
        assertNotNull(req);
        JsonNode body = new ObjectMapper().readTree(req.body());
        assertEquals("https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/logging.read",
                body.get("scope").asText());

        verify(oauthProxyMetrics, times(1)).recordUpstreamRequest(
                eq(OauthProviderLabel.GOOGLE_LOGGING),
                eq(UpstreamHttpCallLabels.ENDPOINT_GOOGLE_STS),
                eq(200),
                eq(REGION),
                anyDouble());
    }

    @Test
    void exchange_bigquery_success_sendsExpectedScopes() throws Exception {
        String token = exchange.exchange(ATHENZ_ID_TOKEN, AudienceConstants.PROVIDER_GOOGLE_BIGQUERY);

        assertEquals("sts-token", token);
        CapturedRequest req = captured.poll();
        assertNotNull(req);
        JsonNode body = new ObjectMapper().readTree(req.body());
        assertEquals("https://www.googleapis.com/auth/cloud-platform.read-only https://www.googleapis.com/auth/devstorage.read_only",
                body.get("scope").asText());

        verify(oauthProxyMetrics, times(1)).recordUpstreamRequest(
                eq(OauthProviderLabel.GOOGLE_BIGQUERY),
                eq(UpstreamHttpCallLabels.ENDPOINT_GOOGLE_STS),
                eq(200),
                eq(REGION),
                anyDouble());
    }

    @Test
    void exchange_withUserProject_overridesFallback() throws Exception {
        String token = exchange.exchange(ATHENZ_ID_TOKEN, AudienceConstants.PROVIDER_GOOGLE_MONITORING, "my-billing-project");

        assertEquals("sts-token", token);
        CapturedRequest req = captured.poll();
        assertNotNull(req);
        ObjectMapper om = new ObjectMapper();
        JsonNode options = om.readTree(om.readTree(req.body()).get("options").asText());
        assertEquals("my-billing-project", options.get("userProject").asText());
    }

    @Test
    void exchange_blankUserProject_usesFallback() throws Exception {
        String token = exchange.exchange(ATHENZ_ID_TOKEN, AudienceConstants.PROVIDER_GOOGLE_MONITORING, "   ");

        assertEquals("sts-token", token);
        CapturedRequest req = captured.poll();
        assertNotNull(req);
        ObjectMapper om = new ObjectMapper();
        JsonNode options = om.readTree(om.readTree(req.body()).get("options").asText());
        assertEquals("core-mcpworkspace-p", options.get("userProject").asText());
    }

    // ---------- HTTP error paths ----------

    @Test
    void exchange_non200_returnsNullAndRecordsStatus() {
        responseStatus = 403;
        responseBody = "{\"error\":\"denied\"}";

        String token = exchange.exchange(ATHENZ_ID_TOKEN, AudienceConstants.PROVIDER_GOOGLE_BIGQUERY);

        assertNull(token);
        verify(oauthProxyMetrics, times(1)).recordUpstreamRequest(
                eq(OauthProviderLabel.GOOGLE_BIGQUERY),
                eq(UpstreamHttpCallLabels.ENDPOINT_GOOGLE_STS),
                eq(403),
                eq(REGION),
                anyDouble());
    }

    @Test
    void exchange_malformedResponseBody_returnsNull() {
        responseStatus = 200;
        responseBody = "not-json";

        String token = exchange.exchange(ATHENZ_ID_TOKEN, AudienceConstants.PROVIDER_GOOGLE_MONITORING);

        assertNull(token);
    }

    @Test
    void exchange_200WithNullAccessToken_returnsNull() {
        responseStatus = 200;
        responseBody = "{\"token_type\":\"Bearer\",\"expires_in\":3600}";

        String token = exchange.exchange(ATHENZ_ID_TOKEN, AudienceConstants.PROVIDER_GOOGLE_MONITORING);

        assertNull(token);
        verify(oauthProxyMetrics, times(1)).recordUpstreamRequest(
                eq(OauthProviderLabel.GOOGLE_MONITORING),
                eq(UpstreamHttpCallLabels.ENDPOINT_GOOGLE_STS),
                eq(200),
                eq(REGION),
                anyDouble());
    }
}
