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
package io.athenz.mop.resource;

import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DatadogUserInfoResource}. The resource proxies
 * {@code https://api.datadoghq.com/api/v2/current_user} and re-projects the JSON-API-shaped
 * payload to flat top-level claims so Quarkus' {@code UserInfo.get("email")} can find them.
 */
// Mocking HttpClient.send(HttpRequest, BodyHandler<T>) inherently produces unchecked warnings on
// the BodyHandler type parameter. Localized to the test surface; production code is fully typed.
@SuppressWarnings("unchecked")
@ExtendWith(MockitoExtension.class)
class DatadogUserInfoResourceTest {

    @Mock
    OauthProxyMetrics oauthProxyMetrics;

    @Mock
    TelemetryRequestContext telemetryRequestContext;

    @Mock
    HttpClient httpClient;

    private DatadogUserInfoResource resource;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        resource = new DatadogUserInfoResource();
        resource.oauthProxyMetrics = oauthProxyMetrics;
        resource.telemetryRequestContext = telemetryRequestContext;
        resource.currentUserUrl = "https://api.datadoghq.com/api/v2/current_user";
        resource.setHttpClient(httpClient);
    }

    @Test
    void get_missingAuthorizationHeader_returns401() {
        Response r = resource.get(null);
        assertEquals(401, r.getStatus());
    }

    @Test
    void get_authorizationNotBearer_returns401() {
        Response r = resource.get("Basic deadbeef");
        assertEquals(401, r.getStatus());
    }

    @Test
    void get_emptyBearerToken_returns401() {
        Response r = resource.get("Bearer    ");
        assertEquals(401, r.getStatus());
    }

    @Test
    void get_happyPath_flattensDataAttributesToTopLevel() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        String body = "{\n" +
                "  \"data\": {\n" +
                "    \"type\": \"users\",\n" +
                "    \"id\": \"e92be4dd-2ca3-40d5-8a2a-73191475fabd\",\n" +
                "    \"attributes\": {\n" +
                "      \"email\": \"yosrixp@yahooinc.com\",\n" +
                "      \"handle\": \"yosrixp@yahooinc.com\",\n" +
                "      \"uuid\":  \"e92be4dd-2ca3-40d5-8a2a-73191475fabd\"\n" +
                "    }\n" +
                "  }\n" +
                "}";
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn(body);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer ddoat_test");
        assertEquals(200, r.getStatus());
        Map<String, Object> entity = (Map<String, Object>) r.getEntity();
        assertNotNull(entity);
        // Flat top-level claims that Quarkus UserInfo can navigate. BaseResource.getUsername
        // strips @domain when the claim name contains "email", so the stored lookupKey will be
        // "yosrixp" — the short id we want.
        assertEquals("yosrixp@yahooinc.com", entity.get("email"));
        assertEquals("e92be4dd-2ca3-40d5-8a2a-73191475fabd", entity.get("id"));
        assertEquals("yosrixp@yahooinc.com", entity.get("handle"));
        assertEquals("e92be4dd-2ca3-40d5-8a2a-73191475fabd", entity.get("sub"));
    }

    @Test
    void get_forwardsBearerHeaderToUpstream() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn("{\"data\":{\"id\":\"x\",\"attributes\":{\"email\":\"a@b.com\"}}}");
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        when(httpClient.send(captor.capture(), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer ddoat_specific_token");
        assertEquals(200, r.getStatus());
        HttpRequest sent = captor.getValue();
        assertEquals(URI.create("https://api.datadoghq.com/api/v2/current_user"), sent.uri());
        assertEquals("GET", sent.method());
        // Authorization header is forwarded verbatim with the Bearer prefix re-applied.
        assertTrue(sent.headers().firstValue("Authorization").orElse("").contains("ddoat_specific_token"),
                "Authorization header must be forwarded to upstream Datadog identity API");
        assertTrue(sent.headers().firstValue("Accept").orElse("").contains("application/json"),
                "Accept header must indicate JSON");
    }

    @Test
    void get_upstream401_returns401() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(401);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer ddoat_bad");
        assertEquals(401, r.getStatus());
    }

    @Test
    void get_upstream5xx_returns502() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(503);
        when(upstream.body()).thenReturn("Service Unavailable");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer ddoat_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_ioException_returns502() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("network down"));

        Response r = resource.get("Bearer ddoat_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_malformedUpstreamJson_returns502() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn("not-json");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer ddoat_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_missingIdentityClaims_returns502() throws Exception {
        // current_user shape with no email/uuid/handle/id — nothing to project to top level.
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn("{\"data\":{\"type\":\"users\"}}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer ddoat_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_uuidFallbackToId_whenUuidMissing() throws Exception {
        // If attributes.uuid is missing but data.id is present, the resource projects "sub" from
        // data.id so Quarkus has a stable subject to bind onto.
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn(
                "{\"data\":{\"id\":\"abc-123\",\"attributes\":{\"email\":\"a@b.com\"}}}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer ddoat_x");
        assertEquals(200, r.getStatus());
        Map<String, Object> entity = (Map<String, Object>) r.getEntity();
        assertEquals("abc-123", entity.get("id"));
        assertEquals("abc-123", entity.get("sub"));
        assertNull(entity.get("handle"), "handle should not be present when missing in upstream");
        // Verify we used a stable insertion order so the response is deterministic.
        assertTrue(entity instanceof LinkedHashMap);
    }
}
