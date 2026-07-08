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
 * Unit tests for {@link DatahubUserInfoResource}. The resource POSTs the GraphQL {@code me}
 * query to the configured {@code mop.datahub.graphql-url} endpoint and re-projects
 * {@code data.me.corpUser.properties.email} / {@code username} / {@code urn} /
 * {@code properties.fullName} to flat top-level claims so Quarkus' {@code UserInfo.get("email")}
 * can find them. Mirrors {@link LinearUserInfoResourceTest}. Uses a synthetic
 * {@code example.test} endpoint — the HTTP client is mocked, nothing leaves the test.
 */
// Mocking HttpClient.send(HttpRequest, BodyHandler<T>) inherently produces unchecked warnings on
// the BodyHandler type parameter. Localized to the test surface; production code is fully typed.
@SuppressWarnings("unchecked")
@ExtendWith(MockitoExtension.class)
class DatahubUserInfoResourceTest {

    /** Fake GraphQL endpoint — the HTTP client is mocked, so no request ever leaves the test. */
    private static final String TEST_GRAPHQL_URL = "https://datahub.example.test/api/graphql";

    private static final String FULL_ME_BODY = "{\n" +
            "  \"data\": {\n" +
            "    \"me\": {\n" +
            "      \"corpUser\": {\n" +
            "        \"urn\": \"urn:li:corpuser:testuser\",\n" +
            "        \"username\": \"testuser\",\n" +
            "        \"properties\": {\n" +
            "          \"active\": true,\n" +
            "          \"displayName\": \"Test User\",\n" +
            "          \"fullName\": \"Test User\",\n" +
            "          \"email\": \"testuser@example.com\"\n" +
            "        }\n" +
            "      }\n" +
            "    }\n" +
            "  },\n" +
            "  \"extensions\": {}\n" +
            "}";

    @Mock
    OauthProxyMetrics oauthProxyMetrics;

    @Mock
    TelemetryRequestContext telemetryRequestContext;

    @Mock
    HttpClient httpClient;

    private DatahubUserInfoResource resource;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        resource = new DatahubUserInfoResource();
        resource.oauthProxyMetrics = oauthProxyMetrics;
        resource.telemetryRequestContext = telemetryRequestContext;
        resource.graphqlUrl = TEST_GRAPHQL_URL;
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
    void get_happyPath_flattensCorpUserToTopLevel() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn(FULL_ME_BODY);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer dh_at_test");
        assertEquals(200, r.getStatus());
        Map<String, Object> entity = (Map<String, Object>) r.getEntity();
        assertNotNull(entity);
        // Flat top-level claims that Quarkus UserInfo can navigate. BaseResource.getUsername
        // strips @domain when the claim name contains "email", so the stored lookupKey will be
        // "testuser" — the short id we want.
        assertEquals("testuser@example.com", entity.get("email"));
        assertEquals("testuser", entity.get("username"));
        assertEquals("Test User", entity.get("name"));
        assertEquals("urn:li:corpuser:testuser", entity.get("sub"));
    }

    @Test
    void get_postsMeQueryWithBearerHeader() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn(FULL_ME_BODY);
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        when(httpClient.send(captor.capture(), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer dh_at_specific_token");
        assertEquals(200, r.getStatus());
        HttpRequest sent = captor.getValue();
        assertEquals(URI.create(TEST_GRAPHQL_URL), sent.uri());
        assertEquals("POST", sent.method(),
                "DataHub identity is read via a GraphQL POST, not a REST GET");
        assertTrue(sent.headers().firstValue("Authorization").orElse("").contains("dh_at_specific_token"),
                "Authorization header must be forwarded to the upstream DataHub GraphQL API");
        assertTrue(sent.headers().firstValue("Content-Type").orElse("").contains("application/json"),
                "Content-Type must be application/json for GraphQL POST");
        assertTrue(sent.headers().firstValue("Accept").orElse("").contains("application/json"),
                "Accept header must indicate JSON");
    }

    @Test
    void get_upstream401_returns401() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(401);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer dh_bad");
        assertEquals(401, r.getStatus());
    }

    @Test
    void get_graphqlErrorsBody_returns401() throws Exception {
        // DataHub GraphQL surfaces auth failures as HTTP 200 with a top-level "errors" array.
        // Treating that as success would let Quarkus accept an empty userinfo as identity-bound.
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn(
                "{\"errors\":[{\"message\":\"Unauthorized\"}],\"data\":{\"me\":null}}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer dh_x");
        assertEquals(401, r.getStatus());
    }

    @Test
    void get_upstream5xx_returns502() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(503);
        when(upstream.body()).thenReturn("Service Unavailable");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer dh_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_ioException_returns502() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("network down"));

        Response r = resource.get("Bearer dh_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_malformedUpstreamJson_returns502() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn("not-json");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer dh_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_missingIdentityClaims_returns502() throws Exception {
        // corpUser shape with no email/username/urn — nothing to project to top level.
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn("{\"data\":{\"me\":{\"corpUser\":{}}}}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer dh_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_minimalCorpUser_setsSubFromUsernameWhenUrnMissing() throws Exception {
        // Email + username present but no urn/fullName — output should still flatten;
        // `sub` falls back to username and `name` falls back to displayName (absent here).
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn(
                "{\"data\":{\"me\":{\"corpUser\":{\"username\":\"testuser\","
                        + "\"properties\":{\"email\":\"a@b.com\"}}}}}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer dh_x");
        assertEquals(200, r.getStatus());
        Map<String, Object> entity = (Map<String, Object>) r.getEntity();
        assertEquals("a@b.com", entity.get("email"));
        assertEquals("testuser", entity.get("username"));
        assertEquals("testuser", entity.get("sub"),
                "sub falls back to username when the corpuser urn is missing");
        assertNull(entity.get("name"), "name should not be present when missing in upstream");
        // Verify we used a stable insertion order so the response is deterministic.
        assertTrue(entity instanceof LinkedHashMap);
    }

    @Test
    void get_nameFallsBackToDisplayName() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn(
                "{\"data\":{\"me\":{\"corpUser\":{\"urn\":\"urn:li:corpuser:testuser\","
                        + "\"username\":\"testuser\","
                        + "\"properties\":{\"email\":\"a@b.com\",\"displayName\":\"Display Only\"}}}}}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer dh_x");
        assertEquals(200, r.getStatus());
        Map<String, Object> entity = (Map<String, Object>) r.getEntity();
        assertEquals("Display Only", entity.get("name"),
                "name falls back to properties.displayName when fullName is absent");
    }
}
