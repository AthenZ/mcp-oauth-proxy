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
 * Unit tests for {@link WisdomAiUserInfoResource}. The resource POSTs the GraphQL
 * {@code currentUser} query to {@code https://wisdom.ouryahoo.com/graphql} and re-projects
 * {@code data.currentUser.email} / {@code data.currentUser.id} / {@code data.currentUser.name} to
 * flat top-level claims so Quarkus' {@code UserInfo.get("email")} can find them.
 *
 * <p>The live WisdomAI response sometimes returns {@code "name": ""} (empty string). Empty
 * strings are stripped to {@code null} (treated as missing) so they do not show up as claims.
 * The configured username claim is {@code email} so the missing {@code name} never participates
 * in lookup -- there is a dedicated case below to pin that behavior.
 */
// Mocking HttpClient.send(HttpRequest, BodyHandler<T>) inherently produces unchecked warnings on
// the BodyHandler type parameter. Localized to the test surface; production code is fully typed.
@SuppressWarnings("unchecked")
@ExtendWith(MockitoExtension.class)
class WisdomAiUserInfoResourceTest {

    @Mock
    OauthProxyMetrics oauthProxyMetrics;

    @Mock
    TelemetryRequestContext telemetryRequestContext;

    @Mock
    HttpClient httpClient;

    private WisdomAiUserInfoResource resource;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        resource = new WisdomAiUserInfoResource();
        resource.oauthProxyMetrics = oauthProxyMetrics;
        resource.telemetryRequestContext = telemetryRequestContext;
        resource.graphqlUrl = "https://wisdom.ouryahoo.com/graphql";
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
    void get_happyPath_flattensCurrentUserToTopLevel() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        // Matches the live WisdomAI sample response shape (with synthetic identity values).
        String body = "{\n" +
                "  \"data\": {\n" +
                "    \"currentUser\": {\n" +
                "      \"id\": \"1234567890\",\n" +
                "      \"name\": \"Alice Example\",\n" +
                "      \"email\": \"alice@example.com\"\n" +
                "    }\n" +
                "  }\n" +
                "}";
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn(body);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer wai_oat_test");
        assertEquals(200, r.getStatus());
        Map<String, Object> entity = (Map<String, Object>) r.getEntity();
        assertNotNull(entity);
        // Flat top-level claims that Quarkus UserInfo can navigate. BaseResource.getUsername
        // strips @domain when the claim name contains "email", so the stored lookupKey will be
        // "alice" -- the short id we want.
        assertEquals("alice@example.com", entity.get("email"));
        assertEquals("1234567890", entity.get("id"));
        assertEquals("Alice Example", entity.get("name"));
        assertEquals("1234567890", entity.get("sub"));
    }

    @Test
    void get_liveSample_withEmptyName_flattensEmailAndId() throws Exception {
        // The live sample response from the WisdomAI integration showed name="" (empty string).
        // textOrNull treats empty strings as absent so they are not added to the projection.
        // The configured username claim is `email`, so a missing `name` does not impact lookup.
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn(
                "{\"data\":{\"currentUser\":{\"id\":\"1234567890\",\"name\":\"\",\"email\":\"alice@example.com\"}}}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer wai_oat_test");
        assertEquals(200, r.getStatus());
        Map<String, Object> entity = (Map<String, Object>) r.getEntity();
        assertEquals("alice@example.com", entity.get("email"));
        assertEquals("1234567890", entity.get("id"));
        assertEquals("1234567890", entity.get("sub"));
        assertNull(entity.get("name"),
                "empty-string name from upstream must not appear as a top-level claim");
    }

    @Test
    void get_postsCurrentUserQueryWithBearerHeader() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn(
                "{\"data\":{\"currentUser\":{\"id\":\"x\",\"name\":\"x\",\"email\":\"a@b.com\"}}}");
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        when(httpClient.send(captor.capture(), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer wai_oat_specific_token");
        assertEquals(200, r.getStatus());
        HttpRequest sent = captor.getValue();
        assertEquals(URI.create("https://wisdom.ouryahoo.com/graphql"), sent.uri());
        assertEquals("POST", sent.method(),
                "WisdomAI identity is read via a GraphQL POST, not a REST GET");
        // Authorization header is forwarded verbatim with the Bearer prefix re-applied.
        assertTrue(sent.headers().firstValue("Authorization").orElse("").contains("wai_oat_specific_token"),
                "Authorization header must be forwarded to upstream WisdomAI GraphQL API");
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

        Response r = resource.get("Bearer wai_bad");
        assertEquals(401, r.getStatus());
    }

    @Test
    void get_graphqlErrorsBody_returns401() throws Exception {
        // WisdomAI/GraphQL surfaces auth failures as HTTP 200 with a top-level "errors" array.
        // Treating that as success would let Quarkus accept an empty userinfo as identity-bound.
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn(
                "{\"errors\":[{\"message\":\"Authentication required\"}],\"data\":{\"currentUser\":null}}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer wai_x");
        assertEquals(401, r.getStatus());
    }

    @Test
    void get_upstream5xx_returns502() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(503);
        when(upstream.body()).thenReturn("Service Unavailable");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer wai_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_ioException_returns502() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("network down"));

        Response r = resource.get("Bearer wai_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_malformedUpstreamJson_returns502() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn("not-json");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer wai_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_missingIdentityClaims_returns502() throws Exception {
        // currentUser shape with no email/id/name -- nothing to project to top level.
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn("{\"data\":{\"currentUser\":{}}}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer wai_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_minimalCurrentUser_setsSubFromId() throws Exception {
        // Email + id present but no name -- output should still flatten and `sub` falls back to id.
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn(
                "{\"data\":{\"currentUser\":{\"id\":\"abc-123\",\"email\":\"a@b.com\"}}}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer wai_x");
        assertEquals(200, r.getStatus());
        Map<String, Object> entity = (Map<String, Object>) r.getEntity();
        assertEquals("abc-123", entity.get("id"));
        assertEquals("abc-123", entity.get("sub"));
        assertEquals("a@b.com", entity.get("email"));
        assertNull(entity.get("name"), "name should not be present when missing in upstream");
        assertTrue(entity instanceof LinkedHashMap);
    }
}
