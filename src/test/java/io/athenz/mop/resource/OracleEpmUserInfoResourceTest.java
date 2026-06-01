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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OracleEpmUserInfoResource}. The resource passes through Oracle's flat
 * OIDC userinfo response (sub / preferred_username / name / given_name / family_name) verbatim
 * and additionally projects an {@code email} claim from {@code preferred_username} (or
 * {@code sub}) so {@code BaseResource.getUsername} (which only strips {@code @domain} when the
 * claim NAME contains "email") can yield the short id.
 */
// Mocking HttpClient.send(HttpRequest, BodyHandler<T>) inherently produces unchecked warnings on
// the BodyHandler type parameter. Localized to the test surface; production code is fully typed.
@SuppressWarnings("unchecked")
@ExtendWith(MockitoExtension.class)
class OracleEpmUserInfoResourceTest {

    @Mock
    OauthProxyMetrics oauthProxyMetrics;

    @Mock
    TelemetryRequestContext telemetryRequestContext;

    @Mock
    HttpClient httpClient;

    private OracleEpmUserInfoResource resource;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        resource = new OracleEpmUserInfoResource();
        resource.oauthProxyMetrics = oauthProxyMetrics;
        resource.telemetryRequestContext = telemetryRequestContext;
        resource.userinfoUrl = "https://idcs-test.identity.oraclecloud.com/oauth2/v1/userinfo";
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
    void get_happyPath_passesThroughAndProjectsEmail() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        String body = "{\n" +
                "  \"sub\": \"testuser@example.com\",\n" +
                "  \"preferred_username\": \"testuser@example.com\",\n" +
                "  \"name\": \"Yosri Amarneh\",\n" +
                "  \"given_name\": \"Yosri\",\n" +
                "  \"family_name\": \"Amarneh\"\n" +
                "}";
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn(body);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer oepm_test");
        assertEquals(200, r.getStatus());
        Map<String, Object> entity = (Map<String, Object>) r.getEntity();
        assertNotNull(entity);
        // Oracle's flat claims pass through verbatim.
        assertEquals("testuser@example.com", entity.get("sub"));
        assertEquals("testuser@example.com", entity.get("preferred_username"));
        assertEquals("Yosri Amarneh", entity.get("name"));
        // Projected `email` matches preferred_username so BaseResource.getUsername strips the
        // @domain suffix when claim=email is bound on the OIDC tenant.
        assertEquals("testuser@example.com", entity.get("email"));
    }

    @Test
    void get_emailProjection_fallsBackToSubWhenPreferredUsernameMissing() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn("{\"sub\":\"alice@yahooinc.com\",\"name\":\"Alice\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer oepm_x");
        Map<String, Object> entity = (Map<String, Object>) r.getEntity();
        assertEquals("alice@yahooinc.com", entity.get("email"),
                "when preferred_username is missing, the proxy must fall back to sub for the email projection");
    }

    @Test
    void get_emailProjection_doesNotOverwriteUpstreamEmail() throws Exception {
        // If Oracle ever starts returning a top-level email claim, the proxy must NOT clobber it.
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn(
                "{\"sub\":\"x@y.com\",\"preferred_username\":\"x@y.com\",\"email\":\"explicit@y.com\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer oepm_x");
        Map<String, Object> entity = (Map<String, Object>) r.getEntity();
        assertEquals("explicit@y.com", entity.get("email"),
                "upstream email claim must take precedence over the synthetic projection");
    }

    @Test
    void get_forwardsBearerHeaderToUpstream() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn("{\"sub\":\"a@b.com\"}");
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        when(httpClient.send(captor.capture(), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer oepm_specific_token");
        assertEquals(200, r.getStatus());
        HttpRequest sent = captor.getValue();
        assertEquals(URI.create("https://idcs-test.identity.oraclecloud.com/oauth2/v1/userinfo"), sent.uri());
        assertEquals("GET", sent.method(),
                "Oracle IDCS userinfo is a GET (not GraphQL POST)");
        assertTrue(sent.headers().firstValue("Authorization").orElse("").contains("oepm_specific_token"),
                "Authorization header must be forwarded to upstream Oracle IDCS userinfo");
        assertTrue(sent.headers().firstValue("Accept").orElse("").contains("application/json"),
                "Accept header must indicate JSON");
    }

    @Test
    void get_upstream401_returns401() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(401);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer oepm_bad");
        assertEquals(401, r.getStatus());
    }

    @Test
    void get_upstream5xx_returns502() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(503);
        when(upstream.body()).thenReturn("Service Unavailable");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer oepm_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_ioException_returns502() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("network down"));

        Response r = resource.get("Bearer oepm_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_malformedUpstreamJson_returns502() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn("not-json");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer oepm_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_nonObjectJson_returns502() throws Exception {
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn("[\"not\",\"an\",\"object\"]");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer oepm_x");
        assertEquals(502, r.getStatus());
    }

    @Test
    void get_missingSubClaim_returns502() throws Exception {
        // Oracle's userinfo always returns sub. If it's missing the downstream identity binding
        // would silently break, so we fail with 502 to make the misconfiguration loud.
        HttpResponse<String> upstream = (HttpResponse<String>) org.mockito.Mockito.mock(HttpResponse.class);
        when(upstream.statusCode()).thenReturn(200);
        when(upstream.body()).thenReturn("{\"name\":\"No Sub\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstream);

        Response r = resource.get("Bearer oepm_x");
        assertEquals(502, r.getStatus());
    }
}
