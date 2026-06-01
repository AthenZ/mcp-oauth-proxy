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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Synthetic OIDC UserInfo endpoint for the WisdomAI tenant.
 *
 * <p>WisdomAI's Descope-backed OAuth authorization server does not expose a flat OIDC userinfo
 * endpoint. Identity is reachable only through WisdomAI's GraphQL API at
 * {@code https://wisdom.ouryahoo.com/graphql} via the {@code currentUser} query, which returns:
 *
 * <pre>
 * { "data": { "currentUser": { "id": "&lt;numeric&gt;", "name": "", "email": "testuser@example.com" } } }
 * </pre>
 *
 * <p>Quarkus' {@link io.quarkus.oidc.UserInfo} only navigates top-level claims, so we proxy the
 * WisdomAI response through this resource and re-project {@code data.currentUser.email} /
 * {@code data.currentUser.id} / {@code data.currentUser.name} to flat top-level claims that
 * {@code BaseResource.getUsername} can consume.
 *
 * <p>This is the same pattern used by {@link LinearUserInfoResource} and
 * {@link DatadogUserInfoResource}; the path is exposed via
 * {@code quarkus.oidc.wisdomai.user-info-path} which Quarkus calls with the just-issued bearer
 * access token after the code exchange completes. The live WisdomAI response sometimes returns
 * {@code "name": ""}; that is fine -- the configured username claim is {@code email}, so the
 * empty {@code name} never participates in lookup.
 */
@ApplicationScoped
@Path("/internal/wisdomai/oauth-userinfo")
public class WisdomAiUserInfoResource {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    /** Default WisdomAI GraphQL endpoint. Overridable for tests via {@code mop.wisdomai.graphql-url}. */
    private static final String DEFAULT_GRAPHQL_URL = "https://wisdom.ouryahoo.com/graphql";
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);

    /** Minimal {@code currentUser} GraphQL query -- fields we map to flat OIDC-style claims. */
    private static final String CURRENT_USER_QUERY_BODY =
            "{\"query\":\"query CurrentUser { currentUser { id name email } }\"}";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @ConfigProperty(name = "mop.wisdomai.graphql-url", defaultValue = DEFAULT_GRAPHQL_URL)
    String graphqlUrl;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    TelemetryRequestContext telemetryRequestContext;

    private volatile HttpClient httpClient;

    @PostConstruct
    void init() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(HTTP_TIMEOUT)
                .build();
    }

    /** Test seam: replace the underlying HTTP client. */
    void setHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response get(@HeaderParam(HttpHeaders.AUTHORIZATION) String authorization) {
        long startNanos = System.nanoTime();
        telemetryRequestContext.setOauthProvider(OauthProviderLabel.WISDOMAI);
        if (authorization == null) {
            return finishUserinfo(startNanos, false, 401, "invalid_token", "missing_bearer",
                    Response.status(Response.Status.UNAUTHORIZED).build());
        }
        String trimmed = authorization.trim();
        if (!trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return finishUserinfo(startNanos, false, 401, "invalid_token", "not_bearer",
                    Response.status(Response.Status.UNAUTHORIZED).build());
        }
        String token = trimmed.substring(7).trim();
        if (token.isEmpty()) {
            return finishUserinfo(startNanos, false, 401, "invalid_token", "empty_token",
                    Response.status(Response.Status.UNAUTHORIZED).build());
        }

        HttpRequest req;
        try {
            req = HttpRequest.newBuilder(URI.create(graphqlUrl))
                    .timeout(HTTP_TIMEOUT)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                    .POST(HttpRequest.BodyPublishers.ofString(CURRENT_USER_QUERY_BODY, StandardCharsets.UTF_8))
                    .build();
        } catch (IllegalArgumentException e) {
            log.error("WisdomAI synthetic userinfo: invalid GraphQL URL: {}", graphqlUrl, e);
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "invalid_url",
                    Response.status(Response.Status.BAD_GATEWAY).build());
        }

        HttpResponse<String> resp;
        try {
            resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            log.warn("WisdomAI synthetic userinfo: I/O error calling GraphQL currentUser", e);
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "io_error",
                    Response.status(Response.Status.BAD_GATEWAY).build());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("WisdomAI synthetic userinfo: interrupted calling GraphQL currentUser", e);
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "interrupted",
                    Response.status(Response.Status.BAD_GATEWAY).build());
        }

        int status = resp.statusCode();
        if (status == 401 || status == 403) {
            return finishUserinfo(startNanos, false, 401, "invalid_token", "upstream_unauthorized",
                    Response.status(Response.Status.UNAUTHORIZED).build());
        }
        if (status < 200 || status >= 300) {
            log.warn("WisdomAI synthetic userinfo: upstream returned status={} body_len={}",
                    status, resp.body() != null ? resp.body().length() : 0);
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "upstream_status_" + status,
                    Response.status(Response.Status.BAD_GATEWAY).build());
        }

        LinkedHashMap<String, Object> flat = new LinkedHashMap<>();
        try {
            JsonNode root = OBJECT_MAPPER.readTree(resp.body() != null ? resp.body() : "{}");
            // GraphQL surfaces auth/permission failures as a 200 with a top-level "errors" array
            // and a null/missing data.currentUser. Treat that as a 401 so Quarkus does not accept
            // an empty userinfo as success.
            if (root.has("errors") && root.path("errors").isArray() && !root.path("errors").isEmpty()) {
                log.warn("WisdomAI synthetic userinfo: GraphQL returned errors: {}", root.path("errors"));
                return finishUserinfo(startNanos, false, 401, "invalid_token", "graphql_errors",
                        Response.status(Response.Status.UNAUTHORIZED).build());
            }
            JsonNode currentUser = root.path("data").path("currentUser");
            String email = textOrNull(currentUser.path("email"));
            String id = textOrNull(currentUser.path("id"));
            String name = textOrNull(currentUser.path("name"));
            if (email != null) {
                flat.put("email", email);
            }
            if (id != null) {
                flat.put("id", id);
            }
            if (name != null) {
                flat.put("name", name);
            }
            if (id != null) {
                flat.put("sub", id);
            }
        } catch (Exception e) {
            log.warn("WisdomAI synthetic userinfo: failed to parse GraphQL response", e);
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "parse_failed",
                    Response.status(Response.Status.BAD_GATEWAY).build());
        }

        if (flat.isEmpty()) {
            log.warn("WisdomAI synthetic userinfo: GraphQL response missing identity claims");
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "missing_claims",
                    Response.status(Response.Status.BAD_GATEWAY).build());
        }

        return finishUserinfo(startNanos, true, 200, null, null, Response.ok(flat).build());
    }

    private static String textOrNull(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        if (!node.isTextual()) {
            return null;
        }
        String s = node.asText();
        return (s == null || s.isEmpty()) ? null : s;
    }

    private Response finishUserinfo(long startNanos, boolean success, int httpStatus,
            String errorType, String userinfoFailureReason, Response response) {
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        oauthProxyMetrics.recordUserinfoDuration(OauthProviderLabel.WISDOMAI, success,
                userinfoFailureReason, seconds);
        oauthProxyMetrics.recordUserinfoRequest(OauthProviderLabel.WISDOMAI, success, httpStatus,
                errorType, userinfoFailureReason);
        return response;
    }
}
