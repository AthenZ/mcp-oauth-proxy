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
import java.time.Duration;
import java.util.LinkedHashMap;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Synthetic OIDC UserInfo endpoint for the Datadog tenant.
 *
 * <p>Datadog's MCP authorization server does not expose a flat OIDC userinfo endpoint. The
 * working identity API for an MCP-issued zero-scope access token is
 * {@code GET https://api.datadoghq.com/api/v2/users}. With a zero-scope token the response is
 * filtered to the calling user's own row, so {@code data} is a single-element list (Datadog's
 * documented list shape). The element is JSON-API-shaped:
 *
 * <pre>
 * {
 *   "data": [
 *     { "type": "users", "id": "&lt;uuid&gt;",
 *       "attributes": { "email": "...", "handle": "...", "uuid": "..." } }
 *   ],
 *   "meta": { ... }
 * }
 * </pre>
 *
 * <p>Quarkus' {@link io.quarkus.oidc.UserInfo} only navigates top-level claims, so we proxy the
 * Datadog response through this resource and re-project the first {@code data} element's
 * {@code attributes.email} / {@code id} / {@code attributes.handle} / {@code attributes.uuid}
 * to flat top-level claims that {@code BaseResource.getUsername} can consume. We also accept a
 * single-object {@code data: { ... }} response shape defensively in case Datadog later
 * collapses zero-scope responses to the {@code current_user}-style envelope.
 *
 * <p>This is the same pattern used by {@link EmbraceSyntheticUserInfoResource}; the path is
 * exposed via {@code quarkus.oidc.datadog.user-info-path} which Quarkus calls with the
 * just-issued bearer access token after the code exchange completes.
 *
 * <p><b>Zero-scope token:</b> Yahoo's MCP integration explicitly requests no scopes from
 * Datadog (the OIDC tenant sets {@code authentication.scopes: []}), so the issued AT only
 * carries whatever Datadog's MCP product implicitly grants. {@code /api/v2/users} works under
 * those rules and returns a one-element list filtered to the requesting user; do not switch
 * to scope-gated endpoints like {@code /api/v2/current_user} without first re-introducing
 * scopes on the OIDC tenant.
 *
 * <p><b>Diagnostics:</b> on non-2xx upstream responses this resource logs the truncated
 * Datadog error body (max 512 chars) so the actual reason ({@code invalid_token},
 * {@code insufficient_scope}, wrong site, etc.) is visible in the application log; bodies
 * from {@code /api/v2/users} are JSON error envelopes and contain no secrets.
 */
@ApplicationScoped
@Path("/internal/datadog/oauth-userinfo")
public class DatadogUserInfoResource {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    /**
     * Default Datadog identity API endpoint. {@code /api/v2/users} is the documented list-users
     * endpoint; with a zero-scope MCP access token Datadog filters the response to a single
     * element (the calling user). The legacy {@code /api/v2/current_user} alternative requires
     * scopes Datadog does not grant to MCP tokens. Overridable per env via
     * {@code mop.datadog.current-user-url}.
     */
    private static final String DEFAULT_CURRENT_USER_URL = "https://api.datadoghq.com/api/v2/users";

    /** Cap on the upstream-body fragment we log on non-2xx responses. Datadog error envelopes are JSON; no secrets. */
    private static final int UPSTREAM_BODY_LOG_LIMIT = 512;
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @ConfigProperty(name = "mop.datadog.current-user-url", defaultValue = DEFAULT_CURRENT_USER_URL)
    String currentUserUrl;

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
        telemetryRequestContext.setOauthProvider(OauthProviderLabel.DATADOG);
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
            req = HttpRequest.newBuilder(URI.create(currentUserUrl))
                    .timeout(HTTP_TIMEOUT)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                    .GET()
                    .build();
        } catch (IllegalArgumentException e) {
            log.error("Datadog synthetic userinfo: invalid current_user URL: {}", currentUserUrl, e);
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "invalid_url",
                    Response.status(Response.Status.BAD_GATEWAY).build());
        }

        HttpResponse<String> resp;
        try {
            resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            log.warn("Datadog synthetic userinfo: I/O error calling current_user", e);
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "io_error",
                    Response.status(Response.Status.BAD_GATEWAY).build());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Datadog synthetic userinfo: interrupted calling current_user", e);
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "interrupted",
                    Response.status(Response.Status.BAD_GATEWAY).build());
        }

        int status = resp.statusCode();
        if (status == 401 || status == 403) {
            // Log the truncated upstream body so the next 401 is diagnosable from the application
            // log: Datadog returns JSON error envelopes (e.g. {"errors":["..."],"code":"invalid_token"})
            // that distinguish wrong-site / insufficient-scope / revoked-token without leaking secrets.
            log.warn("Datadog synthetic userinfo: upstream {} from {} (token ends ...{}, body={})",
                    status, currentUserUrl, lastEightOf(token), truncate(resp.body(), UPSTREAM_BODY_LOG_LIMIT));
            return finishUserinfo(startNanos, false, 401, "invalid_token", "upstream_unauthorized",
                    Response.status(Response.Status.UNAUTHORIZED).build());
        }
        if (status < 200 || status >= 300) {
            log.warn("Datadog synthetic userinfo: upstream returned status={} from {} (body={})",
                    status, currentUserUrl, truncate(resp.body(), UPSTREAM_BODY_LOG_LIMIT));
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "upstream_status_" + status,
                    Response.status(Response.Status.BAD_GATEWAY).build());
        }

        LinkedHashMap<String, Object> flat = new LinkedHashMap<>();
        try {
            JsonNode root = OBJECT_MAPPER.readTree(resp.body() != null ? resp.body() : "{}");
            // /api/v2/users returns { "data": [ { ... } ] }; current_user-style would be
            // { "data": { ... } }. Accept either so a future Datadog change in either direction
            // doesn't silently 502 us. We always pick the first element when the list shape is
            // present — with a zero-scope MCP token Datadog filters to a single row.
            JsonNode dataNode = root.path("data");
            JsonNode userNode;
            if (dataNode.isArray()) {
                userNode = dataNode.size() > 0 ? dataNode.get(0) : null;
            } else if (dataNode.isObject()) {
                userNode = dataNode;
            } else {
                userNode = null;
            }
            if (userNode != null) {
                JsonNode attrs = userNode.path("attributes");
                String email = textOrNull(attrs.path("email"));
                String handle = textOrNull(attrs.path("handle"));
                String uuid = textOrNull(attrs.path("uuid"));
                String id = textOrNull(userNode.path("id"));
                if (email != null) {
                    flat.put("email", email);
                }
                if (id != null) {
                    flat.put("id", id);
                }
                if (handle != null) {
                    flat.put("handle", handle);
                }
                String sub = uuid != null ? uuid : id;
                if (sub != null) {
                    flat.put("sub", sub);
                }
            }
        } catch (Exception e) {
            log.warn("Datadog synthetic userinfo: failed to parse identity response", e);
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "parse_failed",
                    Response.status(Response.Status.BAD_GATEWAY).build());
        }

        if (flat.isEmpty()) {
            log.warn("Datadog synthetic userinfo: identity response missing identity claims");
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

    /** Truncates an upstream body for log output. Replaces newlines with literal {@code \n} so the log line stays single-line. */
    static String truncate(String body, int maxChars) {
        if (body == null) {
            return "<null>";
        }
        String oneLine = body.replace("\n", "\\n").replace("\r", "");
        if (oneLine.length() <= maxChars) {
            return oneLine;
        }
        return oneLine.substring(0, maxChars) + "...[truncated " + (oneLine.length() - maxChars) + " chars]";
    }

    /** Last 8 chars of the bearer (or {@code <empty>}). Avoids logging the full token while letting an operator correlate. */
    static String lastEightOf(String token) {
        if (token == null || token.isEmpty()) {
            return "<empty>";
        }
        return token.length() <= 8 ? token : token.substring(token.length() - 8);
    }

    private Response finishUserinfo(long startNanos, boolean success, int httpStatus,
            String errorType, String userinfoFailureReason, Response response) {
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        oauthProxyMetrics.recordUserinfoDuration(OauthProviderLabel.DATADOG, success,
                userinfoFailureReason, seconds);
        oauthProxyMetrics.recordUserinfoRequest(OauthProviderLabel.DATADOG, success, httpStatus,
                errorType, userinfoFailureReason);
        return response;
    }
}
