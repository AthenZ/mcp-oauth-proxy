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

import com.fasterxml.jackson.core.type.TypeReference;
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
 * Synthetic OIDC UserInfo endpoint for the Oracle EPM tenant.
 *
 * <p>Unlike Datadog (JSON-API shape) and Linear (GraphQL), Oracle IDCS already returns a flat
 * OIDC-shaped userinfo response:
 *
 * <pre>
 * { "sub": "testuser@example.com", "preferred_username": "testuser@example.com",
 *   "name": "Yosri Amarneh", "given_name": "Yosri", "family_name": "Amarneh", ... }
 * </pre>
 *
 * <p>This proxy exists not to flatten claims but to keep stage/prod synthetic UserInfo behind
 * in-pod loopback (the pod cannot reach its own public hostname). On a 2xx response we re-encode
 * the body through Jackson to normalize the content-type and drop any non-JSON fields. Same
 * pattern Linear/Datadog use; the only difference is that no claim re-projection is performed.
 *
 * <p>Path is exposed via {@code quarkus.oidc.oracle-epm.user-info-path} which Quarkus calls with
 * the just-issued bearer access token after the code exchange completes.
 */
@ApplicationScoped
@Path("/internal/oracle-epm/oauth-userinfo")
public class OracleEpmUserInfoResource {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    /** Default Oracle IDCS userinfo endpoint. Overridable for tests via {@code mop.oracle-epm.userinfo-url}. */
    private static final String DEFAULT_USERINFO_URL =
            "https://idcs-c0b7a2ce098d48a0a78b94a30f9e42a1.identity.oraclecloud.com/oauth2/v1/userinfo";
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final TypeReference<LinkedHashMap<String, Object>> ORDERED_MAP_TYPE =
            new TypeReference<LinkedHashMap<String, Object>>() {};

    @ConfigProperty(name = "mop.oracle-epm.userinfo-url", defaultValue = DEFAULT_USERINFO_URL)
    String userinfoUrl;

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
        telemetryRequestContext.setOauthProvider(OauthProviderLabel.ORACLE_EPM);
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
            req = HttpRequest.newBuilder(URI.create(userinfoUrl))
                    .timeout(HTTP_TIMEOUT)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                    .GET()
                    .build();
        } catch (IllegalArgumentException e) {
            log.error("Oracle EPM synthetic userinfo: invalid userinfo URL: {}", userinfoUrl, e);
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "invalid_url",
                    Response.status(Response.Status.BAD_GATEWAY).build());
        }

        HttpResponse<String> resp;
        try {
            resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            log.warn("Oracle EPM synthetic userinfo: I/O error calling upstream userinfo", e);
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "io_error",
                    Response.status(Response.Status.BAD_GATEWAY).build());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Oracle EPM synthetic userinfo: interrupted calling upstream userinfo", e);
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "interrupted",
                    Response.status(Response.Status.BAD_GATEWAY).build());
        }

        int status = resp.statusCode();
        if (status == 401 || status == 403) {
            return finishUserinfo(startNanos, false, 401, "invalid_token", "upstream_unauthorized",
                    Response.status(Response.Status.UNAUTHORIZED).build());
        }
        if (status < 200 || status >= 300) {
            log.warn("Oracle EPM synthetic userinfo: upstream returned status={} body_len={}",
                    status, resp.body() != null ? resp.body().length() : 0);
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "upstream_status_" + status,
                    Response.status(Response.Status.BAD_GATEWAY).build());
        }

        // Pass through the Oracle response as-is, but route it through Jackson so the response
        // is canonical JSON (Quarkus enforces application/json on its UserInfo binding) and
        // project an `email` claim so BaseResource.getUsername (which only strips `@domain` when
        // the claim NAME contains "email") works against Oracle's email-shaped sub.
        LinkedHashMap<String, Object> body;
        try {
            JsonNode root = OBJECT_MAPPER.readTree(resp.body() != null ? resp.body() : "{}");
            if (!root.isObject()) {
                log.warn("Oracle EPM synthetic userinfo: upstream returned non-object JSON");
                return finishUserinfo(startNanos, false, 502, "bad_gateway", "non_object",
                        Response.status(Response.Status.BAD_GATEWAY).build());
            }
            // Iterate stable JSON-object iteration order (Jackson preserves source order for
            // ObjectNode by default); LinkedHashMap keeps it deterministic on the wire.
            body = OBJECT_MAPPER.convertValue(root, ORDERED_MAP_TYPE);
        } catch (Exception e) {
            log.warn("Oracle EPM synthetic userinfo: failed to parse upstream response", e);
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "parse_failed",
                    Response.status(Response.Status.BAD_GATEWAY).build());
        }

        // Defensive: Oracle's userinfo always returns at least `sub`. If it's missing, downstream
        // BaseResource.getUsername would fall back to subject lookup which is the wrong key.
        Object sub = body.get("sub");
        if (sub == null || sub.toString().isEmpty()) {
            log.warn("Oracle EPM synthetic userinfo: upstream response missing sub claim");
            return finishUserinfo(startNanos, false, 502, "bad_gateway", "missing_sub",
                    Response.status(Response.Status.BAD_GATEWAY).build());
        }

        // Project a top-level `email` claim from preferred_username / sub if Oracle did not
        // include one. We bind the OIDC tenant to claim=email (BaseResource.getUsername strips
        // `@domain` only when the claim name contains "email"), so this projection ensures the
        // stored lookupKey is the short id (e.g. "testuser" for "testuser@example.com") matching
        // every other provider that uses email-shaped claims.
        if (body.get("email") == null || body.get("email").toString().isEmpty()) {
            Object preferredUsername = body.get("preferred_username");
            String email = preferredUsername != null && !preferredUsername.toString().isEmpty()
                    ? preferredUsername.toString() : sub.toString();
            body.put("email", email);
        }

        return finishUserinfo(startNanos, true, 200, null, null, Response.ok(body).build());
    }

    private Response finishUserinfo(long startNanos, boolean success, int httpStatus,
            String errorType, String userinfoFailureReason, Response response) {
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        oauthProxyMetrics.recordUserinfoDuration(OauthProviderLabel.ORACLE_EPM, success,
                userinfoFailureReason, seconds);
        oauthProxyMetrics.recordUserinfoRequest(OauthProviderLabel.ORACLE_EPM, success, httpStatus,
                errorType, userinfoFailureReason);
        return response;
    }
}
