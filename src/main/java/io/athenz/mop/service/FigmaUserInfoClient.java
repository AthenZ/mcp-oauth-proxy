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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Calls {@code GET https://api.figma.com/v1/me} with a Figma access token and parses the
 * response into a {@link FigmaUser}.
 *
 * <p>Used by the custom Figma callback resource to resolve the authenticated user's email
 * (which becomes the MoP {@code lookupKey} after {@code @domain} stripping). This replaces
 * the Quarkus {@code UserInfo} bean that the L0 (stock-tenant) Figma flow relied on; we own
 * this call now because Quarkus does not own the upstream OAuth flow for the {@code figma}
 * provider — see {@link io.athenz.mop.resource.FigmaResource} for the rationale.
 *
 * <p>The Figma {@code /v1/me} response shape (as observed in the Figma API docs) is:
 * <pre>
 * {
 *   "id": "&lt;numeric user id&gt;",
 *   "handle": "&lt;handle&gt;",
 *   "img_url": "...",
 *   "email": "&lt;user@example.com&gt;"
 * }
 * </pre>
 */
@ApplicationScoped
public class FigmaUserInfoClient {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    static final String FIGMA_USERINFO_URI = "https://api.figma.com/v1/me";
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);

    private final HttpClient httpClient;

    @Inject
    ObjectMapper objectMapper;

    public FigmaUserInfoClient() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(HTTP_TIMEOUT)
                .build();
    }

    /**
     * Fetches the authenticated user's profile from {@code /v1/me}.
     *
     * @param accessToken opaque Figma bearer token (starts with {@code figu_}).
     * @return the parsed user profile.
     * @throws FigmaUserInfoException on any non-2xx response, parse failure, or transport error.
     */
    public FigmaUser fetchMe(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new FigmaUserInfoException("access token is empty");
        }
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(FIGMA_USERINFO_URI))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .timeout(HTTP_TIMEOUT)
                .GET()
                .build();
        try {
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() / 100 != 2) {
                log.error("Figma /v1/me returned status={} body={}", resp.statusCode(), resp.body());
                throw new FigmaUserInfoException(
                        "Figma /v1/me returned non-2xx: status=" + resp.statusCode());
            }
            return objectMapper.readValue(resp.body(), FigmaUser.class);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FigmaUserInfoException("Figma /v1/me interrupted", e);
        } catch (IOException e) {
            throw new FigmaUserInfoException("Figma /v1/me transport failure: " + e.getMessage(), e);
        }
    }

    /** Subset of the Figma {@code /v1/me} response we consume. Unknown fields ignored. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record FigmaUser(
            @JsonProperty("id") String id,
            @JsonProperty("email") String email,
            @JsonProperty("handle") String handle
    ) {
    }

    /** Thrown for any failure resolving Figma user info; callers map to a 500 callback response. */
    public static class FigmaUserInfoException extends RuntimeException {
        public FigmaUserInfoException(String message) {
            super(message);
        }

        public FigmaUserInfoException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
