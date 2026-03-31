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
package io.athenz.mop.client;

import io.athenz.mop.tls.SslContextProducer;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Direct ZMS HTTP client for {@code GET /zms/v1/resource?principal=...&action=gcp.assume_role} with mTLS.
 * The Athenz ZMS Java client does not expose this API.
 */
@ApplicationScoped
public class ZmsAssumeRoleResourceClient {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    public static final String ASSUME_ROLE_ACTION = "gcp.assume_role";

    @Inject
    SslContextProducer sslContextProducer;

    @ConfigProperty(name = "server.athenz.zms.endpoint")
    String zmsEndpoint;

    /**
     * @return response body JSON, or null on non-200 or error
     */
    public String getAssumeRoleResourceJson(String principal) {
        if (principal == null || principal.isBlank()) {
            return null;
        }
        try {
            String url = buildAssumeRoleResourceUrl(zmsEndpoint, principal);
            HttpClient client = HttpClient.newBuilder().sslContext(sslContextProducer.get()).build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) {
                log.warn("ZMS resource API failed: status={} body={}", response.statusCode(), response.body());
                return null;
            }
            return response.body();
        } catch (Exception e) {
            log.warn("ZMS resource API error: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Builds {@code GET .../zms/v1/resource?principal=...&action=gcp.assume_role}. If the configured
     * endpoint already ends with {@code /zms/v1}, only {@code /resource} is appended.
     */
    public static String buildAssumeRoleResourceUrl(String zmsEndpoint, String principal) {
        String base = trimTrailingSlash(zmsEndpoint);
        String resourceBase = base.endsWith("/zms/v1") ? base + "/resource" : base + "/zms/v1/resource";
        String query = "principal=" + URLEncoder.encode(principal, StandardCharsets.UTF_8) + "&action=" + ASSUME_ROLE_ACTION;
        return resourceBase + "?" + query;
    }

    private static String trimTrailingSlash(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '/') {
            end--;
        }
        return end == s.length() ? s : s.substring(0, end);
    }
}
