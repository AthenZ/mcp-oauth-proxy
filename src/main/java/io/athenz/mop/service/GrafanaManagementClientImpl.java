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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.athenz.mop.model.grafana.GrafanaMintTokenRequest;
import io.athenz.mop.model.grafana.GrafanaMintTokenResponse;
import io.athenz.mop.model.grafana.GrafanaTokenInfo;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class GrafanaManagementClientImpl implements GrafanaManagementClient {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private final ObjectMapper objectMapper;
    private final GrafanaHttpExecutor grafanaHttpExecutor;

    @Inject
    public GrafanaManagementClientImpl(ObjectMapper objectMapper, GrafanaHttpExecutor grafanaHttpExecutor) {
        this.objectMapper = objectMapper;
        this.grafanaHttpExecutor = grafanaHttpExecutor;
    }

    @Override
    public String mintToken(String baseUrl, String saId, String adminBearer, String tokenName, long secondsToLive) {
        String url = tokensUrl(baseUrl, saId);
        if (url == null || StringUtils.isBlank(adminBearer) || StringUtils.isBlank(tokenName)) {
            return null;
        }
        try {
            String body = objectMapper.writeValueAsString(new GrafanaMintTokenRequest(tokenName, secondsToLive));
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", "Bearer " + adminBearer)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> resp = grafanaHttpExecutor.send(req);
            int status = resp.statusCode();
            if (status < 200 || status >= 300) {
                log.warn("Grafana mintToken failed: status={} name={}", status, tokenName);
                return null;
            }
            GrafanaMintTokenResponse parsed = objectMapper.readValue(resp.body(), GrafanaMintTokenResponse.class);
            if (parsed == null || StringUtils.isBlank(parsed.key())) {
                log.warn("Grafana mintToken returned empty key name={}", tokenName);
                return null;
            }
            return parsed.key();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Grafana mintToken error: {}", e.getMessage());
            return null;
        } catch (IOException e) {
            log.warn("Grafana mintToken error: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public List<GrafanaTokenInfo> listTokens(String baseUrl, String saId, String adminBearer) {
        String url = tokensUrl(baseUrl, saId);
        if (url == null || StringUtils.isBlank(adminBearer)) {
            return List.of();
        }
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", "Bearer " + adminBearer)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<String> resp = grafanaHttpExecutor.send(req);
            int status = resp.statusCode();
            if (status < 200 || status >= 300) {
                log.warn("Grafana listTokens failed: status={}", status);
                return List.of();
            }
            List<GrafanaTokenInfo> parsed =
                    objectMapper.readValue(resp.body(), new TypeReference<List<GrafanaTokenInfo>>() {});
            return parsed != null ? parsed : List.of();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Grafana listTokens error: {}", e.getMessage());
            return List.of();
        } catch (IOException e) {
            log.warn("Grafana listTokens error: {}", e.getMessage());
            return List.of();
        }
    }

    @Override
    public boolean deleteToken(String baseUrl, String saId, String adminBearer, long tokenId) {
        String base = tokensUrl(baseUrl, saId);
        if (base == null || StringUtils.isBlank(adminBearer)) {
            return false;
        }
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(base + "/" + tokenId))
                    .header("Authorization", "Bearer " + adminBearer)
                    .header("Accept", "application/json")
                    .DELETE()
                    .build();
            HttpResponse<String> resp = grafanaHttpExecutor.send(req);
            int status = resp.statusCode();
            if (status < 200 || status >= 300) {
                log.warn("Grafana deleteToken failed: status={} id={}", status, tokenId);
                return false;
            }
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Grafana deleteToken error: {}", e.getMessage());
            return false;
        } catch (IOException e) {
            log.warn("Grafana deleteToken error: {}", e.getMessage());
            return false;
        }
    }

    static String tokensUrl(String baseUrl, String saId) {
        String base = normalizeBase(baseUrl);
        if (base == null || StringUtils.isBlank(saId)) {
            return null;
        }
        return base + "/api/serviceaccounts/" + saId.trim() + "/tokens";
    }

    static String normalizeBase(String baseUrl) {
        if (StringUtils.isBlank(baseUrl)) {
            return null;
        }
        String t = baseUrl.trim();
        while (t.endsWith("/")) {
            t = t.substring(0, t.length() - 1);
        }
        return t;
    }
}
