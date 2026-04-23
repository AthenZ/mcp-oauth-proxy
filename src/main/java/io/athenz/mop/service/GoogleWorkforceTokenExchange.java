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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.athenz.mop.config.GoogleWorkforceTokenExchangeConfig;
import io.athenz.mop.config.GoogleWorkforceTokenExchangeConfig.ServiceConfig;
import io.athenz.mop.model.GcpExchangeTokenRequest;
import io.athenz.mop.model.GcpExchangeTokenResponse;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.UpstreamHttpCallLabels;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Exchanges Athenz id_token for Google STS access token via Workforce Pools.
 * STS only; no IAM Credentials API and no service account.
 * Uses the same request/response shape as ZTS GcpTokenProvider.getExchangeToken().
 * Scopes are selected per audience from {@code server.token-exchange.google-workforce.services.<audience>.scopes}.
 */
@ApplicationScoped
public class GoogleWorkforceTokenExchange {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
    private static final String REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    private static final String FALLBACK_STS_USER_PROJECT = "core-mcpworkspace-p";

    @Inject
    GoogleWorkforceTokenExchangeConfig config;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Exchange Athenz id_token for Google STS access token.
     *
     * @param athenzIdToken raw Athenz ID token (JWT)
     * @param audience      resource audience (must match a key under {@code google-workforce.services})
     * @return STS access token string, or null on failure
     */
    public String exchange(String athenzIdToken, String audience) {
        return exchange(athenzIdToken, audience, null);
    }

    /**
     * Same as {@link #exchange(String, String)}; {@code userProject} is sent as STS {@code userProject}
     * when non-blank, otherwise the built-in fallback project id is used.
     */
    public String exchange(String athenzIdToken, String audience, String userProject) {
        if (athenzIdToken == null || athenzIdToken.isBlank() || audience == null || audience.isBlank()) {
            return null;
        }
        Map<String, ServiceConfig> services = config.services();
        ServiceConfig serviceConfig = services != null ? services.get(audience) : null;
        if (serviceConfig == null) {
            log.warn("Google Workforce exchange: no service config for audience: {}", audience);
            return null;
        }
        List<String> scopeList = serviceConfig.scopes();
        if (scopeList == null || scopeList.isEmpty()) {
            log.warn("Google Workforce exchange: no scopes configured for audience: {}", audience);
            return null;
        }
        String scope = String.join(" ", scopeList);
        try {
            GcpExchangeTokenRequest exchangeTokenRequest = new GcpExchangeTokenRequest();
            exchangeTokenRequest.setGrantType(GRANT_TYPE);
            exchangeTokenRequest.setAudience(config.audience());
            exchangeTokenRequest.setScope(scope);
            exchangeTokenRequest.setRequestedTokenType(REQUESTED_TOKEN_TYPE);
            exchangeTokenRequest.setSubjectToken(athenzIdToken);
            exchangeTokenRequest.setSubjectTokenType(SUBJECT_TOKEN_TYPE);
            String billingProject = (userProject != null && !userProject.isBlank())
                    ? userProject
                    : FALLBACK_STS_USER_PROJECT;
            exchangeTokenRequest.setOptions(objectMapper.writeValueAsString(Map.of("userProject", billingProject)));

            String json = objectMapper.writeValueAsString(exchangeTokenRequest);

            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(config.stsTokenUrl()))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                    .build();

            long startNanos = System.nanoTime();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
            String providerLabel = OauthProviderLabel.normalize(audience);
            oauthProxyMetrics.recordUpstreamRequest(providerLabel, UpstreamHttpCallLabels.ENDPOINT_GOOGLE_STS, response.statusCode(),
                    metricsRegionProvider.primaryRegion(), seconds);

            if (response.statusCode() != 200) {
                log.warn("Google STS token-exchange failed: status={} body={}", response.statusCode(), response.body());
                return null;
            }

            GcpExchangeTokenResponse exchangeTokenResponse = objectMapper.readValue(response.body(), GcpExchangeTokenResponse.class);
            return exchangeTokenResponse != null ? exchangeTokenResponse.getAccessToken() : null;
        } catch (Exception e) {
            log.warn("Google STS token-exchange error: {}", e.getMessage());
            return null;
        }
    }
}
