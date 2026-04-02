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

import java.io.IOException;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.UpstreamHttpCallLabels;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 * Single implementation of TokenClient used for all providers (Okta, Google, GitHub, etc.).
 * Sets Accept: application/json so providers that require it (e.g. GitHub) return JSON.
 */
@ApplicationScoped
public class DefaultExchangeTokenClient implements TokenClient {

    @Inject
    OauthProxyMetrics metrics;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    @Override
    public TokenResponse execute(TokenRequest request) throws IOException, ParseException {
        long startNanos = System.nanoTime();
        HTTPRequest httpRequest = request.toHTTPRequest();
        httpRequest.setHeader("Accept", "application/json");
        HTTPResponse httpResponse = httpRequest.send();
        TokenResponse tokenResponse = TokenResponse.parse(httpResponse);
        String p = UpstreamHttpCallLabels.oauthProvider();
        String ep = UpstreamHttpCallLabels.upstreamEndpoint();
        if (p != null && ep != null) {
            double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
            metrics.recordUpstreamRequest(p, ep, httpResponse.getStatusCode(),
                    metricsRegionProvider.primaryRegion(), seconds);
        }
        return tokenResponse;
    }
}
