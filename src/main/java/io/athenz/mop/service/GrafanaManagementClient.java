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

import io.athenz.mop.model.grafana.GrafanaTokenInfo;
import java.util.List;

/**
 * Grafana Cloud service-account management API.
 * All calls target {@code {baseUrl}/api/serviceaccounts/{saId}/tokens[/{tokenId}]}.
 */
public interface GrafanaManagementClient {

    /**
     * Creates a new service-account token.
     *
     * @return the {@code key} value from the response, or {@code null} on any failure (non-2xx, I/O, parse).
     */
    String mintToken(String baseUrl, String saId, String adminBearer, String tokenName, long secondsToLive);

    /**
     * Lists all tokens on the service account. Returns an empty list on any failure; callers should not rely on
     * exceptions to detect errors.
     */
    List<GrafanaTokenInfo> listTokens(String baseUrl, String saId, String adminBearer);

    /**
     * Deletes the token with the given numeric id.
     *
     * @return {@code true} iff Grafana responded with a 2xx status.
     */
    boolean deleteToken(String baseUrl, String saId, String adminBearer, long tokenId);
}
