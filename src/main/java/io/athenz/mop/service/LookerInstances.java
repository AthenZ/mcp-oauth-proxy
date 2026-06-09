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

import io.athenz.mop.telemetry.OauthProviderLabel;
import java.util.Set;

/**
 * Canonical set of Looker MCP instance provider ids and helpers shared by the Looker
 * token-exchange / refresh / callback wiring.
 *
 * <p>Each Looker deployment is modeled as its own provider id (e.g. {@code looker-ouryahoo},
 * {@code looker-enterprise}) so its L2 canonical upstream-RT row and the bare
 * {@code (lookupKey, provider)} row in {@code mcp-oauth-proxy-tokens} are keyed per instance and
 * never collide across instances for the same user. The instances differ only by host, client_id,
 * and resource/MCP URL; the OAuth shape is identical (public PKCE, S256, AT ~1h, non-rotating RT).
 *
 * <p>The token endpoint for every Looker instance is {@code https://<host>/api/token}; the host is
 * carried by the {@code server.token-exchange.remote-servers.endpoints[?name=<provider>].endpoint}
 * value resolved via {@link ConfigService#getRemoteServerEndpoint(String)}.
 */
public final class LookerInstances {

    /** Looker token endpoint path appended to the per-instance host. */
    public static final String TOKEN_PATH = "/api/token";

    /** All Looker instance provider ids. */
    public static final Set<String> PROVIDERS = Set.of(
            OauthProviderLabel.LOOKER_MAW,
            OauthProviderLabel.LOOKER_OURYAHOO,
            OauthProviderLabel.LOOKER_FINANCE,
            OauthProviderLabel.LOOKER_HR,
            OauthProviderLabel.LOOKER_SEARCH,
            OauthProviderLabel.LOOKER_ENTERPRISE,
            OauthProviderLabel.LOOKER_PRISM_MAIL);

    private LookerInstances() {
    }

    /** True when {@code provider} is one of the Looker instance ids. */
    public static boolean isLooker(String provider) {
        return provider != null && !provider.isEmpty() && PROVIDERS.contains(provider);
    }

    /**
     * Derives the Looker token endpoint ({@code https://<host>/api/token}) from a configured
     * per-instance host base (e.g. {@code https://looker.ouryahoo.com}). Returns {@code null}
     * when the base is missing/blank so callers fail loudly rather than calling a bogus URL.
     */
    public static String tokenEndpoint(String endpointBase) {
        if (endpointBase == null || endpointBase.isBlank()) {
            return null;
        }
        String base = endpointBase.trim();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return base + TOKEN_PATH;
    }
}
