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
package io.athenz.mop.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithName;
import java.util.Collections;
import java.util.Map;

/**
 * Per-instance Looker configuration. Looker instances are public PKCE clients
 * ({@code token_endpoint_auth_method=none}) so there is <strong>no client secret</strong> — the
 * only per-instance value the upstream refresh path needs is the {@code client_id}.
 *
 * <p>Keys are the Looker instance provider ids (e.g. {@code looker-ouryahoo},
 * {@code looker-enterprise}); see {@link io.athenz.mop.service.LookerInstances}.
 *
 * <p>Example values.yaml:
 * <pre>
 *   server:
 *     token-exchange:
 *       looker:
 *         client-ids:
 *           looker-ouryahoo:  "looker-ouryahoo-mcp-local-65191ca3-..."
 *           looker-enterprise: "looker-enterprise-mcp-local-73afae53-..."
 * </pre>
 */
@ConfigMapping(prefix = "server.token-exchange.looker")
public interface LookerConfig {

    /** Map of Looker instance provider id -&gt; public OAuth client_id. */
    @WithName("client-ids")
    Map<String, String> clientIds();

    /** Returns the configured client_id for {@code provider}, or {@code null} when unset. */
    default String clientId(String provider) {
        Map<String, String> map = clientIds();
        if (map == null || provider == null) {
            return null;
        }
        return map.get(provider);
    }

    /** Never-null view of the client-id map. */
    default Map<String, String> safeClientIds() {
        Map<String, String> map = clientIds();
        return map == null ? Collections.emptyMap() : map;
    }
}
