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
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;

@ConfigMapping(prefix = "server.token-exchange.grafana")
public interface GrafanaTokenExchangeConfig {

    /**
     * Credentials map key for the Grafana Cloud service-account admin bearer token (must match a key in
     * {@link io.athenz.mop.secret.K8SSecretsProvider#getCredentials}).
     * Use {@code grafana-api-stage} or {@code grafana-api-prod} to match Kubernetes secret data keys in
     * {@code mop-credentials}.
     */
    @WithName("admin-token-secret-key")
    @WithDefault("grafana-api-prod")
    String adminTokenSecretKey();

    /**
     * Prefix for the {@code name} field of minted tokens; the full name is
     * {@code <prefix><short_id>.<unix_ts_seconds>} to guarantee uniqueness across mints for the same user.
     */
    @WithName("token-name-prefix")
    @WithDefault("mcp.")
    String tokenNamePrefix();

    /** TTL (seconds) passed to Grafana's token mint API. */
    @WithName("seconds-to-live")
    @WithDefault("3600")
    long secondsToLive();

    /**
     * Kill-switch for the Grafana token cleaner (CronJob). When {@code false} the cleaner exits cleanly without
     * calling the Grafana API.
     */
    @WithName("cleanup-enabled")
    @WithDefault("true")
    boolean cleanupEnabled();
}
