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
import java.util.List;

@ConfigMapping(prefix = "server.token-exchange.splunk")
public interface SplunkTokenExchangeConfig {

    /**
     * Credentials map key for the Splunk management bearer (must match a key from {@link io.athenz.mop.secret.K8SSecretsProvider#getCredentials}).
     * Use {@code splunk-api-stage} or {@code splunk-api-prod} to match Kubernetes secret data keys in {@code mop-credentials}.
     */
    @WithName("admin-token-secret-key")
    @WithDefault("splunk-api-stage")
    String adminTokenSecretKey();

    @WithName("mirror-user-prefix")
    @WithDefault("mcp.")
    String mirrorUserPrefix();

    /** Audience parameter passed to Splunk token mint API (not MoP resource audience). */
    @WithName("splunk-token-audience")
    @WithDefault("mcp")
    String splunkTokenAudience();

    @WithName("token-expires-on")
    @WithDefault("+1h")
    String tokenExpiresOn();

    /**
     * Baseline Splunk roles always assigned to the mirror user (YAML list); defaults when omitted are {@code yahoo_user}
     * and {@code mcp_user}. The mirror also receives every role returned for the real Splunk account named by the
     * id_token username claim (e.g. {@code short_id}), so the mirror user gets baseline roles plus that account's roles.
     */
    @WithName("allowed-roles")
    @WithDefault("yahoo_user,mcp_user")
    List<String> allowedRoles();
}
