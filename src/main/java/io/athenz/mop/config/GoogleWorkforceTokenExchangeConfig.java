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
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Generic per-service Google Workforce Pools configuration. Each entry under {@code services}
 * is keyed by MCP audience (e.g. {@code google-monitoring}, {@code google-logging},
 * {@code google-bigquery}) and carries its own {@code scopes} and {@code gcp-role-name}.
 * Adding a new GCP MCP is a pure config change — no new code branch required.
 */
@ConfigMapping(prefix = "server.token-exchange.google-workforce")
public interface GoogleWorkforceTokenExchangeConfig {

    @WithName("sts-token-url")
    String stsTokenUrl();

    String audience();

    Map<String, ServiceConfig> services();

    interface ServiceConfig {
        List<String> scopes();

        @WithName("gcp-role-name")
        Optional<String> gcpRoleName();
    }
}
