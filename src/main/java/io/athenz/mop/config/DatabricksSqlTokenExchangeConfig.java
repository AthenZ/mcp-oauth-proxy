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

/**
 * Databricks SQL MCP: Okta ID token exchange at each workspace {@code POST /oidc/v1/token}.
 */
@ConfigMapping(prefix = "server.token-exchange.databricks-sql")
public interface DatabricksSqlTokenExchangeConfig {

    @WithName("workspace-host-template")
    @WithDefault("https://%s.cloud.databricks.com")
    String workspaceHostTemplate();

    /** Path prefix before the workspace segment; segment is followed by {@code /mcp}. */
    @WithName("resource-path-prefix")
    @WithDefault("/v1/databricks-sql/")
    String resourcePathPrefix();

    /** Regex applied only to the workspace path segment (e.g. {@code dbc-…} deployment id). */
    @WithName("workspace-segment-pattern")
    @WithDefault("^dbc-[a-zA-Z0-9.-]+$")
    String workspaceSegmentPattern();

    @WithName("oauth-scope")
    @WithDefault("sql")
    String oauthScope();
}
