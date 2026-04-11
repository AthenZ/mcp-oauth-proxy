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

import io.athenz.mop.config.DatabricksSqlTokenExchangeConfig;
import java.net.URI;
import java.util.Optional;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;

/**
 * Parses MCP resource URLs for Databricks SQL ({@code .../v1/databricks-sql/<segment>/mcp}),
 * validates the workspace segment, and builds the workspace API host.
 */
public final class DatabricksSqlWorkspaceResolver {

    private DatabricksSqlWorkspaceResolver() {
    }

    /** Resolved workspace: full token URL host and hostname used for storage keys. */
    public record DatabricksSqlWorkspace(String workspaceBaseUrl, String hostname) {}

    /**
     * Extract and validate workspace from {@code resource} URI path, then build
     * {@code https://<deployment>.cloud.databricks.com} (or template equivalent).
     */
    public static Optional<DatabricksSqlWorkspace> resolve(String resource, DatabricksSqlTokenExchangeConfig config) {
        if (StringUtils.isBlank(resource) || config == null) {
            return Optional.empty();
        }
        URI uri;
        try {
            uri = URI.create(resource.trim());
        } catch (Exception e) {
            return Optional.empty();
        }
        String path = uri.getPath();
        if (StringUtils.isBlank(path)) {
            return Optional.empty();
        }
        String prefix = normalizePrefix(config.resourcePathPrefix());
        if (!path.startsWith(prefix)) {
            return Optional.empty();
        }
        String tail = path.substring(prefix.length());
        String suffix = "/mcp";
        if (!tail.endsWith(suffix) || tail.length() <= suffix.length()) {
            return Optional.empty();
        }
        String segment = tail.substring(0, tail.length() - suffix.length());
        if (segment.isEmpty() || segment.indexOf('/') >= 0) {
            return Optional.empty();
        }
        Pattern p;
        try {
            p = Pattern.compile(config.workspaceSegmentPattern());
        } catch (Exception e) {
            return Optional.empty();
        }
        if (!p.matcher(segment).matches()) {
            return Optional.empty();
        }
        String template = config.workspaceHostTemplate();
        if (StringUtils.isBlank(template) || !template.contains("%s")) {
            return Optional.empty();
        }
        String workspaceUrl;
        try {
            workspaceUrl = String.format(template, segment);
        } catch (Exception e) {
            return Optional.empty();
        }
        URI ws;
        try {
            ws = URI.create(workspaceUrl);
        } catch (Exception e) {
            return Optional.empty();
        }
        String host = ws.getHost();
        if (StringUtils.isBlank(host)) {
            return Optional.empty();
        }
        return Optional.of(new DatabricksSqlWorkspace(workspaceUrl, host));
    }

    static String normalizePrefix(String prefix) {
        if (prefix == null || prefix.isEmpty()) {
            return "/";
        }
        String p = prefix.startsWith("/") ? prefix : "/" + prefix;
        return p.endsWith("/") ? p : p + "/";
    }
}
