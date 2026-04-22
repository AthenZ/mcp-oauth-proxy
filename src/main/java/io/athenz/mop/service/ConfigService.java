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

import io.athenz.mop.config.ResourceConfig;
import io.athenz.mop.config.TokenExchangeServersConfig;
import io.athenz.mop.model.ResourceMeta;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class ConfigService {

    @Inject
    ResourceConfig resourceConfig;

    @Inject
    TokenExchangeServersConfig tokenExchangeServersConfig;

    @ConfigProperty(name = "server.token-exchange.idp")
    String defaultIDP;

    /** Exact URI → metadata (populated at init and when a pattern first matches). */
    Map<String, ResourceMeta> resourceMetaMap = new HashMap<>();

    /** Glob-style patterns from {@code resourceMapping} entries whose {@code uri} contains {@code *}. */
    List<PatternEntry> resourcePatterns = new ArrayList<>();

    Map<String, String> remoteServerMap = new HashMap<>();

    Map<String, String> remoteServerUsernameClaimMap = new HashMap<>();

    Map<String, String> remoteServerServiceAccountIdMap = new HashMap<>();

    @PostConstruct
    void init() {
        for (ResourceConfig.ResourceMapping rm : resourceConfig.resourceMapping()) {
            ResourceMeta meta = new ResourceMeta(
                    rm.scopes(),
                    rm.domain(),
                    rm.token().idp(),
                    rm.token().as(),
                    rm.token().jag().enabled(),
                    rm.token().jag().issuer(),
                    rm.token().audience().orElse(null));
            if (isWildcardUri(rm.uri())) {
                resourcePatterns.add(new PatternEntry(globToRegex(rm.uri()), meta, rm.uri()));
            } else {
                resourceMetaMap.put(rm.uri(), meta);
            }
        }
        for (TokenExchangeServersConfig.RemoteServer rs : tokenExchangeServersConfig.endpoints()) {
            remoteServerMap.put(rs.name(), rs.endpoint());
            remoteServerUsernameClaimMap.put(rs.name(), rs.usernameClaim());
            rs.serviceAccountId().ifPresent(saId -> remoteServerServiceAccountIdMap.put(rs.name(), saId));
        }
    }

    public String getRemoteServerEndpoint(String key) {
        return remoteServerMap.get(key);
    }

    public String getRemoteServerUsernameClaim(String key) {
        return remoteServerUsernameClaimMap.get(key);
    }

    /**
     * @return provider-specific service-account id configured on the {@code remote-servers.endpoints[?name=key]}
     * entry, or {@code null} when not set. Used by providers like Grafana whose token API is scoped to a
     * service-account id.
     */
    public String getRemoteServerServiceAccountId(String key) {
        return remoteServerServiceAccountIdMap.get(key);
    }

    public ResourceMeta getResourceMeta(String key) {
        ResourceMeta meta = resourceMetaMap.get(key);
        if (meta != null) {
            return meta;
        }
        for (PatternEntry entry : resourcePatterns) {
            if (entry.pattern.matcher(key).matches()) {
                resourceMetaMap.put(key, entry.meta);
                return entry.meta;
            }
        }
        return null;
    }

    public String getDefaultIDP() {
        return defaultIDP;
    }

    static boolean isWildcardUri(String uri) {
        return uri != null && uri.contains("*");
    }

    /**
     * Turn a single-segment glob ({@code *} → {@code [^/]*}) into a compiled {@link Pattern}.
     * Example: {@code https://<host>/v1/databricks-sql/<workspace-id>/mcp}
     * {@literal *}{@code /mcp} matches a concrete workspace id segment (e.g. {@code dbc-44743f95-b8ca}).
     */
    static Pattern globToRegex(String glob) {
        String regex = Pattern.quote(glob).replace("*", "\\E[^/]*\\Q");
        return Pattern.compile(regex);
    }

    static final class PatternEntry {
        final Pattern pattern;
        final ResourceMeta meta;
        final String originalGlob;

        PatternEntry(Pattern pattern, ResourceMeta meta, String originalGlob) {
            this.pattern = pattern;
            this.meta = meta;
            this.originalGlob = originalGlob;
        }
    }
}
