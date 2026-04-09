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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.athenz.mop.client.ZmsAssumeRoleResourceClient;
import io.athenz.mop.model.GcpZmsPrincipalScope;
import io.athenz.mop.model.ZmsResourceAssertion;
import io.athenz.mop.model.ZmsResourcePrincipalEntry;
import io.athenz.mop.model.ZmsResourceResponse;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds GCP workforce scope and billing project from ZMS {@code GET /zms/v1/resource} with
 * {@code action=gcp.assume_role}, filtering assertions to the configured short role name(s)
 * (e.g. {@code gcp.fed.mcp.user}, or comma-separated values such as
 * {@code gcp.fed.mcp.user, gcp.fed.mcp.monitoring.user}). An assertion matches if its {@code role}
 * contains {@code role.}<em>shortName</em> for any entry. Uses a direct HTTPS call with mTLS; the ZMS Java client
 * does not support this endpoint.
 */
@ApplicationScoped
public class ZMSServiceImpl {

    private static final Logger log = LoggerFactory.getLogger(ZMSServiceImpl.class);

    private static final Pattern GCP_PROJECT_RESOURCE = Pattern.compile("^projects/([^/]+)/");

    @Inject
    ZmsAssumeRoleResourceClient zmsAssumeRoleResourceClient;

    @ConfigProperty(name = "server.token-exchange.gcp-role-name", defaultValue = "gcp.fed.mcp.user")
    String defaultGcpRoleName;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Resolves Athenz scope and default GCP billing project for the principal via ZMS resource API.
     * Assertions must match {@code action=gcp.assume_role}, {@code effect=ALLOW}, and
     * {@code role} containing {@code role.shortName} for at least one configured short name (e.g.
     * {@code msd.stage:role.gcp.fed.mcp.user} for short name {@code gcp.fed.mcp.user}).
     * Scope parts are the full {@code role} strings from matching assertions, plus {@code openid}.
     * The first matching assertion whose {@code resource} is {@code projects/projectId/roles/...}
     * supplies {@link GcpZmsPrincipalScope#defaultBillingProject()}.
     *
     * @param roleMember full Athenz principal name (e.g. user.shortid)
     * @param roleName   short role name(s), comma-separated and trimmed (e.g. {@code gcp.fed.mcp.user, gcp.fed.mcp.monitoring.user}),
     *                   or null/blank to use config default (which may also be comma-separated)
     * @return never null; on failure or empty matches, scope is {@code openid} and billing project is null
     */
    public GcpZmsPrincipalScope getScopeForPrincipal(String roleMember, String roleName) {
        String raw = roleName != null && !roleName.isBlank() ? roleName : defaultGcpRoleName;
        List<String> roleMarkers = roleMarkersFromRaw(raw);
        if (roleMarkers.isEmpty()) {
            return new GcpZmsPrincipalScope("openid", null);
        }
        try {
            String json = zmsAssumeRoleResourceClient.getAssumeRoleResourceJson(roleMember);
            if (json == null || json.isBlank()) {
                return new GcpZmsPrincipalScope("openid", null);
            }
            return parseAssumeRoleResourceResponse(json, roleMarkers);
        } catch (Exception e) {
            log.warn("ZMS assume_role resource parse failed: {}", e.getMessage());
            return new GcpZmsPrincipalScope("openid", null);
        }
    }

    static List<String> roleMarkersFromRaw(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        List<String> markers = new ArrayList<>();
        for (String part : raw.split(",")) {
            String shortName = part.trim();
            if (!shortName.isEmpty()) {
                markers.add("role." + shortName);
            }
        }
        return markers;
    }

    GcpZmsPrincipalScope parseAssumeRoleResourceResponse(String json, List<String> roleMarkers) throws Exception {
        ZmsResourceResponse root = objectMapper.readValue(json, ZmsResourceResponse.class);
        List<ZmsResourcePrincipalEntry> resources = root.getResources();
        if (resources == null || resources.isEmpty()) {
            return new GcpZmsPrincipalScope("openid", null);
        }
        Set<String> scopeRoles = new LinkedHashSet<>();
        String billingProject = null;
        for (ZmsResourcePrincipalEntry res : resources) {
            List<ZmsResourceAssertion> assertions = res.getAssertions();
            if (assertions == null || assertions.isEmpty()) {
                continue;
            }
            for (ZmsResourceAssertion assertion : assertions) {
                if (!matchesAssumeRoleAssertion(assertion, roleMarkers)) {
                    continue;
                }
                String fullRole = assertion.getRole();
                if (fullRole != null && !fullRole.isBlank()) {
                    scopeRoles.add(fullRole);
                }
                if (billingProject == null) {
                    String project = extractGcpProjectId(assertion.getResource());
                    if (project != null && !project.isBlank()) {
                        billingProject = project;
                    }
                }
            }
        }
        if (scopeRoles.isEmpty()) {
            return new GcpZmsPrincipalScope("openid", null);
        }
        ArrayList<String> parts = new ArrayList<>(scopeRoles);
        parts.add("openid");
        return new GcpZmsPrincipalScope(String.join(" ", parts), billingProject);
    }

    private static boolean matchesAssumeRoleAssertion(ZmsResourceAssertion assertion, List<String> roleMarkers) {
        String assertionRole = assertion.getRole();
        if (assertionRole == null || roleMarkers.isEmpty()) {
            return false;
        }
        boolean roleMatches = false;
        for (String marker : roleMarkers) {
            if (assertionRole.contains(marker)) {
                roleMatches = true;
                break;
            }
        }
        if (!roleMatches) {
            return false;
        }
        if (!ZmsAssumeRoleResourceClient.ASSUME_ROLE_ACTION.equals(assertion.getAction())) {
            return false;
        }
        return "ALLOW".equals(assertion.getEffect());
    }

    static String extractGcpProjectId(String resource) {
        if (resource == null || resource.isBlank()) {
            return null;
        }
        Matcher m = GCP_PROJECT_RESOURCE.matcher(resource);
        return m.find() ? m.group(1) : null;
    }
}
