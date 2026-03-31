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
 * {@code action=gcp.assume_role}, filtering assertions to the configured short role name
 * (e.g. {@code gcp.fed.mcp.user}). Uses a direct HTTPS call with mTLS; the ZMS Java client
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
     * {@code role} containing the configured short name as {@code role.shortName} (e.g.
     * {@code msd.stage:role.gcp.fed.mcp.user} for short name {@code gcp.fed.mcp.user}).
     * Scope parts are the full {@code role} strings from matching assertions, plus {@code openid}.
     * The first matching assertion whose {@code resource} is {@code projects/projectId/roles/...}
     * supplies {@link GcpZmsPrincipalScope#defaultBillingProject()}.
     *
     * @param roleMember full Athenz principal name (e.g. user.shortid)
     * @param roleName   short role name (e.g. gcp.fed.mcp.user), or null to use config default
     * @return never null; on failure or empty matches, scope is {@code openid} and billing project is null
     */
    public GcpZmsPrincipalScope getScopeForPrincipal(String roleMember, String roleName) {
        String shortRole = roleName != null && !roleName.isBlank() ? roleName : defaultGcpRoleName;
        String roleMarker = "role." + shortRole;
        try {
            String json = zmsAssumeRoleResourceClient.getAssumeRoleResourceJson(roleMember);
            if (json == null || json.isBlank()) {
                return new GcpZmsPrincipalScope("openid", null);
            }
            return parseAssumeRoleResourceResponse(json, roleMarker);
        } catch (Exception e) {
            log.warn("ZMS assume_role resource parse failed: {}", e.getMessage());
            return new GcpZmsPrincipalScope("openid", null);
        }
    }

    GcpZmsPrincipalScope parseAssumeRoleResourceResponse(String json, String roleMarker) throws Exception {
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
            for (ZmsResourceAssertion a : assertions) {
                if (!matchesAssumeRoleAssertion(a, roleMarker)) {
                    continue;
                }
                String fullRole = a.getRole();
                if (fullRole != null && !fullRole.isBlank()) {
                    scopeRoles.add(fullRole);
                }
                if (billingProject == null) {
                    String project = extractGcpProjectId(a.getResource());
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

    private static boolean matchesAssumeRoleAssertion(ZmsResourceAssertion a, String roleMarker) {
        String assertionRole = a.getRole();
        if (assertionRole == null || !assertionRole.contains(roleMarker)) {
            return false;
        }
        if (!ZmsAssumeRoleResourceClient.ASSUME_ROLE_ACTION.equals(a.getAction())) {
            return false;
        }
        return "ALLOW".equals(a.getEffect());
    }

    static String extractGcpProjectId(String resource) {
        if (resource == null || resource.isBlank()) {
            return null;
        }
        Matcher m = GCP_PROJECT_RESOURCE.matcher(resource);
        return m.find() ? m.group(1) : null;
    }
}
