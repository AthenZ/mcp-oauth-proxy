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

import com.yahoo.athenz.zms.DomainList;
import com.yahoo.athenz.zms.ZMSClient;
import io.athenz.mop.client.ZMSClientProducer;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.ArrayList;
import java.util.List;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the space-separated scope string for ZTS token-exchange from ZMS role discovery.
 * Uses ZMS getDomainListByRole(roleMember, roleName) and returns scope in the form
 * "domain1:role.roleName domain2:role.roleName openid".
 */
@ApplicationScoped
public class ZMSServiceImpl {

    private static final Logger log = LoggerFactory.getLogger(ZMSServiceImpl.class);

    @Inject
    ZMSClientProducer zmsClientProducer;

    @ConfigProperty(name = "server.token-exchange.gcp-role-name", defaultValue = "gcp.fed.mcp.user")
    String defaultGcpRoleName;

    /**
     * Get the scope string for Athenz ID token exchange for the given principal.
     * Calls ZMS getDomainListByRole(roleMember, roleName), then for each domain returned
     * adds "domain:role.roleName" to the list, joins with space and appends " openid".
     * <p>
     * The role member must be the Athenz principal name in the form {@code user.<shortid>},
     * where {@code shortid} is the value of the {@code shortid} claim from the Okta id_token
     * (not the {@code sub} claim).
     *
     * @param roleMember full Athenz principal name (e.g. user.foobar from shortid claim)
     * @param roleName   short role name (e.g. gcp.fed.mcp.user), or null to use config default
     * @return space-separated scope string (e.g. "msd.stage:role.gcp.fed.mcp.user openid"),
     *         or "openid" only if no domains returned; never null
     */
    public String getScopeForPrincipal(String roleMember, String roleName) {
        String role = roleName != null && !roleName.isBlank() ? roleName : defaultGcpRoleName;
        List<String> scopeParts = new ArrayList<>();
        try {
            ZMSClient zmsClient = zmsClientProducer.getZMSClient();
            DomainList domainList = zmsClient.getDomainListByRole(roleMember, role);
            if (domainList != null && domainList.getNames() != null) {
                for (String domain : domainList.getNames()) {
                    scopeParts.add(domain + ":role." + role);
                }
            }
        } catch (Exception e) {
            return "openid";
        }
        scopeParts.add("openid");
        return String.join(" ", scopeParts);
    }
}
