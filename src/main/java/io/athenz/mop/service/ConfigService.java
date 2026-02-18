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
import java.util.HashMap;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class ConfigService {
    
    @Inject
    ResourceConfig resourceConfig;

    @Inject
    TokenExchangeServersConfig tokenExchangeServersConfig;

    @ConfigProperty(name = "server.token-exchange.idp")
    String defaultIDP;

    Map<String, ResourceMeta> resourceMetaMap = new HashMap<>();

    Map<String, String> remoteServerMap = new HashMap<>();

    Map<String, String> remoteServerUsernameClaimMap = new HashMap<>();


    @PostConstruct
    void  init() {
        for(ResourceConfig.ResourceMapping rm : resourceConfig.resourceMapping()) {
            resourceMetaMap.put(rm.uri(), new ResourceMeta(rm.scopes(), rm.domain(), rm.token().idp(), rm.token().as(),
                    rm.token().jag().enabled(), rm.token().jag().issuer(), rm.token().audience().orElse(null)));
        }
        for(TokenExchangeServersConfig.RemoteServer rs : tokenExchangeServersConfig.endpoints()) {
            remoteServerMap.put(rs.name(), rs.endpoint());
            remoteServerUsernameClaimMap.put(rs.name(), rs.usernameClaim());
        }
    }
    
    public String getRemoteServerEndpoint(String key) {
        return remoteServerMap.get(key);
    }

    public String getRemoteServerUsernameClaim(String key) {
        return remoteServerUsernameClaimMap.get(key);
    }

    public ResourceMeta getResourceMeta(String key) {
        return resourceMetaMap.get(key);
    }

    public String getDefaultIDP() {
        return defaultIDP;
    }
}
