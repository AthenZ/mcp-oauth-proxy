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
package io.athenz.mop.quarkus;

import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.TenantConfigResolver;
import io.quarkus.oidc.client.registration.ClientMetadata;
import io.quarkus.oidc.client.registration.OidcClientRegistration;
import io.quarkus.oidc.client.registration.OidcClientRegistrations;
import io.quarkus.oidc.client.registration.RegisteredClient;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.util.List;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class CustomTenantConfigResolver implements TenantConfigResolver {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    OidcClientRegistrations clientRegs;

    @Inject
    @ConfigProperty(name = "quarkus.oidc-client-registration.atlassian-mcp.auth-server-url", defaultValue = "https://cf.mcp.atlassian.com")
    String atlassianAuthServerUrl;

    @Inject
    @ConfigProperty(name = "server.host")
    String host;

    @Override
    public Uni<OidcTenantConfig> resolve(RoutingContext routingContext,
                                         OidcRequestContext<OidcTenantConfig> requestContext) {

        String path = routingContext.request().path();
        if (routingContext.request().path().startsWith("/atlassian-mcp")) {
            log.info("Atlassian-mcp oidc tenant config based on registered client");
            OidcClientRegistration tenantClientReg = clientRegs.getClientRegistration("atlassian-mcp");
            log.info("Found atlassian-mcp client registration: {}", tenantClientReg != null);
            return tenantClientReg.registeredClient().onItem().transform(
                client -> createTenantConfig("atlassian-mcp", client)
            );
        }
        return null;
    }

    // Convert metadata of registered clients to OidcTenantConfig
    private OidcTenantConfig createTenantConfig(String tenantId, RegisteredClient client) {
        ClientMetadata metadata = client.metadata();
        log.info("Found atlassian-mcp client metadata: {} {}", metadata.getClientId(), metadata.getClientName());

        String redirectPath = URI.create(metadata.getRedirectUris().get(0)).getPath();
    OidcTenantConfig oidcConfig =
        OidcTenantConfig.authServerUrl(atlassianAuthServerUrl)
            .tenantId(tenantId)
                .authorizationPath("/v1/authorize")
                .tokenPath("/v1/token")
                .introspectionPath("/v1/introspect")
                .discoveryEnabled(false)
            .applicationType(io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType.WEB_APP)
            .tenantPath("/" + tenantId + "/*")
            .clientName(metadata.getClientName())
            .clientId(metadata.getClientId())
            .credentials(metadata.getClientSecret())
            .authentication()
            .scopes(List.of("default"))
            .redirectPath(redirectPath)
            .pkceRequired(true)
            .end()
            .build();
        log.info("Created OidcTenantConfig for tenantId: {} with redirectPath: {}", tenantId, redirectPath);
        return oidcConfig;
    }
}
