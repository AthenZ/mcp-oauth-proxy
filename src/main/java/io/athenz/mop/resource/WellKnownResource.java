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
package io.athenz.mop.resource;

import io.athenz.mop.model.OAuthAuthorizationServer;
import io.athenz.mop.model.OpenIdConfiguration;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.lang.invoke.MethodHandles;
import java.security.Security;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OAuth 2.0 / OpenID Connect Discovery endpoints
 * RFC 8414: OAuth 2.0 Authorization Server Metadata
 * OpenID Connect Discovery 1.0
 */
@Path("/")
public class WellKnownResource {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ConfigProperty(name = "server.host", defaultValue = "localhost")
    String host;

    @GET
    @Path("/.well-known/openid-configuration")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getOpenIdConfiguration() {
        log.debug("Serving OpenID Connect discovery document");

        String baseUrl = getBaseUrl();

        OpenIdConfiguration config =
            new OpenIdConfiguration(
                getIssuerUrl(),
                baseUrl + "/authorize",
                baseUrl + "/token",
                baseUrl + "/register",
                baseUrl + "/userinfo",
                List.of("code", "token", "id_token token"),
                List.of("public"),
                List.of("ES256"),
                List.of("openid", "offline_access"), // Minimal scopes for JWT generation
                List.of("tls_client_auth", "none"), // RFC 8705: mTLS client authentication and none
                List.of("sub", "aud", "iss", "exp", "iat"),
                List.of("client_credentials", "authorization_code"), // OAuth 2.1: Both grant types
                List.of("S256")
            );

        return Response.ok(config).build();
    }

    @GET
    @Path("/.well-known/oauth-authorization-server")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getOAuthAuthorizationServer() {
        log.debug("Serving OAuth 2.0 authorization server metadata (RFC 8414)");

        String baseUrl = getBaseUrl();

        OAuthAuthorizationServer server =
            new OAuthAuthorizationServer(
                getIssuerUrl(),
                baseUrl + "/authorize",
                baseUrl + "/token",
                baseUrl + "/register",
                List.of("code", "token", "id_token token"),  // OAuth 2.1: code response type for auth code flow
                List.of("client_credentials", "authorization_code"), // OAuth 2.1: Both grant types
                List.of("tls_client_auth", "none"), // RFC 8705: mTLS client authentication and none only
                List.of("ES256"),
                List.of("S256")
            );

        return Response.ok(server).build();
    }

    private String getBaseUrl() {
        return String.format("https://%s", host);
    }

    private String getIssuerUrl() {
        return getBaseUrl();
    }
}
