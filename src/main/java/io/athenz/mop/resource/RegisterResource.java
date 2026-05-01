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

import io.athenz.mop.model.RegisterRequest;
import io.athenz.mop.model.RegisterResponse;
import io.athenz.mop.service.RedirectUriValidator;
import io.athenz.mop.telemetry.OauthClientLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.lang.invoke.MethodHandles;
import java.util.*;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("/register")
public class RegisterResource {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    JsonWebToken jwt;

    @Inject
    RedirectUriValidator redirectUriValidator;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @ConfigProperty(name = "server.athenz.register.domain")
    String registerDomain;

    @ConfigProperty(name = "server.athenz.register.role")
    String registerRole;

    @ConfigProperty(name = "server.validate-attestation-jwt", defaultValue = "false")
    boolean validateAttestationJwt;

    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(@Valid RegisterRequest request) {
        log.info("register call for client: {} and token subject: {}", request.clientName(), jwt.getSubject());
        String oauthClient = OauthClientLabel.normalize(request.clientName());
        if (request.redirectUris() == null || request.redirectUris().isEmpty()) {
            oauthProxyMetrics.recordDynamicClientRegistration(false, "invalid_request", oauthClient);
            return Response.status(Response.Status.BAD_REQUEST).entity("redirect_uris is required").build();
        }

        // Validate all redirect URIs using the centralized validator
        if (!redirectUriValidator.validateRedirectUris(request.redirectUris(), request.clientName())) {
            log.error("Invalid redirect_uris for client: {}, uris: {}", request.clientName(), request.redirectUris());
            oauthProxyMetrics.recordDynamicClientRegistration(false, "invalid_redirect_uri", oauthClient);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("redirect_uris validation failed - must use allowed prefixes and valid format")
                    .build();
        }

        if (request.clientName() == null || request.clientName().isEmpty()) {
            oauthProxyMetrics.recordDynamicClientRegistration(false, "invalid_client_name", oauthClient);
            return Response.status(Response.Status.BAD_REQUEST).entity("client_name validation failed").build();
        }

        // Reject '#' in client_name: the per-MCP-client bearer row in mcp-oauth-proxy-tokens uses
        // "<clientId>#<userId>" as its DynamoDB partition-key value, and TokenStore backends split
        // on the first '#' on read to recover (clientId, userId). Allowing '#' here would let one
        // client masquerade as another by registering a name like "Cursor#evil".
        if (request.clientName().indexOf('#') >= 0) {
            log.error("Rejecting client registration: client_name contains '#': {}", request.clientName());
            oauthProxyMetrics.recordDynamicClientRegistration(false, "invalid_client_name", oauthClient);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("client_name must not contain '#'")
                    .build();
        }

        if (validateAttestationJwt && !isValidAttestationJwt(request)) {
            oauthProxyMetrics.recordDynamicClientRegistration(false, "forbidden", oauthClient);
            return Response.status(Response.Status.FORBIDDEN).entity("token does not come from expected domain and/or role").build();
        }
        RegisterResponse registerResponse = new RegisterResponse(request.clientName(), request.clientName(), request.redirectUris());
        log.info("registered client: {} with redirect_uris: {}", registerResponse.clientName(), registerResponse.redirectUris());
        oauthProxyMetrics.recordDynamicClientRegistration(true, null, oauthClient);
        return Response.ok(registerResponse).build();
    }

    private boolean isValidAttestationJwt(RegisterRequest request) {
        List<Object> tokenScopesTemp = jwt.getClaim("scp");
        List<String> tokenScopes = new ArrayList<>();
        for (Object tokenScope : tokenScopesTemp) {
            String ts = tokenScope.toString();
            ts = ts.replaceAll("\"", "");
            tokenScopes.add(ts);
        }

        return jwt.getSubject().equals(request.clientName()) && jwt.getAudience().contains(registerDomain)
                && tokenScopes.contains(registerRole);
    }
}
