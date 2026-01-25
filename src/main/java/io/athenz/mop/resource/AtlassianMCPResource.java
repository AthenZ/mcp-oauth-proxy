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

import io.athenz.mop.model.OAuth2AuthorizationRequest;
import io.athenz.mop.service.AuthorizerService;
import io.quarkus.oidc.RefreshToken;
import io.quarkus.security.Authenticated;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.BeanParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.lang.invoke.MethodHandles;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OAuth 2.1 Authorization Endpoint (RFC 6749 Section 3.1)
 * Implements authorization code flow with mandatory PKCE (RFC 7636)
 */
@Path("/atlassian-mcp/authorize")
public class AtlassianMCPResource {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    JsonWebToken accessToken;

    @Inject
    RefreshToken refreshToken;

    /**
     * OAuth 2.1 Authorization Endpoint
     * GET /authorize?response_type=code&client_id=...&redirect_uri=...&scope=...&state=...&code_challenge=...&code_challenge_method=S256
     */
    @GET
    @Authenticated
    @Produces(MediaType.TEXT_HTML)
    public Response authorize(@Valid @BeanParam OAuth2AuthorizationRequest request) {
        log.info("Atlassian request to store tokens: {}", request);
        return Response.ok("close window").build();
    }

}
