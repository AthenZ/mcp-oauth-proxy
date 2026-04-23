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

import io.athenz.mop.model.AuthorizationCode;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.service.AuthCodeRegionResolver;
import io.athenz.mop.service.AuthorizerService;
import io.athenz.mop.service.ConfigService;
import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.oidc.OidcSession;
import io.quarkus.oidc.RefreshToken;
import io.quarkus.oidc.UserInfo;
import io.quarkus.security.Authenticated;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.lang.invoke.MethodHandles;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OAuth 2.1 Authorization Endpoint (RFC 6749 Section 3.1)
 * Implements authorization code flow with mandatory PKCE (RFC 7636)
 */
@Path("/atlassian/authorize")
public class AtlassianResource extends BaseResource {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    static final String PROVIDER = "atlassian";

    @Inject
    AuthorizerService authorizerService;

    // Use AccessTokenCredential (not JsonWebToken) so we tolerate opaque access tokens.
    @Inject
    AccessTokenCredential accessTokenCredential;

    @Inject
    RefreshToken refreshToken;

    @Inject
    AuthCodeRegionResolver authCodeRegionResolver;

    @ConfigProperty(name = "server.token-exchange.idp")
    String providerDefault;

    @Inject
    OidcSession oidcSession;

    @Inject
    ConfigService configService;

    @Inject
    UserInfo userInfo;

    /**
     * Secondary Authorization Endpoint to return to
     * after Atlassian OAuth flow is completed
     * GET /authorize?state=...
     */
    @GET
    @Authenticated
    @Produces(MediaType.TEXT_HTML)
    public Response authorize(@QueryParam("state") String state) {
        log.info("Atlassian request to store tokens: ");
        if (state == null || state.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "invalid_request",
                            "error_description", "Missing state parameter"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        AuthorizationCode authorizationCode = authCodeRegionResolver.resolve(state, providerDefault).authorizationCode();
        if (authorizationCode == null) {
            log.warn("Atlassian callback: authorization code not found for state (local or cross-region)");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "invalid_grant",
                            "error_description", "Authorization code not found or expired"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        // Use same lookup key as used to obtain record from old table (username from userInfo + provider claim)
        String lookupKey = getUsername(userInfo, configService.getRemoteServerUsernameClaim(PROVIDER), null);
        String refreshToStore = (refreshToken != null) ? refreshToken.getToken() : null;
        if (refreshToStore == null || refreshToStore.isEmpty()) {
            TokenWrapper existing = authorizerService.getUserToken(lookupKey, PROVIDER);
            refreshToStore = (existing != null && existing.refreshToken() != null) ? existing.refreshToken() : null;
        }
        String rawAccessToken = accessTokenCredential != null ? accessTokenCredential.getToken() : null;
        authorizerService.storeTokens(
            lookupKey,
            authorizationCode.getSubject(),
            rawAccessToken,
            rawAccessToken,
            refreshToStore,
            PROVIDER
        );
        
        logoutFromProvider(PROVIDER, oidcSession);

        return buildSuccessRedirect(authorizationCode.getRedirectUri(), state, authorizationCode.getState());
    }

}
