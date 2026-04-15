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
import io.athenz.mop.service.AuthCodeRegionResolver;
import io.athenz.mop.service.AuthorizerService;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.RefreshTokenService;
import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.oidc.OidcSession;
import io.quarkus.oidc.UserInfo;
import io.quarkus.security.Authenticated;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Unified OAuth callback handler for all Google Workspace services.
 * The provider name is extracted from the URL path via {@code @PathParam}.
 */
@Path("/{provider: google-(?:drive|docs|sheets|slides|gmail|calendar|tasks|chat|forms|keep|meet|cloud-platform)}/authorize")
public class GoogleWorkspaceResource extends BaseResource {

    private static final Logger log = LoggerFactory.getLogger(GoogleWorkspaceResource.class);

    @Inject
    AuthorizerService authorizerService;

    @Inject
    AccessTokenCredential accessTokenCredential;

    @Inject
    AuthCodeRegionResolver authCodeRegionResolver;

    @Inject
    UserInfo userInfo;

    @ConfigProperty(name = "server.token-exchange.idp")
    String providerDefault;

    @Inject
    OidcSession oidcSession;

    @Inject
    ConfigService configService;

    @Inject
    RefreshTokenService refreshTokenService;

    @PathParam("provider")
    String provider;

    @GET
    @Authenticated
    @Produces(MediaType.TEXT_HTML)
    public Response authorize(@QueryParam("state") String state) {
        if (state == null || state.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of(
                    "error", "invalid_request",
                    "error_description", "Missing state parameter"))
                .type(MediaType.APPLICATION_JSON)
                .build();
        }
        log.info("{} request to store tokens for user: {}", provider, userInfo.getEmail());
        AuthorizationCode authorizationCode = authCodeRegionResolver.resolve(state, providerDefault).authorizationCode();
        if (authorizationCode == null) {
            log.warn("{} callback: authorization code not found for state (local or cross-region)", provider);
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of(
                    "error", "invalid_grant",
                    "error_description", "Authorization code not found or expired"))
                .type(MediaType.APPLICATION_JSON)
                .build();
        }

        String lookupKey = getUsername(userInfo, configService.getRemoteServerUsernameClaim(provider), null);
        String newAccessToken = accessTokenCredential.getToken();
        String newIdToken = accessTokenCredential.getToken();
        String newRefreshToken = (accessTokenCredential.getRefreshToken() != null)
            ? accessTokenCredential.getRefreshToken().getToken()
            : null;

        String existingUpstreamRefresh = refreshTokenService.getUpstreamRefreshToken(authorizationCode.getSubject(), provider);

        String refreshTokenToStore;
        if (newRefreshToken != null) {
            refreshTokenToStore = newRefreshToken;
            log.info("{}: Using new refresh token from authorization response", provider);
        } else if (existingUpstreamRefresh != null) {
            refreshTokenToStore = existingUpstreamRefresh;
            log.info("{}: Refresh token not in response, using existing refresh token from new table", provider);
        } else {
            log.warn("{}: No refresh token received and none found in storage. This may indicate first consent failed.", provider);
            logoutFromProvider(provider, oidcSession);
            return Response.serverError().build();
        }
        authorizerService.storeTokens(
            lookupKey,
            authorizationCode.getSubject(),
            newIdToken,
            newAccessToken,
            refreshTokenToStore,
            provider);

        logoutFromProvider(provider, oidcSession);
        return buildSuccessRedirect(authorizationCode.getRedirectUri(), state, authorizationCode.getState());
    }
}
