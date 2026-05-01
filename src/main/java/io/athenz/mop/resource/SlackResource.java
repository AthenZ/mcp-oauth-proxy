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
 * Secondary OAuth callback handler for Slack.
 * After Quarkus OIDC completes the Slack OAuth v2 user-scope flow,
 * this resource stores the resulting tokens and redirects back to
 * the original OAuth client.
 */
@Path("/slack/authorize")
public class SlackResource extends BaseResource {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    static final String PROVIDER = "slack";

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
        log.info("Slack request to store tokens for user: {}", userInfo.get("user_id"));
        AuthorizationCode authorizationCode = authCodeRegionResolver.resolve(state, providerDefault).authorizationCode();
        if (authorizationCode == null) {
            log.warn("Slack callback: authorization code not found for state (local or cross-region)");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "invalid_grant",
                            "error_description", "Authorization code not found or expired"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        String lookupKey = getUsername(userInfo, configService.getRemoteServerUsernameClaim(PROVIDER), null);
        String newAccessToken = accessTokenCredential.getToken();
        String newRefreshToken = (accessTokenCredential.getRefreshToken() != null)
                ? accessTokenCredential.getRefreshToken().getToken()
                : null;

        String existingUpstreamRefresh = refreshTokenService.getUpstreamRefreshToken(authorizationCode.getSubject(), PROVIDER);

        String refreshTokenToStore;
        if (newRefreshToken != null) {
            refreshTokenToStore = newRefreshToken;
            log.info("Slack: Using new refresh token from authorization response");
        } else if (existingUpstreamRefresh != null) {
            refreshTokenToStore = existingUpstreamRefresh;
            log.info("Slack: Refresh token not in response, using existing refresh token from upstream table");
        } else {
            log.warn("Slack: No refresh token received and none found in storage. This may indicate first consent failed.");
            logoutFromProvider(PROVIDER, oidcSession);
            return Response.serverError().build();
        }

        authorizerService.storeTokens(
                lookupKey,
                authorizationCode.getSubject(),
                newAccessToken,
                newAccessToken,
                refreshTokenToStore,
                PROVIDER,
                authorizationCode.getClientId());

        logoutFromProvider(PROVIDER, oidcSession);
        return buildSuccessRedirect(authorizationCode.getRedirectUri(), state, authorizationCode.getState());
    }
}
