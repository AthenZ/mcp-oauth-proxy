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
import io.athenz.mop.service.LookerInstances;
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
import java.lang.invoke.MethodHandles;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Secondary authorization endpoint MoP returns to after a Looker instance's upstream OAuth code
 * flow completes. One class serves all Looker instances: the {@code {provider}} path template is
 * regex-constrained to {@code looker-*} so it never collides with the dedicated per-provider
 * resources (Linear, Datadog, ...). Each Looker instance has its own Quarkus OIDC tenant
 * ({@code quarkus.oidc.looker-<instance>}) whose {@code redirect-path} is
 * {@code /looker-<instance>/authorize/callback}; with {@code restore-path-after-redirect: true}
 * Quarkus bounces the browser back to {@code /looker-<instance>/authorize?state=<mopAuthCode>} --
 * this method.
 *
 * <p>Looker access tokens last ~1 hour ({@code expires_in=3599/3600}); the 8-arg
 * {@link AuthorizerService#storeTokens(String, String, String, String, String, String, String, Long)}
 * overload pins the bare {@code (lookupKey, provider)} row to that lifetime.
 *
 * <p>Looker instances are public PKCE clients ({@code token_endpoint_auth_method=none}), so the
 * {@code looker-*} OIDC tenants have no {@code credentials} block -- PKCE alone authenticates the
 * client. Looker does <strong>not</strong> rotate the refresh token (the refresh response returns
 * {@code refresh_token:null}); the non-rotating RT is preserved by
 * {@link io.athenz.mop.service.LookerUpstreamRefreshClient}.
 *
 * <p>Identity comes from Looker's flat {@code /api/4.0/user} endpoint (configured as the tenant's
 * {@code user-info-path}); the username claim is {@code email}.
 */
@Path("/{provider:looker-[a-z0-9-]+}/authorize")
public class LookerResource extends BaseResource {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    /** Looker's documented access-token lifetime (~1 h, {@code expires_in=3599/3600}). */
    static final long LOOKER_ACCESS_TOKEN_LIFETIME_SECONDS = 3_600L;

    @Inject
    AuthorizerService authorizerService;

    @Inject
    AccessTokenCredential accessTokenCredential;

    @Inject
    AuthCodeRegionResolver authCodeRegionResolver;

    @ConfigProperty(name = "server.token-exchange.idp")
    String providerDefault;

    @Inject
    UserInfo userInfo;

    @Inject
    OidcSession oidcSession;

    @Inject
    ConfigService configService;

    @Inject
    RefreshTokenService refreshTokenService;

    @GET
    @Authenticated
    @Produces(MediaType.TEXT_HTML)
    public Response authorize(@PathParam("provider") String provider, @QueryParam("state") String state) {
        if (!LookerInstances.isLooker(provider)) {
            log.warn("Looker callback: unknown Looker instance provider={}", provider);
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of(
                            "error", "invalid_request",
                            "error_description", "Unknown Looker instance"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
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
            log.warn("Looker callback ({}): authorization code not found for state (local or cross-region)", provider);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "invalid_grant",
                            "error_description", "Authorization code not found or expired"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        String lookupKey = getUsername(userInfo, configService.getRemoteServerUsernameClaim(provider), null);
        log.info("Looker ({}) request to store tokens for user: {}", provider, lookupKey);
        String refreshToStore = null;
        if (accessTokenCredential.getRefreshToken() != null) {
            refreshToStore = accessTokenCredential.getRefreshToken().getToken();
        }
        if (refreshToStore == null || refreshToStore.isEmpty()) {
            // Borrow the canonical upstream RT from mcp-oauth-proxy-refresh-tokens (rotation-aware,
            // sibling-aware) when this Looker callback has no fresh RT in the OIDC session --
            // covers second/third MCP-client windows relogging into an existing Looker upstream
            // session (Looker only returns the RT on the initial code exchange).
            String existingUpstream = refreshTokenService.getUpstreamRefreshToken(lookupKey, provider);
            refreshToStore = (existingUpstream != null && !existingUpstream.isEmpty()) ? existingUpstream : null;
        }
        authorizerService.storeTokens(
                lookupKey,
                authorizationCode.getSubject(),
                accessTokenCredential.getToken(),
                accessTokenCredential.getToken(),
                refreshToStore,
                provider,
                authorizationCode.getClientId(),
                LOOKER_ACCESS_TOKEN_LIFETIME_SECONDS);
        logoutFromProvider(provider, oidcSession);
        return buildSuccessRedirect(authorizationCode.getRedirectUri(), state, authorizationCode.getState());
    }
}
