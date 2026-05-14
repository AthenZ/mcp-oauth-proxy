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
 * Secondary authorization endpoint MoP returns to after the upstream Figma OAuth code flow
 * completes. Mirrors {@link GithubResource} / {@link AtlassianResource}: Quarkus OIDC owns
 * the {@code /figma/authorize/callback} leg (configured via
 * {@code quarkus.oidc.figma.authentication.redirect-path}), then with
 * {@code restore-path-after-redirect: true} it bounces the browser back to
 * {@code /figma/authorize?state=<mopAuthCode>} -- this method.
 *
 * <p>The 8-arg {@link AuthorizerService#storeTokens(String, String, String, String, String,
 * String, String, Long)} overload is used so the bare {@code (lookupKey, "figma")} row in
 * {@code mcp-oauth-proxy-tokens} TTLs to {@code now + 90d + 5m} instead of the global
 * {@code server.token-store.expiry} (~8h in stage/prod). Without this override the row would
 * evict 8 hours after consent and force re-consent long before the real Figma access token
 * (90 d) expires.
 */
@Path("/figma/authorize")
public class FigmaResource extends BaseResource {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    static final String PROVIDER = "figma";

    /** Figma's documented access-token lifetime (90 d). Pinned so the L1 bare row outlives the 8h global default. */
    static final long FIGMA_ACCESS_TOKEN_LIFETIME_SECONDS = 7_776_000L;

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
    public Response authorize(@QueryParam("state") String state) {
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
            log.warn("Figma callback: authorization code not found for state (local or cross-region)");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "invalid_grant",
                            "error_description", "Authorization code not found or expired"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        String lookupKey = getUsername(userInfo, configService.getRemoteServerUsernameClaim(PROVIDER), null);
        log.info("Figma request to store tokens for user: {}", lookupKey);
        String refreshToStore = null;
        if (accessTokenCredential.getRefreshToken() != null) {
            refreshToStore = accessTokenCredential.getRefreshToken().getToken();
        }
        if (refreshToStore == null || refreshToStore.isEmpty()) {
            // Borrow the canonical upstream RT from mcp-oauth-proxy-refresh-tokens
            // (rotation-aware, sibling-aware) when this Figma callback has no fresh RT in the
            // OIDC session -- covers second/third MCP-client windows relogging into an
            // existing Figma upstream session.
            String existingUpstream = refreshTokenService.getUpstreamRefreshToken(lookupKey, PROVIDER);
            refreshToStore = (existingUpstream != null && !existingUpstream.isEmpty()) ? existingUpstream : null;
        }
        authorizerService.storeTokens(
                lookupKey,
                authorizationCode.getSubject(),
                accessTokenCredential.getToken(),
                accessTokenCredential.getToken(),
                refreshToStore,
                PROVIDER,
                authorizationCode.getClientId(),
                FIGMA_ACCESS_TOKEN_LIFETIME_SECONDS);
        logoutFromProvider(PROVIDER, oidcSession);
        return buildSuccessRedirect(authorizationCode.getRedirectUri(), state, authorizationCode.getState());
    }
}
