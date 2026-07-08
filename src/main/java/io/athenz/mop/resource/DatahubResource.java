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
 * Secondary authorization endpoint MoP returns to after the upstream DataHub (Acryl) OAuth code
 * flow completes. Mirrors {@link RootlyResource} / {@link FigmaResource}: Quarkus OIDC owns the
 * {@code /datahub/authorize/callback} leg (configured via
 * {@code quarkus.oidc.datahub.authentication.redirect-path}), then with
 * {@code restore-path-after-redirect: true} it bounces the browser back to
 * {@code /datahub/authorize?state=<mopAuthCode>} -- this method.
 *
 * <p>DataHub is a confidential {@code client_secret_basic} + PKCE client. Its advertised OIDC
 * userinfo endpoint ({@code /auth/userinfo}) rejects MCP-resource access tokens, so the tenant's
 * {@code user-info-path} points at the in-pod synthetic proxy
 * ({@link DatahubUserInfoResource}) which flattens DataHub's GraphQL {@code me} query.
 *
 * <p>We deliberately do <strong>not</strong> pin an access-token lifetime on the bare row:
 * DataHub access tokens are short-lived (~1h) and MoP relies on the real upstream
 * {@code expires_in} reported by DataHub on each refresh, never a fabricated constant. The
 * canonical upstream RT row TTL (6 months) lives in the L2 store and is governed separately by
 * {@code server.upstream-token.expiry-seconds-by-provider.datahub}. So this resource uses the
 * 7-arg {@link AuthorizerService#storeTokens(String, String, String, String, String, String, String)}
 * overload (no {@code accessTokenLifetimeSeconds}).
 */
@Path("/datahub/authorize")
public class DatahubResource extends BaseResource {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    static final String PROVIDER = "datahub";

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
            log.warn("DataHub callback: authorization code not found for state (local or cross-region)");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "invalid_grant",
                            "error_description", "Authorization code not found or expired"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        String lookupKey = getUsername(userInfo, configService.getRemoteServerUsernameClaim(PROVIDER), null);
        log.info("DataHub request to store tokens for user: {}", lookupKey);
        String refreshToStore = null;
        if (accessTokenCredential.getRefreshToken() != null) {
            refreshToStore = accessTokenCredential.getRefreshToken().getToken();
        }
        if (refreshToStore == null || refreshToStore.isEmpty()) {
            // Borrow the canonical upstream RT from mcp-oauth-proxy-refresh-tokens
            // (rotation-aware, sibling-aware) when this DataHub callback has no fresh RT in the
            // OIDC session -- covers second/third MCP-client windows relogging into an
            // existing DataHub upstream session.
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
                authorizationCode.getClientId());
        logoutFromProvider(PROVIDER, oidcSession);
        return buildSuccessRedirect(authorizationCode.getRedirectUri(), state, authorizationCode.getState());
    }
}
