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
import io.athenz.mop.telemetry.AuthCodeValidationReason;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.oidc.OidcSession;
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
 * Callback after Embrace OAuth authorization code flow (PKCE).
 * Embrace does not return an {@code id_token} or expose UserInfo. Quarkus uses {@code user-info-path} to MoP's
 * {@link EmbraceSyntheticUserInfoResource}, which validates the access JWT against Embrace JWKS and returns claims.
 * The lookup key uses claims from the access token (e.g. {@code sub}) via {@link #getUsername}.
 */
@Path("/embrace/authorize")
public class EmbraceResource extends BaseResource {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    static final String PROVIDER = "embrace";

    @Inject
    AuthorizerService authorizerService;

    @Inject
    AccessTokenCredential accessTokenCredential;

    @Inject
    AuthCodeRegionResolver authCodeRegionResolver;

    @ConfigProperty(name = "server.token-exchange.idp")
    String providerDefault;

    @Inject
    OidcSession oidcSession;

    @Inject
    ConfigService configService;

    @Inject
    RefreshTokenService refreshTokenService;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    TelemetryRequestContext telemetryRequestContext;

    @GET
    @Authenticated
    @Produces(MediaType.TEXT_HTML)
    public Response authorize(@QueryParam("state") String state) {
        telemetryRequestContext.setOauthProvider(OauthProviderLabel.EMBRACE);
        if (state == null || state.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "invalid_request",
                            "error_description", "Missing state parameter"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        String accessToken = accessTokenCredential.getToken();
        String lookupKey = getUsername(null, configService.getRemoteServerUsernameClaim(PROVIDER), accessToken);
        AuthorizationCode authorizationCode = authCodeRegionResolver.resolve(state, providerDefault).authorizationCode();
        if (authorizationCode == null) {
            log.warn("Embrace callback: authorization code not found for state");
            oauthProxyMetrics.recordAuthCodeValidationFailure(OauthProviderLabel.EMBRACE, AuthCodeValidationReason.NOT_FOUND);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "invalid_grant",
                            "error_description", "Authorization code not found or expired"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        String newAccessToken = accessToken;
        String newIdToken = accessToken;
        String newRefreshToken = (accessTokenCredential.getRefreshToken() != null)
                ? accessTokenCredential.getRefreshToken().getToken()
                : null;

        String existingUpstreamRefresh = refreshTokenService.getUpstreamRefreshToken(authorizationCode.getSubject(), PROVIDER);

        String refreshTokenToStore;
        if (newRefreshToken != null) {
            refreshTokenToStore = newRefreshToken;
        } else if (existingUpstreamRefresh != null) {
            refreshTokenToStore = existingUpstreamRefresh;
        } else {
            log.warn("Embrace callback: no refresh token from provider or storage");
            logoutFromProvider(PROVIDER, oidcSession);
            return Response.serverError().build();
        }

        authorizerService.storeTokens(
                lookupKey,
                authorizationCode.getSubject(),
                newIdToken,
                newAccessToken,
                refreshTokenToStore,
                PROVIDER,
                authorizationCode.getClientId());

        logoutFromProvider(PROVIDER, oidcSession);
        return buildSuccessRedirect(authorizationCode.getRedirectUri(), state, authorizationCode.getState());
    }
}
