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
import io.athenz.mop.service.AuthorizerService;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.RefreshTokenService;
import io.athenz.mop.store.AuthCodeStore;
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
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OAuth 2.1 Authorization Endpoint (RFC 6749 Section 3.1)
 * Implements authorization code flow with mandatory PKCE (RFC 7636)
 */
@Path("/google/authorize")
public class GoogleResource extends BaseResource {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    static final String PROVIDER = "google";

    @Inject
    AuthorizerService authorizerService;

    @Inject
    AccessTokenCredential accessTokenCredential;

    @Inject
    AuthCodeStore authCodeStore;

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

    /**
   * Secondary Authorization Endpoint to return to
   * after Google OAuth flow is completed
   * GET /authorize?state=...
   */
  @GET
  @Authenticated
  @Produces(MediaType.TEXT_HTML)
  public Response authorize(@QueryParam("state") String state) {
    if (state != null) {
      log.info("Google request to store tokens for user: {}", userInfo.getEmail());
      AuthorizationCode authorizationCode = authCodeStore.getAuthCode(state, providerDefault);

      // Use same lookup key as used to obtain record from old table (username from userInfo + provider claim)
      String lookupKey = getUsername(userInfo, configService.getRemoteServerUsernameClaim(PROVIDER), null);
      String newAccessToken = accessTokenCredential.getToken();
      String newIdToken = accessTokenCredential.getToken(); // Google uses same token for both
      String newRefreshToken = (accessTokenCredential.getRefreshToken() != null)
          ? accessTokenCredential.getRefreshToken().getToken()
          : null;

      // Existing refresh when Google does not send one: read from new table (same subject as token exchange)
      String existingUpstreamRefresh = refreshTokenService.getUpstreamRefreshToken(authorizationCode.getSubject(), PROVIDER);

      String refreshTokenToStore;
      if (newRefreshToken != null) {
        refreshTokenToStore = newRefreshToken;
        log.info("Google: Using new refresh token from authorization response");
      } else if (existingUpstreamRefresh != null) {
        refreshTokenToStore = existingUpstreamRefresh;
        log.info("Google: Refresh token not in response, using existing refresh token from new table");
      } else {
        log.warn("Google: No refresh token received and none found in storage. This may indicate first consent failed.");
        logoutFromProvider(PROVIDER, oidcSession);
        return Response.serverError().build();
      }
      // Store tokens in old table (access, id, refresh); new table populated at auth code exchange
      authorizerService.storeTokens(
          lookupKey,
          authorizationCode.getSubject(),
          newIdToken,
          newAccessToken,
          refreshTokenToStore,
          PROVIDER);

      logoutFromProvider(PROVIDER, oidcSession);
      return buildSuccessRedirect(authorizationCode.getRedirectUri(), state, authorizationCode.getState());
    }
    return Response.status(Response.Status.CREATED).build();
  }
}
