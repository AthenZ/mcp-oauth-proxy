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
import io.athenz.mop.model.OAuth2ErrorResponse;
import io.athenz.mop.model.ResourceMeta;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.service.AudienceConstants;
import io.athenz.mop.service.AuthorizationCodeService;
import io.athenz.mop.service.AuthorizerService;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.RedirectUriValidator;
import io.athenz.mop.service.UpstreamRefreshService;
import io.athenz.mop.telemetry.OauthClientLabel;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.quarkus.oidc.IdToken;
import io.quarkus.oidc.RefreshToken;
import io.quarkus.oidc.UserInfo;
import io.quarkus.security.Authenticated;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OAuth 2.1 Authorization Endpoint (RFC 6749 Section 3.1)
 * Implements authorization code flow with mandatory PKCE (RFC 7636)
 */
@Path("/authorize")
public class AuthorizeResource extends BaseResource {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    AuthorizerService authorizerService;

    @Inject
    AuthorizationCodeService authorizationCodeService;

    @Inject
    RedirectUriValidator redirectUriValidator;

    @Inject
    @IdToken
    JsonWebToken idToken;

    @Inject
    JsonWebToken accessToken;

    @Inject
    RefreshToken refreshToken;

    @Inject
    ConfigService configService;

    @Inject
    UpstreamRefreshService upstreamRefreshService;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @ConfigProperty(name = "server.host", defaultValue = "localhost")
    String host;

    @ConfigProperty(name = "server.token-exchange.idp")
    String providerDefault;

    @Inject
    UserInfo userInfo;

    /**
     * OAuth 2.1 Authorization Endpoint
     * GET /authorize?response_type=code&client_id=...&redirect_uri=...&scope=...&state=...&code_challenge=...&code_challenge_method=S256
     */
    @GET
    @Authenticated
    @Produces(MediaType.TEXT_HTML)
    public Response authorize(@Valid @BeanParam OAuth2AuthorizationRequest request) {
        log.info("OAuth 2.1 authorization request from client: {}", request.getClientId());
        String oauthClient = OauthClientLabel.normalize(request.getClientId());

        // Validate response_type (must be "code" for OAuth 2.1)
        if (!"code".equals(request.getResponseType())) {
            log.warn("Unsupported response_type: {}. OAuth 2.1 only supports 'code'", request.getResponseType());
            return recordAuthorizeRedirect(buildErrorRedirect(request.getRedirectUri(), request.getState(),
                    OAuth2ErrorResponse.ErrorCode.UNSUPPORTED_GRANT_TYPE,
                    "OAuth 2.1 only supports response_type=code"), oauthClient, false, "unsupported_grant_type");
        }

        // Validate code_challenge_method (must be S256, plain is deprecated)
        if (!"S256".equals(request.getCodeChallengeMethod())) {
            log.warn("Unsupported code_challenge_method: {}. OAuth 2.1 requires S256",
                    request.getCodeChallengeMethod());
            return recordAuthorizeRedirect(buildErrorRedirect(request.getRedirectUri(), request.getState(),
                    OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                    "code_challenge_method must be S256 (plain is deprecated in OAuth 2.1)"), oauthClient, false, "invalid_request");
        }

        // Validate redirect_uri
        if (!redirectUriValidator.isValidRedirectUri(request.getRedirectUri(), request.getClientId())) {
            log.error("Invalid redirect_uri for client {}: {}", request.getClientId(), request.getRedirectUri());
            // Per RFC 6749 Section 4.1.2.1, do NOT redirect on invalid redirect_uri
            return recordAuthorizeRedirect(Response.status(Response.Status.BAD_REQUEST)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                            "Invalid or missing redirect_uri"))
                    .build(), oauthClient, false, "invalid_request");
        }

        if (request.getResource() == null || request.getResource().isEmpty()) {
            log.error("Invalid provider {} for client {}", request.getResource(), request.getClientId());
            return recordAuthorizeRedirect(Response.status(Response.Status.BAD_REQUEST)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                            "Invalid or missing resource"))
                    .build(), oauthClient, false, "invalid_request");
        }

        // Extract subject from authenticated key (OIDC IdToken)
        String subject = idToken != null ? idToken.getSubject() : accessToken.getSubject();
        if (subject == null || subject.isEmpty()) {
            log.error("Unable to extract subject from token");
            return recordAuthorizeRedirect(buildErrorRedirect(request.getRedirectUri(), request.getState(),
                    OAuth2ErrorResponse.ErrorCode.SERVER_ERROR,
                    "Unable to determine user identity"), oauthClient, false, "server_error");
        }
        ResourceMeta resourceMeta = configService.getResourceMeta(request.getResource());

        String lookupKey = getUsername(userInfo, configService.getRemoteServerUsernameClaim(providerDefault), accessToken.getRawToken());
        String oidcRefreshToken = refreshToken != null ? refreshToken.getToken() : null;
        String refreshToStore = computeRefreshToStore(lookupKey, oidcRefreshToken);
        refreshToStore = preferCentralizedOktaUpstreamRefresh(subject, refreshToStore);

        authorizerService.storeTokens(
        lookupKey,
        subject,
        idToken != null ? idToken.getRawToken() : null,
        accessToken.getRawToken(),
        refreshToStore,
        providerDefault);
        log.info("after storeToken call in AuthorizeResource Token issuer: {} subject: {} resourceMeta.idpServer: {}", providerDefault, subject,
                resourceMeta.idpServer());

        log.info("Generating authorization code for subject: {}, client: {}", subject, request.getClientId());
    // Generate secure authorization code with PKCE parameters
    String code =
        authorizationCodeService.generateCode(
            request.getClientId(),
            subject,
            request.getRedirectUri(),
            request.getScope(),
            request.getResource(),
            request.getCodeChallenge(),
            request.getCodeChallengeMethod(),
            request.getState());

        if (!providerDefault.equals(resourceMeta.idpServer())) {
            log.info("resource: {} with non default idp: {}", request.getResource(), resourceMeta.idpServer());
            TokenWrapper tokenWrapper = authorizerService.getUserToken(subject, resourceMeta.idpServer());
            if (tokenWrapper == null) {
                log.error("no token found for subject: {} provider: {}", subject, resourceMeta.idpServer());
                String redirectUri = String.format("https://%s/%s/authorize", host, resourceMeta.idpServer());
                log.info("redirecting to {} for authorization", redirectUri);
                return recordAuthorizeRedirect(buildRedirect(redirectUri, code), oauthClient, true, null);
            }
        }
        // Build success redirect with authorization code
        return recordAuthorizeRedirect(buildSuccessRedirect(request.getRedirectUri(), code, request.getState()), oauthClient, true, null);
    }

    private Response recordAuthorizeRedirect(Response response, String oauthClient, boolean success, String errorType) {
        oauthProxyMetrics.recordAuthorizeRedirect(OauthProviderLabel.normalize(providerDefault), success, errorType, oauthClient);
        return response;
    }

    /**
     * Chooses which refresh token to store: reuses existing active upstream refresh token when present
     * (so multiple resources share one Okta RT and a second login does not overwrite it).
     * Package-private for unit testing.
     */
    String computeRefreshToStore(String lookupKey, String oidcRefreshToken) {
        TokenWrapper existing = authorizerService.getUserToken(lookupKey, providerDefault);
        if (existing != null
                && existing.refreshToken() != null
                && !existing.refreshToken().isEmpty()
                && existing.ttl() != null
                && existing.ttl() > Instant.now().getEpochSecond()) {
            log.info("Reusing existing active {} refresh token for lookupKey={} (second or subsequent login for another resource)",
                    providerDefault, lookupKey);
            return existing.refreshToken();
        }
        return oidcRefreshToken;
    }

    /**
     * When centralized upstream already has a refresh token (e.g. rotated via MOP refresh), use it instead of
     * the OIDC session token so relogin with an active Quarkus session does not persist a stale RT.
     * Package-private for unit testing.
     */
    String preferCentralizedOktaUpstreamRefresh(String subject, String refreshToStore) {
        if (!AudienceConstants.PROVIDER_OKTA.equals(providerDefault) || subject == null || subject.isEmpty()) {
            return refreshToStore;
        }
        String providerUserId = AudienceConstants.PROVIDER_OKTA + "#" + subject;
        return upstreamRefreshService.getCurrentUpstream(providerUserId)
                .map(rec -> rec.encryptedOktaRefreshToken())
                .filter(rt -> rt != null && !rt.isEmpty())
                .orElse(refreshToStore);
    }
}
