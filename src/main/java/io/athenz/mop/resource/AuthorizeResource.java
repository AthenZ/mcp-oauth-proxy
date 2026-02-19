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
import io.athenz.mop.service.AuthorizationCodeService;
import io.athenz.mop.service.AuthorizerService;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.RedirectUriValidator;
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
        log.info("OAuth 2.1 authorization request from client: {} {}", request.getClientId(), userInfo.getUserInfoString());

        // Validate response_type (must be "code" for OAuth 2.1)
        if (!"code".equals(request.getResponseType())) {
            log.warn("Unsupported response_type: {}. OAuth 2.1 only supports 'code'", request.getResponseType());
            return buildErrorRedirect(request.getRedirectUri(), request.getState(),
                    OAuth2ErrorResponse.ErrorCode.UNSUPPORTED_GRANT_TYPE,
                    "OAuth 2.1 only supports response_type=code");
        }

        // Validate code_challenge_method (must be S256, plain is deprecated)
        if (!"S256".equals(request.getCodeChallengeMethod())) {
            log.warn("Unsupported code_challenge_method: {}. OAuth 2.1 requires S256",
                    request.getCodeChallengeMethod());
            return buildErrorRedirect(request.getRedirectUri(), request.getState(),
                    OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                    "code_challenge_method must be S256 (plain is deprecated in OAuth 2.1)");
        }

        // Validate redirect_uri
        if (!redirectUriValidator.isValidRedirectUri(request.getRedirectUri(), request.getClientId())) {
            log.error("Invalid redirect_uri for client {}: {}", request.getClientId(), request.getRedirectUri());
            // Per RFC 6749 Section 4.1.2.1, do NOT redirect on invalid redirect_uri
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                            "Invalid or missing redirect_uri"))
                    .build();
        }

        if (request.getResource() == null || request.getResource().isEmpty()) {
            log.error("Invalid provider {} for client {}", request.getResource(), request.getClientId());
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                            "Invalid or missing resource"))
                    .build();
        }

        // Extract subject from authenticated key (OIDC IdToken)
        String subject = idToken != null ? idToken.getSubject() : accessToken.getSubject();
        if (subject == null || subject.isEmpty()) {
            log.error("Unable to extract subject from token");
            return buildErrorRedirect(request.getRedirectUri(), request.getState(),
                    OAuth2ErrorResponse.ErrorCode.SERVER_ERROR,
                    "Unable to determine user identity");
        }
        ResourceMeta resourceMeta = configService.getResourceMeta(request.getResource());

        authorizerService.storeTokens(
        getUsername(userInfo, configService.getRemoteServerUsernameClaim(providerDefault), accessToken.getRawToken()),
        subject,
        idToken != null ? idToken.getRawToken() : null,
        accessToken.getRawToken(),
        refreshToken != null ? refreshToken.getToken() : null,
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
                return buildRedirect(redirectUri, code);
            }
        }
        // Build success redirect with authorization code
        return buildSuccessRedirect(request.getRedirectUri(), code, request.getState());
    }
}
