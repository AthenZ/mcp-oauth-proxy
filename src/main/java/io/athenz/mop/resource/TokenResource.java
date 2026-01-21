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

import com.yahoo.athenz.auth.util.Crypto;
import io.athenz.mop.model.*;
import io.athenz.mop.service.AuthorizationCodeService;
import io.athenz.mop.service.AuthorizerService;
import io.quarkus.security.credential.CertificateCredential;
import io.quarkus.security.credential.Credential;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.lang.invoke.MethodHandles;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("/token")
public class TokenResource {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ConfigProperty(name = "server.host", defaultValue = "localhost")
    String host;

    @ConfigProperty(name = "quarkus.http.ssl-port")
    String port;

    @Inject
    AuthorizerService authorizerService;

    @Inject
    AuthorizationCodeService authorizationCodeService;

    @Inject
    SecurityIdentity securityIdentity;

    /**
     * RFC 6749/OAuth 2.1 compliant token endpoint
     * Accepts application/x-www-form-urlencoded (required by RFC 6749)
     * Supports:
     * - client_credentials grant with mTLS authentication (RFC 8705)
     * - authorization_code grant with PKCE (RFC 7636 / OAuth 2.1)
     */
    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateTokenOAuth2(@Valid OAuth2TokenRequest request) {
        log.info("OAuth2 token request with grant_type: {} for resource: {}", request.getGrantType(),
                request.getResource());

        // Route to appropriate handler based on grant_type
        if ("authorization_code".equals(request.getGrantType())) {
            return handleAuthorizationCodeGrant(request);
        } else if ("client_credentials".equals(request.getGrantType())) {
            return handleClientCredentialsGrant(request);
        } else {
            log.warn("Unsupported grant_type: {}", request.getGrantType());
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.UNSUPPORTED_GRANT_TYPE,
                            "Supported grant types: authorization_code, client_credentials"))
                    .build();
        }
    }

    /**
     * Handle authorization_code grant (RFC 6749 Section 4.1.3 + OAuth 2.1 PKCE)
     * Exchanges authorization code for access token
     */
    private Response handleAuthorizationCodeGrant(OAuth2TokenRequest request) {
        log.info("Processing authorization_code grant");

        // Validate required parameters
        if (request.getCode() == null || request.getCode().isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                            "Missing required parameter: code"))
                    .build();
        }

        if (request.getRedirectUri() == null || request.getRedirectUri().isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                            "Missing required parameter: redirect_uri"))
                    .build();
        }

        if (request.getCodeVerifier() == null || request.getCodeVerifier().isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                            "Missing required parameter: code_verifier (PKCE required in OAuth 2.1)"))
                    .build();
        }

        // Extract or validate client_id
        String clientId = request.getClientId();

        if (clientId == null || clientId.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                            "Missing required parameter: client_id"))
                    .build();
        }

        // Validate and consume authorization code (one-time use + PKCE validation)
        AuthorizationCode authCode = authorizationCodeService.validateAndConsume(
                request.getCode(),
                clientId,
                request.getRedirectUri(),
                request.getCodeVerifier()
        );

        if (authCode == null) {
            log.error("Invalid or expired authorization code");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.INVALID_GRANT,
                            "Invalid or expired authorization code"))
                    .build();
        }

        // TODO: Scope validation can be added once client starts requesting scopes
//        if (request.getScope() == null || !request.getScope().equals(authCode.getScope())) {
//            log.error("mismatched scope between token request and authorization code");
//            return Response.status(Response.Status.BAD_REQUEST)
//                    .entity(OAuth2ErrorResponse.of(
//                            OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
//                            "scope mismatch between token request and authorization code"))
//                    .build();
//        }

        log.info("Authorization code validated for subject: {}, client: {}",
                authCode.getSubject(), authCode.getClientId());

        // Generate token with the subject and parameters from the authorization code
        return getTokenFromResourceAuthorizationServer(
                authCode.getSubject(),
                authCode.getScope(),
                authCode.getResource()
        );
    }

    /**
     * Handle client_credentials grant (RFC 6749 Section 4.4 + RFC 8705)
     * Requires mTLS client authentication
     */
    private Response handleClientCredentialsGrant(OAuth2TokenRequest request) {
        log.info("Processing client_credentials grant");

        // Extract client_id from mTLS certificate (RFC 8705)
        X509Certificate certificate = extractCertificate();
        if (certificate == null) {
            log.error("No client certificate provided for mTLS authentication");
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.INVALID_CLIENT,
                            "Client certificate required for authentication"))
                    .build();
        }

        String clientId;
        try {
            clientId = Crypto.extractX509CertCommonName(certificate);
            log.info("Client authenticated via mTLS: {}", clientId);
        } catch (IllegalArgumentException e) {
            log.error("Failed to extract client_id from certificate", e);
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.INVALID_CLIENT,
                            "Unable to extract client identity from certificate"))
                    .build();
        }

        // Validate resource parameter (RFC 8707)
        String resource = request.getResource();
        if (resource == null || resource.trim().isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                            "Missing required parameter: resource"))
                    .build();
        }

        // Subject is the authenticated client
        String subject = clientId;

        return getTokenFromResourceAuthorizationServer(subject, request.getScope(), resource);
    }

    /**
     * Internal method to get JWT token
     * Shared by both auth_code and client_credentials flows
     */
    private Response getTokenFromResourceAuthorizationServer(String subject, String scopes, String resource) {
        // Perform authorization check
        AuthorizationResultDO authorizationDO = authorizerService.authorize(subject, scopes, resource);

        if (authorizationDO.authResult() == AuthResult.UNAUTHORIZED) {
            log.error("subject: {} is not authorized to call resource: {}", subject, resource);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.UNAUTHORIZED_CLIENT,
                            "Client is not authorized to access the requested resource"))
                    .build();
        }

        if (authorizationDO.authResult() == AuthResult.EXPIRED) {
            log.error("authn expired for subject: {} to call resource: {}", subject, resource);
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.INVALID_GRANT,
                            "Authentication credentials have expired"))
                    .build();
        }

        log.info("Getting JWT for resource: {} and subject: {}", resource, subject);

        TokenResponse response = authorizerService.getTokenFromAuthorizationServer(subject, scopes, resource, authorizationDO.token());
        if (response == null) {
            log.error("Failed to obtain token from authorization server for subject: {}", subject);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.UNAUTHORIZED_CLIENT,
                            "Failed to obtain access token from authorization server"))
                    .build();
        }
        return Response.ok(response).build();

    }
    
    /**
     * Extract X.509 certificate from security context
     */
    private X509Certificate extractCertificate() {
        if (securityIdentity != null && securityIdentity.getCredentials() != null) {
            for (Credential credential : securityIdentity.getCredentials()) {
                if (credential instanceof CertificateCredential certificateCredential) {
                    return certificateCredential.getCertificate();
                }
            }
        }
        return null;
    }
}
