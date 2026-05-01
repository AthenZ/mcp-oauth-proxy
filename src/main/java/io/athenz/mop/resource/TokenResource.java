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
import io.athenz.mop.service.AudienceConstants;
import io.athenz.mop.service.AuthorizationCodeService;
import io.athenz.mop.service.AuthorizerService;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.RefreshTokenService;
import io.athenz.mop.service.UpstreamRefreshException;
import io.athenz.mop.service.UpstreamRefreshService;
import io.athenz.mop.service.UpstreamRefreshTransientException;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthClientLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryProviderResolver;
import io.athenz.mop.telemetry.TelemetryRequestContext;
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
import java.util.Optional;
import java.util.function.Supplier;

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
    ConfigService configService;

    @Inject
    RefreshTokenService refreshTokenService;

    @Inject
    UpstreamRefreshService upstreamRefreshService;

    @Inject
    SecurityIdentity securityIdentity;

    @ConfigProperty(name = "server.refresh-token.expiry-seconds", defaultValue = "7776000")
    long refreshExpirySeconds;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    TelemetryRequestContext telemetryRequestContext;

    @Inject
    TelemetryProviderResolver telemetryProviderResolver;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

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

        telemetryRequestContext.setOauthClient(OauthClientLabel.normalize(request.getClientId()));

        // Route to appropriate handler based on grant_type
        if ("authorization_code".equals(request.getGrantType())) {
            return handleAuthorizationCodeGrant(request);
        } else if ("client_credentials".equals(request.getGrantType())) {
            return handleClientCredentialsGrant(request);
        } else if ("refresh_token".equals(request.getGrantType())) {
            return handleRefreshTokenGrant(request);
        } else {
            log.warn("Unsupported grant_type: {}", request.getGrantType());
            Response r = Response.status(Response.Status.BAD_REQUEST)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.UNSUPPORTED_GRANT_TYPE,
                            "Supported grant types: authorization_code, client_credentials, refresh_token"))
                    .build();
            oauthProxyMetrics.recordTokenIssuance("unknown", request.getGrantType() != null ? request.getGrantType() : "unknown",
                    false, "unsupported_grant_type", telemetryRequestContext.oauthClient());
            return r;
        }
    }

    /**
     * Handle authorization_code grant (RFC 6749 Section 4.1.3 + OAuth 2.1 PKCE)
     * Exchanges authorization code for access token
     */
    private Response handleAuthorizationCodeGrant(OAuth2TokenRequest request) {
        log.info("Processing authorization_code grant");
        long t0 = System.nanoTime();
        String oauthClient = OauthClientLabel.normalize(request.getClientId());
        telemetryRequestContext.setOauthClient(oauthClient);

        // Validate required parameters
        if (request.getCode() == null || request.getCode().isEmpty()) {
            return recordTokenGrant(request.getResource(), "authorization_code", t0, oauthClient,
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity(OAuth2ErrorResponse.of(
                                    OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                                    "Missing required parameter: code"))
                            .build());
        }

        if (request.getRedirectUri() == null || request.getRedirectUri().isEmpty()) {
            return recordTokenGrant(request.getResource(), "authorization_code", t0, oauthClient,
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity(OAuth2ErrorResponse.of(
                                    OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                                    "Missing required parameter: redirect_uri"))
                            .build());
        }

        if (request.getCodeVerifier() == null || request.getCodeVerifier().isEmpty()) {
            return recordTokenGrant(request.getResource(), "authorization_code", t0, oauthClient,
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity(OAuth2ErrorResponse.of(
                                    OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                                    "Missing required parameter: code_verifier (PKCE required in OAuth 2.1)"))
                            .build());
        }

        // Extract or validate client_id
        String clientId = request.getClientId();

        if (clientId == null || clientId.isEmpty()) {
            return recordTokenGrant(request.getResource(), "authorization_code", t0, oauthClient,
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity(OAuth2ErrorResponse.of(
                                    OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                                    "Missing required parameter: client_id"))
                            .build());
        }

        // Validate and consume authorization code (one-time use + PKCE validation)
        AuthorizationCode authCode = authorizationCodeService.validateAndConsume(
                request.getCode(),
                clientId,
                request.getRedirectUri(),
                request.getCodeVerifier(),
                request.getResource()
        );

        if (authCode == null) {
            log.error("Invalid or expired authorization code");
            return recordTokenGrant(request.getResource(), "authorization_code", t0, oauthClient,
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity(OAuth2ErrorResponse.of(
                                    OAuth2ErrorResponse.ErrorCode.INVALID_GRANT,
                                    "Invalid or expired authorization code"))
                            .build());
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

        String resourceForMetrics = authCode.getResource() != null ? authCode.getResource() : request.getResource();

        // Get token response; then attach MOP refresh token if possible (authorization_code only)
        Response response = getTokenFromResourceAuthorizationServer(
                authCode.getSubject(),
                authCode.getScope(),
                authCode.getResource(),
                clientId
        );
        if (response.getStatus() != 200 || response.getEntity() == null) {
            return recordTokenGrant(resourceForMetrics, "authorization_code", t0, oauthClient, response);
        }
        TokenResponse tokenResponse = (TokenResponse) response.getEntity();
        String resource = authCode.getResource() != null ? authCode.getResource() : request.getResource();
        try {
            ResourceMeta resourceMeta = resource != null ? configService.getResourceMeta(resource) : null;
            String provider = resourceMeta != null ? resourceMeta.idpServer() : configService.getDefaultIDP();
            String providerUserId = provider + "#" + authCode.getSubject();
            String subject = authCode.getSubject();

            String upstreamRefresh = firstNonEmpty(
                () -> AudienceConstants.PROVIDER_OKTA.equals(provider)
                        ? upstreamRefreshService.getCurrentUpstream(providerUserId)
                                .map(rec -> rec.encryptedOktaRefreshToken())
                                .filter(rt -> rt != null && !rt.isEmpty())
                                .orElse(null)
                        : null,
                () -> Optional.ofNullable(authorizerService.getUserToken(subject, provider))
                                .map(TokenWrapper::refreshToken)
                                .orElse(null),
                () -> refreshTokenService.getUpstreamRefreshToken(subject, provider)
            );

            if (AudienceConstants.PROVIDER_OKTA.equals(provider) && upstreamRefresh != null && !upstreamRefresh.isEmpty()) {
                upstreamRefreshService.storeInitialUpstreamToken(providerUserId, upstreamRefresh);
            }
            String mopRefresh = refreshTokenService.store(
                    authCode.getSubject(),
                    request.getClientId(),
                    provider,
                    authCode.getSubject(),
                    AudienceConstants.PROVIDER_OKTA.equals(provider) ? null : upstreamRefresh
            );
            if (mopRefresh == null) {
                log.warn("RefreshTokenService.store returned null; returning token response without refresh");
                return recordTokenGrant(resourceForMetrics, "authorization_code", t0, oauthClient, Response.ok(tokenResponse).build());
            }
            TokenResponse withRefresh = new TokenResponse(
                    tokenResponse.accessToken(),
                    tokenResponse.tokenType(),
                    tokenResponse.expiresIn(),
                    tokenResponse.scope(),
                    mopRefresh,
                    refreshExpirySeconds
            );
            log.info("Attached MOP refresh token to authorization_code token response for subject={} clientId={}", authCode.getSubject(), request.getClientId());
            return recordTokenGrant(resourceForMetrics, "authorization_code", t0, oauthClient, Response.ok(withRefresh).build());
        } catch (Exception e) {
            log.warn("Could not create MOP refresh token; returning token response without refresh: {}", e.getMessage());
            return recordTokenGrant(resourceForMetrics, "authorization_code", t0, oauthClient, Response.ok(tokenResponse).build());
        }
    }

    /**
     * Handle client_credentials grant (RFC 6749 Section 4.4 + RFC 8705)
     * Requires mTLS client authentication
     */
    private Response handleClientCredentialsGrant(OAuth2TokenRequest request) {
        log.info("Processing client_credentials grant");
        long t0 = System.nanoTime();

        // Extract client_id from mTLS certificate (RFC 8705)
        X509Certificate certificate = extractCertificate();
        if (certificate == null) {
            log.error("No client certificate provided for mTLS authentication");
            String oc = telemetryRequestContext.oauthClient();
            return recordTokenGrant(request.getResource(), "client_credentials", t0, oc,
                    Response.status(Response.Status.UNAUTHORIZED)
                            .entity(OAuth2ErrorResponse.of(
                                    OAuth2ErrorResponse.ErrorCode.INVALID_CLIENT,
                                    "Client certificate required for authentication"))
                            .build());
        }

        String clientId;
        try {
            clientId = Crypto.extractX509CertCommonName(certificate);
            log.info("Client authenticated via mTLS: {}", clientId);
        } catch (IllegalArgumentException e) {
            log.error("Failed to extract client_id from certificate", e);
            String oc = telemetryRequestContext.oauthClient();
            return recordTokenGrant(request.getResource(), "client_credentials", t0, oc,
                    Response.status(Response.Status.UNAUTHORIZED)
                            .entity(OAuth2ErrorResponse.of(
                                    OAuth2ErrorResponse.ErrorCode.INVALID_CLIENT,
                                    "Unable to extract client identity from certificate"))
                            .build());
        }

        String oauthClient = OauthClientLabel.normalize(clientId);
        telemetryRequestContext.setOauthClient(oauthClient);

        // Validate resource parameter (RFC 8707)
        String resource = request.getResource();
        if (resource == null || resource.trim().isEmpty()) {
            return recordTokenGrant(null, "client_credentials", t0, oauthClient,
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity(OAuth2ErrorResponse.of(
                                    OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST,
                                    "Missing required parameter: resource"))
                            .build());
        }

        // Subject is the authenticated client
        String subject = clientId;

        // For client_credentials, the mTLS-authenticated client_id IS the calling MCP client.
        Response r = getTokenFromResourceAuthorizationServer(subject, request.getScope(), resource, clientId);
        return recordTokenGrant(resource, "client_credentials", t0, oauthClient, r);
    }

    /**
     * Handle refresh_token grant (OAuth 2.0 BCP): validate, rotate on ACTIVE, upstream refresh, return new tokens.
     * The per-(userId, provider) grant lock was removed; restore steps live in
     * {@code .cursor/plans/refresh_grant_user_provider_lock.plan.md}.
     */
    private Response handleRefreshTokenGrant(OAuth2TokenRequest request) {
        log.info("Processing refresh_token grant");
        long t0 = System.nanoTime();
        String oauthClient = OauthClientLabel.normalize(request.getClientId());
        telemetryRequestContext.setOauthClient(oauthClient);
        String resourceUri = request.getResource();

        if (request.getRefreshToken() == null || request.getRefreshToken().isEmpty()) {
            return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Missing required parameter: refresh_token"));
        }
        if (request.getClientId() == null || request.getClientId().isEmpty()) {
            return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Missing required parameter: client_id"));
        }
        if (request.getResource() == null || request.getResource().trim().isEmpty()) {
            return recordTokenGrant(null, "refresh_token", t0, oauthClient, invalidGrant("Missing required parameter: resource"));
        }

        // 1. Resolve (userId, provider) from presented refresh token (for grant flow and logging).
        var lockKeyOpt = refreshTokenService.lookupUserIdAndProviderForLock(request.getRefreshToken(), request.getClientId());
        if (lockKeyOpt.isEmpty()) {
            return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Invalid or expired refresh token"));
        }
        String userId = lockKeyOpt.get().userId();
        String provider = lockKeyOpt.get().provider();

        RefreshTokenValidationResult result = refreshTokenService.validate(request.getRefreshToken(), request.getClientId());
        switch (result.status()) {
            case INVALID:
            case REVOKED:
                return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Invalid or expired refresh token"));
            case ROTATED_REPLAY:
                refreshTokenService.handleReplay(request.getRefreshToken());
                return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Invalid or expired refresh token"));
            case ACTIVE:
                if (result.record() == null) {
                    return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Invalid or expired refresh token"));
                }
                RefreshTokenRotateResult rotateResult = refreshTokenService.rotate(request.getRefreshToken(), request.getClientId());
                if (rotateResult == null) {
                    log.warn("refresh_token grant failed: rotate() returned null for userId={} provider={}", userId, provider);
                    return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Invalid or expired refresh token"));
                }
                String providerUserId = result.record().providerUserId();
                RefreshAndTokenResult refreshResult;
                if (providerUserId != null && providerUserId.startsWith(AudienceConstants.PROVIDER_OKTA + "#")) {
                    upstreamRefreshService.ensureMigratedFromLegacyIfNeeded(providerUserId, result.record());
                    try {
                        var oktaTokens = upstreamRefreshService.refreshUpstream(providerUserId);
                        refreshResult = authorizerService.completeRefreshWithOktaTokens(
                                userId, provider, request.getResource(), oktaTokens, request.getClientId());
                    } catch (IllegalStateException e) {
                        log.warn("refresh_token grant: upstream refresh lock not acquired: {}", e.getMessage());
                        return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient,
                                Response.status(Response.Status.SERVICE_UNAVAILABLE)
                                        .entity(OAuth2ErrorResponse.of(OAuth2ErrorResponse.ErrorCode.SERVER_ERROR,
                                                "Temporarily unavailable; please retry"))
                                        .build());
                    } catch (UpstreamRefreshTransientException e) {
                        // Cross-region replication lag (peer rotated the upstream token; local pod
                        // hasn't seen it yet even after a brief in-process wait). The user's MoP
                        // refresh-token family is still valid — do NOT revoke. Return 401 so the
                        // client retries; the next attempt typically lands after replication.
                        log.warn("refresh_token grant: transient upstream refresh failure (replication lag): {}", e.getMessage());
                        return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient,
                                Response.status(Response.Status.UNAUTHORIZED)
                                        .entity(OAuth2ErrorResponse.of(
                                                OAuth2ErrorResponse.ErrorCode.INVALID_GRANT,
                                                "Temporarily unavailable; please retry"))
                                        .build());
                    } catch (UpstreamRefreshException e) {
                        log.warn("refresh_token grant failed: centralized upstream refresh: {}", e.getMessage());
                        authorizerService.cleanupAfterTerminalUpstreamRefreshFailure(
                                userId,
                                provider,
                                result.record().encryptedUpstreamRefreshToken());
                        refreshTokenService.revokeFamily(result.record().tokenFamilyId());
                        return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Invalid or expired refresh token"));
                    }
                } else {
                    refreshResult = authorizerService.refreshUpstreamAndGetToken(
                            userId,
                            provider,
                            request.getResource(),
                            result.record().encryptedUpstreamRefreshToken(),
                            request.getClientId()
                    );
                    if (refreshResult != null && refreshResult.newUpstreamRefreshToken() != null
                            && !refreshResult.newUpstreamRefreshToken().isEmpty()) {
                        refreshTokenService.updateUpstreamRefreshForAllRowsWithUserAndProvider(
                                userId,
                                provider,
                                refreshResult.newUpstreamRefreshToken());
                    }
                }
                if (refreshResult == null) {
                    log.error("refresh_token grant failed: upstream refresh failed; revoking token family for userId={} provider={} resource={} tokenFamilyId={} (upstream OAuth error body should appear in ERROR logs from token exchange)",
                            userId, provider, request.getResource(), result.record().tokenFamilyId());
                    refreshTokenService.revokeFamily(result.record().tokenFamilyId());
                    return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Invalid or expired refresh token"));
                }
                TokenResponse withNewRefresh = new TokenResponse(
                        refreshResult.tokenResponse().accessToken(),
                        refreshResult.tokenResponse().tokenType(),
                        refreshResult.tokenResponse().expiresIn(),
                        refreshResult.tokenResponse().scope(),
                        rotateResult.rawToken(),
                        refreshExpirySeconds
                );
                return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, Response.ok(withNewRefresh).build());
            default:
                return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Invalid or expired refresh token"));
        }
    }

    private Response invalidGrant(String message) {
        return Response.status(Response.Status.BAD_REQUEST)
                .entity(OAuth2ErrorResponse.of(OAuth2ErrorResponse.ErrorCode.INVALID_GRANT, message))
                .build();
    }

    /**
     * Internal method to get JWT token
     * Shared by both auth_code and client_credentials flows.
     *
     * <p>For passthrough providers (Google Workspace, GitHub, Slack, Embrace, Atlassian, Okta-as-default)
     * the bearer returned to the client IS the upstream IDP access token. When a second/third MCP
     * client (e.g. Claude after Cursor) joins an existing upstream session, the bare row's access
     * token belongs to whichever client triggered the OIDC callback last — returning it would
     * result in /userinfo's access_token_hash GSI resolving to a row whose partition key collides
     * across clients. To avoid that, when we detect a warm cache + missing per-client row for
     * this {@code clientId}, we mint a fresh upstream bearer via
     * {@link AuthorizerService#mintBearerForWarmCacheClient}.
     */
    private Response getTokenFromResourceAuthorizationServer(String subject, String scopes, String resource, String clientId) {
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

        // Warm auth-code path for passthrough providers: when a per-client bearer row
        // already exists for this (clientId, subject, provider), reuse it; otherwise mint a fresh
        // upstream bearer for this client so /userinfo's GSI lookup resolves deterministically.
        // Audience-style providers (Glean, GCP, Splunk, Grafana, Evaluate, Databricks) do their
        // own per-call exchanged-token mint inside AuthorizerService.getTokenFromAuthorizationServer
        // and write the per-client row from there, so we skip the warm-mint short-circuit for them.
        if (clientId != null && !clientId.isEmpty() && resource != null) {
            ResourceMeta resourceMeta = configService.getResourceMeta(resource);
            String provider = resourceMeta != null ? resourceMeta.idpServer() : configService.getDefaultIDP();
            boolean isPassthrough = resourceMeta == null
                    || resourceMeta.audience() == null
                    || !AudienceConstants.storesExchangedTokenForUserinfo(resourceMeta.audience());
            if (isPassthrough && provider != null) {
                TokenWrapper perClientRow = authorizerService.getUserTokenForClient(subject, provider, clientId);
                if (perClientRow != null && perClientRow.accessToken() != null && !perClientRow.isExpired()) {
                    log.info("Reusing existing per-client bearer row for subject={} provider={} clientId={}", subject, provider, clientId);
                    long expiresIn = perClientRow.ttl() != null
                            ? Math.max(0L, perClientRow.ttl() - (System.currentTimeMillis() / 1000L))
                            : 3600L;
                    return Response.ok(new TokenResponse(
                            perClientRow.accessToken(),
                            "Bearer",
                            expiresIn,
                            scopes
                    )).build();
                }
                TokenWrapper bareRow = authorizationDO.token();
                if (bareRow != null && bareRow.refreshToken() != null && !bareRow.refreshToken().isEmpty()) {
                    TokenResponse minted = authorizerService.mintBearerForWarmCacheClient(
                            subject, provider, resource, clientId, bareRow.refreshToken());
                    if (minted != null) {
                        return Response.ok(minted).build();
                    }
                    log.warn("Warm-mint returned null for subject={} provider={} clientId={}; falling back to passthrough exchange",
                            subject, provider, clientId);
                }
            }
        }

        log.info("Getting JWT for resource: {} and subject: {}", resource, subject);

        TokenResponse response = authorizerService.getTokenFromAuthorizationServer(subject, scopes, resource, authorizationDO.token(), clientId);
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

    @SafeVarargs
    private String firstNonEmpty(Supplier<String>... suppliers) {
        for (Supplier<String> supplier : suppliers) {
            String value = supplier.get();
            if (value != null && !value.isEmpty()) {
                return value;
            }
        }
        return null;
    }

    private Response recordTokenGrant(String resourceUri, String grantType, long startNanos, String oauthClient, Response response) {
        String provider = telemetryProviderResolver.fromResourceUri(resourceUri);
        boolean ok = response.getStatus() == 200;
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        oauthProxyMetrics.recordTokenExchangeDurationE2E(provider, grantType, ok, oauthClient,
                metricsRegionProvider.primaryRegion(), seconds);
        String err = ok ? null : errorTypeForHttpStatus(response.getStatus());
        oauthProxyMetrics.recordTokenIssuance(provider, grantType, ok, err, oauthClient);
        if ("authorization_code".equals(grantType)) {
            oauthProxyMetrics.recordAuthCodeExchange(provider, ok, response.getStatus(), err, oauthClient);
        } else if ("refresh_token".equals(grantType)) {
            oauthProxyMetrics.recordRefreshTokenExchange(provider, ok, response.getStatus(), err, oauthClient);
        } else if ("client_credentials".equals(grantType)) {
            oauthProxyMetrics.recordClientCredentialsGrant(ok, err, oauthClient);
        }
        return response;
    }

    private static String errorTypeForHttpStatus(int status) {
        if (status == 400) {
            return "invalid_grant";
        }
        if (status == 401 || status == 403) {
            return "unauthorized_client";
        }
        if (status >= 500) {
            return "internal";
        }
        return "invalid_grant";
    }
}
