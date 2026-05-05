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
import io.athenz.mop.service.UpstreamExchangeException;
import io.athenz.mop.service.UpstreamProviderClassifier;
import io.athenz.mop.service.UpstreamRefreshException;
import io.athenz.mop.service.UpstreamRefreshResponse;
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
    UpstreamProviderClassifier upstreamProviderClassifier;

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

        Response invalidTarget = validateResourceMappedIfPresent(request);
        if (invalidTarget != null) {
            String oauthClient = telemetryRequestContext.oauthClient();
            String grantType = request.getGrantType() != null ? request.getGrantType() : "unknown";
            oauthProxyMetrics.recordTokenIssuance("unknown", grantType, false, "invalid_target", oauthClient);
            return invalidTarget;
        }

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
     * Reject token requests whose wire {@code resource} parameter does not map to any
     * ResourceMeta we know about, with 400 {@code invalid_target} per RFC 8707 §2. Returns
     * {@code null} (caller proceeds normally) when {@code resource} is absent/blank or when
     * it resolves to a known ResourceMeta (including pattern-matched wildcards).
     *
     * <p>Emits {@code mop_token_resource_validation_total} for every non-blank resource —
     * either {@code (accepted, known_mapped)} or {@code (rejected, unknown_resource)}. Absent
     * or blank resource is intentionally NOT observed, matching the behavior here (no rejection,
     * no counter sample) so dashboards reflect only resources the gate actually inspected.
     */
    private Response validateResourceMappedIfPresent(OAuth2TokenRequest request) {
        String resource = request.getResource();
        if (resource == null || resource.trim().isEmpty()) {
            return null;
        }
        String grantType = request.getGrantType() != null ? request.getGrantType() : "unknown";
        String oauthClient = telemetryRequestContext.oauthClient();
        if (configService.getResourceMeta(resource) != null) {
            oauthProxyMetrics.recordTokenResourceValidation(true, "known_mapped", grantType, oauthClient);
            return null;
        }
        log.warn("Rejecting token request with unknown resource: grant_type={} resource={} clientId={}",
                grantType, resource, request.getClientId());
        oauthProxyMetrics.recordTokenResourceValidation(false, "unknown_resource", grantType, oauthClient);
        return Response.status(Response.Status.BAD_REQUEST)
                .entity(OAuth2ErrorResponse.of(
                        OAuth2ErrorResponse.ErrorCode.INVALID_TARGET,
                        "Unknown resource: " + resource))
                .build();
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
        // provider and audience are declared outside the try/catch so the failure-path ERROR
        // logs below can still report them; resourceMeta lookup itself is cheap and does not
        // throw for unknown resources (returns null), so this does not widen the failure surface.
        ResourceMeta resourceMeta = resource != null ? configService.getResourceMeta(resource) : null;
        String provider = resourceMeta != null ? resourceMeta.idpServer() : configService.getDefaultIDP();
        String audience = resourceMeta != null ? resourceMeta.audience() : null;
        try {
            String providerUserId = provider + "#" + authCode.getSubject();
            String subject = authCode.getSubject();

            // Resolve the upstream refresh token to seed the new MoP refresh-token row with.
            //
            // The order matters and reflects the data flow at consent time:
            //
            //   1. For Okta, the canonical durable upstream RT lives in the
            //      mcp-oauth-proxy-upstream-tokens (L2) table, seeded by
            //      AuthorizerService.storeTokens during the Okta callback. Read that first.
            //
            //   2. For every non-Okta provider (Google/Slack/GitHub/Embrace/...), the
            //      *Resource.authorize callback persists the upstream RT it just received from
            //      the IdP into the mcp-oauth-proxy-tokens table as a bare (lookupKey, provider)
            //      session marker via AuthorizerService.storeTokens. That row carries the
            //      most-recently-issued upstream RT for this (provider, user) pair and is the
            //      authoritative seed for a brand-new MoP refresh-tokens row. Read it before
            //      falling back to the refresh-tokens GSI.
            //
            //      Why this matters: the GSI lookup (step 3) only finds something when at least
            //      one prior MoP refresh-tokens row exists for this (provider, user). On the very
            //      first MoP-side login for a given user/provider (or after every prior row has
            //      been REVOKED), the GSI returns null and the new row would be created with no
            //      upstream RT — the next /token refresh_token call then fails with "no upstream
            //      refresh token", revoking the freshly-issued family. Reading the bare session
            //      marker prevents this orphan-row failure mode.
            //
            //   3. As a final fallback, the refresh-tokens GSI (rotation-aware, sibling-aware).
            //      Note that this path can return a stale or poisoned upstream RT inherited from
            //      a sibling row whose status=ACTIVE only reflects MoP's local belief, not the
            //      IdP's truth — see GoogleWorkspaceResource.lookupExistingUpstreamRefresh for
            //      the inheritance probe that mitigates that for the consent-time write path.
            // For promoted providers (okta + the 12 google-workspace providers) the canonical
            // upstream RT is in the L2 mcp-oauth-proxy-upstream-tokens table; check there first.
            // For native-IdP providers (slack/github/atlassian/embrace) the L2 row is intentionally
            // absent and we go straight to the bare session marker.
            String upstreamRefresh = firstNonEmpty(
                () -> upstreamProviderClassifier.isUpstreamPromoted(provider)
                        ? upstreamRefreshService.getCurrentUpstream(providerUserId)
                                .map(rec -> rec.encryptedOktaRefreshToken())
                                .filter(rt -> rt != null && !rt.isEmpty())
                                .orElse(null)
                        : null,
                () -> readBareSessionMarkerUpstreamRt(subject, provider)
            );
            if (upstreamRefresh == null || upstreamRefresh.isEmpty()) {
                upstreamRefresh = refreshTokenService.getUpstreamRefreshToken(subject, provider);
            }

            // Seed L2 for any promoted provider whose authorize callback just delivered a fresh
            // upstream RT. Idempotent under contention: storeInitialUpstreamToken skips the write
            // when an ACTIVE row already carries the same RT, and re-seeds only when the existing
            // row is non-ACTIVE (revoked) so the user-driven re-consent recovers cleanly.
            if (upstreamProviderClassifier.isUpstreamPromoted(provider)
                    && upstreamRefresh != null && !upstreamRefresh.isEmpty()) {
                upstreamRefreshService.storeInitialUpstreamToken(providerUserId, upstreamRefresh);
            }
            // The audience label (declared above with provider, since we need it in the ERROR
            // logs in the catch) is the resource-side identity (Splunk, Glean, Grafana, ...). It
            // does NOT change the provider column (which remains the IdP — okta, slack, github,
            // etc.). It is recorded purely for diagnostics so that, when scanning the
            // refresh-tokens table by (userId, provider=okta), an operator can tell which audience
            // each Okta-rooted family was minted for. For non-Okta IdPs where audience equals
            // provider, we still record it to keep the column populated and uniform; absence
            // signals an unmapped resource (or the resource didn't declare audience yet).
            // For any promoted provider (okta + the 12 google-workspace providers) the canonical
            // upstream RT lives in L2; do NOT also write it to the legacy
            // encrypted_upstream_refresh_token column on the new MoP refresh-token row. Writing
            // it there would re-introduce the sibling-inheritance trap that motivated the L2
            // promotion (Bug #1) — a stale "ACTIVE" sibling row's column gets read on the next
            // /token even though the L2 row has the truth.
            String mopRefresh = refreshTokenService.store(
                    authCode.getSubject(),
                    request.getClientId(),
                    provider,
                    authCode.getSubject(),
                    upstreamProviderClassifier.isUpstreamPromoted(provider) ? null : upstreamRefresh,
                    audience
            );
            if (mopRefresh == null) {
                // store() returned null — the implementation chose not to persist (e.g. backend
                // unreachable, conditional check failed). The client gets a usable access_token
                // but no refresh_token, which silently degrades sliding-session behavior; raise
                // it to ERROR so operators see it in dashboards. Response stays 200 because the
                // login itself succeeded; only the durability of the refresh path was lost.
                log.error("RefreshTokenService.store returned null; refresh_token will be omitted from response. "
                        + "subject={} clientId={} provider={} audience={} resource={} — "
                        + "client will not be able to slide its session and must re-login when access_token expires.",
                        authCode.getSubject(), request.getClientId(), provider, audience, resourceForMetrics);
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
            // Same contract as the null-return branch above: response stays 200 (the access_token
            // is valid and the user can use the resource), but the refresh path is silently lost.
            // This is the symptom that masked the AWS DBE "No Crypto Action configured" bug for
            // ~7 minutes in stage on 2026-05-03 — the WARN was buried in normal traffic and the
            // exception class/cause were dropped (only e.getMessage() was logged). Promote to
            // ERROR with the full stack trace and the offending exception class so the next
            // regression of this kind is loud and self-explanatory in ops dashboards.
            log.error("Could not create MOP refresh token; refresh_token will be omitted from response. "
                            + "subject={} clientId={} provider={} audience={} resource={} cause={}: {}",
                    authCode.getSubject(), request.getClientId(), provider, audience, resourceForMetrics,
                    e.getClass().getName(), e.getMessage(), e);
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
            case ROTATED_GRACE_SUCCESSOR:
            case ACTIVE:
                if (result.record() == null) {
                    return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Invalid or expired refresh token"));
                }
                RefreshTokenRotateResult rotateResult;
                RefreshTokenRecord rotateSourceRecord;
                if (result.status() == RefreshTokenValidationResult.Status.ROTATED_GRACE_SUCCESSOR) {
                    // Layer 2: client presented a recently-rotated RT. Don't revoke the family —
                    // mint a brand-new RT off the family's most recent ACTIVE descendant so the
                    // duplicate caller still gets working credentials.
                    if (result.successor() == null) {
                        log.warn("refresh_token grant: ROTATED_GRACE_SUCCESSOR with null successor; falling back to invalid_grant userId={} provider={}", userId, provider);
                        return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Invalid or expired refresh token"));
                    }
                    rotateResult = refreshTokenService.rotateGraceSuccessor(result.successor());
                    if (rotateResult == null) {
                        log.warn("refresh_token grant: rotateGraceSuccessor returned null (successor concurrently rotated/revoked); userId={} provider={}", userId, provider);
                        return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Invalid or expired refresh token"));
                    }
                    log.info("refresh_token grant: served via rotated-grace successor userId={} provider={} familyId={}",
                            userId, provider, result.record().tokenFamilyId());
                    rotateSourceRecord = result.successor();
                } else {
                    rotateResult = refreshTokenService.rotate(request.getRefreshToken(), request.getClientId());
                    if (rotateResult == null) {
                        // rotate() returns null in three distinct cases:
                        //   (a) per-RT lock timeout — see preceding WARN from RefreshTokenServiceImpl
                        //       and metric mop_refresh_token_inflight_lock_total{outcome="timeout"};
                        //   (b) ConditionalCheckFailed under lock (row already rotated cross-region) —
                        //       caller's next retry will hit L2 grace;
                        //   (c) row-not-found / validation drift between validate() and rotate().
                        // The per-call inflight-lock metric distinguishes (a) from (b)/(c).
                        log.warn("refresh_token grant failed: rotate() returned null userId={} provider={} clientId={}",
                                userId, provider, request.getClientId());
                        return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Invalid or expired refresh token"));
                    }
                    rotateSourceRecord = result.record();
                }
                String providerUserId = rotateSourceRecord.providerUserId();
                RefreshAndTokenResult refreshResult;
                // Promoted providers (okta + the 12 google-workspace providers) all go through
                // the centralized L2 upstream-refresh path. Native-IdP providers (slack, github,
                // atlassian, embrace, ...) keep using the legacy per-row upstream RT.
                boolean providerPromoted = upstreamProviderClassifier.isUpstreamPromoted(provider);
                if (providerPromoted) {
                    if (providerUserId == null || !providerUserId.contains("#")) {
                        // Defensive: the rotated-source row was written by an old code path that
                        // did not include a provider#sub key. Reconstruct it so the L2 lookup
                        // works. This branch should be unreachable for newly minted rows.
                        providerUserId = provider + "#" + userId;
                    }
                    // Read-side legacy migration. Runs for ANY promoted provider, not just Okta:
                    // the L2 promotion was rolled out *after* Google families were already in
                    // flight under the legacy per-row upstream-RT model. Without this seed step
                    // the very first refresh_token /token call after deployment would find no
                    // L2 row and throw "no upstream RT — re-authentication required", revoking
                    // an otherwise healthy family. Idempotent: storeInitialUpstreamToken inside
                    // ensureMigratedFromLegacyIfNeeded short-circuits when an active row already
                    // exists with the same RT.
                    upstreamRefreshService.ensureMigratedFromLegacyIfNeeded(
                            providerUserId, provider, rotateSourceRecord);
                    try {
                        UpstreamRefreshResponse upstream = upstreamRefreshService.refreshUpstream(
                                providerUserId, provider, request.getClientId());
                        // Reuse completeRefreshWithOktaTokens for every promoted provider — its
                        // Okta-specific work (OktaSessionCache.put) is gated on provider==okta and
                        // the rest of the body (tokenStore write, downstream resource exchange,
                        // bearer index repop) is provider-agnostic. We adapt the response into an
                        // OktaTokens shape so the existing call signature is unchanged.
                        var adapted = new io.athenz.mop.service.OktaTokens(
                                upstream.accessToken(),
                                upstream.refreshToken(),
                                upstream.idToken(),
                                (int) Math.min(Integer.MAX_VALUE, Math.max(0L, upstream.expiresInSeconds())));
                        refreshResult = authorizerService.completeRefreshWithOktaTokens(
                                userId, provider, request.getResource(), adapted, request.getClientId());
                        // After a successful promoted-provider refresh, nullify any legacy
                        // encrypted_upstream_refresh_token columns lingering on per-MCP-client
                        // rows. The L2 row is now the source of truth and a stale legacy column
                        // would re-introduce the sibling-inheritance trap that motivated the
                        // L2 promotion. No-op on the Okta path because Okta rows already write
                        // null into that column on rotation; here we paint over any historical
                        // residue once per (user, provider) pair.
                        if (refreshResult != null && !AudienceConstants.PROVIDER_OKTA.equals(provider)) {
                            refreshTokenService.nullifyLegacyUpstreamColumnForUserProvider(userId, provider);
                        }
                    } catch (IllegalStateException e) {
                        log.warn("refresh_token grant: upstream refresh lock not acquired: {}", e.getMessage());
                        return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient,
                                Response.status(Response.Status.SERVICE_UNAVAILABLE)
                                        .entity(OAuth2ErrorResponse.of(OAuth2ErrorResponse.ErrorCode.SERVER_ERROR,
                                                "Temporarily unavailable; please retry"))
                                        .build());
                    } catch (UpstreamRefreshTransientException e) {
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
                                rotateSourceRecord.encryptedUpstreamRefreshToken());
                        refreshTokenService.revokeFamily(rotateSourceRecord.tokenFamilyId());
                        return recordTokenGrant(resourceUri, "refresh_token", t0, oauthClient, invalidGrant("Invalid or expired refresh token"));
                    }
                } else {
                    refreshResult = authorizerService.refreshUpstreamAndGetToken(
                            userId,
                            provider,
                            request.getResource(),
                            rotateSourceRecord.encryptedUpstreamRefreshToken(),
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
                            userId, provider, request.getResource(), rotateSourceRecord.tokenFamilyId());
                    refreshTokenService.revokeFamily(rotateSourceRecord.tokenFamilyId());
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

        TokenResponse response;
        try {
            response = authorizerService.getTokenFromAuthorizationServer(
                    subject, scopes, resource, authorizationDO.token(), clientId);
        } catch (UpstreamExchangeException e) {
            // Generic upstream-exchange failure (Splunk "Role=… is not grantable", Databricks
            // 401 from workspace, GCP STS 400, etc.) — surface the upstream message verbatim
            // as 401 invalid_token (RFC 6750 §3.1) instead of the historical 500 NPE.
            log.warn("Upstream token exchange failed for subject={} resource={}: {}",
                    subject, resource, e.getMessage());
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(OAuth2ErrorResponse.of(
                            OAuth2ErrorResponse.ErrorCode.INVALID_TOKEN,
                            e.getMessage()))
                    .build();
        }
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

    /**
     * Read the upstream refresh token from the bare {@code (key, provider)} session marker row
     * that {@code AuthorizerService.storeTokens} writes to {@code mcp-oauth-proxy-tokens} during
     * the IdP callback (e.g. {@code GoogleWorkspaceResource.authorize}). This row carries the
     * most-recently-issued upstream RT for this {@code (provider, user)} pair regardless of
     * whether any MoP refresh-tokens row exists yet, and is the only seed source that survives
     * a fully-cleared family table.
     *
     * <p>The session marker is keyed by {@code lookupKey} (the value returned by
     * {@code getUsername} for the provider, often but not always equal to the OAuth subject).
     * The {@code /token} request only carries the OAuth {@code subject} from the auth code, so
     * we read by {@code subject} first; for providers whose username claim differs, the
     * fallback caller should pass the {@code lookupKey} variant on a subsequent call. In
     * practice for Google {@code subject == lookupKey} since the username claim is the Google
     * subject. Returns {@code null} for Okta (which uses the dedicated L2 upstream-tokens
     * table) and when no marker row is found.
     */
    private String readBareSessionMarkerUpstreamRt(String key, String provider) {
        if (AudienceConstants.PROVIDER_OKTA.equals(provider) || key == null || provider == null) {
            return null;
        }
        TokenWrapper marker = authorizerService.getUserToken(key, provider);
        if (marker != null && marker.refreshToken() != null && !marker.refreshToken().isEmpty()) {
            return marker.refreshToken();
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
