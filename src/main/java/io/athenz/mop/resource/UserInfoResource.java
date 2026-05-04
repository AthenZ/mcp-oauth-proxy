/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.resource;

import io.athenz.mop.config.OktaSessionCacheConfig;
import io.athenz.mop.model.BearerIndexRecord;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.service.AudienceConstants;
import io.athenz.mop.service.BearerIndexRegionResolver;
import io.athenz.mop.service.BearerIndexResolution;
import io.athenz.mop.service.OktaTokens;
import io.athenz.mop.service.UpstreamRefreshException;
import io.athenz.mop.service.UpstreamRefreshService;
import io.athenz.mop.service.UserTokenRegionResolver;
import io.athenz.mop.store.BearerIndexStore;
import io.athenz.mop.store.TokenStore;
import io.athenz.mop.telemetry.ExchangeStep;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import io.athenz.mop.util.JwtUtils;
import jakarta.inject.Inject;
import java.util.Date;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("/userinfo")
public class UserInfoResource {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final long TOKEN_STORE_TTL_GRACE_SECONDS = 300L;

    @Inject
    TokenStore tokenStore;

    @Inject
    BearerIndexStore bearerIndexStore;

    @Inject
    BearerIndexRegionResolver bearerIndexRegionResolver;

    @Inject
    UserTokenRegionResolver userTokenRegionResolver;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    @Inject
    TelemetryRequestContext telemetryRequestContext;

    @Inject
    UpstreamRefreshService upstreamRefreshService;

    @Inject
    OktaSessionCacheConfig oktaSessionCacheConfig;

    @ConfigProperty(name = "server.athenz.user-prefix", defaultValue = "")
    String userPrefix;

    @GET
    @Path("/")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUserInfo(@HeaderParam("Authorization") String authorization) {
        long startNanos = System.nanoTime();
        // Validate Authorization header
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            log.warn("Missing or invalid Authorization header");
            return finishUserinfo(startNanos, "unknown", false, 401, "invalid_token", "missing_bearer",
                    Response.status(Response.Status.UNAUTHORIZED)
                            .entity(Map.of(
                                    "error", "invalid_token",
                                    "error_description", "Missing or invalid Authorization header"
                            ))
                            .type(MediaType.APPLICATION_JSON)
                            .build());
        }

        String accessToken = authorization.substring("Bearer ".length());
        log.info("Processing userinfo request");
        String accessTokenHash = JwtUtils.hashAccessToken(accessToken);
        BearerIndexResolution bearerResolution = bearerIndexRegionResolver.resolveByHash(accessTokenHash);
        BearerIndexRecord bearerRow = bearerResolution.record();
        boolean fromFallback = bearerResolution.resolvedFromFallback();

        if (bearerRow == null) {
            log.debug("Bearer-index row not found for userinfo lookup");
            return finishUserinfo(startNanos, "unknown", false, 401, "invalid_token", "token_not_found",
                    Response.status(Response.Status.UNAUTHORIZED)
                            .entity(Map.of(
                                    "error", "invalid_token",
                                    "error_description", "Token not found"
                            ))
                            .type(MediaType.APPLICATION_JSON)
                            .build());
        }

        long currentTime = Instant.now().getEpochSecond();
        // Prefer the bearer's own exp when known; otherwise fall back to ttl. Either way, a
        // present-or-past exp/ttl means the bearer has expired and the index row should be
        // garbage-collected by DDB TTL — we 401 here so MCP clients refresh.
        long expiry = bearerRow.exp() > 0 ? bearerRow.exp() : bearerRow.ttl();
        if (expiry > 0 && currentTime >= expiry) {
            log.warn("Bearer expired per bearer-index. Current time: {}, exp: {}, ttl: {}",
                    currentTime, bearerRow.exp(), bearerRow.ttl());
            String p = OauthProviderLabel.normalize(bearerRow.provider());
            return finishUserinfo(startNanos, p, false, 401, "invalid_token", "token_expired",
                    Response.status(Response.Status.UNAUTHORIZED)
                            .entity(Map.of(
                                    "error", "invalid_token",
                                    "error_description", "Token has expired"
                            ))
                            .type(MediaType.APPLICATION_JSON)
                            .build());
        }

        String user = bearerRow.userId();
        String bearerClientId = bearerRow.clientId();
        String bearerProvider = bearerRow.provider();
        String providerLabel = OauthProviderLabel.normalize(bearerProvider);
        telemetryRequestContext.setOauthProvider(providerLabel);
        log.info("Resolved bearer-index row for user: {}, provider: {}, clientId: {} (fromFallback={})",
                user, bearerProvider, bearerClientId, fromFallback);

        TokenWrapper oktaToken = userTokenRegionResolver
                .resolveByUserProvider(user, AudienceConstants.PROVIDER_OKTA,
                        UserTokenRegionResolver.CALL_SITE_USERINFO_OKTA_LOOKUP)
                .token();

        String idToken = oktaToken != null ? oktaToken.idToken() : null;
        boolean idTokenStrictlyFresh = idToken != null && !idToken.isEmpty()
                && jwtExpInFuture(idToken, /* skewSeconds= */ 0);

        if (!idTokenStrictlyFresh) {
            log.info("Okta id_token expired or absent for user: {} (idTokenPresent={}); attempting upstream refresh",
                    user, idToken != null && !idToken.isEmpty());
            String priorIdToken = idToken;
            TokenWrapper refreshed = tryRefreshOktaToken(user);
            if (refreshed != null && refreshed.idToken() != null && !refreshed.idToken().isEmpty()) {
                oktaToken = refreshed;
                idToken = refreshed.idToken();
                if (oktaSessionCacheConfig.enabled()) {
                    oauthProxyMetrics.recordUserinfoOktaCacheOutcome(
                            priorIdToken == null || priorIdToken.isEmpty() ? "absent_refreshed" : "expired_refreshed");
                }
            } else if (priorIdToken != null && !priorIdToken.isEmpty()) {
                // Stale-claims fallback: refresh failed but the cache held a parseable id_token.
                // The gateway is holding a still-valid upstream-provider bearer; do not 401 just
                // because our cached Okta id_token expired. Identity claims (sub/email/short_id)
                // are stable across refreshes within one Okta session, and buildUserInfo strips
                // iat/exp from the response, so the response is functionally equivalent.
                log.warn("Okta upstream refresh failed for user: {}; serving userinfo from stale cached id_token claims", user);
                if (oktaSessionCacheConfig.enabled()) {
                    oauthProxyMetrics.recordUserinfoOktaCacheOutcome("stale_claims_served");
                }
                idToken = priorIdToken;
            }
        } else if (oktaSessionCacheConfig.enabled()) {
            oauthProxyMetrics.recordUserinfoOktaCacheOutcome("fresh_hit");
        }

        if (idToken == null || idToken.isEmpty()) {
            log.error("Okta id_token still unavailable after refresh attempt for user: {}", user);
            return finishUserinfo(startNanos, providerLabel, false, 401, "server_error", "okta_upstream_refresh_failed",
                    Response.status(Response.Status.UNAUTHORIZED)
                            .entity(Map.of(
                                    "error", "server_error",
                                    "error_description", "Okta token record not found"
                            ))
                            .type(MediaType.APPLICATION_JSON)
                            .build());
        }

        Map<String, Object> userInfo = buildUserInfo(idToken, bearerProvider);
        // Surface mcp_client_id from the bearer-index row when present (omitted for legacy
        // bare-row bearers minted before the index existed; those go through the natural
        // 401-then-refresh drain at rollout time).
        if (bearerClientId != null && !bearerClientId.isEmpty() && !userInfo.isEmpty()) {
            userInfo.put("mcp_client_id", bearerClientId);
        }
        log.info("Successfully returned userinfo for user={} provider={} clientId={} (claims not logged)",
                user, bearerProvider, bearerClientId);
        return finishUserinfo(startNanos, providerLabel, true, 200, null, null,
                Response.ok(userInfo).type(MediaType.APPLICATION_JSON).build());
    }

    private Response finishUserinfo(long startNanos, String oauthProvider, boolean success, int httpStatus,
                                    String errorType, String userinfoFailureReason, Response response) {
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        oauthProxyMetrics.recordUserinfoDuration(oauthProvider, success, userinfoFailureReason, seconds);
        oauthProxyMetrics.recordUserinfoRequest(oauthProvider, success, httpStatus, errorType, userinfoFailureReason);
        return response;
    }

    /**
     * Attempt to refresh the Okta id_token via the centralized upstream refresh store.
     * Uses the same distributed lock and optimistic versioning as the /token refresh_token grant.
     *
     * @return refreshed Okta TokenWrapper (stored in token store), or null on any failure
     */
    private TokenWrapper tryRefreshOktaToken(String user) {
        long t0 = System.nanoTime();
        try {
            String subject = (userPrefix != null && !userPrefix.isEmpty() && user.startsWith(userPrefix))
                    ? user.substring(userPrefix.length())
                    : user;
            String providerUserId = AudienceConstants.PROVIDER_OKTA + "#" + subject;
            OktaTokens oktaTokens = upstreamRefreshService.refreshUpstream(providerUserId);
            if (oktaTokens == null || oktaTokens.idToken() == null || oktaTokens.idToken().isEmpty()) {
                log.warn("Upstream Okta refresh returned no id_token for user: {}", user);
                recordUserinfoUpstreamRefresh(t0, false);
                return null;
            }
            long ttlSec = oktaTokens.expiresIn() > 0 ? oktaTokens.expiresIn() : 3600L;
            long absoluteTtl = Instant.now().getEpochSecond() + ttlSec + TOKEN_STORE_TTL_GRACE_SECONDS;
            TokenWrapper refreshed = new TokenWrapper(
                    user,
                    AudienceConstants.PROVIDER_OKTA,
                    oktaTokens.idToken(),
                    oktaTokens.accessToken(),
                    oktaTokens.refreshToken(),
                    absoluteTtl
            );
            tokenStore.storeUserToken(user, AudienceConstants.PROVIDER_OKTA, refreshed);
            // Index the freshly-rotated Okta bearer so the very next /userinfo call (or any
            // /userinfo from a different pod that lands on this same bearer) resolves via the
            // dedicated bearer-index table. The clientId is unknown at this site (no MCP client
            // is in play during the upstream-refresh fan-out), so the row stores the bearer with
            // an empty clientId — acceptable, since /userinfo only surfaces mcp_client_id when
            // it is non-empty.
            try {
                String hash = JwtUtils.hashAccessToken(oktaTokens.accessToken());
                long exp = Instant.now().getEpochSecond() + ttlSec;
                bearerIndexStore.putBearer(hash, user, "", AudienceConstants.PROVIDER_OKTA, exp, absoluteTtl);
                oauthProxyMetrics.recordBearerIndexWrite(true);
            } catch (Exception e) {
                log.warn("bearer-index write failed inside tryRefreshOktaToken for user={}: {}", user, e.getMessage());
                oauthProxyMetrics.recordBearerIndexWrite(false);
            }
            log.info("Stored refreshed Okta tokens for user: {} via /userinfo upstream refresh", user);
            recordUserinfoUpstreamRefresh(t0, true);
            return refreshed;
        } catch (UpstreamRefreshException e) {
            log.warn("Upstream Okta refresh failed for user {}: {}", user, e.getMessage());
            recordUserinfoUpstreamRefresh(t0, false);
            return null;
        } catch (IllegalStateException e) {
            log.warn("Could not acquire upstream refresh lock for user {}: {}", user, e.getMessage());
            recordUserinfoUpstreamRefresh(t0, false);
            return null;
        }
    }

    /**
     * Returns {@code true} when the JWT's {@code exp} claim is in the future by at least
     * {@code skewSeconds}. Returns {@code false} on parse failure or when the claim is absent —
     * the caller treats that as "not fresh" and falls through to the upstream-refresh path.
     */
    static boolean jwtExpInFuture(String token, long skewSeconds) {
        if (token == null || token.isEmpty()) {
            return false;
        }
        Object claim = JwtUtils.getClaimFromToken(token, "exp");
        if (claim == null) {
            return false;
        }
        long expEpoch;
        if (claim instanceof Date d) {
            expEpoch = d.toInstant().getEpochSecond();
        } else if (claim instanceof Number n) {
            expEpoch = n.longValue();
        } else {
            return false;
        }
        return (expEpoch - Instant.now().getEpochSecond()) >= skewSeconds;
    }

    private void recordUserinfoUpstreamRefresh(long startNanos, boolean success) {
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        oauthProxyMetrics.recordExchangeStep(ExchangeStep.UPSTREAM_REFRESH, OauthProviderLabel.OKTA, success,
                success ? null : "unauthorized", "", metricsRegionProvider.primaryRegion(), seconds);
    }

    /**
     * Builds a userinfo response with all claims from the id_token.
     *
     * @param idToken The id_token JWT
     * @return Map containing all claims from the id_token
     */
    private Map<String, Object> buildUserInfo(String idToken, String provider) {
        Map<String, Object> allClaims = JwtUtils.getAllClaimsFromToken(idToken);
        if (allClaims == null) {
            log.warn("Failed to extract claims from id_token");
            return new HashMap<>();
        }

        Map<String, Object> userInfo = new HashMap<>();
        for (Map.Entry<String, Object> entry : allClaims.entrySet()) {
            String claimName = entry.getKey();
            // Exclude JWT metadata claims and specific internal claims that shouldn't be in userinfo response
            // Standard OIDC userinfo should include: sub, name, given_name, family_name,
            // middle_name, nickname, preferred_username, profile, picture, website,
            // email, email_verified, gender, birthdate, zoneinfo, locale, phone_number,
            // phone_number_verified, address, updated_at, and any custom claims
            if (!claimName.equals("iat") && !claimName.equals("exp") &&
                !claimName.equals("nbf") && !claimName.equals("jti") &&
                !claimName.equals("iss") && !claimName.equals("aud") &&
                !claimName.equals("azp") && !claimName.equals("nonce") &&
                !claimName.equals("auth_time") && !claimName.equals("at_hash") &&
                !claimName.equals("c_hash") && !claimName.equals("ver") &&
                !claimName.equals("personId") && !claimName.equals("countryCode") &&
                !claimName.equals("user_contingent_type") && !claimName.equals("amr")) {
                userInfo.put(claimName, entry.getValue());
            }
        }
        if (!userInfo.isEmpty()) {
            userInfo.put("mcp_resource_idp", provider);
        }
        return userInfo;
    }
}
