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
package io.athenz.mop.service;

import com.yahoo.athenz.zms.Access;
import com.yahoo.athenz.zms.ZMSClient;
import io.athenz.mop.model.*;
import io.athenz.mop.store.BearerIndexStore;
import io.athenz.mop.store.TokenStore;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.util.JwtUtils;
import io.quarkus.oidc.RefreshToken;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.util.Date;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class AuthorizerService {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String TOKEN_TYPE = "Bearer";
    /** Grace period (seconds) added to token expiry when storing in the token store so the record is not evicted right away. */
    private static final long TOKEN_STORE_TTL_GRACE_SECONDS = 300L; // 5 minutes

    @Inject
    ZMSClient zmsClient;

    @ConfigProperty(name = "server.athenz.user-prefix")
    String userPrefix;

    @Inject
    TokenStore tokenStore;

    @Inject
    TokenExchangeServiceProducer tokenExchangeServiceProducer;

    @ConfigProperty(name = "server.token-store.expiry", defaultValue = "300")
    Long ttl;

    @ConfigProperty(name = "server.athenz.authorization-domain")
    String authorizationDomain;

    @ConfigProperty(name = "server.athenz.authorization-action")
    String authorizationAction;

    @ConfigProperty(name = "server.athenz.resource-authorization", defaultValue = "false")
    boolean zmsResourceAuthorization;

    @Inject
    ConfigService configService;

    @Inject
    ExchangedTokenUserinfoStoreProviderResolver exchangedTokenUserinfoStoreProviderResolver;

    @Inject
    UserTokenRegionResolver userTokenRegionResolver;

    @Inject
    RefreshCoordinationService refreshCoordinationService;

    @Inject
    RefreshTokenService refreshTokenService;

    @Inject
    OktaSessionCache oktaSessionCache;

    @Inject
    io.athenz.mop.config.OktaSessionCacheConfig oktaSessionCacheConfig;

    @Inject
    UpstreamRefreshService upstreamRefreshService;

    @Inject
    BearerIndexStore bearerIndexStore;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    UpstreamProviderClassifier upstreamProviderClassifier;

    @Inject
    IdpSessionCache idpSessionCache;

    /**
     * Best-effort write of one row to {@code mcp-oauth-proxy-bearer-index}. Failures are
     * swallowed and recorded via {@code mop_bearer_index_write_total{outcome=failure}}; the
     * bearer is still returned to the MCP client and the next /userinfo call will 401 once,
     * triggering a transparent client refresh that repopulates the index.
     */
    void writeBearerIndex(String accessToken, String userId, String clientId, String provider,
                          long absoluteTtlEpochSeconds) {
        if (accessToken == null || accessToken.isEmpty() || userId == null || userId.isEmpty()
                || provider == null || provider.isEmpty()) {
            return;
        }
        try {
            String hash = JwtUtils.hashAccessToken(accessToken);
            long exp = expFromJwtOrTtlMinusGrace(accessToken, absoluteTtlEpochSeconds);
            bearerIndexStore.putBearer(hash, userId, clientId, provider, exp, absoluteTtlEpochSeconds);
            oauthProxyMetrics.recordBearerIndexWrite(true);
        } catch (Exception e) {
            log.warn("bearer-index write failed for userId={} clientId={} provider={}: {}",
                    userId, clientId, provider, e.getMessage());
            oauthProxyMetrics.recordBearerIndexWrite(false);
        }
    }

    /**
     * Resolve the bearer's own {@code exp} epoch seconds. Prefer the JWT's {@code exp} claim when
     * present (works for Okta-issued and other JWT bearers); fall back to the storage ttl minus the
     * 5-minute grace we add when persisting (so the index row carries a value that is &le; ttl).
     */
    private long expFromJwtOrTtlMinusGrace(String accessToken, long absoluteTtlEpochSeconds) {
        try {
            Object claim = JwtUtils.getClaimFromToken(accessToken, "exp");
            if (claim instanceof Date d) {
                return d.toInstant().getEpochSecond();
            }
            if (claim instanceof Number n) {
                return n.longValue();
            }
        } catch (Exception ignored) {
            // not a JWT (opaque bearer) or parse failed; fall through to ttl-derived exp
        }
        long derived = absoluteTtlEpochSeconds - TOKEN_STORE_TTL_GRACE_SECONDS;
        return derived > 0 ? derived : absoluteTtlEpochSeconds;
    }

    /**
     * Compose the DynamoDB partition-key value for a per-MCP-client bearer row in
     * {@code mcp-oauth-proxy-tokens}. Falls back to the bare {@code user} when {@code clientId}
     * is null/blank so unauthenticated edge paths degrade to today's behavior. Sanitizes any
     * '#' in {@code clientId} (defense-in-depth; DCR registration also rejects '#').
     */
    /**
     * Compose the {@code "okta#<sub>"} {@code providerUserId} used as the shared Okta upstream
     * session cache key. {@code lookupKey} is the prefixed user form stored in DDB partition
     * keys ({@code userPrefix + sub}); we strip {@code userPrefix} here so the key matches the
     * one written by {@code UpstreamRefreshService} / {@code TokenResource}. Returns
     * {@code null} when {@code lookupKey} is blank.
     */
    String oktaProviderUserId(String lookupKey) {
        return userProviderKey(lookupKey, AudienceConstants.PROVIDER_OKTA);
    }

    /**
     * Compose the canonical L2 row key {@code "<provider>#<sub>"} for any promoted upstream IdP.
     * Strips the configured {@code userPrefix} so the key shape matches what {@link UpstreamRefreshService}
     * writes. Returns {@code null} when either argument is blank.
     */
    String userProviderKey(String lookupKey, String provider) {
        if (lookupKey == null || lookupKey.isEmpty() || provider == null || provider.isEmpty()) {
            return null;
        }
        String subject = (userPrefix != null && !userPrefix.isEmpty() && lookupKey.startsWith(userPrefix))
                ? lookupKey.substring(userPrefix.length())
                : lookupKey;
        if (subject.isEmpty()) {
            return null;
        }
        return provider + "#" + subject;
    }

    static String compositeUserKey(String clientId, String user) {
        if (clientId == null || clientId.isEmpty()) {
            return user;
        }
        String safeClientId = clientId.indexOf('#') >= 0 ? clientId.replace("#", "_") : clientId;
        return safeClientId + "#" + user;
    }

    /**
     * Backward-compatible overload that delegates with {@code clientId=null}. Only writes the
     * bare {@code (lookupKey, provider)} row. New callers should pass {@code clientId} via the
     * 6-arg overload so a per-client bearer row is also written.
     */
    public void storeTokens(String lookupKey, JsonWebToken idToken, JsonWebToken accessToken, RefreshToken refreshToken, String provider) {
        storeTokens(lookupKey, idToken, accessToken, refreshToken, provider, null);
    }

    public void storeTokens(String lookupKey, JsonWebToken idToken, JsonWebToken accessToken, RefreshToken refreshToken, String provider, String clientId) {
        String user = userPrefix + accessToken.getName();
        storeTokens(
                user,
                lookupKey,
                idToken != null ? idToken.getRawToken() : null,
                accessToken.getRawToken(),
                refreshToken != null ? refreshToken.getToken() : null,
                provider,
                clientId
        );
    }

    /**
     * Store both the bare upstream-session-marker row {@code (lookupKey, provider)} (used by
     * AuthorizeResource to skip upstream OAuth on subsequent MCP clients and by TokenResource's
     * upstream-RT inheritance chain) AND a per-MCP-client bearer row
     * {@code (clientId#lookupKey, provider)} (resolved by /userinfo via the access_token_hash GSI).
     * When {@code clientId} is null/empty (legacy callers), only the bare row is written.
     */
    /**
     * Backward-compatible overload that delegates with {@code clientId=null}. Only writes the
     * bare {@code (lookupKey, provider)} row. Prefer the 7-arg overload for new callers.
     */
    public void storeTokens(String user, String lookupKey, String idToken, String accessToken, String refreshToken, String provider) {
        storeTokens(user, lookupKey, idToken, accessToken, refreshToken, provider, null);
    }

    public void storeTokens(String user, String lookupKey, String idToken, String accessToken, String refreshToken, String provider, String clientId) {
        log.info("storing tokens for lookupKey: {} and user: {} from provider: {} (clientId={})", lookupKey, user, provider, clientId);
        long nowSeconds = Instant.now().getEpochSecond();
        long absoluteTtl = nowSeconds + ttl + TOKEN_STORE_TTL_GRACE_SECONDS;
        TokenWrapper cachedToken = new TokenWrapper(
                user,
                provider,
                idToken,
                accessToken,
                refreshToken,
                absoluteTtl
        );
        // The bare (lookupKey, provider) row is still the upstream-IDP session marker that
        // AuthorizeResource:193 / TokenResource's firstNonEmpty inheritance and the Okta
        // OktaSessionCache repopulation path both read; keep writing it.
        tokenStore.storeUserToken(lookupKey, provider, cachedToken);
        // The per-client (clientId#lookupKey, provider) row is no longer written. Bearer
        // resolution now goes through the dedicated mcp-oauth-proxy-bearer-index table; that
        // is the canonical /userinfo lookup, immune to the multi-window access-token-hash
        // clobber that motivated this change.
        writeBearerIndex(accessToken, lookupKey, clientId, provider, absoluteTtl);
        if (upstreamProviderClassifier.isUpstreamPromoted(provider)) {
            // Login (and any other promoted-IdP write) is the canonical seeder of the upstream
            // tiers:
            //   L0 (per-pod IdpSessionCache for promoted Google providers / OktaSessionCache for Okta)
            //   L1 (bare (userId, provider) row in mcp-oauth-proxy-tokens, written above)
            //   L2 (mcp-oauth-proxy-upstream-tokens, canonical RT for the (provider, sub) pair)
            //
            // Without the L2 seed, refresh works only as long as L0/L1 stay warm; the next
            // refresh after they expire reads L2, finds nothing, and the family is terminally
            // revoked with "No upstream refresh token" — exactly the gslides Bug #2 we're
            // promoting Google providers to L2 to fix. Seeding L2 here makes the upstream RT
            // durable across pod restarts, cache evictions, and cross-region failovers.
            //
            // Native-IdP providers (Slack, GitHub, Atlassian, Embrace) are out of scope: they
            // continue to read/write the legacy per-row encrypted_upstream_refresh_token.
            String providerUserId = userProviderKey(lookupKey, provider);
            if (providerUserId != null) {
                if (AudienceConstants.PROVIDER_OKTA.equals(provider)) {
                    if (oktaSessionCacheConfig.enabled() && idToken != null && !idToken.isEmpty()) {
                        oktaSessionCache.put(providerUserId,
                                OktaSessionEntry.from(idToken, accessToken, refreshToken));
                    }
                } else if (clientId != null && !clientId.isEmpty()) {
                    // Per-client L0 cell for promoted Google providers. Sub is the part after
                    // the provider#: same as L2 row key shape.
                    String sub = providerUserId.substring(provider.length() + 1);
                    String clientKey = IdpSessionCache.clientKey(clientId, provider, sub);
                    if (clientKey != null && accessToken != null && !accessToken.isEmpty()) {
                        long now = Instant.now().getEpochSecond();
                        long expiresIn = Math.max(0L, absoluteTtl - TOKEN_STORE_TTL_GRACE_SECONDS - now);
                        idpSessionCache.put(clientKey,
                                IdpSessionEntry.from(accessToken, idToken, expiresIn, now));
                    }
                }
                if (refreshToken != null && !refreshToken.isEmpty()) {
                    // storeInitialUpstreamToken is idempotent: it skips the write when a non-empty
                    // ACTIVE row already exists, preventing relogin from downgrading a freshly-
                    // rotated upstream RT back to the OIDC-session value. For non-ACTIVE rows
                    // (REVOKED_INVALID_GRANT) it re-seeds with version=1 — that's the explicit
                    // "log in again after revoke" recovery path.
                    upstreamRefreshService.storeInitialUpstreamToken(providerUserId, refreshToken);
                }
            }
        }
    }

    public TokenWrapper getUserToken(String lookupKey, String provider) {
        return userTokenRegionResolver
                .resolveByUserProvider(lookupKey, provider, UserTokenRegionResolver.CALL_SITE_AUTHORIZER_GET_USER_TOKEN)
                .token();
    }

    /**
     * Read the per-MCP-client bearer row {@code (clientId#lookupKey, provider)} if present.
     * Returns {@code null} when {@code clientId} is null/empty (no composite key to construct)
     * or when no such row exists.
     */
    public TokenWrapper getUserTokenForClient(String lookupKey, String provider, String clientId) {
        if (clientId == null || clientId.isEmpty()) {
            return null;
        }
        return userTokenRegionResolver
                .resolveByUserProvider(compositeUserKey(clientId, lookupKey), provider,
                        UserTokenRegionResolver.CALL_SITE_AUTHORIZER_GET_USER_TOKEN)
                .token();
    }

    public AuthorizationResultDO authorize(String subject, String scopes, String resource) {
        log.info("check authorization for subject: {} scopes: {} resource: {}", subject, scopes, resource);
        ResourceMeta resourceMeta = configService.getResourceMeta(resource);
        String provider = resourceMeta != null ? resourceMeta.idpServer() : configService.getDefaultIDP();
        TokenWrapper token = userTokenRegionResolver
                .resolveByUserProvider(subject, provider, UserTokenRegionResolver.CALL_SITE_AUTHORIZE_USER_TOKEN)
                .token();

        if (token == null) {
            return new AuthorizationResultDO(AuthResult.EXPIRED, null);
        }
        String userFromToken = token.key();
        log.info("{} logged in within last X minutes", userFromToken);
        // TODO: This is broken until we implement okta uid to zms user mapping
        if (zmsResourceAuthorization) {
            String zmsAction = authorizationAction;
            String zmsResource = authorizationDomain + ":" + resource;
            log.info("making zms access call for action: {} and resource: {} for userFromToken: {}", zmsAction, zmsResource, userFromToken);
            Access access = zmsClient.getAccessExt(zmsAction, zmsResource, null, userFromToken);
            if (!access.getGranted()) {
                return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
            }
        }
        return new AuthorizationResultDO(AuthResult.AUTHORIZED, token);
    }

    /**
     * Backward-compatible overload (no clientId; per-client bearer row not written). Prefer
     * the 5-arg variant.
     */
    public TokenResponse getTokenFromAuthorizationServer(String subject, String scopes, String resource, TokenWrapper token) {
        return getTokenFromAuthorizationServer(subject, scopes, resource, token, null);
    }

    public TokenResponse getTokenFromAuthorizationServer(String subject, String scopes, String resource, TokenWrapper token, String clientId) {
        TokenResponse tokenResponse;
        ResourceMeta resourceMeta = configService.getResourceMeta(resource);
        if (resourceMeta == null) {
            log.error("no resource meta found for resource: {}", resource);
            return null;
        }

        TokenExchangeService accessTokenIssuer = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(resourceMeta.authorizationServer());
        if (resourceMeta.jagEnabled()) {
            // TODO: validate that requested scopes are part of resourceMeta.scopes()
            // as of now we are ignoring the requested scopes and using the ones defined in resource meta
            TokenExchangeService jagTokenIssuer = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(resourceMeta.jagIssuer());

            TokenExchangeDO jagTokenRequestDO = new TokenExchangeDO(
                    resourceMeta.scopes(),
                    resource,
                    resourceMeta.domain(),
                    configService.getRemoteServerEndpoint(resourceMeta.jagIssuer()),
                    token
            );

            AuthorizationResultDO jagDO = jagTokenIssuer.getJWTAuthorizationGrantFromIdentityProvider(jagTokenRequestDO);
            TokenExchangeDO accessTokenRequestDO = new TokenExchangeDO(
                    resourceMeta.scopes(),
                    resource,
                    resourceMeta.domain(),
                    configService.getRemoteServerEndpoint(resourceMeta.authorizationServer()),
                    jagDO.token()
            );
            AuthorizationResultDO atDO = accessTokenIssuer.getAccessTokenFromResourceAuthorizationServer(accessTokenRequestDO);
            requireUpstreamAuthorized(atDO, resource, token);

            log.info("token-exchange response: ttl: {}", atDO.token().ttl());

            tokenResponse = new TokenResponse(
                    atDO.token().accessToken(),
                    TOKEN_TYPE,
                    sanitizeExpiresIn(atDO.token().ttl()),
                    tokenResponseScope(atDO, resourceMeta)
            );

        } else {

            TokenExchangeDO accessTokenRequestDO = new TokenExchangeDO(
                    resourceMeta.scopes(),
                    resource,
                    resourceMeta.domain(),
                    configService.getRemoteServerEndpoint(resourceMeta.authorizationServer()),
                    token
            );
            AuthorizationResultDO atDO = accessTokenIssuer.getAccessTokenFromResourceAuthorizationServer(accessTokenRequestDO);
            requireUpstreamAuthorized(atDO, resource, token);

            log.info("non token-exchange response: ttl: {}", atDO.token().ttl());

            storeExchangedTokenByAudienceIfNeeded(resource, token, atDO.token(), clientId);

            tokenResponse = new TokenResponse(
                    atDO.token().accessToken(),
                    TOKEN_TYPE,
                    sanitizeExpiresIn(atDO.token().ttl()),
                    tokenResponseScope(atDO, resourceMeta)
            );
        }
        return tokenResponse;
    }

    /**
     * Guard the two {@link #getTokenFromAuthorizationServer} branches against the historical NPE
     * site where {@code atDO.token().ttl()} was dereferenced unconditionally on failure (every
     * audience-style provider returns {@code AuthorizationResultDO(UNAUTHORIZED, null)} on error).
     *
     * <p>Throws {@link UpstreamExchangeException} carrying the upstream provider's
     * {@link AuthorizationResultDO#errorMessage()} so {@link
     * io.athenz.mop.resource.TokenResource} can surface it as a 401 {@code invalid_token} body.
     * Generic for every audience provider — no provider-specific branching.</p>
     */
    private static void requireUpstreamAuthorized(AuthorizationResultDO atDO, String resource, TokenWrapper token) {
        if (atDO != null && atDO.token() != null && atDO.authResult() == AuthResult.AUTHORIZED) {
            return;
        }
        String upstream = atDO != null ? atDO.errorMessage() : null;
        log.warn("Access-token exchange failed for resource={} subject={} authResult={} upstream={}",
                resource,
                token != null ? token.key() : null,
                atDO != null ? atDO.authResult() : "null",
                upstream);
        throw new UpstreamExchangeException(
                upstream != null ? upstream : "upstream token exchange failed; see server logs");
    }

    private static String tokenResponseScope(AuthorizationResultDO atDO, ResourceMeta resourceMeta) {
        if (atDO != null && StringUtils.isNotBlank(atDO.oauthScope())) {
            return atDO.oauthScope();
        }
        return resourceMeta != null ? resourceMeta.scopes().toString() : "";
    }

    /**
     * Store exchanged token in DynamoDB when the resource has an audience that uses a dedicated provider
     * (Glean, Gcp Monitoring, Gcp Logging, Splunk). Stores with provider = audience so /userinfo can resolve by token.
     *
     * @param resource The resource URI being accessed
     * @param oktaToken The original Okta token containing the user/subject
     * @param exchangedToken The token obtained from token exchange
     */
    private void storeExchangedTokenByAudienceIfNeeded(String resource, TokenWrapper oktaToken, TokenWrapper exchangedToken, String clientId) {
        ResourceMeta resourceMeta = configService.getResourceMeta(resource);
        if (resourceMeta == null || resourceMeta.audience() == null) {
            return;
        }
        String audience = resourceMeta.audience();
        if (!AudienceConstants.storesExchangedTokenForUserinfo(audience)) {
            return;
        }
        String storeProvider = exchangedTokenUserinfoStoreProviderResolver.resolve(resource, audience);
        log.info("Storing exchanged token for user: {} provider: {} clientId: {}", oktaToken.key(), storeProvider, clientId);

        long nowSeconds = Instant.now().getEpochSecond();
        long absoluteTtl = nowSeconds + (exchangedToken.ttl() != null ? exchangedToken.ttl() : 3600L) + TOKEN_STORE_TTL_GRACE_SECONDS;

        TokenWrapper toStore = new TokenWrapper(
                oktaToken.key(),
                storeProvider,
                null,
                exchangedToken.accessToken(),
                null,
                absoluteTtl
        );

        // Per the bearer-index plan, the per-client (clientId#userId, storeProvider) row in
        // mcp-oauth-proxy-tokens is no longer written; /userinfo bearer resolution now goes
        // through the dedicated bearer-index table.
        writeBearerIndex(exchangedToken.accessToken(), oktaToken.key(), clientId, storeProvider, absoluteTtl);
        log.info("Indexed exchanged token in bearer-index for user: {} provider: {} clientId: {} with ttl: {}",
                oktaToken.key(), storeProvider, clientId, toStore.ttl());
    }

    /**
     * Store the token we are returning to the client so /userinfo can resolve it by access token hash.
     * For Glean (token exchange) we store under provider "glean". For other resources (GitHub, Google, Okta)
     * we store under the upstream provider so the returned access token is findable by hash.
     *
     * @param resource       The resource URI from the refresh request
     * @param userId         User id (subject) from the refresh token record
     * @param provider       Upstream IDP (okta, github, google)
     * @param upstreamToken   The upstream token we stored (used for Glean to get user key)
     * @param returnedToken  The token we are returning to the client (may be exchanged or same as upstream)
     */
    private void storeRefreshedAccessToken(String resource, String userId, String provider,
                                          TokenWrapper upstreamToken, TokenWrapper returnedToken, String clientId) {
        ResourceMeta resourceMeta = configService.getResourceMeta(resource);
        String storeProvider;
        long absoluteTtl;
        String audience = resourceMeta != null ? resourceMeta.audience() : null;
        boolean storeByAudience = AudienceConstants.storesExchangedTokenForUserinfo(audience);
        if (resourceMeta != null && storeByAudience) {
            storeProvider = exchangedTokenUserinfoStoreProviderResolver.resolve(resource, audience);
            absoluteTtl = Instant.now().getEpochSecond() + (returnedToken.ttl() != null ? returnedToken.ttl() : 3600L) + TOKEN_STORE_TTL_GRACE_SECONDS;
            log.info("Indexing exchanged refreshed token for subject: {} provider: {} so /userinfo can resolve it", userId, storeProvider);
        } else {
            storeProvider = provider;
            absoluteTtl = returnedToken.ttl() != null ? returnedToken.ttl() : Instant.now().getEpochSecond() + 3600L;
            log.info("Indexing returned refreshed token for subject: {} provider: {} so /userinfo can resolve it", userId, storeProvider);
        }
        // Per the bearer-index plan: per-client (clientId#userId, storeProvider) rows in
        // mcp-oauth-proxy-tokens are no longer written. /userinfo resolves bearers via the new
        // dedicated bearer-index table. The bare (userId, provider) row was already updated by
        // refreshUpstreamAndGetTokenLocked / completeRefreshWithOktaTokens; we don't double-write.
        writeBearerIndex(returnedToken.accessToken(), userId, clientId, storeProvider, absoluteTtl);
    }

    /**
     * Refresh upstream IDP tokens using the given refresh token, update the token store,
     * then exchange the new access token for the resource (e.g. Okta/Glean exchange at
     * TokenExchangeServiceOktaImpl 87-92) and return that exchanged token. Used by refresh_token grant.
     * When the IDP returns a new refresh token, it is included in the result so the caller can
     * persist it in the new refresh token table.
     *
     * @param userId                  internal user id (lookup key)
     * @param provider                upstream IDP (e.g. okta)
     * @param resource                resource URI for scope/metadata
     * @param upstreamRefreshToken    decrypted upstream refresh token from refresh table
     * @return RefreshAndTokenResult with new access token and new upstream refresh (if IDP returned one), or null on failure
     */
    /**
     * Backward-compatible overload (no clientId; per-client bearer row not written). Prefer
     * the 5-arg variant.
     */
    public RefreshAndTokenResult refreshUpstreamAndGetToken(String userId, String provider, String resource,
                                                           String upstreamRefreshToken) {
        return refreshUpstreamAndGetToken(userId, provider, resource, upstreamRefreshToken, null);
    }

    public RefreshAndTokenResult refreshUpstreamAndGetToken(String userId, String provider, String resource,
                                                           String upstreamRefreshToken, String clientId) {
        if (StringUtils.isBlank(upstreamRefreshToken)) {
            log.warn("refreshUpstreamAndGetToken: no upstream refresh token for user {} provider {}", userId, provider);
            return null;
        }
        // Generalized per-(provider, user) distributed lock: serialize concurrent refresh calls
        // for the same upstream identity across all MCP clients so the IdP only sees one refresh
        // per "burst" and the rotated RT is propagated atomically. Same pattern UpstreamRefreshService
        // applies for Okta; here we extend it to all OIDC providers (Google Workspace, GitHub, Slack,
        // Embrace, Atlassian).
        String lockKey = provider + "#" + userId;
        try {
            refreshCoordinationService.acquireUpstream(lockKey);
        } catch (IllegalStateException e) {
            log.warn("refreshUpstreamAndGetToken: could not acquire upstream lock for {}: {}", lockKey, e.getMessage());
            return null;
        }
        try {
            return refreshUpstreamAndGetTokenLocked(userId, provider, resource, upstreamRefreshToken, clientId);
        } finally {
            try {
                refreshCoordinationService.releaseUpstream(lockKey);
            } catch (Exception e) {
                log.warn("refreshUpstreamAndGetToken: lock release failed for {}: {}", lockKey, e.getMessage());
            }
        }
    }

    private RefreshAndTokenResult refreshUpstreamAndGetTokenLocked(String userId, String provider, String resource,
                                                                   String upstreamRefreshToken, String clientId) {
        TokenExchangeService exchangeService = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(provider);
        TokenWrapper newToken = exchangeService.refreshWithUpstreamToken(upstreamRefreshToken);
        if (newToken == null) {
            log.error("refreshUpstreamAndGetToken: upstream IDP refresh failed (refreshWithUpstreamToken returned null) for user {} provider {}; see ERROR log from token exchange for upstream response body",
                    userId, provider);
            cleanupAfterTerminalUpstreamRefreshFailure(userId, provider, upstreamRefreshToken);
            return null;
        }
        long nowSeconds = Instant.now().getEpochSecond();
        long absoluteTtl = nowSeconds + (newToken.ttl() != null ? newToken.ttl() : 3600L) + TOKEN_STORE_TTL_GRACE_SECONDS;
        String newUpstreamRefresh = StringUtils.isNotBlank(newToken.refreshToken()) ? newToken.refreshToken() : null;
        TokenWrapper toStore = new TokenWrapper(
                userId,
                provider,
                newToken.idToken(),
                newToken.accessToken(),
                newToken.refreshToken(),
                absoluteTtl
        );
        tokenStore.storeUserToken(userId, provider, toStore);

        ResourceMeta resourceMeta = configService.getResourceMeta(resource);
        if (resourceMeta == null) {
            log.error("refreshUpstreamAndGetTokenLocked: resourceMeta is null for resource={} user={} provider={}; "
                    + "refusing to fall back to raw upstream token. This indicates the RFC 8707 validation gate "
                    + "in TokenResource was bypassed.", resource, userId, provider);
            return null;
        }
        // Run the new access token through the resource's authorization server (e.g. Okta/Glean exchange)
        // so the client receives the same exchanged token as in the auth_code flow (TokenExchangeServiceOktaImpl 87-92)
        TokenExchangeService accessTokenIssuer = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(
                resourceMeta.authorizationServer());
        TokenExchangeDO accessTokenRequestDO = new TokenExchangeDO(
                resourceMeta.scopes(),
                resource,
                resourceMeta.domain(),
                configService.getRemoteServerEndpoint(resourceMeta.authorizationServer()),
                toStore
        );
        AuthorizationResultDO atDO = accessTokenIssuer.getAccessTokenFromResourceAuthorizationServer(accessTokenRequestDO);
        if (atDO == null || atDO.token() == null || atDO.authResult() != AuthResult.AUTHORIZED) {
            log.warn("Token exchange after refresh failed for user={} resource={} upstream={}",
                    userId, resource, atDO != null ? atDO.errorMessage() : null);
            return null;
        }
        storeRefreshedAccessToken(resource, userId, provider, toStore, atDO.token(), clientId);
        String scopeStr = tokenResponseScope(atDO, resourceMeta);
        TokenResponse tokenResponse = new TokenResponse(
                atDO.token().accessToken(),
                TOKEN_TYPE,
                sanitizeExpiresIn(atDO.token().ttl()),
                scopeStr
        );
        return new RefreshAndTokenResult(tokenResponse, newUpstreamRefresh);
    }

    /**
     * After centralized Okta refresh, store Okta tokens and run resource token exchange (Glean, GCP, etc.).
     * Does not return a new upstream refresh for per-row refresh table updates — upstream is only in the
     * centralized store.
     */
    /**
     * Backward-compatible overload (no clientId; per-client bearer row not written). Prefer the
     * 5-arg variant.
     */
    public RefreshAndTokenResult completeRefreshWithOktaTokens(String userId, String provider, String resource, OktaTokens oktaTokens) {
        return completeRefreshWithOktaTokens(userId, provider, resource, oktaTokens, null);
    }

    public RefreshAndTokenResult completeRefreshWithOktaTokens(String userId, String provider, String resource, OktaTokens oktaTokens, String clientId) {
        if (oktaTokens == null) {
            return null;
        }
        long ttlSec = oktaTokens.expiresIn() > 0 ? oktaTokens.expiresIn() : 3600L;
        long nowSeconds = Instant.now().getEpochSecond();
        long absoluteTtl = nowSeconds + ttlSec + TOKEN_STORE_TTL_GRACE_SECONDS;
        TokenWrapper toStore = new TokenWrapper(
                userId,
                provider,
                oktaTokens.idToken(),
                oktaTokens.accessToken(),
                oktaTokens.refreshToken(),
                absoluteTtl
        );
        tokenStore.storeUserToken(userId, provider, toStore);
        if (AudienceConstants.PROVIDER_OKTA.equals(provider) && oktaSessionCacheConfig.enabled()
                && oktaTokens.idToken() != null && !oktaTokens.idToken().isEmpty()) {
            // Idempotent with the L0 write inside UpstreamRefreshService.refreshUpstream(): we
            // re-publish the same id/access tokens here so a future code path that lands a row
            // by a different L1-only route still keeps L0 hot. Caffeine's put is unconditional.
            String providerUserId = oktaProviderUserId(userId);
            if (providerUserId != null) {
                oktaSessionCache.put(providerUserId,
                        OktaSessionEntry.from(oktaTokens.idToken(), oktaTokens.accessToken(),
                                oktaTokens.refreshToken()));
            }
        }

        ResourceMeta resourceMeta = configService.getResourceMeta(resource);
        // Defense-in-depth: same contract as refreshUpstreamAndGetTokenLocked. The /token endpoint
        // already gated unknown resources with invalid_target (RFC 8707), so resourceMeta should
        // never be null here. If it is, fail loudly rather than silently issue a raw Okta AT — see
        // the Databricks "connect once then 401" regression that motivated the gate.
        if (resourceMeta == null) {
            log.error("completeRefreshWithOktaTokens: resourceMeta is null for resource={} user={} provider={}; "
                    + "refusing to fall back to raw upstream token. This indicates the RFC 8707 validation gate "
                    + "in TokenResource was bypassed.", resource, userId, provider);
            return null;
        }
        TokenExchangeService accessTokenIssuer = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(
                resourceMeta.authorizationServer());
        TokenExchangeDO accessTokenRequestDO = new TokenExchangeDO(
                resourceMeta.scopes(),
                resource,
                resourceMeta.domain(),
                configService.getRemoteServerEndpoint(resourceMeta.authorizationServer()),
                toStore
        );
        AuthorizationResultDO atDO = accessTokenIssuer.getAccessTokenFromResourceAuthorizationServer(accessTokenRequestDO);
        if (atDO == null || atDO.token() == null || atDO.authResult() != AuthResult.AUTHORIZED) {
            log.warn("Token exchange after centralized Okta refresh failed for user={} resource={} upstream={}",
                    userId, resource, atDO != null ? atDO.errorMessage() : null);
            return null;
        }
        storeRefreshedAccessToken(resource, userId, provider, toStore, atDO.token(), clientId);
        String scopeStr = tokenResponseScope(atDO, resourceMeta);
        TokenResponse tokenResponse = new TokenResponse(
                atDO.token().accessToken(),
                TOKEN_TYPE,
                sanitizeExpiresIn(atDO.token().ttl()),
                scopeStr
        );
        return new RefreshAndTokenResult(tokenResponse, null);
    }

    /**
     * Coerce {@code rawTtl} to a sane RFC 6749 §5.1 {@code expires_in} *duration* in seconds.
     *
     * <p>Contract: every {@link TokenExchangeService} implementation should return a
     * {@code TokenWrapper.ttl} carrying a duration in seconds. Four pass-through providers
     * (Slack, GitHub, Atlassian, Embrace) instead re-emit the input {@code TokenWrapper} that
     * {@code AuthorizerService} built for storage, whose {@code ttl} field is the *absolute* DDB
     * epoch (now + lifetime + grace). Without normalization that value would leak onto the wire
     * as {@code expires_in = 1.7e9}, which a spec-conformant client interprets as a 50-year
     * lifetime.
     *
     * <p>Policy:
     * <ul>
     *   <li>null / non-positive → fall back to {@link #DEFAULT_EXPIRES_IN_SECONDS}.
     *   <li>looks like an absolute epoch (greater than "duration sanity ceiling" of ~30 days) →
     *       treat as absolute and convert back to a duration via {@code rawTtl - now()}, then
     *       run the result through this same sanitizer. If even that comes out non-positive
     *       (token already expired) or still absurd (clock skew, garbage), fall back to the
     *       default. Crucially we do NOT silently emit a 1.7e9 wire value.
     *   <li>otherwise → return as-is, capped to {@link #MAX_REASONABLE_DURATION_SECONDS} so a
     *       buggy upstream that returns 5e10 doesn't poison the response.
     * </ul>
     */
    static final long DEFAULT_EXPIRES_IN_SECONDS = 3600L;
    // ~30 days. Anything strictly larger is almost certainly an absolute epoch (current epoch
    // ≈ 1.78e9 ≫ 2.6e6) and we'll convert it back to a duration via `rawTtl - now()`.
    private static final long DURATION_SANITY_CEILING_SECONDS = 60L * 60L * 24L * 30L;
    // Hard ceiling on what we'll emit on the wire. Above this we cap rather than echo back a
    // garbage upstream value. 24h is well above every legitimate access-token lifetime we issue
    // today (longest is Slack's 12h refresh cycle).
    private static final long MAX_REASONABLE_DURATION_SECONDS = 60L * 60L * 24L;

    static long sanitizeExpiresIn(Long rawTtl) {
        return sanitizeExpiresIn(rawTtl, Instant.now().getEpochSecond());
    }

    // Package-visible variant for deterministic unit testing.
    static long sanitizeExpiresIn(Long rawTtl, long nowSeconds) {
        if (rawTtl == null || rawTtl <= 0L) {
            return DEFAULT_EXPIRES_IN_SECONDS;
        }
        if (rawTtl > DURATION_SANITY_CEILING_SECONDS) {
            // Looks like an absolute epoch leaked through (pass-through TokenExchangeService impl
            // returned the storage-side TokenWrapper whose `ttl` is `now + lifetime + grace`).
            // Convert back to a duration: remaining = absolute - now.
            long remaining = rawTtl - nowSeconds;
            if (remaining <= 0L) {
                // The token already expired by clock; we can't honestly say "valid for X seconds".
                // Emit the default so the client treats it as short-lived and refreshes promptly.
                return DEFAULT_EXPIRES_IN_SECONDS;
            }
            if (remaining > MAX_REASONABLE_DURATION_SECONDS) {
                return MAX_REASONABLE_DURATION_SECONDS;
            }
            return remaining;
        }
        if (rawTtl > MAX_REASONABLE_DURATION_SECONDS) {
            return MAX_REASONABLE_DURATION_SECONDS;
        }
        return rawTtl;
    }

    /**
     * Warm auth-code path for passthrough providers (Google Workspace, GitHub, Slack, Embrace,
     * Atlassian, Okta-as-default): when a second/third MCP client (e.g. Claude or Codex) joins
     * an existing upstream session that was originally cold-bootstrapped by another client (e.g.
     * Cursor), the bare row {@code (userId, provider)} carries an access token minted for that
     * other client. Returning it as-is would resolve via /userinfo's GSI to a row whose partition
     * key collides across clients, so we instead mint a fresh upstream bearer for the current
     * MCP client by calling {@code refreshWithUpstreamToken(bareUpstreamRT)} under the
     * generalized per-{@code (provider, user)} distributed lock, then write it into a per-client
     * bearer row {@code (clientId#userId, provider)}.
     *
     * <p>Each call to {@code refreshWithUpstreamToken} causes the OIDC provider to mint a fresh
     * signed access token even when the same upstream RT is replayed, so three concurrent warm
     * clients yield three distinct bearers with three distinct {@code access_token_hash} values
     * — no GSI collision.
     *
     * <p>If the upstream rotates the RT during this call, we propagate the new RT into the bare
     * row (keeps {@code AuthorizeResource:193} session marker / inheritance fresh) and into all
     * sibling MoP refresh-token rows for {@code (userId, provider)} so other clients' refresh
     * grants don't fail with a stale upstream RT.
     *
     * @return the fresh per-client bearer wrapped in a {@link TokenResponse}, or {@code null} if
     *         the upstream refresh failed (caller should fall back to the existing path or
     *         surface a 401).
     */
    public TokenResponse mintBearerForWarmCacheClient(String userId, String provider, String resource, String clientId,
                                                       String sharedUpstreamRefreshToken) {
        if (clientId == null || clientId.isEmpty()) {
            log.warn("mintBearerForWarmCacheClient called with empty clientId; refusing to mint a bearer that would land in a bare row");
            return null;
        }
        if (sharedUpstreamRefreshToken == null || sharedUpstreamRefreshToken.isEmpty()) {
            log.warn("mintBearerForWarmCacheClient: no shared upstream refresh token for user {} provider {}; cannot mint", userId, provider);
            return null;
        }

        // Promoted-provider re-route: route through UpstreamRefreshService so the L2 row is the
        // canonical RT source instead of the bare-row's `sharedUpstreamRefreshToken` argument.
        // This gives the warm-mint path the same guarantees as the refresh-token grant:
        //   - DDB-backed lock (no lock-key mismatch with concurrent refresh callers)
        //   - Version-CAS write of rotated RT + staged AT in one atomic update
        //   - Per-client L0 cell populated as a side effect (subsequent same-client calls hit
        //     Path B without any lock or upstream call)
        //   - Path E reuse-within-grace fires across the auth-code grant just like /token,
        //     so a 2nd MCP client consenting within 30s of a sibling rotation reuses the
        //     staged AT instead of issuing a fresh Google call.
        // The legacy path below stays in place for native-IdP providers (slack/github/atlassian/
        // embrace) which do not (yet) have an L2 row.
        if (upstreamProviderClassifier.isUpstreamPromoted(provider)) {
            return mintBearerForWarmCacheClientPromoted(userId, provider, clientId);
        }

        String lockKey = provider + "#" + userId;
        try {
            refreshCoordinationService.acquireUpstream(lockKey);
        } catch (IllegalStateException e) {
            log.warn("mintBearerForWarmCacheClient: could not acquire upstream lock for {}: {}", lockKey, e.getMessage());
            return null;
        }
        try {
            TokenExchangeService exchangeService = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(provider);
            TokenWrapper newToken;
            try {
                newToken = exchangeService.refreshWithUpstreamToken(sharedUpstreamRefreshToken);
            } catch (Exception e) {
                log.warn("mintBearerForWarmCacheClient: refreshWithUpstreamToken threw for user {} provider {}: {}",
                        userId, provider, e.getMessage());
                return null;
            }
            if (newToken == null) {
                log.warn("mintBearerForWarmCacheClient: refreshWithUpstreamToken returned null for user {} provider {}", userId, provider);
                return null;
            }
            long nowSeconds = Instant.now().getEpochSecond();
            long absoluteTtl = nowSeconds + (newToken.ttl() != null ? newToken.ttl() : 3600L) + TOKEN_STORE_TTL_GRACE_SECONDS;
            String rotatedUpstreamRefresh = StringUtils.isNotBlank(newToken.refreshToken()) ? newToken.refreshToken() : null;
            String effectiveUpstreamRefresh = rotatedUpstreamRefresh != null ? rotatedUpstreamRefresh : sharedUpstreamRefreshToken;

            // Refresh the bare row so AuthorizeResource:193 / firstNonEmpty inheritance see the
            // freshest upstream session marker (access_token + possibly rotated RT). Do NOT use
            // the per-client overload here: the bare row has no clientId.
            TokenWrapper bareRowUpdate = new TokenWrapper(
                    userId,
                    provider,
                    newToken.idToken(),
                    newToken.accessToken(),
                    effectiveUpstreamRefresh,
                    absoluteTtl
            );
            tokenStore.storeUserToken(userId, provider, bareRowUpdate);

            // Per the bearer-index plan, the per-client (clientId#userId, provider) row is no
            // longer written; the freshly-minted per-client bearer is indexed in
            // mcp-oauth-proxy-bearer-index instead, where /userinfo resolves it without GSI
            // collisions across windows.
            writeBearerIndex(newToken.accessToken(), userId, clientId, provider, absoluteTtl);

            if (rotatedUpstreamRefresh != null) {
                try {
                    refreshTokenService.updateUpstreamRefreshForAllRowsWithUserAndProvider(userId, provider, rotatedUpstreamRefresh);
                } catch (Exception e) {
                    log.warn("mintBearerForWarmCacheClient: failed to propagate rotated upstream RT to refresh-token rows for user {} provider {}: {}",
                            userId, provider, e.getMessage());
                }
            }

            log.info("mintBearerForWarmCacheClient: minted fresh bearer for user {} provider {} clientId {} (rotatedUpstreamRT={})",
                    userId, provider, clientId, rotatedUpstreamRefresh != null);

            return new TokenResponse(
                    newToken.accessToken(),
                    TOKEN_TYPE,
                    sanitizeExpiresIn(newToken.ttl()),
                    null
            );
        } finally {
            try {
                refreshCoordinationService.releaseUpstream(lockKey);
            } catch (Exception e) {
                log.warn("mintBearerForWarmCacheClient: lock release failed for {}: {}", lockKey, e.getMessage());
            }
        }
    }

    /**
     * Promoted-provider warm-mint path. Routes through {@link UpstreamRefreshService#refreshUpstream}
     * so that L2 is the canonical RT source and the per-client L0 cell + bearer-index entry are
     * populated atomically with the rotated AT.
     *
     * <p>Comparison with the legacy code path above:
     * <ul>
     *   <li>No explicit {@link RefreshCoordinationService#acquireUpstream} call — the L2 row's
     *       DDB-backed lock is obtained inside {@code refreshUpstream}, so the surrounding
     *       in-process lock would be a no-op at best and a deadlock risk at worst.</li>
     *   <li>No {@code refreshTokenService.updateUpstreamRefreshForAllRowsWithUserAndProvider}
     *       fan-out — the L2 row IS the canonical RT for promoted providers, and the legacy
     *       per-row column is nullified by {@code RefreshTokenServiceImpl.nullifyLegacyUpstreamColumnForUserProvider}
     *       on the next rotation.</li>
     *   <li>Bare row {@code TokenWrapper} update remains so that any code still reading the
     *       bare row's {@code accessToken}/{@code refreshToken} (e.g. the AuthorizeResource
     *       upstream-RT inheritance fallback) sees a fresh marker. The {@code refreshToken}
     *       column on the bare row stays in sync via the L2 → legacy nullification migration
     *       on the refresh-tokens table; for the bare row we reuse the rotated RT to keep the
     *       inheritance window working until the next consent.</li>
     * </ul>
     */
    private TokenResponse mintBearerForWarmCacheClientPromoted(String userId, String provider, String clientId) {
        String providerUserId = userProviderKey(userId, provider);
        if (providerUserId == null) {
            log.warn("mintBearerForWarmCacheClientPromoted: cannot build provider_user_id for user {} provider {}; refusing to mint",
                    userId, provider);
            return null;
        }
        UpstreamRefreshResponse refreshResponse;
        try {
            refreshResponse = upstreamRefreshService.refreshUpstream(providerUserId, provider, clientId);
        } catch (UpstreamRefreshException e) {
            log.warn("mintBearerForWarmCacheClientPromoted: refreshUpstream failed for user {} provider {} clientId {}: {}",
                    userId, provider, clientId, e.getMessage());
            return null;
        } catch (Exception e) {
            log.warn("mintBearerForWarmCacheClientPromoted: unexpected error during refreshUpstream for user {} provider {} clientId {}: {}",
                    userId, provider, clientId, e.getMessage());
            return null;
        }
        if (refreshResponse == null || refreshResponse.accessToken() == null) {
            log.warn("mintBearerForWarmCacheClientPromoted: refreshUpstream returned null/empty AT for user {} provider {} clientId {}",
                    userId, provider, clientId);
            return null;
        }

        long nowSeconds = Instant.now().getEpochSecond();
        long expiresIn = refreshResponse.expiresInSeconds() > 0 ? refreshResponse.expiresInSeconds() : 3600L;
        long absoluteTtl = nowSeconds + expiresIn + TOKEN_STORE_TTL_GRACE_SECONDS;

        // Bare row update: keep the inheritance marker fresh. The L2 row already holds the
        // canonical rotated RT; we just mirror it onto the bare row so AuthorizeResource's
        // first-non-empty inheritance lookup sees a usable upstream session.
        // For Path E (reuse_within_grace) refreshResponse.refreshToken is null because no
        // rotation happened — fall back to leaving the bare row's RT untouched in that case
        // by reading the existing wrapper.
        String rotatedUpstreamRefresh = refreshResponse.refreshToken();
        TokenWrapper existingBare = tokenStore.getUserToken(userId, provider);
        String effectiveBareRefresh = rotatedUpstreamRefresh != null
                ? rotatedUpstreamRefresh
                : (existingBare != null ? existingBare.refreshToken() : null);
        TokenWrapper bareRowUpdate = new TokenWrapper(
                userId,
                provider,
                refreshResponse.idToken(),
                refreshResponse.accessToken(),
                effectiveBareRefresh,
                absoluteTtl
        );
        tokenStore.storeUserToken(userId, provider, bareRowUpdate);

        writeBearerIndex(refreshResponse.accessToken(), userId, clientId, provider, absoluteTtl);

        log.info("mintBearerForWarmCacheClientPromoted: minted fresh bearer for user {} provider {} clientId {} (rotatedUpstreamRT={})",
                userId, provider, clientId, rotatedUpstreamRefresh != null);

        return new TokenResponse(
                refreshResponse.accessToken(),
                TOKEN_TYPE,
                sanitizeExpiresIn(expiresIn),
                /* scope */ null
        );
    }

    /**
     * After upstream refresh fails terminally (e.g. {@code invalid_grant}): drop cached IdP tokens from the token store
     * and best-effort revoke the upstream refresh token at the IdP when the provider implements it.
     *
     * <p>Bearer-index trade-off: any bearer-index rows minted before this terminal failure are
     * left in place. The bearer-index table has no user/family GSI (only PK on H(bearer)) and we
     * deliberately did not add one — every bearer the upstream IdP minted will already have an
     * {@code exp} that lapses well within the bearer-index TTL we set, so /userinfo will reject
     * those bearers via the natural exp check before TTL evicts the row. Adding active deletion
     * would require either tracking bearer hashes per family (extra writes everywhere) or a
     * fan-out scan (expensive). The TTL is the durable backstop.
     */
    public void cleanupAfterTerminalUpstreamRefreshFailure(String userId, String provider, String upstreamRefreshToken) {
        if (StringUtils.isBlank(userId) || StringUtils.isBlank(provider)) {
            return;
        }
        try {
            tokenStore.deleteUserToken(userId, provider);
        } catch (Exception e) {
            log.warn("Failed to delete token store entry for userId={} provider={}: {}", userId, provider, e.getMessage());
        }
        if (AudienceConstants.PROVIDER_OKTA.equals(provider) && oktaSessionCacheConfig.enabled()) {
            String providerUserId = oktaProviderUserId(userId);
            if (providerUserId != null) {
                oktaSessionCache.invalidate(providerUserId);
            }
        }
        if (StringUtils.isNotBlank(upstreamRefreshToken)) {
            try {
                tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(provider)
                        .revokeUpstreamRefreshToken(upstreamRefreshToken.trim());
            } catch (Exception e) {
                log.warn("Upstream refresh token revoke failed for provider {}: {}", provider, e.getMessage());
            }
        }
    }

}
