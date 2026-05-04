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

import io.athenz.mop.model.RefreshTokenLockKey;
import io.athenz.mop.model.RefreshTokenRecord;
import io.athenz.mop.model.RefreshTokenRotateResult;
import io.athenz.mop.model.RefreshTokenValidationResult;

import java.util.Optional;

/**
 * Service for MOP-minted opaque refresh tokens: generation, hashing, storage,
 * validation, rotation, and family revocation per OAuth 2.0 BCP (RFC 9126).
 */
public interface RefreshTokenService {

    /**
     * Generate a secure opaque refresh token (rt_ + base64url 32 bytes).
     * Minimum 256-bit entropy; never log the value.
     */
    String generateSecureToken();

    /**
     * SHA-256 hash of the token for storage and lookup. No secret; hash only.
     */
    String hashToken(String rawToken);

    /**
     * Store a new refresh token (ACTIVE). Called after successful authorization_code exchange.
     * Stores only hashed token and encrypted upstream refresh; returns the raw token for the client.
     *
     * @param userId              internal user id (lookup key)
     * @param clientId            MCP client id
     * @param provider            upstream IDP (okta, google, github)
     * @param providerSubject     IDP subject
     * @param upstreamRefreshToken upstream refresh token to encrypt and store (may be null)
     * @return the raw MOP refresh token to return to the client
     */
    default String store(String userId, String clientId, String provider, String providerSubject,
                         String upstreamRefreshToken) {
        return store(userId, clientId, provider, providerSubject, upstreamRefreshToken, null);
    }

    /**
     * Store a new refresh token with an explicit {@code audience} label. Same semantics as
     * {@link #store(String, String, String, String, String)} except the audience is recorded on
     * the row.
     *
     * <p>The audience is purely diagnostic: it lets operators tell, when scanning the
     * refresh-tokens table, whether a row written under {@code provider="okta"} was minted for
     * Splunk, Glean, Grafana, etc. No code path uses {@code audience} to make an
     * authentication/authorization decision; preserve that property when adding new call sites.
     * Pass {@code null} for non-Okta IdPs where audience equals provider.
     */
    String store(String userId, String clientId, String provider, String providerSubject,
                 String upstreamRefreshToken, String audience);

    /**
     * Look up (userId, provider) for the given refresh token and clientId for distributed lock key.
     * Used to acquire the per-(userId, provider) lock before full validation.
     * Returns empty if token not found or clientId does not match.
     */
    Optional<RefreshTokenLockKey> lookupUserIdAndProviderForLock(String refreshToken, String clientId);

    /**
     * Validate refresh token and resolve replay/active.
     * Binding: clientId must match. Expiry and status enforced.
     *
     * <p>When the row is found in {@code ROTATED} status, this method consults the
     * <em>rotated-grace window</em> ({@code server.refresh-token.rotated-grace-seconds}). If the
     * rotation happened within the grace window, the result is
     * {@link RefreshTokenValidationResult.Status#ROTATED_GRACE_SUCCESSOR} carrying the most recent
     * ACTIVE descendant in the same family. Older rotations remain
     * {@link RefreshTokenValidationResult.Status#ROTATED_REPLAY} (genuine stolen-RT defense).</p>
     */
    RefreshTokenValidationResult validate(String refreshToken, String clientId);

    /**
     * Rotate token: mark current as ROTATED, insert new ACTIVE token in same family.
     * Atomic via TransactWriteItems with condition status=ACTIVE.
     *
     * <p>Calls are serialized cross-pod by a per-RT distributed lock keyed on the SHA-256 hash of
     * the presented refresh token. A per-pod in-memory cache also holds the result for a short
     * window so concurrent callers presenting the same RT receive the same rotation outcome
     * (singleflight); see {@code server.refresh-token.inflight-cache-seconds}.</p>
     *
     * @return the new MOP token and new row primary key (for updating upstream token by key), or
     *     null if validation failed or concurrent rotation (replay)
     */
    RefreshTokenRotateResult rotate(String refreshToken, String clientId);

    /**
     * Re-rotate against a grace successor: when {@link #validate} returned
     * {@link RefreshTokenValidationResult.Status#ROTATED_GRACE_SUCCESSOR}, the duplicate caller
     * still needs a working RT pair. This rotates the most recent ACTIVE child in the family —
     * staying in the same family (no revoke), and minting a brand-new RT for the duplicate
     * caller. Idempotent under contention via the same per-RT lock used by {@link #rotate}.
     *
     * @param successor the most recent ACTIVE descendant returned from {@code validate}
     * @return the freshly minted RT pair, or null if the successor was rotated/revoked while we
     *     were trying (in which case the caller should fall back to {@code invalid_grant})
     */
    RefreshTokenRotateResult rotateGraceSuccessor(RefreshTokenRecord successor);

    /**
     * Revoke all tokens in the family (status = REVOKED). Query by token_family_id (GSI2).
     */
    void revokeFamily(String tokenFamilyId);

    /**
     * Handle replay: revoke family and log security event. No token value in logs.
     */
    void handleReplay(String refreshToken);

    /**
     * Look up the current upstream (IDP) refresh token for the given user and provider from the
     * refresh token table (mcp-oauth-proxy-refresh-tokens). This is the source of truth for refresh
     * tokens; the old tokens table (mcp-oauth-proxy-tokens) holds only id_token and access_token.
     *
     * @param userId   internal user id (same lookup key as used in token store)
     * @param provider upstream IDP (e.g. okta, google, github, atlassian)
     * @return the decrypted upstream refresh token, or null if none found or not stored
     */
    String getUpstreamRefreshToken(String userId, String provider);

    /**
     * Update the upstream (IDP) refresh token for the row identified by the given MOP refresh token.
     * Used after a refresh grant when the IDP returns a new refresh token: the new table row
     * (created by rotate) is updated so the next refresh uses the latest upstream token.
     * Prefer {@link #updateUpstreamRefreshForToken(String, String, String)} when you have the
     * rotate result (avoids GSI eventual consistency when the row was just written).
     *
     * @param mopRefreshToken    the MOP refresh token (raw value) that identifies the row to update
     * @param newUpstreamRefresh the new upstream refresh token from the IDP (only updated if non-null and non-empty)
     */
    void updateUpstreamRefreshForToken(String mopRefreshToken, String newUpstreamRefresh);

    /**
     * Update the upstream (IDP) refresh token for the row identified by primary key.
     * Use this after rotate() when you have the new row's IDs — avoids lookup by hash (GSI),
     * which can be eventually consistent and miss the row immediately after rotation.
     *
     * @param refreshTokenId     the new row's refresh_token_id from the rotate result
     * @param providerUserId    the new row's provider_user_id from the rotate result
     * @param newUpstreamRefresh the new upstream refresh token from the IDP (only updated if non-null and non-empty)
     */
    void updateUpstreamRefreshForToken(String refreshTokenId, String providerUserId, String newUpstreamRefresh);

    /**
     * Update the upstream (IDP) refresh token for all rows with the given (user_id, provider).
     * Used after Okta refresh when the IDP returns a new refresh token: every MOP refresh token
     * for this user+provider (e.g. Glean and Google Monitoring clients) must see the same upstream.
     *
     * @param userId             internal user id
     * @param provider           upstream IDP (e.g. okta)
     * @param newUpstreamRefresh the new upstream refresh token from the IDP (only applied if non-null and non-empty)
     */
    void updateUpstreamRefreshForAllRowsWithUserAndProvider(String userId, String provider, String newUpstreamRefresh);

    /**
     * Clear the legacy {@code encrypted_upstream_refresh_token} column on every per-MCP-client
     * row for the given {@code (user_id, provider)} pair. Called after a successful L2-promoted
     * upstream refresh so the canonical RT lives only in the L2 row going forward.
     *
     * <p>This is a one-shot per-user migration step: once the legacy column is null, future
     * refreshes for this {@code (user, provider)} will read from L2 (the canonical row) and the
     * sibling-inheritance trap (Bug #1) cannot recur. The fallback to the legacy column on
     * {@link #getUpstreamRefreshToken(String, String)} only fires when the L2 row does not
     * exist for the user yet (mid-migration), which after this nullification it always does.
     *
     * <p>Safe to call when no rows match (no-op). Failures are logged and swallowed: the
     * upstream refresh has already succeeded and we do not want to fail the user-visible call
     * because of a best-effort cleanup write.
     */
    void nullifyLegacyUpstreamColumnForUserProvider(String userId, String provider);
}
