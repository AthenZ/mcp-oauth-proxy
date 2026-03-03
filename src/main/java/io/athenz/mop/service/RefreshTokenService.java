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

import io.athenz.mop.model.RefreshTokenRotateResult;
import io.athenz.mop.model.RefreshTokenValidationResult;

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
    String store(String userId, String clientId, String provider, String providerSubject,
                 String upstreamRefreshToken);

    /**
     * Validate refresh token and resolve replay/active.
     * Binding: clientId must match. Expiry and status enforced.
     */
    RefreshTokenValidationResult validate(String refreshToken, String clientId);

    /**
     * Rotate token: mark current as ROTATED, insert new ACTIVE token in same family.
     * Atomic via TransactWriteItems with condition status=ACTIVE. Strict single-use rotation; no grace cache.
     *
     * @return the new MOP token and new row primary key (for updating upstream token by key), or null if validation failed or concurrent rotation (replay)
     */
    RefreshTokenRotateResult rotate(String refreshToken, String clientId);

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
}
