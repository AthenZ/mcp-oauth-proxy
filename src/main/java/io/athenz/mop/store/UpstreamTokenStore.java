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
package io.athenz.mop.store;

import io.athenz.mop.model.UpstreamTokenRecord;
import java.util.Optional;

public interface UpstreamTokenStore {

    void save(UpstreamTokenRecord record);

    Optional<UpstreamTokenRecord> get(String providerUserId);

    /**
     * Replace the upstream refresh token when {@code version} still matches. Increments version
     * by 1 and {@code rotationCount} by 1. Existing two-arg overload retained for callers that
     * do not stage an access token (Okta path today; pre-staged-AT row writes).
     *
     * @return true if the conditional write succeeded
     */
    boolean updateWithVersionCheck(String providerUserId, String newPlainUpstreamRefreshToken, long expectedVersion);

    /**
     * Replace the upstream refresh token AND stage the just-minted access token in a single
     * conditional write. The {@code lastMinted*} trio is persisted atomically with the rotated
     * RT so a second client arriving at the L2 lock can read both fields in one consistent get.
     *
     * <p>Callers that don't have a fresh AT to stage (e.g. token-only rotation paths) MUST use
     * the two-arg overload above. This three-arg form is only meaningful when the rotation was
     * driven by a successful upstream refresh whose AT we want to amortize across clients.
     *
     * @param providerUserId             canonical L2 row key ({@code provider#sub})
     * @param newPlainUpstreamRefreshToken rotated RT to store as the new canonical secret
     * @param newAccessToken             plaintext AT to stage for reuse-within-grace
     * @param newAccessTokenExpiresAt    absolute epoch seconds at which the staged AT expires
     * @param expectedVersion            current row version for CAS
     * @return true if the conditional write succeeded
     */
    boolean updateWithVersionCheckAndStagedAt(String providerUserId, String newPlainUpstreamRefreshToken,
                                              String newAccessToken, long newAccessTokenExpiresAt,
                                              long expectedVersion);

    /**
     * Soft-delete an upstream-token row: flip {@code status} to {@code REVOKED_INVALID_GRANT},
     * record {@code revokedAt} / {@code revokedReason}, clear the encrypted refresh token, and
     * shorten the row's {@code ttl} to {@code now + revokedRetentionDays} so DynamoDB TTL reaps
     * the audit trail after the configured retention. The write is CAS-protected on
     * {@code expectedVersion} so a peer pod that already rotated the row to {@code expectedVersion + 1}
     * is preserved (the peer won; nothing to revoke).
     *
     * @return true if the conditional write succeeded; false if the row was missing or had been
     *         rotated concurrently
     */
    boolean markRevoked(String providerUserId, long expectedVersion, String reason);

    /**
     * Hard delete. Reserved for tests and the legacy migration path; production code should call
     * {@link #markRevoked(String, long, String)} so an audit trail survives the next investigation.
     */
    void delete(String providerUserId);
}
