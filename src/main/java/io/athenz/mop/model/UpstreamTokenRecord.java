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
package io.athenz.mop.model;

/**
 * One canonical upstream refresh token per {@code provider_user_id} (e.g. {@code okta#subject}
 * or {@code google-slides#subject}). The refresh value is encrypted at rest by the DynamoDB
 * encryption client; at the application layer this record carries plaintext after decrypt on read.
 *
 * <p>Originally Okta-only, the row is now generalized for promoted upstream IdP providers
 * (Google Workspace today). The field name {@code encryptedOktaRefreshToken} is kept for backward
 * compatibility with the on-disk attribute name; renaming would require a cross-region DBE schema
 * migration that is intentionally deferred.
 *
 * <p>{@code status} implements soft-delete semantics: only {@link #STATUS_ACTIVE} rows participate
 * in the refresh path. Any other value (e.g. {@link #STATUS_REVOKED_INVALID_GRANT}) keeps the row
 * around as an audit trail until DynamoDB TTL eviction. Reads from older rows that predate this
 * field default to {@code ACTIVE} for backward compatibility.
 *
 * <p>The {@code lastMinted*} trio stages the most-recently-minted upstream access token alongside
 * the rotated RT in a single CAS write. A second client arriving at the L2 lock within a short
 * grace window (see {@code server.upstream-token.l2-at-reuse-grace-seconds}) can copy that AT
 * into its own per-client cells without issuing a fresh upstream refresh, which is what gives
 * "N concurrent clients = 1 upstream call when contended". The trio is optional on read: rows
 * that predate the staged-AT change return null/0 and the caller falls through to a normal
 * upstream call.
 */
public record UpstreamTokenRecord(
        String providerUserId,
        String encryptedOktaRefreshToken,
        String lastRotatedAt,
        long version,
        long ttl,
        String createdAt,
        String updatedAt,
        String status,
        String revokedAt,
        String revokedReason,
        long rotationCount,
        String lastMintedAccessToken,
        long lastMintedAtExpiresAt,
        long lastMintedAtRotationVersion
) {

    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_REVOKED_INVALID_GRANT = "REVOKED_INVALID_GRANT";

    /**
     * Convenience constructor that fills the soft-delete fields with their default ACTIVE values
     * AND zero-fills the staged-AT trio. Predates the {@code status / revokedAt / revokedReason /
     * rotationCount} schema additions and the later {@code lastMinted*} additions; preserved for
     * callers (mostly tests) that don't care about those fields.
     */
    public UpstreamTokenRecord(
            String providerUserId,
            String encryptedOktaRefreshToken,
            String lastRotatedAt,
            long version,
            long ttl,
            String createdAt,
            String updatedAt) {
        this(providerUserId, encryptedOktaRefreshToken, lastRotatedAt, version, ttl, createdAt, updatedAt,
                STATUS_ACTIVE, null, null, 0L, null, 0L, 0L);
    }

    /**
     * Pre-staged-AT 11-arg constructor preserved so existing call sites (tests and earlier
     * production helpers) compile without modification. Zero-fills the {@code lastMinted*} trio.
     */
    public UpstreamTokenRecord(
            String providerUserId,
            String encryptedOktaRefreshToken,
            String lastRotatedAt,
            long version,
            long ttl,
            String createdAt,
            String updatedAt,
            String status,
            String revokedAt,
            String revokedReason,
            long rotationCount) {
        this(providerUserId, encryptedOktaRefreshToken, lastRotatedAt, version, ttl, createdAt, updatedAt,
                status, revokedAt, revokedReason, rotationCount, null, 0L, 0L);
    }

    /** True when the row is consultable by the refresh path. */
    public boolean isActive() {
        return status == null || status.isEmpty() || STATUS_ACTIVE.equals(status);
    }

    /**
     * True when the staged AT is freshly minted (rotated within {@code graceSeconds}) AND has at
     * least {@code minRemainingSeconds} of lifetime left at {@code nowEpochSeconds}. Both checks
     * are required: a stale "rotated 25s ago" entry whose AT is about to expire would be served
     * as a near-dead AT, and a freshly-minted AT whose timestamp got skewed wildly into the past
     * could otherwise trick the second client into bypassing the refresh.
     *
     * @param nowEpochSeconds       current wall clock in epoch seconds
     * @param graceSeconds          rotation freshness window (the L2 row's
     *                              {@code lastMintedAtExpiresAt} minus its derived rotated-at
     *                              must be within this many seconds of now — we approximate
     *                              "rotated within grace" by checking the staged AT's remaining
     *                              lifetime; see {@link UpstreamRefreshService})
     * @param minRemainingSeconds   minimum AT TTL required for reuse (defends against handing
     *                              out an AT that's about to expire mid-flight)
     */
    public boolean stagedAtIsFresh(long nowEpochSeconds, long graceSeconds, long minRemainingSeconds) {
        if (lastMintedAccessToken == null || lastMintedAccessToken.isEmpty()) {
            return false;
        }
        if (lastMintedAtExpiresAt <= 0L) {
            return false;
        }
        long remaining = lastMintedAtExpiresAt - nowEpochSeconds;
        if (remaining < minRemainingSeconds) {
            return false;
        }
        // The staged AT was minted at most graceSeconds ago iff (expires_at - now) is within
        // (atLifetime - graceSeconds, atLifetime]. We don't track the full AT lifetime on the
        // row (Google may return any of 3599/2999/etc.), so we approximate: if the AT has
        // _more_ than (atLifetime - graceSeconds) of life left it must have been minted recently.
        // Since we can't recover the original lifetime, we use a conservative heuristic: the
        // staged AT is "freshly rotated" when it has been minted within the grace window AND
        // we can verify that via the rotation_version on the row tracking the version that
        // produced it. Callers wanting the strict timestamp check should compare
        // {@code lastMintedAtRotationVersion} against {@code version} (equal when the staged AT
        // was produced by the most recent rotation; differs once a peer rotated again).
        // Lifetime check: assume a typical 3600s AT lifetime; require remaining > (3600 - grace).
        long assumedAtLifetime = 3600L;
        long minRemainingForFreshness = assumedAtLifetime - graceSeconds;
        return remaining >= minRemainingForFreshness;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String providerUserId;
        private String encryptedOktaRefreshToken;
        private String lastRotatedAt;
        private long version = 1L;
        private long ttl;
        private String createdAt;
        private String updatedAt;
        private String status = STATUS_ACTIVE;
        private String revokedAt;
        private String revokedReason;
        private long rotationCount = 0L;
        private String lastMintedAccessToken;
        private long lastMintedAtExpiresAt = 0L;
        private long lastMintedAtRotationVersion = 0L;

        public Builder providerUserId(String v) {
            this.providerUserId = v;
            return this;
        }

        public Builder encryptedOktaRefreshToken(String v) {
            this.encryptedOktaRefreshToken = v;
            return this;
        }

        public Builder lastRotatedAt(String v) {
            this.lastRotatedAt = v;
            return this;
        }

        public Builder version(long v) {
            this.version = v;
            return this;
        }

        public Builder ttl(long v) {
            this.ttl = v;
            return this;
        }

        public Builder createdAt(String v) {
            this.createdAt = v;
            return this;
        }

        public Builder updatedAt(String v) {
            this.updatedAt = v;
            return this;
        }

        public Builder status(String v) {
            this.status = v;
            return this;
        }

        public Builder revokedAt(String v) {
            this.revokedAt = v;
            return this;
        }

        public Builder revokedReason(String v) {
            this.revokedReason = v;
            return this;
        }

        public Builder rotationCount(long v) {
            this.rotationCount = v;
            return this;
        }

        public Builder lastMintedAccessToken(String v) {
            this.lastMintedAccessToken = v;
            return this;
        }

        public Builder lastMintedAtExpiresAt(long v) {
            this.lastMintedAtExpiresAt = v;
            return this;
        }

        public Builder lastMintedAtRotationVersion(long v) {
            this.lastMintedAtRotationVersion = v;
            return this;
        }

        public UpstreamTokenRecord build() {
            return new UpstreamTokenRecord(
                    providerUserId,
                    encryptedOktaRefreshToken,
                    lastRotatedAt,
                    version,
                    ttl,
                    createdAt,
                    updatedAt,
                    status,
                    revokedAt,
                    revokedReason,
                    rotationCount,
                    lastMintedAccessToken,
                    lastMintedAtExpiresAt,
                    lastMintedAtRotationVersion
            );
        }
    }
}
