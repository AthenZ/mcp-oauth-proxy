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
 * Result of validating a refresh token.
 * <ul>
 *   <li>{@code INVALID}: token not found, expired, or wrong client</li>
 *   <li>{@code REVOKED}: token family was revoked</li>
 *   <li>{@code ROTATED_REPLAY}: token was rotated and the rotation is older than the grace
 *       window; family must be revoked (genuine stolen-RT defense)</li>
 *   <li>{@code ROTATED_GRACE_SUCCESSOR}: token was rotated <em>recently</em> (within
 *       {@code server.refresh-token.rotated-grace-seconds}). Treat the duplicate call as a
 *       benign client retry and serve from the successor row carried in {@link #successor()}
 *       instead of revoking the family.</li>
 *   <li>{@code ACTIVE}: token is valid and should be rotated</li>
 * </ul>
 *
 * <p>The {@code successor} field is non-null only for {@code ROTATED_GRACE_SUCCESSOR} and points
 * at the most recent ACTIVE descendant in the same token family. Callers re-rotate against this
 * successor so the duplicate caller receives a fresh, working RT pair without any family
 * revocation.</p>
 */
public record RefreshTokenValidationResult(
    Status status,
    RefreshTokenRecord record,
    String replacedByTokenValue,
    RefreshTokenRecord successor
) {
    public enum Status {
        INVALID,
        REVOKED,
        ROTATED_REPLAY,
        ROTATED_GRACE_SUCCESSOR,
        ACTIVE
    }

    public static RefreshTokenValidationResult invalid() {
        return new RefreshTokenValidationResult(Status.INVALID, null, null, null);
    }

    public static RefreshTokenValidationResult revoked(RefreshTokenRecord record) {
        return new RefreshTokenValidationResult(Status.REVOKED, record, null, null);
    }

    public static RefreshTokenValidationResult rotatedReplay(RefreshTokenRecord record) {
        return new RefreshTokenValidationResult(Status.ROTATED_REPLAY, record, null, null);
    }

    public static RefreshTokenValidationResult rotatedGraceSuccessor(RefreshTokenRecord parent,
                                                                    RefreshTokenRecord successor) {
        return new RefreshTokenValidationResult(Status.ROTATED_GRACE_SUCCESSOR, parent, null, successor);
    }

    public static RefreshTokenValidationResult active(RefreshTokenRecord record) {
        return new RefreshTokenValidationResult(Status.ACTIVE, record, null, null);
    }
}
