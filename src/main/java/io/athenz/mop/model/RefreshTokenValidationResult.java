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
 * - INVALID: token not found, expired, or wrong client
 * - REVOKED: token family was revoked
 * - ROTATED_REPLAY: token was rotated (replay); family must be revoked
 * - ACTIVE: token is valid and should be rotated
 */
public record RefreshTokenValidationResult(
    Status status,
    RefreshTokenRecord record,
    String replacedByTokenValue
) {
    public enum Status {
        INVALID,
        REVOKED,
        ROTATED_REPLAY,
        ACTIVE
    }

    public static RefreshTokenValidationResult invalid() {
        return new RefreshTokenValidationResult(Status.INVALID, null, null);
    }

    public static RefreshTokenValidationResult revoked(RefreshTokenRecord record) {
        return new RefreshTokenValidationResult(Status.REVOKED, record, null);
    }

    public static RefreshTokenValidationResult rotatedReplay(RefreshTokenRecord record) {
        return new RefreshTokenValidationResult(Status.ROTATED_REPLAY, record, null);
    }

    public static RefreshTokenValidationResult active(RefreshTokenRecord record) {
        return new RefreshTokenValidationResult(Status.ACTIVE, record, null);
    }
}
