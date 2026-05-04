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

/**
 * Immutable entry stored in the per-client {@link IdpSessionCache} (L0).
 *
 * <p>Carries the user-bound upstream access token plus its absolute expiry so freshness
 * decisions are O(1). Unlike {@link OktaSessionEntry}, this entry does NOT carry a refresh
 * token — the canonical RT lives only in L2 (the {@code mcp-oauth-proxy-upstream-tokens} table).
 * This is deliberate: per-client L0/L1 must never be a source of truth for refresh material
 * for promoted providers (Google rotates RT on every refresh and we want exactly one writer).
 *
 * <p>{@code idToken} is included for providers that return one on refresh (rare for Google;
 * common for Okta). May be null/empty.
 */
public record IdpSessionEntry(
        String accessToken,
        String idToken,
        long accessTokenExpEpoch
) {

    /**
     * Build an entry from a raw response. {@code expiresInSeconds} is interpreted as a duration
     * relative to {@code nowEpochSeconds}; both are required to be non-negative.
     */
    public static IdpSessionEntry from(String accessToken, String idToken,
                                        long expiresInSeconds, long nowEpochSeconds) {
        long expEpoch = nowEpochSeconds + Math.max(0L, expiresInSeconds);
        return new IdpSessionEntry(accessToken, idToken, expEpoch);
    }
}
