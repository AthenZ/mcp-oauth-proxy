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

import io.athenz.mop.util.JwtUtils;
import java.util.Date;

/**
 * Immutable entry stored in the per-pod Okta upstream session cache (L0).
 *
 * <p>Carries the user-bound Okta tokens plus their pre-parsed expiries so cache freshness
 * decisions are O(1) at read time. Parsing happens once at insert time.
 *
 * <ul>
 *   <li>{@code idTokenExpEpoch} — required for Splunk, Grafana, Databricks, Evaluate, GCP
 *       Workforce, ZTS, and {@code /userinfo}; {@code -1} if the id_token is absent or
 *       unparseable.</li>
 *   <li>{@code accessTokenExpEpoch} — required for Glean / Okta-as-AS, which forwards the
 *       access_token to Okta's token-exchange endpoint; {@code -1} if the access_token is
 *       opaque (non-JWT) or unparseable.</li>
 * </ul>
 *
 * <p>{@link #minExp()} returns the earlier of the two known expiries so a single freshness
 * check protects every consumer with one rule.
 */
public record OktaSessionEntry(
        String idToken,
        String accessToken,
        String refreshToken,
        long idTokenExpEpoch,
        long accessTokenExpEpoch
) {

    /**
     * Effective expiry for cache-freshness decisions: the earlier of the two known expiries.
     * Returns {@code -1} if neither token's {@code exp} is parseable (treat as miss).
     */
    public long minExp() {
        if (idTokenExpEpoch < 0 && accessTokenExpEpoch < 0) {
            return -1;
        }
        if (idTokenExpEpoch < 0) {
            return accessTokenExpEpoch;
        }
        if (accessTokenExpEpoch < 0) {
            return idTokenExpEpoch;
        }
        return Math.min(idTokenExpEpoch, accessTokenExpEpoch);
    }

    /**
     * Parses the {@code exp} claims off the supplied raw tokens once and returns an immutable
     * entry. Either token may be null/blank/opaque; the corresponding {@code expEpoch} is set
     * to {@code -1} in that case.
     */
    public static OktaSessionEntry from(String idToken, String accessToken, String refreshToken) {
        return new OktaSessionEntry(
                idToken,
                accessToken,
                refreshToken,
                parseExpEpoch(idToken),
                parseExpEpoch(accessToken));
    }

    /**
     * Convenience constructor for {@link OktaTokens} produced by {@code OktaTokenClient}.
     */
    public static OktaSessionEntry from(OktaTokens tokens) {
        if (tokens == null) {
            return null;
        }
        return from(tokens.idToken(), tokens.accessToken(), tokens.refreshToken());
    }

    private static long parseExpEpoch(String jwt) {
        if (jwt == null || jwt.isEmpty()) {
            return -1L;
        }
        Object exp = JwtUtils.getClaimFromToken(jwt, "exp");
        if (exp == null) {
            return -1L;
        }
        if (exp instanceof Date d) {
            return d.toInstant().getEpochSecond();
        }
        if (exp instanceof Number n) {
            return n.longValue();
        }
        return -1L;
    }
}
