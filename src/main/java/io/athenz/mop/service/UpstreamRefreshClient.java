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
 * Provider-agnostic contract for a single upstream refresh-token call.
 *
 * <p>Implementations adapt the protocol-specific shape (Okta OIDC, Google OAuth2 web,
 * potentially others) into a common {@link UpstreamRefreshResponse}. Used by
 * {@link UpstreamRefreshService} so it can serialize refreshes and cache results without
 * knowing which IdP it's talking to.
 *
 * <p>Error contract:
 * <ul>
 *   <li>A genuine {@code invalid_grant} from the upstream MUST throw an exception that
 *       {@link UpstreamRefreshService} treats as terminal (revokes the L2 row). For Okta this
 *       is {@code OktaTokenRevokedException}; for Google we use the same type so the existing
 *       handling continues to work.</li>
 *   <li>Transient/retryable errors MUST throw {@link UpstreamRefreshTransientException} so the
 *       lock holder retries and the row is not poisoned.</li>
 *   <li>Permanent non-revocation failures (config, network, parse) MAY throw any other
 *       {@link RuntimeException}. The service maps these to a non-revoking {@code 503} response
 *       — we do not destroy the L2 row on infrastructure errors.</li>
 * </ul>
 */
public interface UpstreamRefreshClient {

    /**
     * Calls the upstream IdP with the supplied refresh token and returns the rotated token set.
     *
     * @param providerUserId       the canonical L2 row key, of the form {@code provider#sub}
     *                             (used for telemetry / logging only — implementations are not
     *                             expected to mutate any DDB row).
     * @param upstreamRefreshToken plaintext refresh token previously stored on the L2 row.
     * @return the rotated token set; the {@code refreshToken} field is the new RT to write back
     *         to L2 (Google rotates on every refresh; Okta rotates only on certain conditions —
     *         implementations may return the original RT if the upstream did not rotate).
     */
    UpstreamRefreshResponse refresh(String providerUserId, String upstreamRefreshToken);
}
