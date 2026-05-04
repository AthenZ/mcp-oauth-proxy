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

import io.athenz.mop.model.BearerIndexRecord;

/**
 * Bearer-index lookup store. Maps {@code H(bearer)} (sha512 hex) to the owning
 * {@code (userId, clientId, provider, exp, ttl)} pointer, with {@code H(bearer)} as the primary key.
 *
 * <p>Each minted bearer gets its own immutable row, so concurrent same-{@code (userId, clientId,
 * provider)} bearers from different MCP-client windows never overwrite each other (the multi-window
 * /userinfo 401 bug). Rows hold no token material — DynamoDB TTL evicts them shortly after the
 * underlying bearer can no longer be used.
 */
public interface BearerIndexStore {

    /**
     * Insert (or overwrite) the row keyed by {@code accessTokenHash}. Idempotent for retries: a
     * second mint that produces the same hash simply rewrites the same {@code (userId, clientId,
     * provider, exp, ttl)} mapping.
     *
     * @param accessTokenHash sha512 hex of the bearer
     * @param userId          owning user id
     * @param clientId        MoP client id; pass {@code null} or empty to skip surfacing
     *                        {@code mcp_client_id} on the /userinfo response
     * @param provider        provider key (okta, glean, splunk, ...)
     * @param exp             bearer's own expiry, epoch seconds; {@code 0} when unknown
     * @param ttl             DynamoDB TTL, epoch seconds; row auto-evicts at/after this time
     */
    void putBearer(String accessTokenHash, String userId, String clientId, String provider,
                   long exp, long ttl);

    /**
     * Look up the row for the given hash. Returns {@code null} when the row is absent.
     */
    BearerIndexRecord getBearer(String accessTokenHash);

    /**
     * Best-effort delete. Used by family/upstream revoke paths so a freshly-revoked bearer
     * stops resolving via /userinfo before its DynamoDB TTL kicks in. Failures are logged and
     * swallowed; the TTL is the durable backstop.
     */
    void deleteBearer(String accessTokenHash);
}
