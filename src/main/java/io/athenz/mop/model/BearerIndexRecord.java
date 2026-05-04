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
 * One row of the {@code mcp-oauth-proxy-bearer-index} table. Carries no token material —
 * just the pointer attributes /userinfo needs to render its response.
 *
 * @param accessTokenHash sha512 hex of the bearer MoP returned to the MCP client
 * @param userId          owning user id
 * @param clientId        MoP client id; may be empty for legacy bare rows
 * @param provider        provider key (okta, glean, splunk, ...)
 * @param exp             bearer's own expiry, epoch seconds; 0 when unknown
 * @param ttl             DynamoDB TTL, epoch seconds; row is auto-evicted at/after this time
 */
public record BearerIndexRecord(
        String accessTokenHash,
        String userId,
        String clientId,
        String provider,
        long exp,
        long ttl) {
}
