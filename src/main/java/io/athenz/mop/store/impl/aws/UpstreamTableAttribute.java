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
package io.athenz.mop.store.impl.aws;

/**
 * DynamoDB attribute names for {@code mcp-oauth-proxy-upstream-tokens} (partition key only).
 *
 * <p>The original table was Okta-only; the {@code encrypted_okta_refresh_token} attribute name
 * is now used for any promoted provider's canonical RT (Google Workspace today). The name is
 * misleading but renaming requires a cross-region DBE schema migration we do not want to
 * couple with the L2 promotion change.
 *
 * <p>The {@code LAST_MINTED_*} attributes stage the most-recently-minted access token so a
 * second client arriving at the L2 lock within a short grace window can reuse it without
 * issuing a fresh upstream refresh. They are written atomically alongside the rotated RT in
 * {@link UpstreamTokenStoreDynamoDbImpl#updateWithVersionCheck}.
 */
public enum UpstreamTableAttribute {
    PROVIDER_USER_ID("provider_user_id"),
    ENCRYPTED_OKTA_REFRESH_TOKEN("encrypted_okta_refresh_token"),
    LAST_ROTATED_AT("last_rotated_at"),
    VERSION("version"),
    TTL("ttl"),
    CREATED_AT("created_at"),
    UPDATED_AT("updated_at"),
    STATUS("status"),
    REVOKED_AT("revoked_at"),
    REVOKED_REASON("revoked_reason"),
    ROTATION_COUNT("rotation_count"),
    LAST_MINTED_ACCESS_TOKEN("last_minted_access_token"),
    LAST_MINTED_AT_EXPIRES_AT("last_minted_at_expires_at"),
    LAST_MINTED_AT_ROTATION_VERSION("last_minted_at_rotation_version");

    private final String name;

    UpstreamTableAttribute(String name) {
        this.name = name;
    }

    public String attr() {
        return name;
    }
}
