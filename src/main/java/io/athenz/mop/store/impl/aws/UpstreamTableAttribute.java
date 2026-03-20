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
 */
public enum UpstreamTableAttribute {
    PROVIDER_USER_ID("provider_user_id"),
    ENCRYPTED_OKTA_REFRESH_TOKEN("encrypted_okta_refresh_token"),
    LAST_ROTATED_AT("last_rotated_at"),
    VERSION("version"),
    TTL("ttl"),
    CREATED_AT("created_at"),
    UPDATED_AT("updated_at");

    private final String name;

    UpstreamTableAttribute(String name) {
        this.name = name;
    }

    public String attr() {
        return name;
    }
}
