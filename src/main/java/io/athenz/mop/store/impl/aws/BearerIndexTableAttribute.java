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
 * DynamoDB attribute names for the {@code mcp-oauth-proxy-bearer-index} table.
 * The bearer-index row holds no token material; it is purely a pointer that maps
 * {@code H(bearer)} to the owning {@code (userId, clientId, provider)} triple so
 * /userinfo can resolve a presented bearer without ever overwriting siblings.
 */
public enum BearerIndexTableAttribute {
    ACCESS_TOKEN_HASH("access_token_hash"),
    USER_ID("user_id"),
    CLIENT_ID("client_id"),
    PROVIDER("provider"),
    EXP("exp"),
    TTL("ttl");

    private final String attributeName;

    BearerIndexTableAttribute(String attributeName) {
        this.attributeName = attributeName;
    }

    public String attr() {
        return attributeName;
    }
}
