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
 * DynamoDB attribute names for the mcp-oauth-proxy-refresh-tokens table.
 * Schema per MOP Refresh Token Design Document.
 */
public enum RefreshTableAttribute {
    REFRESH_TOKEN_ID("refresh_token_id"),
    PROVIDER_USER_ID("provider_user_id"),
    REFRESH_TOKEN_HASH("refresh_token_hash"),
    USER_ID("user_id"),
    CLIENT_ID("client_id"),
    PROVIDER("provider"),
    PROVIDER_SUBJECT("provider_subject"),
    ENCRYPTED_UPSTREAM_REFRESH_TOKEN("encrypted_upstream_refresh_token"),
    STATUS("status"),
    TOKEN_FAMILY_ID("token_family_id"),
    ROTATED_FROM("rotated_from"),
    REPLACED_BY("replaced_by"),
    ROTATED_AT("rotated_at"),
    ISSUED_AT("issued_at"),
    EXPIRES_AT("expires_at"),
    TTL("ttl");

    private final String attributeName;

    RefreshTableAttribute(String attributeName) {
        this.attributeName = attributeName;
    }

    public String attr() {
        return attributeName;
    }
}
