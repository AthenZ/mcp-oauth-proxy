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

public enum TokenTableAttribute {
    USER("user"),
    PROVIDER("provider"),
    ID_TOKEN("id_token"),
    ACCESS_TOKEN("access_token"),
    REFRESH_TOKEN("refresh_token"),
    TTL("ttl"),
    AUTH_CODE_JSON("auth_code_json"),
    AUTH_TOKENS_JSON("auth_tokens_json"),
    ACCESS_TOKEN_HASH("access_token_hash");

    private final String attributeName;

    TokenTableAttribute(String attributeName) {
        this.attributeName = attributeName;
    }

    public String attr() {
        return attributeName;
    }
}
