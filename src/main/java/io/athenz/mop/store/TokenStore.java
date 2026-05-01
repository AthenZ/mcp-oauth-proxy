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

import io.athenz.mop.model.TokenWrapper;

public interface TokenStore {
    /**
     * Store a per-MCP-client bearer row. Composes the partition-key value as
     * "<clientId>#<user>" so multiple MCP clients (Cursor, Claude, Codex) can each
     * have their own bearer for the same (user, provider) without overwriting each
     * other. /userinfo's access_token_hash GSI then resolves each client's bearer
     * to its own row.
     */
    void storeUserToken(String user, String provider, String clientId, TokenWrapper token);

    /**
     * Store a row that is NOT scoped to an MCP client (e.g. the upstream-IDP
     * session marker / refresh-token cache row used by AuthorizeResource and the
     * upstream-refresh-inheritance lookup, or the Okta SSO row refreshed by
     * /userinfo's own internal Okta refresh path).
     */
    void storeUserToken(String user, String provider, TokenWrapper token);

    TokenWrapper getUserToken(String user, String provider);
    TokenWrapper getUserTokenByAccessTokenHash(String accessTokenHash);

    /** Remove the row for this user/provider (e.g. after upstream refresh is no longer valid). */
    void deleteUserToken(String user, String provider);
}
