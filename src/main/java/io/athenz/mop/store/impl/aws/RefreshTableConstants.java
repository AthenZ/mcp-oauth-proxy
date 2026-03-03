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
 * GSI and status constants for the mcp-oauth-proxy-refresh-tokens table.
 */
public final class RefreshTableConstants {

    private RefreshTableConstants() {
    }

    /** GSI1: user_id + provider */
    public static final String GSI_USER_PROVIDER = "user-provider-index";

    /** GSI2: token_family_id */
    public static final String GSI_TOKEN_FAMILY = "token-family-index";

    /** GSI3: refresh_token_hash for validation lookup */
    public static final String GSI_REFRESH_TOKEN_HASH = "refresh-token-hash-index";

    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_ROTATED = "ROTATED";
    public static final String STATUS_REVOKED = "REVOKED";
}
