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

import com.nimbusds.oauth2.sdk.TokenErrorResponse;

/**
 * Formats OAuth token endpoint error payloads for logging (no secrets).
 */
public final class UpstreamTokenRefreshErrors {

    private UpstreamTokenRefreshErrors() {
    }

    /**
     * Returns the upstream JSON error body when available (RFC 6749 / OIDC error response).
     */
    public static String formatTokenError(TokenErrorResponse response) {
        if (response == null) {
            return "null";
        }
        try {
            if (response.getErrorObject() != null) {
                return response.getErrorObject().toJSONObject().toString();
            }
        } catch (Exception ignored) {
        }
        try {
            return response.toJSONObject().toString();
        } catch (Exception ex) {
            return String.valueOf(response);
        }
    }
}
