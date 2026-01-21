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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OAuth 2.0 error response as per RFC 6749 Section 5.2
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record OAuth2ErrorResponse(
    @JsonProperty("error") String error,
    @JsonProperty("error_description") String errorDescription,
    @JsonProperty("error_uri") String errorUri
) {
    /**
     * Standard OAuth 2.0 error codes
     */
    public static class ErrorCode {
        public static final String INVALID_REQUEST = "invalid_request";
        public static final String INVALID_CLIENT = "invalid_client";
        public static final String INVALID_GRANT = "invalid_grant";
        public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
        public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
        public static final String INVALID_SCOPE = "invalid_scope";
        public static final String SERVER_ERROR = "server_error";
        public static final String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";
    }

    /**
     * Create error response with just error code
     */
    public static OAuth2ErrorResponse of(String error) {
        return new OAuth2ErrorResponse(error, null, null);
    }

    /**
     * Create error response with error code and description
     */
    public static OAuth2ErrorResponse of(String error, String description) {
        return new OAuth2ErrorResponse(error, description, null);
    }
}
