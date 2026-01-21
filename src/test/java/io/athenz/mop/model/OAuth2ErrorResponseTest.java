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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.athenz.mop.model.OAuth2ErrorResponse;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OAuth2ErrorResponseTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void testErrorResponseWithErrorOnly() throws Exception {
        OAuth2ErrorResponse response = OAuth2ErrorResponse.of("invalid_request");

        assertEquals("invalid_request", response.error());
        assertNull(response.errorDescription());
        assertNull(response.errorUri());

        // Verify JSON serialization
        String json = objectMapper.writeValueAsString(response);
        assertTrue(json.contains("\"error\":\"invalid_request\""));
        assertFalse(json.contains("error_description"));
        assertFalse(json.contains("error_uri"));
    }

    @Test
    void testErrorResponseWithDescription() throws Exception {
        OAuth2ErrorResponse response = OAuth2ErrorResponse.of(
                "invalid_grant",
                "The provided authorization grant is invalid");

        assertEquals("invalid_grant", response.error());
        assertEquals("The provided authorization grant is invalid", response.errorDescription());
        assertNull(response.errorUri());

        // Verify JSON serialization
        String json = objectMapper.writeValueAsString(response);
        assertTrue(json.contains("\"error\":\"invalid_grant\""));
        assertTrue(json.contains("\"error_description\":\"The provided authorization grant is invalid\""));
        assertFalse(json.contains("error_uri"));
    }

    @Test
    void testErrorResponseWithAllFields() throws Exception {
        OAuth2ErrorResponse response = new OAuth2ErrorResponse(
                "invalid_client",
                "Client authentication failed",
                "https://example.com/docs/errors/invalid_client");

        assertEquals("invalid_client", response.error());
        assertEquals("Client authentication failed", response.errorDescription());
        assertEquals("https://example.com/docs/errors/invalid_client", response.errorUri());

        // Verify JSON serialization
        String json = objectMapper.writeValueAsString(response);
        assertTrue(json.contains("\"error\":\"invalid_client\""));
        assertTrue(json.contains("\"error_description\":\"Client authentication failed\""));
        assertTrue(json.contains("\"error_uri\":\"https://example.com/docs/errors/invalid_client\""));
    }

    @Test
    void testErrorCodes() {
        // Verify all standard error codes are defined
        assertEquals("invalid_request", OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST);
        assertEquals("invalid_client", OAuth2ErrorResponse.ErrorCode.INVALID_CLIENT);
        assertEquals("invalid_grant", OAuth2ErrorResponse.ErrorCode.INVALID_GRANT);
        assertEquals("unauthorized_client", OAuth2ErrorResponse.ErrorCode.UNAUTHORIZED_CLIENT);
        assertEquals("unsupported_grant_type", OAuth2ErrorResponse.ErrorCode.UNSUPPORTED_GRANT_TYPE);
        assertEquals("invalid_scope", OAuth2ErrorResponse.ErrorCode.INVALID_SCOPE);
        assertEquals("server_error", OAuth2ErrorResponse.ErrorCode.SERVER_ERROR);
        assertEquals("temporarily_unavailable", OAuth2ErrorResponse.ErrorCode.TEMPORARILY_UNAVAILABLE);
    }

    @Test
    void testDeserialization() throws Exception {
        String json = "{\"error\":\"invalid_scope\",\"error_description\":\"The requested scope is invalid\"}";

        OAuth2ErrorResponse response = objectMapper.readValue(json, OAuth2ErrorResponse.class);

        assertEquals("invalid_scope", response.error());
        assertEquals("The requested scope is invalid", response.errorDescription());
        assertNull(response.errorUri());
    }
}
