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

import io.athenz.mop.model.TokenResponse;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TokenResponseTest {

    @Test
    void testRecordConstruction() {
        TokenResponse response = new TokenResponse(
                "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
                "Bearer",
                3600L,
                "openid profile"
        );

        assertEquals("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...", response.accessToken());
        assertEquals("Bearer", response.tokenType());
        assertEquals(3600L, response.expiresIn());
        assertEquals("openid profile", response.scope());
    }

    @Test
    void testRecordConstruction_WithNullScope() {
        TokenResponse response = new TokenResponse(
                "token123",
                "Bearer",
                3600L,
                null
        );

        assertEquals("token123", response.accessToken());
        assertEquals("Bearer", response.tokenType());
        assertEquals(3600L, response.expiresIn());
        assertNull(response.scope());
    }

    @Test
    void testRecordConstruction_WithNullExpiresIn() {
        TokenResponse response = new TokenResponse(
                "token456",
                "Bearer",
                null,
                "openid"
        );

        assertEquals("token456", response.accessToken());
        assertEquals("Bearer", response.tokenType());
        assertNull(response.expiresIn());
        assertEquals("openid", response.scope());
    }

    @Test
    void testRecordEquality() {
        TokenResponse response1 = new TokenResponse(
                "token123",
                "Bearer",
                3600L,
                "openid"
        );

        TokenResponse response2 = new TokenResponse(
                "token123",
                "Bearer",
                3600L,
                "openid"
        );

        assertEquals(response1, response2);
        assertEquals(response1.hashCode(), response2.hashCode());
    }

    @Test
    void testRecordInequality_DifferentToken() {
        TokenResponse response1 = new TokenResponse(
                "token123",
                "Bearer",
                3600L,
                "openid"
        );

        TokenResponse response2 = new TokenResponse(
                "token456",
                "Bearer",
                3600L,
                "openid"
        );

        assertNotEquals(response1, response2);
    }

    @Test
    void testRecordInequality_DifferentTokenType() {
        TokenResponse response1 = new TokenResponse(
                "token123",
                "Bearer",
                3600L,
                "openid"
        );

        TokenResponse response2 = new TokenResponse(
                "token123",
                "MAC",
                3600L,
                "openid"
        );

        assertNotEquals(response1, response2);
    }

    @Test
    void testToString() {
        TokenResponse response = new TokenResponse(
                "token123",
                "Bearer",
                3600L,
                "openid profile"
        );

        String toString = response.toString();
        assertTrue(toString.contains("token123"));
        assertTrue(toString.contains("Bearer"));
        assertTrue(toString.contains("3600"));
        assertTrue(toString.contains("openid profile"));
    }

    @Test
    void testRecordWithDifferentExpiresIn() {
        TokenResponse shortLived = new TokenResponse("token1", "Bearer", 60L, "read");
        TokenResponse longLived = new TokenResponse("token1", "Bearer", 86400L, "read");

        assertNotEquals(shortLived, longLived);
    }
}
