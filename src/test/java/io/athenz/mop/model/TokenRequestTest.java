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

import io.athenz.mop.model.TokenRequest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TokenRequestTest {

    @Test
    void testRecordConstruction() {
        TokenRequest request = new TokenRequest(
                "https://api.example.com",
                "user@example.com",
                "openid profile",
                3600L
        );

        assertEquals("https://api.example.com", request.resource());
        assertEquals("user@example.com", request.subject());
        assertEquals("openid profile", request.scopes());
        assertEquals(3600L, request.expiresIn());
    }

    @Test
    void testRecordConstruction_WithNullScopes() {
        TokenRequest request = new TokenRequest(
                "https://api.example.com",
                "user@example.com",
                null,
                3600L
        );

        assertEquals("https://api.example.com", request.resource());
        assertEquals("user@example.com", request.subject());
        assertNull(request.scopes());
        assertEquals(3600L, request.expiresIn());
    }

    @Test
    void testRecordConstruction_WithNullExpiresIn() {
        TokenRequest request = new TokenRequest(
                "https://api.example.com",
                "user@example.com",
                "openid",
                null
        );

        assertEquals("https://api.example.com", request.resource());
        assertEquals("user@example.com", request.subject());
        assertEquals("openid", request.scopes());
        assertNull(request.expiresIn());
    }

    @Test
    void testRecordEquality() {
        TokenRequest request1 = new TokenRequest(
                "https://api.example.com",
                "user@example.com",
                "openid",
                3600L
        );

        TokenRequest request2 = new TokenRequest(
                "https://api.example.com",
                "user@example.com",
                "openid",
                3600L
        );

        assertEquals(request1, request2);
        assertEquals(request1.hashCode(), request2.hashCode());
    }

    @Test
    void testRecordInequality_DifferentResource() {
        TokenRequest request1 = new TokenRequest(
                "https://api.example.com",
                "user@example.com",
                "openid",
                3600L
        );

        TokenRequest request2 = new TokenRequest(
                "https://different.example.com",
                "user@example.com",
                "openid",
                3600L
        );

        assertNotEquals(request1, request2);
    }

    @Test
    void testRecordInequality_DifferentSubject() {
        TokenRequest request1 = new TokenRequest(
                "https://api.example.com",
                "user1@example.com",
                "openid",
                3600L
        );

        TokenRequest request2 = new TokenRequest(
                "https://api.example.com",
                "user2@example.com",
                "openid",
                3600L
        );

        assertNotEquals(request1, request2);
    }

    @Test
    void testToString() {
        TokenRequest request = new TokenRequest(
                "https://api.example.com",
                "user@example.com",
                "openid",
                3600L
        );

        String toString = request.toString();
        assertTrue(toString.contains("https://api.example.com"));
        assertTrue(toString.contains("user@example.com"));
        assertTrue(toString.contains("openid"));
        assertTrue(toString.contains("3600"));
    }
}
