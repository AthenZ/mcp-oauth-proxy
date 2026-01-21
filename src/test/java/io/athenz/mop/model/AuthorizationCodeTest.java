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

import io.athenz.mop.model.AuthorizationCode;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class AuthorizationCodeTest {

    @Test
    void testConstructor_AllParameters() {
        Instant expiresAt = Instant.now().plusSeconds(300);
        AuthorizationCode authCode = new AuthorizationCode(
                "code123",
                "client-id",
                "user@example.com",
                "https://example.com/callback",
                "openid profile",
                "https://resource.example.com",
                "challenge123",
                "S256",
                expiresAt,
                "state123"
        );

        assertEquals("code123", authCode.getCode());
        assertEquals("client-id", authCode.getClientId());
        assertEquals("user@example.com", authCode.getSubject());
        assertEquals("https://example.com/callback", authCode.getRedirectUri());
        assertEquals("openid profile", authCode.getScope());
        assertEquals("https://resource.example.com", authCode.getResource());
        assertEquals("challenge123", authCode.getCodeChallenge());
        assertEquals("S256", authCode.getCodeChallengeMethod());
        assertEquals(expiresAt, authCode.getExpiresAt());
        assertEquals("state123", authCode.getState());
        assertFalse(authCode.isUsed());
    }

    @Test
    void testDefaultConstructor() {
        AuthorizationCode authCode = new AuthorizationCode();
        assertNotNull(authCode);
        assertNull(authCode.getCode());
        assertNull(authCode.getClientId());
        assertNull(authCode.getSubject());
        assertFalse(authCode.isUsed());
    }

    @Test
    void testSettersAndGetters() {
        AuthorizationCode authCode = new AuthorizationCode();
        Instant expiresAt = Instant.now().plusSeconds(300);

        authCode.setCode("code456");
        authCode.setClientId("client-456");
        authCode.setSubject("test@example.com");
        authCode.setRedirectUri("https://test.com/callback");
        authCode.setScope("read write");
        authCode.setResource("https://api.example.com");
        authCode.setCodeChallenge("challenge456");
        authCode.setCodeChallengeMethod("S256");
        authCode.setExpiresAt(expiresAt);
        authCode.setState("state456");
        authCode.setUsed(true);

        assertEquals("code456", authCode.getCode());
        assertEquals("client-456", authCode.getClientId());
        assertEquals("test@example.com", authCode.getSubject());
        assertEquals("https://test.com/callback", authCode.getRedirectUri());
        assertEquals("read write", authCode.getScope());
        assertEquals("https://api.example.com", authCode.getResource());
        assertEquals("challenge456", authCode.getCodeChallenge());
        assertEquals("S256", authCode.getCodeChallengeMethod());
        assertEquals(expiresAt, authCode.getExpiresAt());
        assertEquals("state456", authCode.getState());
        assertTrue(authCode.isUsed());
    }

    @Test
    void testMarkAsUsed() {
        Instant expiresAt = Instant.now().plusSeconds(300);
        AuthorizationCode authCode = new AuthorizationCode(
                "code123", "client-id", "user@example.com",
                "https://example.com/callback", "openid", "https://resource.example.com",
                "challenge", "S256", expiresAt, "state"
        );

        assertFalse(authCode.isUsed());
        authCode.markAsUsed();
        assertTrue(authCode.isUsed());
    }

    @Test
    void testIsExpired_NotExpired() {
        Instant futureExpiry = Instant.now().plusSeconds(300);
        AuthorizationCode authCode = new AuthorizationCode(
                "code123", "client-id", "user@example.com",
                "https://example.com/callback", "openid", "https://resource.example.com",
                "challenge", "S256", futureExpiry, "state"
        );

        assertFalse(authCode.isExpired());
    }

    @Test
    void testIsExpired_Expired() {
        Instant pastExpiry = Instant.now().minusSeconds(300);
        AuthorizationCode authCode = new AuthorizationCode(
                "code123", "client-id", "user@example.com",
                "https://example.com/callback", "openid", "https://resource.example.com",
                "challenge", "S256", pastExpiry, "state"
        );

        assertTrue(authCode.isExpired());
    }

    @Test
    void testIsValid_ValidCode() {
        Instant futureExpiry = Instant.now().plusSeconds(300);
        AuthorizationCode authCode = new AuthorizationCode(
                "code123", "client-id", "user@example.com",
                "https://example.com/callback", "openid", "https://resource.example.com",
                "challenge", "S256", futureExpiry, "state"
        );

        assertTrue(authCode.isValid());
    }

    @Test
    void testIsValid_UsedCode() {
        Instant futureExpiry = Instant.now().plusSeconds(300);
        AuthorizationCode authCode = new AuthorizationCode(
                "code123", "client-id", "user@example.com",
                "https://example.com/callback", "openid", "https://resource.example.com",
                "challenge", "S256", futureExpiry, "state"
        );

        authCode.markAsUsed();
        assertFalse(authCode.isValid());
    }

    @Test
    void testIsValid_ExpiredCode() {
        Instant pastExpiry = Instant.now().minusSeconds(300);
        AuthorizationCode authCode = new AuthorizationCode(
                "code123", "client-id", "user@example.com",
                "https://example.com/callback", "openid", "https://resource.example.com",
                "challenge", "S256", pastExpiry, "state"
        );

        assertFalse(authCode.isValid());
    }

    @Test
    void testIsValid_UsedAndExpired() {
        Instant pastExpiry = Instant.now().minusSeconds(300);
        AuthorizationCode authCode = new AuthorizationCode(
                "code123", "client-id", "user@example.com",
                "https://example.com/callback", "openid", "https://resource.example.com",
                "challenge", "S256", pastExpiry, "state"
        );

        authCode.markAsUsed();
        assertFalse(authCode.isValid());
        assertTrue(authCode.isUsed());
        assertTrue(authCode.isExpired());
    }

    @Test
    void testIsExpired_ExactExpiryTime() throws InterruptedException {
        Instant expiresAt = Instant.now().plusMillis(100);
        AuthorizationCode authCode = new AuthorizationCode(
                "code123", "client-id", "user@example.com",
                "https://example.com/callback", "openid", "https://resource.example.com",
                "challenge", "S256", expiresAt, "state"
        );

        assertFalse(authCode.isExpired());
        Thread.sleep(150);
        assertTrue(authCode.isExpired());
    }
}
