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

import io.athenz.mop.model.AuthorizationCodeTokensDO;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AuthorizationCodeTokensDOTest {

    @Test
    void testGetAndSetIdToken() {
        AuthorizationCodeTokensDO tokensDO = new AuthorizationCodeTokensDO();
        String idToken = "test-id-token";

        tokensDO.setIdToken(idToken);

        assertEquals(idToken, tokensDO.getIdToken());
    }

    @Test
    void testGetAndSetAccessToken() {
        AuthorizationCodeTokensDO tokensDO = new AuthorizationCodeTokensDO();
        String accessToken = "test-access-token";

        tokensDO.setAccessToken(accessToken);

        assertEquals(accessToken, tokensDO.getAccessToken());
    }

    @Test
    void testGetAndSetRefreshToken() {
        AuthorizationCodeTokensDO tokensDO = new AuthorizationCodeTokensDO();
        String refreshToken = "test-refresh-token";

        tokensDO.setRefreshToken(refreshToken);

        assertEquals(refreshToken, tokensDO.getRefreshToken());
    }

    @Test
    void testGetAndSetAccessTokenExpiresIn() {
        AuthorizationCodeTokensDO tokensDO = new AuthorizationCodeTokensDO();
        Long expiresIn = 3600L;

        tokensDO.setAccessTokenExpiresIn(expiresIn);

        assertEquals(expiresIn, tokensDO.getAccessTokenExpiresIn());
    }

    @Test
    void testGetAndSetAccessTokenScope() {
        AuthorizationCodeTokensDO tokensDO = new AuthorizationCodeTokensDO();
        String scope = "read write";

        tokensDO.setAccessTokenScope(scope);

        assertEquals(scope, tokensDO.getAccessTokenScope());
    }

    @Test
    void testAllFieldsSetCorrectly() {
        AuthorizationCodeTokensDO tokensDO = new AuthorizationCodeTokensDO();
        String idToken = "id-token-123";
        String accessToken = "access-token-456";
        String refreshToken = "refresh-token-789";
        Long expiresIn = 7200L;
        String scope = "openid profile email";

        tokensDO.setIdToken(idToken);
        tokensDO.setAccessToken(accessToken);
        tokensDO.setRefreshToken(refreshToken);
        tokensDO.setAccessTokenExpiresIn(expiresIn);
        tokensDO.setAccessTokenScope(scope);

        assertEquals(idToken, tokensDO.getIdToken());
        assertEquals(accessToken, tokensDO.getAccessToken());
        assertEquals(refreshToken, tokensDO.getRefreshToken());
        assertEquals(expiresIn, tokensDO.getAccessTokenExpiresIn());
        assertEquals(scope, tokensDO.getAccessTokenScope());
    }

    @Test
    void testNullValues() {
        AuthorizationCodeTokensDO tokensDO = new AuthorizationCodeTokensDO();

        assertNull(tokensDO.getIdToken());
        assertNull(tokensDO.getAccessToken());
        assertNull(tokensDO.getRefreshToken());
        assertNull(tokensDO.getAccessTokenExpiresIn());
        assertNull(tokensDO.getAccessTokenScope());
    }

    @Test
    void testSetNullValues() {
        AuthorizationCodeTokensDO tokensDO = new AuthorizationCodeTokensDO();
        tokensDO.setIdToken("initial");
        tokensDO.setAccessToken("initial");
        tokensDO.setRefreshToken("initial");
        tokensDO.setAccessTokenExpiresIn(1000L);
        tokensDO.setAccessTokenScope("initial");

        tokensDO.setIdToken(null);
        tokensDO.setAccessToken(null);
        tokensDO.setRefreshToken(null);
        tokensDO.setAccessTokenExpiresIn(null);
        tokensDO.setAccessTokenScope(null);

        assertNull(tokensDO.getIdToken());
        assertNull(tokensDO.getAccessToken());
        assertNull(tokensDO.getRefreshToken());
        assertNull(tokensDO.getAccessTokenExpiresIn());
        assertNull(tokensDO.getAccessTokenScope());
    }

    @Test
    void testAccessTokenExpiresInWithZero() {
        AuthorizationCodeTokensDO tokensDO = new AuthorizationCodeTokensDO();

        tokensDO.setAccessTokenExpiresIn(0L);

        assertEquals(0L, tokensDO.getAccessTokenExpiresIn());
    }

    @Test
    void testAccessTokenExpiresInWithNegativeValue() {
        AuthorizationCodeTokensDO tokensDO = new AuthorizationCodeTokensDO();

        tokensDO.setAccessTokenExpiresIn(-1L);

        assertEquals(-1L, tokensDO.getAccessTokenExpiresIn());
    }

    @Test
    void testEmptyStringValues() {
        AuthorizationCodeTokensDO tokensDO = new AuthorizationCodeTokensDO();

        tokensDO.setIdToken("");
        tokensDO.setAccessToken("");
        tokensDO.setRefreshToken("");
        tokensDO.setAccessTokenScope("");

        assertEquals("", tokensDO.getIdToken());
        assertEquals("", tokensDO.getAccessToken());
        assertEquals("", tokensDO.getRefreshToken());
        assertEquals("", tokensDO.getAccessTokenScope());
    }

    @Test
    void testLongTokenStrings() {
        AuthorizationCodeTokensDO tokensDO = new AuthorizationCodeTokensDO();
        String longToken = "a".repeat(10000);

        tokensDO.setIdToken(longToken);
        tokensDO.setAccessToken(longToken);
        tokensDO.setRefreshToken(longToken);

        assertEquals(longToken, tokensDO.getIdToken());
        assertEquals(longToken, tokensDO.getAccessToken());
        assertEquals(longToken, tokensDO.getRefreshToken());
    }

    @Test
    void testAccessTokenExpiresInWithMaxLong() {
        AuthorizationCodeTokensDO tokensDO = new AuthorizationCodeTokensDO();

        tokensDO.setAccessTokenExpiresIn(Long.MAX_VALUE);

        assertEquals(Long.MAX_VALUE, tokensDO.getAccessTokenExpiresIn());
    }

    @Test
    void testMultipleScopesInAccessTokenScope() {
        AuthorizationCodeTokensDO tokensDO = new AuthorizationCodeTokensDO();
        String multipleScopes = "openid profile email read:user write:user admin";

        tokensDO.setAccessTokenScope(multipleScopes);

        assertEquals(multipleScopes, tokensDO.getAccessTokenScope());
    }
}
