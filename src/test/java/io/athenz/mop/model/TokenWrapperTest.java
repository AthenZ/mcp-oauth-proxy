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

import io.athenz.mop.model.TokenWrapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TokenWrapperTest {

    private static final String TEST_USER = "user.testuser";
    private static final String TEST_PROVIDER = "https://test-provider.com";
    private static final String TEST_ID_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.id";
    private static final String TEST_ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.access";
    private static final String TEST_REFRESH_TOKEN = "refresh_token_value";
    private static final Long TEST_TTL = 1735311600L;

    @Test
    void testTokenWrapperCreation() {
        TokenWrapper token = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        assertNotNull(token);
        assertEquals(TEST_USER, token.key());
        assertEquals(TEST_PROVIDER, token.provider());
        assertEquals(TEST_ID_TOKEN, token.idToken());
        assertEquals(TEST_ACCESS_TOKEN, token.accessToken());
        assertEquals(TEST_REFRESH_TOKEN, token.refreshToken());
        assertEquals(TEST_TTL, token.ttl());
    }

    @Test
    void testTokenWrapperWithNullRefreshToken() {
        TokenWrapper token = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                null,  // null refresh token
                TEST_TTL
        );

        assertNotNull(token);
        assertEquals(TEST_USER, token.key());
        assertEquals(TEST_PROVIDER, token.provider());
        assertEquals(TEST_ID_TOKEN, token.idToken());
        assertEquals(TEST_ACCESS_TOKEN, token.accessToken());
        assertNull(token.refreshToken());
        assertEquals(TEST_TTL, token.ttl());
    }

    @Test
    void testTokenWrapperEquality() {
        TokenWrapper token1 = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        TokenWrapper token2 = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        assertEquals(token1, token2);
        assertEquals(token1.hashCode(), token2.hashCode());
    }

    @Test
    void testTokenWrapperInequality() {
        TokenWrapper token1 = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        TokenWrapper token2 = new TokenWrapper(
                "user.different",
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        assertNotEquals(token1, token2);
    }

    @Test
    void testTokenWrapperToString() {
        TokenWrapper token = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        String toString = token.toString();
        assertNotNull(toString);
        assertTrue(toString.contains(TEST_USER));
        assertTrue(toString.contains(TEST_PROVIDER));
    }

    @Test
    void testTokenWrapperImmutability() {
        TokenWrapper token = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        // Verify all fields are accessible
        String user = token.key();
        String provider = token.provider();
        String idToken = token.idToken();
        String accessToken = token.accessToken();
        String refreshToken = token.refreshToken();
        Long ttl = token.ttl();

        // Create new instance with same values
        TokenWrapper token2 = new TokenWrapper(user, provider, idToken, accessToken, refreshToken, ttl);

        // Should be equal
        assertEquals(token, token2);
    }

    @Test
    void testTokenWrapperWithDifferentProviders() {
        TokenWrapper token1 = new TokenWrapper(
                TEST_USER,
                "https://provider1.com",
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        TokenWrapper token2 = new TokenWrapper(
                TEST_USER,
                "https://provider2.com",
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        assertNotEquals(token1, token2);
    }

    @Test
    void testTokenWrapperWithDifferentTTL() {
        TokenWrapper token1 = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                1000L
        );

        TokenWrapper token2 = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                2000L
        );

        assertNotEquals(token1, token2);
    }

    @Test
    void testTokenWrapperNullValues() {
        // Test that record can handle null values for optional fields
        TokenWrapper token = new TokenWrapper(
                null,
                null,
                null,
                null,
                null,
                null
        );

        assertNull(token.key());
        assertNull(token.provider());
        assertNull(token.idToken());
        assertNull(token.accessToken());
        assertNull(token.refreshToken());
        assertNull(token.ttl());
    }

    @Test
    void testTokenWrapperHashCodeConsistency() {
        TokenWrapper token = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        int hashCode1 = token.hashCode();
        int hashCode2 = token.hashCode();

        assertEquals(hashCode1, hashCode2);
    }

    @Test
    void testTokenWrapperEqualsSelf() {
        TokenWrapper token = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        assertEquals(token, token);
    }

    @Test
    void testTokenWrapperNotEqualsNull() {
        TokenWrapper token = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        assertNotEquals(null, token);
    }

    @Test
    void testTokenWrapperNotEqualsDifferentClass() {
        TokenWrapper token = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        assertNotEquals(token, "not a TokenWrapper");
    }

    @Test
    void testTokenWrapperWithEmptyStrings() {
        TokenWrapper token = new TokenWrapper(
                "",
                "",
                "",
                "",
                "",
                0L
        );

        assertEquals("", token.key());
        assertEquals("", token.provider());
        assertEquals("", token.idToken());
        assertEquals("", token.accessToken());
        assertEquals("", token.refreshToken());
        assertEquals(0L, token.ttl());
    }

    @Test
    void testTokenWrapperAccessorMethods() {
        TokenWrapper token = new TokenWrapper(
                TEST_USER,
                TEST_PROVIDER,
                TEST_ID_TOKEN,
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                TEST_TTL
        );

        // Verify that all accessor methods work correctly
        assertDoesNotThrow(() -> {
            token.key();
            token.provider();
            token.idToken();
            token.accessToken();
            token.refreshToken();
            token.ttl();
        });
    }
}
