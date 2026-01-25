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

import io.athenz.mop.store.impl.aws.TokenTableAttribute;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TokenTableAttributeTest {

    @Test
    void testUserAttribute() {
        assertEquals("user", TokenTableAttribute.USER.attr());
    }

    @Test
    void testProviderAttribute() {
        assertEquals("provider", TokenTableAttribute.PROVIDER.attr());
    }

    @Test
    void testIdTokenAttribute() {
        assertEquals("id_token", TokenTableAttribute.ID_TOKEN.attr());
    }

    @Test
    void testAccessTokenAttribute() {
        assertEquals("access_token", TokenTableAttribute.ACCESS_TOKEN.attr());
    }

    @Test
    void testRefreshTokenAttribute() {
        assertEquals("refresh_token", TokenTableAttribute.REFRESH_TOKEN.attr());
    }

    @Test
    void testTtlAttribute() {
        assertEquals("ttl", TokenTableAttribute.TTL.attr());
    }

    @Test
    void testAuthCodeJsonAttribute() {
        assertEquals("auth_code_json", TokenTableAttribute.AUTH_CODE_JSON.attr());
    }

    @Test
    void testAuthTokensJsonAttribute() {
        assertEquals("auth_tokens_json", TokenTableAttribute.AUTH_TOKENS_JSON.attr());
    }

    @Test
    void testEnumValues() {
        TokenTableAttribute[] values = TokenTableAttribute.values();
        assertEquals(8, values.length);
        assertArrayEquals(
                new TokenTableAttribute[]{
                        TokenTableAttribute.USER,
                        TokenTableAttribute.PROVIDER,
                        TokenTableAttribute.ID_TOKEN,
                        TokenTableAttribute.ACCESS_TOKEN,
                        TokenTableAttribute.REFRESH_TOKEN,
                        TokenTableAttribute.TTL,
                        TokenTableAttribute.AUTH_CODE_JSON,
                        TokenTableAttribute.AUTH_TOKENS_JSON
                },
                values
        );
    }

    @Test
    void testValueOf() {
        assertEquals(TokenTableAttribute.USER, TokenTableAttribute.valueOf("USER"));
        assertEquals(TokenTableAttribute.PROVIDER, TokenTableAttribute.valueOf("PROVIDER"));
        assertEquals(TokenTableAttribute.ID_TOKEN, TokenTableAttribute.valueOf("ID_TOKEN"));
        assertEquals(TokenTableAttribute.ACCESS_TOKEN, TokenTableAttribute.valueOf("ACCESS_TOKEN"));
        assertEquals(TokenTableAttribute.REFRESH_TOKEN, TokenTableAttribute.valueOf("REFRESH_TOKEN"));
        assertEquals(TokenTableAttribute.TTL, TokenTableAttribute.valueOf("TTL"));
        assertEquals(TokenTableAttribute.AUTH_CODE_JSON, TokenTableAttribute.valueOf("AUTH_CODE_JSON"));
        assertEquals(TokenTableAttribute.AUTH_TOKENS_JSON, TokenTableAttribute.valueOf("AUTH_TOKENS_JSON"));
    }

    @Test
    void testValueOfInvalidName() {
        assertThrows(IllegalArgumentException.class, () -> {
            TokenTableAttribute.valueOf("INVALID");
        });
    }

    @Test
    void testValueOfNullName() {
        assertThrows(NullPointerException.class, () -> {
            TokenTableAttribute.valueOf(null);
        });
    }

    @Test
    void testAttributeNamesAreUnique() {
        String[] attributeNames = {
                TokenTableAttribute.USER.attr(),
                TokenTableAttribute.PROVIDER.attr(),
                TokenTableAttribute.ID_TOKEN.attr(),
                TokenTableAttribute.ACCESS_TOKEN.attr(),
                TokenTableAttribute.REFRESH_TOKEN.attr(),
                TokenTableAttribute.TTL.attr(),
                TokenTableAttribute.AUTH_CODE_JSON.attr(),
                TokenTableAttribute.AUTH_TOKENS_JSON.attr()
        };

        // Check that all attribute names are unique
        assertEquals(8, java.util.Arrays.stream(attributeNames).distinct().count());
    }

    @Test
    void testAttributeNamesNotNull() {
        for (TokenTableAttribute attribute : TokenTableAttribute.values()) {
            assertNotNull(attribute.attr(), "Attribute name should not be null for " + attribute);
        }
    }

    @Test
    void testAttributeNamesNotEmpty() {
        for (TokenTableAttribute attribute : TokenTableAttribute.values()) {
            assertFalse(attribute.attr().isEmpty(), "Attribute name should not be empty for " + attribute);
        }
    }

    @Test
    void testEnumToString() {
        assertEquals("USER", TokenTableAttribute.USER.toString());
        assertEquals("PROVIDER", TokenTableAttribute.PROVIDER.toString());
        assertEquals("ID_TOKEN", TokenTableAttribute.ID_TOKEN.toString());
        assertEquals("ACCESS_TOKEN", TokenTableAttribute.ACCESS_TOKEN.toString());
        assertEquals("REFRESH_TOKEN", TokenTableAttribute.REFRESH_TOKEN.toString());
        assertEquals("TTL", TokenTableAttribute.TTL.toString());
        assertEquals("AUTH_CODE_JSON", TokenTableAttribute.AUTH_CODE_JSON.toString());
        assertEquals("AUTH_TOKENS_JSON", TokenTableAttribute.AUTH_TOKENS_JSON.toString());
    }

    @Test
    void testEnumName() {
        assertEquals("USER", TokenTableAttribute.USER.name());
        assertEquals("PROVIDER", TokenTableAttribute.PROVIDER.name());
        assertEquals("ID_TOKEN", TokenTableAttribute.ID_TOKEN.name());
        assertEquals("ACCESS_TOKEN", TokenTableAttribute.ACCESS_TOKEN.name());
        assertEquals("REFRESH_TOKEN", TokenTableAttribute.REFRESH_TOKEN.name());
        assertEquals("TTL", TokenTableAttribute.TTL.name());
        assertEquals("AUTH_CODE_JSON", TokenTableAttribute.AUTH_CODE_JSON.name());
        assertEquals("AUTH_TOKENS_JSON", TokenTableAttribute.AUTH_TOKENS_JSON.name());
    }

    @Test
    void testEnumOrdinal() {
        assertEquals(0, TokenTableAttribute.USER.ordinal());
        assertEquals(1, TokenTableAttribute.PROVIDER.ordinal());
        assertEquals(2, TokenTableAttribute.ID_TOKEN.ordinal());
        assertEquals(3, TokenTableAttribute.ACCESS_TOKEN.ordinal());
        assertEquals(4, TokenTableAttribute.REFRESH_TOKEN.ordinal());
        assertEquals(5, TokenTableAttribute.TTL.ordinal());
        assertEquals(6, TokenTableAttribute.AUTH_CODE_JSON.ordinal());
        assertEquals(7, TokenTableAttribute.AUTH_TOKENS_JSON.ordinal());
    }

    @Test
    void testEnumEquality() {
        TokenTableAttribute user1 = TokenTableAttribute.USER;
        TokenTableAttribute user2 = TokenTableAttribute.valueOf("USER");
        assertSame(user1, user2);
        assertEquals(user1, user2);
    }

    @Test
    void testEnumComparison() {
        assertTrue(TokenTableAttribute.USER.compareTo(TokenTableAttribute.PROVIDER) < 0);
        assertTrue(TokenTableAttribute.TTL.compareTo(TokenTableAttribute.USER) > 0);
        assertEquals(0, TokenTableAttribute.ACCESS_TOKEN.compareTo(TokenTableAttribute.ACCESS_TOKEN));
    }

    @Test
    void testAttributeNamingConvention() {
        // Verify that attribute names follow snake_case convention
        assertEquals("user", TokenTableAttribute.USER.attr());
        assertEquals("provider", TokenTableAttribute.PROVIDER.attr());
        assertEquals("id_token", TokenTableAttribute.ID_TOKEN.attr());
        assertEquals("access_token", TokenTableAttribute.ACCESS_TOKEN.attr());
        assertEquals("refresh_token", TokenTableAttribute.REFRESH_TOKEN.attr());
        assertEquals("ttl", TokenTableAttribute.TTL.attr());
        assertEquals("auth_code_json", TokenTableAttribute.AUTH_CODE_JSON.attr());
        assertEquals("auth_tokens_json", TokenTableAttribute.AUTH_TOKENS_JSON.attr());
    }

    @Test
    void testDynamoDBKeyAttributes() {
        // Test that the key attributes (USER and PROVIDER) have correct values
        assertEquals("user", TokenTableAttribute.USER.attr());
        assertEquals("provider", TokenTableAttribute.PROVIDER.attr());
    }

    @Test
    void testTokenAttributes() {
        // Test that token-related attributes have correct values
        assertEquals("id_token", TokenTableAttribute.ID_TOKEN.attr());
        assertEquals("access_token", TokenTableAttribute.ACCESS_TOKEN.attr());
        assertEquals("refresh_token", TokenTableAttribute.REFRESH_TOKEN.attr());
    }

    @Test
    void testTTLAttributeForDynamoDB() {
        // TTL attribute is special in DynamoDB for automatic expiration
        assertEquals("ttl", TokenTableAttribute.TTL.attr());
        assertNotNull(TokenTableAttribute.TTL.attr());
    }
}
