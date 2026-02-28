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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RefreshTableAttributeTest {

    @Test
    void testAttrReturnsSnakeCaseName() {
        assertEquals("refresh_token_id", RefreshTableAttribute.REFRESH_TOKEN_ID.attr());
        assertEquals("provider_user_id", RefreshTableAttribute.PROVIDER_USER_ID.attr());
        assertEquals("refresh_token_hash", RefreshTableAttribute.REFRESH_TOKEN_HASH.attr());
        assertEquals("user_id", RefreshTableAttribute.USER_ID.attr());
        assertEquals("client_id", RefreshTableAttribute.CLIENT_ID.attr());
        assertEquals("provider", RefreshTableAttribute.PROVIDER.attr());
        assertEquals("provider_subject", RefreshTableAttribute.PROVIDER_SUBJECT.attr());
        assertEquals("encrypted_upstream_refresh_token", RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr());
        assertEquals("status", RefreshTableAttribute.STATUS.attr());
        assertEquals("token_family_id", RefreshTableAttribute.TOKEN_FAMILY_ID.attr());
        assertEquals("rotated_from", RefreshTableAttribute.ROTATED_FROM.attr());
        assertEquals("replaced_by", RefreshTableAttribute.REPLACED_BY.attr());
        assertEquals("rotated_at", RefreshTableAttribute.ROTATED_AT.attr());
        assertEquals("issued_at", RefreshTableAttribute.ISSUED_AT.attr());
        assertEquals("expires_at", RefreshTableAttribute.EXPIRES_AT.attr());
        assertEquals("ttl", RefreshTableAttribute.TTL.attr());
    }

    @Test
    void testEnumValues() {
        RefreshTableAttribute[] values = RefreshTableAttribute.values();
        assertEquals(16, values.length);
    }

    @Test
    void testValueOf() {
        assertEquals(RefreshTableAttribute.REFRESH_TOKEN_ID, RefreshTableAttribute.valueOf("REFRESH_TOKEN_ID"));
        assertEquals(RefreshTableAttribute.STATUS, RefreshTableAttribute.valueOf("STATUS"));
        assertEquals(RefreshTableAttribute.ROTATED_AT, RefreshTableAttribute.valueOf("ROTATED_AT"));
        assertEquals(RefreshTableAttribute.TTL, RefreshTableAttribute.valueOf("TTL"));
    }

    @Test
    void testValueOfInvalidName() {
        assertThrows(IllegalArgumentException.class, () -> RefreshTableAttribute.valueOf("INVALID"));
    }

    @Test
    void testAttributeNamesNotNullAndNotEmpty() {
        for (RefreshTableAttribute attr : RefreshTableAttribute.values()) {
            assertNotNull(attr.attr(), "attr() should not be null for " + attr);
            assertFalse(attr.attr().isEmpty(), "attr() should not be empty for " + attr);
        }
    }

    @Test
    void testAttributeNamesUnique() {
        long distinctCount = java.util.Arrays.stream(RefreshTableAttribute.values())
                .map(RefreshTableAttribute::attr)
                .distinct()
                .count();
        assertEquals(RefreshTableAttribute.values().length, distinctCount);
    }
}
