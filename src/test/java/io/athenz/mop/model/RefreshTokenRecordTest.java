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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RefreshTokenRecordTest {

    @Test
    void testCreationWithAllFields() {
        RefreshTokenRecord record = new RefreshTokenRecord(
                "rt-id-1",
                "okta#user1",
                "user1",
                "client1",
                "okta",
                "00uoqmkz1ru90YPep696",
                "enc-upstream",
                "ACTIVE",
                "f1",
                null,
                null,
                0L,
                1000L,
                2000L,
                3000L
        );

        assertNotNull(record);
        assertEquals("rt-id-1", record.refreshTokenId());
        assertEquals("okta#user1", record.providerUserId());
        assertEquals("user1", record.userId());
        assertEquals("client1", record.clientId());
        assertEquals("okta", record.provider());
        assertEquals("00uoqmkz1ru90YPep696", record.providerSubject());
        assertEquals("enc-upstream", record.encryptedUpstreamRefreshToken());
        assertEquals("ACTIVE", record.status());
        assertEquals("f1", record.tokenFamilyId());
        assertNull(record.rotatedFrom());
        assertNull(record.replacedBy());
        assertEquals(0L, record.rotatedAt());
        assertEquals(1000L, record.issuedAt());
        assertEquals(2000L, record.expiresAt());
        assertEquals(3000L, record.ttl());
    }

    @Test
    void testCreationWithRotatedFields() {
        RefreshTokenRecord record = new RefreshTokenRecord(
                "old-id",
                "okta#u",
                "u",
                "c",
                "okta",
                "sub",
                "enc",
                "ROTATED",
                "f1",
                null,
                "new-id",
                12345L,
                1000L,
                2000L,
                3000L
        );

        assertEquals("ROTATED", record.status());
        assertEquals("new-id", record.replacedBy());
        assertEquals(12345L, record.rotatedAt());
    }

    @Test
    void testEquality() {
        RefreshTokenRecord r1 = new RefreshTokenRecord(
                "id", "pu", "u", "c", "okta", "sub", "enc", "ACTIVE",
                "f1", null, null, 0L, 1L, 2L, 3L);
        RefreshTokenRecord r2 = new RefreshTokenRecord(
                "id", "pu", "u", "c", "okta", "sub", "enc", "ACTIVE",
                "f1", null, null, 0L, 1L, 2L, 3L);

        assertEquals(r1, r2);
        assertEquals(r1.hashCode(), r2.hashCode());
    }

    @Test
    void testInequality() {
        RefreshTokenRecord r1 = new RefreshTokenRecord(
                "id1", "pu", "u", "c", "okta", "sub", "enc", "ACTIVE",
                "f1", null, null, 0L, 1L, 2L, 3L);
        RefreshTokenRecord r2 = new RefreshTokenRecord(
                "id2", "pu", "u", "c", "okta", "sub", "enc", "ACTIVE",
                "f1", null, null, 0L, 1L, 2L, 3L);

        assertNotEquals(r1, r2);
    }

    @Test
    void testEqualsSelf() {
        RefreshTokenRecord record = new RefreshTokenRecord(
                "id", "pu", "u", "c", "okta", "sub", "enc", "ACTIVE",
                "f1", null, null, 0L, 1L, 2L, 3L);
        assertEquals(record, record);
    }

    @Test
    void testEqualsNull() {
        RefreshTokenRecord record = new RefreshTokenRecord(
                "id", "pu", "u", "c", "okta", "sub", "enc", "ACTIVE",
                "f1", null, null, 0L, 1L, 2L, 3L);
        assertNotEquals(null, record);
        assertFalse(record.equals(null));
    }

    @Test
    void testEqualsDifferentClass() {
        RefreshTokenRecord record = new RefreshTokenRecord(
                "id", "pu", "u", "c", "okta", "sub", "enc", "ACTIVE",
                "f1", null, null, 0L, 1L, 2L, 3L);
        assertNotEquals(record, "not a record");
    }

    @Test
    void testToString() {
        RefreshTokenRecord record = new RefreshTokenRecord(
                "id", "pu", "u", "c", "okta", "sub", "enc", "ACTIVE",
                "f1", null, null, 0L, 1L, 2L, 3L);
        String s = record.toString();
        assertNotNull(s);
        assertTrue(s.contains("RefreshTokenRecord"));
    }
}
