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

import io.athenz.mop.service.AudienceConstants;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RefreshTokenValidationResultTest {

    private static RefreshTokenRecord sampleRecord() {
        return new RefreshTokenRecord(
                "id", AudienceConstants.PROVIDER_OKTA + "#u", "u", "c", AudienceConstants.PROVIDER_OKTA, "sub", "enc", "ACTIVE",
                "f1", null, null, 0L, 1L, 2L, 3L);
    }

    @Test
    void testInvalid() {
        RefreshTokenValidationResult result = RefreshTokenValidationResult.invalid();

        assertNotNull(result);
        assertEquals(RefreshTokenValidationResult.Status.INVALID, result.status());
        assertNull(result.record());
        assertNull(result.replacedByTokenValue());
    }

    @Test
    void testRevoked() {
        RefreshTokenRecord record = sampleRecord();
        RefreshTokenValidationResult result = RefreshTokenValidationResult.revoked(record);

        assertNotNull(result);
        assertEquals(RefreshTokenValidationResult.Status.REVOKED, result.status());
        assertSame(record, result.record());
        assertNull(result.replacedByTokenValue());
    }

    @Test
    void testRotatedReplay() {
        RefreshTokenRecord record = sampleRecord();
        RefreshTokenValidationResult result = RefreshTokenValidationResult.rotatedReplay(record);

        assertNotNull(result);
        assertEquals(RefreshTokenValidationResult.Status.ROTATED_REPLAY, result.status());
        assertSame(record, result.record());
        assertNull(result.replacedByTokenValue());
    }

    @Test
    void testActive() {
        RefreshTokenRecord record = sampleRecord();
        RefreshTokenValidationResult result = RefreshTokenValidationResult.active(record);

        assertNotNull(result);
        assertEquals(RefreshTokenValidationResult.Status.ACTIVE, result.status());
        assertSame(record, result.record());
        assertNull(result.replacedByTokenValue());
    }

    @Test
    void testStatusEnumValues() {
        RefreshTokenValidationResult.Status[] values = RefreshTokenValidationResult.Status.values();
        assertEquals(4, values.length);
        assertNotNull(RefreshTokenValidationResult.Status.INVALID);
        assertNotNull(RefreshTokenValidationResult.Status.REVOKED);
        assertNotNull(RefreshTokenValidationResult.Status.ROTATED_REPLAY);
        assertNotNull(RefreshTokenValidationResult.Status.ACTIVE);
    }

    @Test
    void testStatusValueOf() {
        assertEquals(RefreshTokenValidationResult.Status.INVALID,
                RefreshTokenValidationResult.Status.valueOf("INVALID"));
        assertEquals(RefreshTokenValidationResult.Status.REVOKED,
                RefreshTokenValidationResult.Status.valueOf("REVOKED"));
        assertEquals(RefreshTokenValidationResult.Status.ROTATED_REPLAY,
                RefreshTokenValidationResult.Status.valueOf("ROTATED_REPLAY"));
        assertEquals(RefreshTokenValidationResult.Status.ACTIVE,
                RefreshTokenValidationResult.Status.valueOf("ACTIVE"));
    }

    @Test
    void testConstructorWithAllParams() {
        RefreshTokenRecord record = sampleRecord();
        RefreshTokenValidationResult result = new RefreshTokenValidationResult(
                RefreshTokenValidationResult.Status.ACTIVE, record, "replaced-token-value");

        assertEquals(RefreshTokenValidationResult.Status.ACTIVE, result.status());
        assertSame(record, result.record());
        assertEquals("replaced-token-value", result.replacedByTokenValue());
    }

    @Test
    void testEquality() {
        RefreshTokenRecord record = sampleRecord();
        RefreshTokenValidationResult r1 = RefreshTokenValidationResult.active(record);
        RefreshTokenValidationResult r2 = RefreshTokenValidationResult.active(record);

        assertEquals(r1, r2);
        assertEquals(r1.hashCode(), r2.hashCode());
    }

    @Test
    void testEqualsSelf() {
        RefreshTokenValidationResult result = RefreshTokenValidationResult.invalid();
        assertEquals(result, result);
    }

    @Test
    void testEqualsNull() {
        RefreshTokenValidationResult result = RefreshTokenValidationResult.invalid();
        assertNotEquals(null, result);
        assertFalse(result.equals(null));
    }

    @Test
    void testEqualsDifferentClass() {
        RefreshTokenValidationResult result = RefreshTokenValidationResult.invalid();
        assertNotEquals(result, "not a result");
    }

    @Test
    void testToString() {
        RefreshTokenValidationResult result = RefreshTokenValidationResult.invalid();
        String s = result.toString();
        assertNotNull(s);
        assertTrue(s.contains("RefreshTokenValidationResult"));
    }
}
