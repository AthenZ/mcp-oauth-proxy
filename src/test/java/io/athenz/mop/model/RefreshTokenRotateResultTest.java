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

class RefreshTokenRotateResultTest {

    @Test
    void testCreation() {
        RefreshTokenRotateResult result = new RefreshTokenRotateResult(
                "rt_newRawToken",
                "new-refresh-token-id",
                "okta#user1"
        );

        assertNotNull(result);
        assertEquals("rt_newRawToken", result.rawToken());
        assertEquals("new-refresh-token-id", result.refreshTokenId());
        assertEquals("okta#user1", result.providerUserId());
    }

    @Test
    void testEquality() {
        RefreshTokenRotateResult r1 = new RefreshTokenRotateResult("raw", "id", "pu");
        RefreshTokenRotateResult r2 = new RefreshTokenRotateResult("raw", "id", "pu");

        assertEquals(r1, r2);
        assertEquals(r1.hashCode(), r2.hashCode());
    }

    @Test
    void testInequality() {
        RefreshTokenRotateResult r1 = new RefreshTokenRotateResult("raw1", "id", "pu");
        RefreshTokenRotateResult r2 = new RefreshTokenRotateResult("raw2", "id", "pu");

        assertNotEquals(r1, r2);
    }

    @Test
    void testEqualsSelf() {
        RefreshTokenRotateResult result = new RefreshTokenRotateResult("raw", "id", "pu");
        assertEquals(result, result);
    }

    @Test
    void testEqualsNull() {
        RefreshTokenRotateResult result = new RefreshTokenRotateResult("raw", "id", "pu");
        assertNotEquals(null, result);
        assertFalse(result.equals(null));
    }

    @Test
    void testEqualsDifferentClass() {
        RefreshTokenRotateResult result = new RefreshTokenRotateResult("raw", "id", "pu");
        assertNotEquals(result, "not a result");
    }

    @Test
    void testToString() {
        RefreshTokenRotateResult result = new RefreshTokenRotateResult("raw", "id", "pu");
        String s = result.toString();
        assertNotNull(s);
        assertTrue(s.contains("RefreshTokenRotateResult"));
    }
}
