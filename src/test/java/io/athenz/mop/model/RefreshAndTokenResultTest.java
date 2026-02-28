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

class RefreshAndTokenResultTest {

    @Test
    void testCreationWithAllFields() {
        TokenResponse tokenResponse = new TokenResponse("access", "Bearer", 3600L, "scope");
        String newUpstream = "new-upstream-refresh-token";
        RefreshAndTokenResult result = new RefreshAndTokenResult(tokenResponse, newUpstream);

        assertNotNull(result);
        assertSame(tokenResponse, result.tokenResponse());
        assertEquals("access", result.tokenResponse().accessToken());
        assertEquals(newUpstream, result.newUpstreamRefreshToken());
    }

    @Test
    void testCreationWithNullNewUpstreamRefreshToken() {
        TokenResponse tokenResponse = new TokenResponse("access", "Bearer", 3600L, "scope");
        RefreshAndTokenResult result = new RefreshAndTokenResult(tokenResponse, null);

        assertNotNull(result);
        assertSame(tokenResponse, result.tokenResponse());
        assertNull(result.newUpstreamRefreshToken());
    }

    @Test
    void testCreationWithEmptyNewUpstreamRefreshToken() {
        TokenResponse tokenResponse = new TokenResponse("access", "Bearer", 3600L, "scope");
        RefreshAndTokenResult result = new RefreshAndTokenResult(tokenResponse, "");

        assertNotNull(result);
        assertEquals("", result.newUpstreamRefreshToken());
    }

    @Test
    void testEquality() {
        TokenResponse tr = new TokenResponse("a", "Bearer", 3600L, "s");
        RefreshAndTokenResult r1 = new RefreshAndTokenResult(tr, "up");
        RefreshAndTokenResult r2 = new RefreshAndTokenResult(tr, "up");

        assertEquals(r1, r2);
        assertEquals(r1.hashCode(), r2.hashCode());
    }

    @Test
    void testInequalityDifferentTokenResponse() {
        RefreshAndTokenResult r1 = new RefreshAndTokenResult(
                new TokenResponse("a1", "Bearer", 3600L, "s"), "up");
        RefreshAndTokenResult r2 = new RefreshAndTokenResult(
                new TokenResponse("a2", "Bearer", 3600L, "s"), "up");

        assertNotEquals(r1, r2);
    }

    @Test
    void testInequalityDifferentNewUpstreamRefreshToken() {
        TokenResponse tr = new TokenResponse("a", "Bearer", 3600L, "s");
        RefreshAndTokenResult r1 = new RefreshAndTokenResult(tr, "up1");
        RefreshAndTokenResult r2 = new RefreshAndTokenResult(tr, "up2");

        assertNotEquals(r1, r2);
    }

    @Test
    void testEqualsSelf() {
        RefreshAndTokenResult result = new RefreshAndTokenResult(
                new TokenResponse("a", "Bearer", 3600L, "s"), "up");
        assertEquals(result, result);
    }

    @Test
    void testEqualsNull() {
        RefreshAndTokenResult result = new RefreshAndTokenResult(
                new TokenResponse("a", "Bearer", 3600L, "s"), "up");
        assertNotEquals(null, result);
        assertFalse(result.equals(null));
    }

    @Test
    void testEqualsDifferentClass() {
        RefreshAndTokenResult result = new RefreshAndTokenResult(
                new TokenResponse("a", "Bearer", 3600L, "s"), "up");
        assertNotEquals(result, "not a RefreshAndTokenResult");
    }

    @Test
    void testToString() {
        RefreshAndTokenResult result = new RefreshAndTokenResult(
                new TokenResponse("a", "Bearer", 3600L, "s"), "up");
        String s = result.toString();
        assertNotNull(s);
        assertTrue(s.contains("RefreshAndTokenResult"));
    }
}
