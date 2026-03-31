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

class GcpZmsPrincipalScopeTest {

    @Test
    void accessors() {
        GcpZmsPrincipalScope s = new GcpZmsPrincipalScope("a openid", "proj-1");
        assertEquals("a openid", s.scope());
        assertEquals("proj-1", s.defaultBillingProject());
    }

    @Test
    void nullBillingProject() {
        GcpZmsPrincipalScope s = new GcpZmsPrincipalScope("openid", null);
        assertNull(s.defaultBillingProject());
    }

    @Test
    void equalsAndHashCode() {
        GcpZmsPrincipalScope a = new GcpZmsPrincipalScope("s", "p");
        GcpZmsPrincipalScope b = new GcpZmsPrincipalScope("s", "p");
        GcpZmsPrincipalScope c = new GcpZmsPrincipalScope("t", "p");
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
        assertNotEquals(null, a);
        assertNotEquals(a, new Object());
    }

    @Test
    void toStringContainsComponents() {
        GcpZmsPrincipalScope s = new GcpZmsPrincipalScope("scope", "bill");
        assertTrue(s.toString().contains("scope"));
        assertTrue(s.toString().contains("bill"));
    }
}
