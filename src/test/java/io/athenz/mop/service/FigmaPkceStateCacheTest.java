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
package io.athenz.mop.service;

import java.util.Optional;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FigmaPkceStateCacheTest {

    @Test
    void putThenPop_returnsEntryAndIsSingleUse() {
        FigmaPkceStateCache cache = new FigmaPkceStateCache();
        cache.put("state-1", "verifier-1", "mop-code-1");

        Optional<FigmaPkceStateCache.Entry> first = cache.pop("state-1");
        assertTrue(first.isPresent());
        assertEquals("verifier-1", first.get().codeVerifier());
        assertEquals("mop-code-1", first.get().mopAuthCode());

        // Single-use semantics: the second pop must return empty (replay protection).
        assertTrue(cache.pop("state-1").isEmpty());
    }

    @Test
    void pop_unknownState_returnsEmpty() {
        FigmaPkceStateCache cache = new FigmaPkceStateCache();
        assertTrue(cache.pop("never-seen").isEmpty());
    }

    @Test
    void pop_nullOrEmpty_returnsEmpty() {
        FigmaPkceStateCache cache = new FigmaPkceStateCache();
        assertTrue(cache.pop(null).isEmpty());
        assertTrue(cache.pop("").isEmpty());
    }

    @Test
    void put_validatesAllArgsNonEmpty() {
        FigmaPkceStateCache cache = new FigmaPkceStateCache();
        assertThrows(IllegalArgumentException.class, () -> cache.put(null, "v", "m"));
        assertThrows(IllegalArgumentException.class, () -> cache.put("", "v", "m"));
        assertThrows(IllegalArgumentException.class, () -> cache.put("s", null, "m"));
        assertThrows(IllegalArgumentException.class, () -> cache.put("s", "", "m"));
        assertThrows(IllegalArgumentException.class, () -> cache.put("s", "v", null));
        assertThrows(IllegalArgumentException.class, () -> cache.put("s", "v", ""));
    }

    @Test
    void distinctStates_areIndependent() {
        FigmaPkceStateCache cache = new FigmaPkceStateCache();
        cache.put("a", "va", "ma");
        cache.put("b", "vb", "mb");

        assertEquals("va", cache.pop("a").orElseThrow().codeVerifier());
        assertEquals("vb", cache.pop("b").orElseThrow().codeVerifier());
    }
}
