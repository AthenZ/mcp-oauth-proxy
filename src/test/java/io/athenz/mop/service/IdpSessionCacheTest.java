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

import io.athenz.mop.config.OktaSessionCacheConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Tests {@link IdpSessionCache} — the per-client (client_id#provider#sub) L0 access-token cache
 * used by promoted Google Workspace providers.
 *
 * <p>Critical contracts under test:
 * <ul>
 *   <li>Composite key shape: {@code <client>#<provider>#<sub>} (and the {@code _no_client_}
 *       placeholder for missing client_id), so two MCP clients of the same Yahoo user never
 *       collide in this cache.</li>
 *   <li>When the cache is disabled by config, every method becomes a no-op — never a NPE.</li>
 *   <li>Get / put / invalidate work as expected when enabled.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class IdpSessionCacheTest {

    @Mock
    OktaSessionCacheConfig config;

    @InjectMocks
    IdpSessionCache cache;

    @BeforeEach
    void setUp() {
        lenient().when(config.l0MaxSize()).thenReturn(100);
        lenient().when(config.l0ExpireAfterWriteSeconds()).thenReturn(3600);
        lenient().when(config.minRemainingSeconds()).thenReturn(60);
    }

    @Test
    void clientKey_buildsCanonicalCompositeKey() {
        assertEquals("client-1#google-slides#user@yahoo.com",
                IdpSessionCache.clientKey("client-1", "google-slides", "user@yahoo.com"));
    }

    @Test
    void clientKey_substitutesPlaceholderForMissingClientId() {
        assertEquals("_no_client_#google-drive#u",
                IdpSessionCache.clientKey(null, "google-drive", "u"));
        assertEquals("_no_client_#google-drive#u",
                IdpSessionCache.clientKey("", "google-drive", "u"));
    }

    @Test
    void clientKey_returnsNullWhenProviderOrSubMissing() {
        assertNull(IdpSessionCache.clientKey("c", null, "u"));
        assertNull(IdpSessionCache.clientKey("c", "", "u"));
        assertNull(IdpSessionCache.clientKey("c", "google-drive", null));
        assertNull(IdpSessionCache.clientKey("c", "google-drive", ""));
    }

    @Test
    void put_thenGet_returnsSameEntry() {
        when(config.enabled()).thenReturn(true);
        cache.init();
        IdpSessionEntry entry = new IdpSessionEntry("at", "id", 1_700_000_000L);

        cache.put("c#google-drive#u", entry);
        Optional<IdpSessionEntry> got = cache.get("c#google-drive#u");

        assertTrue(got.isPresent());
        assertEquals(entry, got.get());
    }

    @Test
    void disabledCache_isNoOpOnAllMutations() {
        when(config.enabled()).thenReturn(false);
        cache.init();

        cache.put("k", new IdpSessionEntry("at", "id", 1L));
        assertTrue(cache.get("k").isEmpty(),
                "disabled cache must report empty for any get; null Caffeine instance must not NPE");
        cache.invalidate("k");
        assertEquals(0L, cache.estimatedSize());
    }

    @Test
    void put_handlesNullArgsAsNoOp() {
        when(config.enabled()).thenReturn(true);
        cache.init();
        cache.put(null, new IdpSessionEntry("at", "id", 1L));
        cache.put("", new IdpSessionEntry("at", "id", 1L));
        cache.put("k", null);
        assertEquals(0L, cache.estimatedSize());
    }

    @Test
    void invalidate_removesEntry() {
        when(config.enabled()).thenReturn(true);
        cache.init();
        cache.put("k", new IdpSessionEntry("at", "id", 1L));
        cache.invalidate("k");
        assertTrue(cache.get("k").isEmpty());
    }

    @Test
    void differentClientIds_doNotCollideForSameProviderAndSub() {
        when(config.enabled()).thenReturn(true);
        cache.init();
        IdpSessionEntry cursor = new IdpSessionEntry("at-cursor", "id-cursor", 1L);
        IdpSessionEntry claude = new IdpSessionEntry("at-claude", "id-claude", 2L);

        // Two MCP clients of the same Google user must each get their own AT cell.
        cache.put(IdpSessionCache.clientKey("cursor", "google-slides", "alice"), cursor);
        cache.put(IdpSessionCache.clientKey("claude", "google-slides", "alice"), claude);

        assertEquals(cursor, cache.get(IdpSessionCache.clientKey("cursor", "google-slides", "alice")).orElseThrow());
        assertEquals(claude, cache.get(IdpSessionCache.clientKey("claude", "google-slides", "alice")).orElseThrow());
    }

    @Test
    void idpSessionEntry_from_computesAbsoluteExpiry() {
        IdpSessionEntry e = IdpSessionEntry.from("at", "id", 3600L, 1_700_000_000L);
        assertEquals(1_700_003_600L, e.accessTokenExpEpoch());
        assertEquals("at", e.accessToken());
        assertEquals("id", e.idToken());
    }

    @Test
    void idpSessionEntry_from_clampsNegativeExpiresInToZero() {
        IdpSessionEntry e = IdpSessionEntry.from("at", "id", -100L, 1_700_000_000L);
        assertEquals(1_700_000_000L, e.accessTokenExpEpoch(),
                "negative expires_in must not push the entry's expiry into the past relative to now");
    }
}
