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
package io.athenz.mop.store.impl.memory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.athenz.mop.model.BearerIndexRecord;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class BearerIndexStoreInMemoryImplTest {

    private BearerIndexStoreInMemoryImpl store;

    @BeforeEach
    void setUp() {
        store = new BearerIndexStoreInMemoryImpl();
    }

    @Test
    void putAndGet_roundTrip() {
        long now = Instant.now().getEpochSecond();
        store.putBearer("h1", "u1", "c1", "okta", now + 600, now + 3600);

        BearerIndexRecord rec = store.getBearer("h1");
        assertNotNull(rec);
        assertEquals("h1", rec.accessTokenHash());
        assertEquals("u1", rec.userId());
        assertEquals("c1", rec.clientId());
        assertEquals("okta", rec.provider());
        assertEquals(now + 600, rec.exp());
        assertEquals(now + 3600, rec.ttl());
    }

    @Test
    void put_normalizesNullStringsToEmpty() {
        long now = Instant.now().getEpochSecond();
        store.putBearer("h1", null, null, null, now + 600, now + 3600);

        BearerIndexRecord rec = store.getBearer("h1");
        assertNotNull(rec);
        assertEquals("", rec.userId());
        assertEquals("", rec.clientId());
        assertEquals("", rec.provider());
    }

    @Test
    void put_skipsEmptyHash() {
        store.putBearer("", "u1", "c1", "okta", 0L, 0L);
        store.putBearer(null, "u1", "c1", "okta", 0L, 0L);
        assertNull(store.getBearer(""));
        assertNull(store.getBearer(null));
    }

    @Test
    void get_evictsExpiredRowsLazily() {
        long now = Instant.now().getEpochSecond();
        store.putBearer("h1", "u1", "c1", "okta", now - 100, now - 50);

        assertNull(store.getBearer("h1"));
        assertNull(store.getBearer("h1"));
    }

    @Test
    void get_zeroTtlMeansNoExpiry() {
        store.putBearer("h1", "u1", "c1", "okta", 0L, 0L);
        assertNotNull(store.getBearer("h1"));
    }

    @Test
    void delete_removesRow() {
        long now = Instant.now().getEpochSecond();
        store.putBearer("h1", "u1", "c1", "okta", now + 600, now + 3600);

        store.deleteBearer("h1");
        assertNull(store.getBearer("h1"));
    }

    @Test
    void delete_emptyHashIsNoOp() {
        long now = Instant.now().getEpochSecond();
        store.putBearer("h1", "u1", "c1", "okta", now + 600, now + 3600);

        store.deleteBearer("");
        store.deleteBearer(null);
        assertNotNull(store.getBearer("h1"));
    }

    @Test
    void multipleBearersForSameUser_notClobbered() {
        long now = Instant.now().getEpochSecond();
        store.putBearer("h-window-1", "u1", "client-A", "okta", now + 600, now + 3600);
        store.putBearer("h-window-2", "u1", "client-A", "okta", now + 700, now + 3700);

        assertNotNull(store.getBearer("h-window-1"));
        assertNotNull(store.getBearer("h-window-2"));
    }
}
