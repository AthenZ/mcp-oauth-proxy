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

import io.athenz.mop.model.BearerIndexRecord;
import io.athenz.mop.store.BearerIndexStore;
import io.athenz.mop.store.MemoryStoreQualifier;
import jakarta.enterprise.context.ApplicationScoped;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * In-memory bearer-index store used by {@code application.dev.yaml} and unit tests. Keeps the
 * exact same semantics as the DynamoDB-backed implementation: each {@code H(bearer)} owns its
 * own row, and rows are evicted lazily on read once their {@code ttl} (epoch seconds) has
 * passed.
 */
@ApplicationScoped
@MemoryStoreQualifier
public class BearerIndexStoreInMemoryImpl implements BearerIndexStore {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private final ConcurrentMap<String, BearerIndexRecord> rows = new ConcurrentHashMap<>();

    @Override
    public void putBearer(String accessTokenHash, String userId, String clientId, String provider,
                          long exp, long ttl) {
        if (accessTokenHash == null || accessTokenHash.isEmpty()) {
            log.warn("bearer-index put skipped: empty accessTokenHash");
            return;
        }
        rows.put(accessTokenHash, new BearerIndexRecord(
                accessTokenHash,
                userId == null ? "" : userId,
                clientId == null ? "" : clientId,
                provider == null ? "" : provider,
                exp,
                ttl));
    }

    @Override
    public BearerIndexRecord getBearer(String accessTokenHash) {
        if (accessTokenHash == null || accessTokenHash.isEmpty()) {
            return null;
        }
        BearerIndexRecord rec = rows.get(accessTokenHash);
        if (rec == null) {
            return null;
        }
        long now = Instant.now().getEpochSecond();
        if (rec.ttl() > 0 && rec.ttl() <= now) {
            rows.remove(accessTokenHash);
            return null;
        }
        return rec;
    }

    @Override
    public void deleteBearer(String accessTokenHash) {
        if (accessTokenHash == null || accessTokenHash.isEmpty()) {
            return;
        }
        rows.remove(accessTokenHash);
    }
}
