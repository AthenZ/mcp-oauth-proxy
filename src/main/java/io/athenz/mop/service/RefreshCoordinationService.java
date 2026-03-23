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

import jakarta.enterprise.context.ApplicationScoped;
import java.lang.invoke.MethodHandles;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Distributed refresh coordination via DynamoDB lease locks.
 * <p>
 * {@link #acquireUpstream(String)} / {@link #releaseUpstream(String)} serialize centralized Okta upstream refresh
 * per {@code provider_user_id}. The former per-(userId, provider) grant lock was removed from this class; see
 * {@code .cursor/plans/refresh_grant_user_provider_lock.plan.md} to restore it.
 */
@ApplicationScoped
public class RefreshCoordinationService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String UPSTREAM_LOCK_PREFIX = "upstream-refresh:";

    @jakarta.inject.Inject
    RefreshLockStore refreshLockStore;

    @ConfigProperty(name = "server.refresh-lock.ttl-seconds", defaultValue = "8")
    long lockTtlSeconds;

    @ConfigProperty(name = "server.refresh-lock.instance-id", defaultValue = "default")
    String instanceId;

    @ConfigProperty(name = "server.refresh-lock.max-retries", defaultValue = "5")
    int maxRetries;

    @ConfigProperty(name = "server.refresh-lock.initial-backoff-ms", defaultValue = "50")
    long initialBackoffMs;

    /**
     * Serialize Okta upstream refresh across all MCP resources for the same {@code provider_user_id}
     * (e.g. {@code okta#subject}). Call {@link #releaseUpstream(String)} in a finally block.
     */
    public void acquireUpstream(String providerUserId) {
        String lockKey = upstreamLockKey(providerUserId);
        long expiresAt = System.currentTimeMillis() / 1000 + lockTtlSeconds;
        long backoffMs = initialBackoffMs;
        for (int attempt = 0; attempt < maxRetries; attempt++) {
            if (refreshLockStore.tryAcquire(lockKey, instanceId, expiresAt)) {
                log.debug("Upstream refresh lock acquired for key={}", lockKey);
                return;
            }
            if (attempt < maxRetries - 1) {
                try {
                    Thread.sleep(backoffMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Upstream refresh lock acquire interrupted for key=" + lockKey, e);
                }
                backoffMs = Math.min(backoffMs * 2, 2000);
            }
        }
        throw new IllegalStateException("Upstream refresh lock could not be acquired after " + maxRetries + " attempts for key=" + lockKey);
    }

    public void releaseUpstream(String providerUserId) {
        String lockKey = upstreamLockKey(providerUserId);
        refreshLockStore.release(lockKey, instanceId);
        log.debug("Upstream refresh lock released for key={}", lockKey);
    }

    private static String upstreamLockKey(String providerUserId) {
        return UPSTREAM_LOCK_PREFIX + (providerUserId != null ? providerUserId : "");
    }
}
