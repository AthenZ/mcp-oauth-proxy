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

/**
 * Distributed lock store for per-(userId, provider) refresh coordination.
 * Lock key format: {@code USER#<userId>#PROVIDER#<provider>}.
 */
public interface RefreshLockStore {

    /**
     * Try to acquire the lock. Succeeds only if the item does not exist or the lock has expired.
     *
     * @param lockKey    lock key (e.g. USER#userId#PROVIDER#provider)
     * @param owner      unique owner id (e.g. instance/pod id)
     * @param expiresAt  epoch seconds when the lock expires
     * @return true if lock was acquired, false if another holder has the lock
     */
    boolean tryAcquire(String lockKey, String owner, long expiresAt);

    /**
     * Release the lock. Only the current owner can release.
     *
     * @param lockKey lock key
     * @param owner  must match the current lock owner
     */
    void release(String lockKey, String owner);
}
