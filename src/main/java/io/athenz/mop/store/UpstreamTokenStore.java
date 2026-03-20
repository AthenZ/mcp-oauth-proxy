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
package io.athenz.mop.store;

import io.athenz.mop.model.UpstreamTokenRecord;
import java.util.Optional;

public interface UpstreamTokenStore {

    void save(UpstreamTokenRecord record);

    Optional<UpstreamTokenRecord> get(String providerUserId);

    /**
     * Replace the Okta refresh token when {@code version} still matches. Increments version by 1.
     *
     * @return true if the conditional write succeeded
     */
    boolean updateWithVersionCheck(String providerUserId, String newPlainOktaRefreshToken, long expectedVersion);

    void delete(String providerUserId);
}
