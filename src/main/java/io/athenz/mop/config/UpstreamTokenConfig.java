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
package io.athenz.mop.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;

@ConfigMapping(prefix = "server.upstream-token")
public interface UpstreamTokenConfig {

    @WithName("table-name")
    String tableName();

    @WithDefault("7776000")
    long expirySeconds();

    @WithDefault("7")
    int ttlBufferDays();
    @WithName("revoked-retention-days")
    @WithDefault("14")
    int revokedRetentionDays();
    
    @WithName("l2-at-reuse-grace-seconds")
    @WithDefault("30")
    long l2AtReuseGraceSeconds();

    @WithName("l2-at-reuse-min-remaining-seconds")
    @WithDefault("60")
    long l2AtReuseMinRemainingSeconds();

    @WithName("replication-wait-millis")
    @WithDefault("750")
    long replicationWaitMillis();
}
