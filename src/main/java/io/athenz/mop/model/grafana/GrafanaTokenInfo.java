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
package io.athenz.mop.model.grafana;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Subset of the list response from {@code GET /api/serviceaccounts/{saId}/tokens}.
 * Example entry:
 * <pre>
 * {
 *   "id": 284,
 *   "name": "mcp.<short-id>.<unix_ts>",
 *   "created": "2026-04-21T05:24:34Z",
 *   "lastUsedAt": null,
 *   "expiration": "2026-04-21T06:24:34Z",
 *   "secondsUntilExpiration": 3384.071399446,
 *   "hasExpired": false,
 *   "isRevoked": false
 * }
 * </pre>
 * The garbage collector uses {@link #hasExpired()} and {@link #isRevoked()} to decide what to delete.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GrafanaTokenInfo(
        long id,
        String name,
        String expiration,
        boolean hasExpired,
        boolean isRevoked) {}
