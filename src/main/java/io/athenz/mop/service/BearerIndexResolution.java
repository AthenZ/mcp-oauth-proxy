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

import io.athenz.mop.model.BearerIndexRecord;

/**
 * Result of resolving a bearer-index row by hash against the local DynamoDB table and the optional
 * cross-region peer table.
 *
 * @param record               the resolved bearer-index pointer row, or {@code null} if absent in both regions
 * @param resolvedFromFallback {@code true} when the row was read from the peer region's table
 */
public record BearerIndexResolution(BearerIndexRecord record, boolean resolvedFromFallback) {
}
