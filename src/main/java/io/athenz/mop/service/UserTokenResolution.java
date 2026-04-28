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

import io.athenz.mop.model.TokenWrapper;

/**
 * Result of resolving a per-user token row against local DynamoDB (or memory store) and the optional
 * cross-region peer table.
 *
 * @param token                 the stored token, or null if not found in either region
 * @param resolvedFromFallback  true if the row was read from the peer region's table
 */
public record UserTokenResolution(TokenWrapper token, boolean resolvedFromFallback) {
}
