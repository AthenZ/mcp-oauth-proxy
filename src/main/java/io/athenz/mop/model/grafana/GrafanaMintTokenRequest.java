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

/**
 * JSON body for {@code POST /api/serviceaccounts/{saId}/tokens}.
 *
 * @param name           Token display name, e.g. {@code mcp.<short_id>.<unix_ts>}.
 * @param secondsToLive  TTL in seconds; Grafana will set the token {@code expiration} accordingly.
 */
public record GrafanaMintTokenRequest(String name, long secondsToLive) {}
