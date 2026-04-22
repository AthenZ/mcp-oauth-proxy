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
 * Response shape from {@code POST /api/serviceaccounts/{saId}/tokens}.
 * Example: {@code {"id":284,"name":"mcp.<short-id>.<unix_ts>","key":"glsa_*****"}}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GrafanaMintTokenResponse(long id, String name, String key) {}
