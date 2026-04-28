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
package io.athenz.mop.model.splunk;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * {@code content} block under one entry in the Splunk authorization-tokens list feed. The full
 * payload contains many additional fields (eai:acl, last_used, etc.) — only {@code claims} is
 * needed by the expired-token cleanup.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SplunkListTokenContent(SplunkTokenClaims claims) {}
