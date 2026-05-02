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
import java.util.List;

/**
 * Subset of a Splunk REST error body, e.g.
 * {@code {"messages":[{"type":"ERROR","text":"Role=power_ads-pbp-008 is not grantable"}]}}.
 *
 * Only {@code messages[].text} is consumed by {@link
 * io.athenz.mop.service.SplunkManagementClientImpl#parseSplunkMessage}; everything else is
 * ignored so unknown sibling fields don't break parsing.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SplunkMessagesResponse(List<SplunkMessage> messages) {}
