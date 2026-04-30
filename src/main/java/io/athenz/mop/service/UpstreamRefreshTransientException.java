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
 * A transient (retryable) upstream-refresh failure. Today this is thrown only when the centralized
 * upstream-token row was rotated in the peer region and DynamoDB Global Tables replication has not
 * landed locally yet — even after a brief in-process wait. The MoP refresh-token family is
 * <em>not</em> the wrong thing here: the user's tokens are still valid; the local pod just can't
 * see the latest Okta refresh value.
 *
 * <p>Callers should treat this differently from the parent {@link UpstreamRefreshException}:
 * <ul>
 *   <li>{@code TokenResource} returns {@code 503 temporarily_unavailable} without revoking the
 *       refresh-token family.</li>
 *   <li>{@code UserInfoResource} continues to return null/401 as before (existing parent catch).</li>
 * </ul>
 */
public class UpstreamRefreshTransientException extends UpstreamRefreshException {

    public UpstreamRefreshTransientException(String message) {
        super(message);
    }
}
