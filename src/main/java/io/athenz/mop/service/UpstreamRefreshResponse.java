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
 * Provider-agnostic upstream refresh response.
 *
 * <p>Mirrors the union of fields {@code OktaTokens} and Google {@code refresh_token} grant
 * responses produce. {@code idToken} and {@code scope} are nullable — Google's refresh response
 * does not include {@code id_token} unless the original consent included openid scope, and
 * {@code scope} may be omitted. {@code expiresInSeconds} is always a duration in seconds (not
 * an absolute epoch); callers compute absolute deadlines from {@code now()}.
 */
public record UpstreamRefreshResponse(
        String accessToken,
        String refreshToken,
        String idToken,
        long expiresInSeconds,
        String scope
) {
}
