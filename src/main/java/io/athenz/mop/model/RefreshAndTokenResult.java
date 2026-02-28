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
package io.athenz.mop.model;

/**
 * Result of refreshing upstream IDP tokens and obtaining a new access token.
 * When the IDP returns a new refresh token, it is included so the caller can
 * persist it in the refresh token table (new table row for the new MOP token).
 */
public record RefreshAndTokenResult(
    TokenResponse tokenResponse,
    String newUpstreamRefreshToken
) {}
