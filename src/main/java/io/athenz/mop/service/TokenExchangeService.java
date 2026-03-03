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

import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;

public interface TokenExchangeService {
    AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO);
    AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO);
    AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(TokenExchangeDO tokenExchangeDO);

    /**
     * Refresh upstream IDP tokens using the given refresh token.
     * Returns new TokenWrapper (access, id, refresh, ttl) or null if not supported or on failure.
     * <p>
     * Refresh token behavior is provider-specific: return the new refresh token in the wrapper
     * when the IDP returns one (caller persists it in the refresh token table). When the IDP does
     * not return a new refresh token, return the existing upstream token so the caller can keep it.
     * </p>
     */
    TokenWrapper refreshWithUpstreamToken(String upstreamRefreshToken);
}
