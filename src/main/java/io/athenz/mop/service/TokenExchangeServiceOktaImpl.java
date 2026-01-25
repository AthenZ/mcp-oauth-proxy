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
import io.athenz.mop.secret.K8SSecretsProvider;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class TokenExchangeServiceOktaImpl implements TokenExchangeService {

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

    @Override
    public AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(TokenExchangeDO tokenExchangeDO) {
        throw new RuntimeException("Not implemented yet");
    }
}
