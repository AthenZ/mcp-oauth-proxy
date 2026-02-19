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

import java.io.IOException;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;

import jakarta.enterprise.context.ApplicationScoped;

/**
 * Implementation of TokenClient that executes token requests via HTTP.
 */
@ApplicationScoped
public class OktaExchangeTokenClient implements TokenClient {
    @Override
    public TokenResponse execute(TokenRequest request) throws IOException, ParseException {
        return TokenResponse.parse(request.toHTTPRequest().send());
    }
}

