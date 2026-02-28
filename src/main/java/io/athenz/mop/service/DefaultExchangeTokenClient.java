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
import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import jakarta.enterprise.context.ApplicationScoped;

/**
 * Single implementation of TokenClient used for all providers (Okta, Google, GitHub, etc.).
 * Sets Accept: application/json so providers that require it (e.g. GitHub) return JSON.
 */
@ApplicationScoped
public class DefaultExchangeTokenClient implements TokenClient {
    @Override
    public TokenResponse execute(TokenRequest request) throws IOException, ParseException {
        HTTPRequest httpRequest = request.toHTTPRequest();
        httpRequest.setHeader("Accept", "application/json");
        return TokenResponse.parse(httpRequest.send());
    }
}
