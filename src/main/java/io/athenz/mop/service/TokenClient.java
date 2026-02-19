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

/**
 * Interface for executing OAuth 2.0 token requests.
 * This abstraction allows for easier testing by enabling mock implementations.
 */
public interface TokenClient {
    /**
     * Execute a token request and return the token response.
     *
     * @param request the token request to execute
     * @return the token response
     * @throws IOException if an I/O error occurs
     * @throws ParseException if the response cannot be parsed
     */
    TokenResponse execute(TokenRequest request) throws IOException, ParseException;
}

