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

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class TokenExchangeServiceProducer {

    @Inject
    TokenExchangeServiceZTSImpl tokenExchangeServiceZTSImpl;

    @Inject
    TokenExchangeServiceOktaImpl tokenExchangeServiceOktaImpl;

    @Inject
    TokenExchangeServiceAtlassianImpl tokenExchangeServiceAtlassianImpl;

    @Inject
    TokenExchangeServiceGithubImpl tokenExchangeServiceGithubImpl;

    @Inject
    TokenExchangeServiceGoogleImpl tokenExchangeServiceGoogleImpl;

    public TokenExchangeService getTokenExchangeServiceImplementation(String idpType) {

        return switch (idpType) {
            case "atlassian" -> tokenExchangeServiceAtlassianImpl;
            case "github" -> tokenExchangeServiceGithubImpl;
            case "google" -> tokenExchangeServiceGoogleImpl;
            case "okta" -> tokenExchangeServiceOktaImpl;
            case "athenz" -> tokenExchangeServiceZTSImpl;
            default -> throw new IllegalArgumentException("Unsupported IDP type: " + idpType);
        };
    }
}
