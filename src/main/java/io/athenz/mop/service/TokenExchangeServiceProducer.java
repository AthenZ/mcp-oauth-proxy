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

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@ApplicationScoped
public class TokenExchangeServiceProducer {

    static final Set<String> GOOGLE_WORKSPACE_PROVIDERS = Set.of(
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform");

    @Inject
    Instance<TokenExchangeServiceGoogleWorkspaceImpl> googleWorkspaceProvider;

    @Inject
    TokenExchangeServiceZTSImpl tokenExchangeServiceZTSImpl;

    @Inject
    TokenExchangeServiceOktaImpl tokenExchangeServiceOktaImpl;

    @Inject
    TokenExchangeServiceAtlassianImpl tokenExchangeServiceAtlassianImpl;

    @Inject
    TokenExchangeServiceGithubImpl tokenExchangeServiceGithubImpl;

    @Inject
    TokenExchangeServiceEmbraceImpl tokenExchangeServiceEmbraceImpl;

    @Inject
    TokenExchangeServiceGcpWorkforceImpl tokenExchangeServiceGcpWorkforceImpl;

    @Inject
    TokenExchangeServiceSplunkImpl tokenExchangeServiceSplunkImpl;

    @Inject
    TokenExchangeServiceDatabricksSqlImpl tokenExchangeServiceDatabricksSqlImpl;

    @Inject
    TokenExchangeServiceSlackImpl tokenExchangeServiceSlackImpl;

    private final Map<String, TokenExchangeService> googleWorkspaceServices = new HashMap<>();

    @PostConstruct
    void init() {
        for (String provider : GOOGLE_WORKSPACE_PROVIDERS) {
            TokenExchangeServiceGoogleWorkspaceImpl svc = googleWorkspaceProvider.get();
            svc.setProviderLabel(provider);
            googleWorkspaceServices.put(provider, svc);
        }
    }

    public TokenExchangeService getTokenExchangeServiceImplementation(String idpType) {
        TokenExchangeService googleSvc = googleWorkspaceServices.get(idpType);
        if (googleSvc != null) {
            return googleSvc;
        }

        return switch (idpType) {
            case "atlassian" -> tokenExchangeServiceAtlassianImpl;
            case "github" -> tokenExchangeServiceGithubImpl;
            case "embrace" -> tokenExchangeServiceEmbraceImpl;
            case "okta" -> tokenExchangeServiceOktaImpl;
            case "glean" -> tokenExchangeServiceOktaImpl;
            case "athenz" -> tokenExchangeServiceZTSImpl;
            case "google-monitoring", "google-logging" -> tokenExchangeServiceGcpWorkforceImpl;
            case "splunk" -> tokenExchangeServiceSplunkImpl;
            case "databricks-sql" -> tokenExchangeServiceDatabricksSqlImpl;
            case "slack" -> tokenExchangeServiceSlackImpl;
            default -> throw new IllegalArgumentException("Unsupported IDP type: " + idpType);
        };
    }
}
