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
package io.athenz.mop.secret;

import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.Configuration;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1Secret;
import io.kubernetes.client.util.Config;
import io.quarkus.arc.Unremovable;
import io.quarkus.credentials.CredentialsProvider;
import jakarta.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
@Unremovable
public class K8SSecretsProvider implements CredentialsProvider {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @ConfigProperty(name = "server.secret.k8s.name")
    String secretName;

    @ConfigProperty(name = "server.secret.k8s.namespace")
    String secretNamespace;

    @Override
    public Map<String, String> getCredentials(String credentialsProviderName) {
        try {
            Map<String, byte[]> data = getSecretFromApiServer(secretName);
            String clientSecret = new String(data.get("client-secret"), StandardCharsets.UTF_8).replaceAll("\\r?\\n$", "");
            String atlassianClientSecret = new String(data.get("atlassian-client-secret"), StandardCharsets.UTF_8).replaceAll("\\r?\\n$", "");
            String githubClientSecret = new String(data.get("github-client-secret"), StandardCharsets.UTF_8).replaceAll("\\r?\\n$", "");
            String googleClientSecret = new String(data.get("google-client-secret"), StandardCharsets.UTF_8).replaceAll("\\r?\\n$", "");
            String oktaTokenExchangeClientSecret = new String(data.get("okta-token-exchange-client-secret"), StandardCharsets.UTF_8).replaceAll("\\r?\\n$", "");
            return Map.of(
                    "okta-client-secret", clientSecret,
                    "atlassian-client-secret", atlassianClientSecret,
                    "github-client-secret", githubClientSecret,
                    "google-client-secret", googleClientSecret,
                    "okta-token-exchange-client-secret", oktaTokenExchangeClientSecret
            );

        } catch (IOException | ApiException e) {
            log.error("failed to read k8s secret {}", e.getMessage());
        }
        return Map.of();
    }

    private @Nullable Map<String, byte[]> getSecretFromApiServer(String pkeySecretName) throws IOException, ApiException {
        ApiClient client = Config.defaultClient();
        Configuration.setDefaultApiClient(client);
        CoreV1Api api = new CoreV1Api();
        V1Secret secret = api.readNamespacedSecret(pkeySecretName, secretNamespace).execute();
        return secret.getData();
    }
}
