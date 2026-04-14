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
import java.util.HashMap;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
@Unremovable
public class K8SSecretsProvider implements CredentialsProvider {

    /**
     * Kubernetes {@link io.kubernetes.client.openapi.models.V1Secret#getData() Secret.data} keys (and, when the same
     * string is used as the {@link #getCredentials} map key, that constant is used for both).
     */
    public static final String SECRET_DATA_KEY_CLIENT_SECRET = "client-secret";

    public static final String SECRET_DATA_KEY_ATLASSIAN_CLIENT_SECRET = "atlassian-client-secret";
    public static final String SECRET_DATA_KEY_GITHUB_CLIENT_SECRET = "github-client-secret";
    public static final String SECRET_DATA_KEY_GOOGLE_CLIENT_SECRET = "google-client-secret";
    public static final String SECRET_DATA_KEY_EMBRACE_CLIENT_SECRET = "embrace-client-secret";
    public static final String SECRET_DATA_KEY_SLACK_CLIENT_SECRET = "slack-client-secret";
    public static final String SECRET_DATA_KEY_OKTA_TOKEN_EXCHANGE_CLIENT_SECRET = "okta-token-exchange-client-secret";

    /** Kubernetes secret data keys for Splunk management API tokens (same names in {@link #getCredentials} map). */
    public static final String SECRET_DATA_KEY_SPLUNK_API_STAGE = "splunk-api-stage";
    public static final String SECRET_DATA_KEY_SPLUNK_API_PROD = "splunk-api-prod";

    /**
     * {@link #getCredentials} map key for the value read from {@link #SECRET_DATA_KEY_CLIENT_SECRET} (Okta OIDC
     * client secret).
     */
    public static final String CREDENTIALS_KEY_OKTA_CLIENT_SECRET = "okta-client-secret";

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @ConfigProperty(name = "server.secret.k8s.name")
    String secretName;

    @ConfigProperty(name = "server.secret.k8s.namespace")
    String secretNamespace;

    @Override
    public Map<String, String> getCredentials(String credentialsProviderName) {
        try {
            Map<String, byte[]> data = getSecretFromApiServer(secretName);
            if (data == null) {
                return Map.of();
            }
            return Map.copyOf(credentialsMapFromData(data));

        } catch (IOException | ApiException e) {
            log.error("failed to read k8s secret {}", e.getMessage());
        }
        return Map.of();
    }

    /**
     * Builds the credentials map from raw Kubernetes secret {@code data} entries (test seam for Splunk keys and trimming).
     */
    static Map<String, String> credentialsMapFromData(Map<String, byte[]> data) {
        String clientSecret = decodeTrimmed(data, SECRET_DATA_KEY_CLIENT_SECRET);
        String atlassianClientSecret = decodeTrimmed(data, SECRET_DATA_KEY_ATLASSIAN_CLIENT_SECRET);
        String githubClientSecret = decodeTrimmed(data, SECRET_DATA_KEY_GITHUB_CLIENT_SECRET);
        String googleClientSecret = decodeTrimmed(data, SECRET_DATA_KEY_GOOGLE_CLIENT_SECRET);
        String embraceClientSecret = decodeTrimmed(data, SECRET_DATA_KEY_EMBRACE_CLIENT_SECRET);
        String slackClientSecret = decodeTrimmed(data, SECRET_DATA_KEY_SLACK_CLIENT_SECRET);
        String oktaTokenExchangeClientSecret = decodeTrimmed(data, SECRET_DATA_KEY_OKTA_TOKEN_EXCHANGE_CLIENT_SECRET);
        String splunkApiStage = decodeTrimmed(data, SECRET_DATA_KEY_SPLUNK_API_STAGE);
        String splunkApiProd = decodeTrimmed(data, SECRET_DATA_KEY_SPLUNK_API_PROD);

        Map<String, String> map = new HashMap<>();
        map.put(CREDENTIALS_KEY_OKTA_CLIENT_SECRET, clientSecret);
        map.put(SECRET_DATA_KEY_ATLASSIAN_CLIENT_SECRET, atlassianClientSecret);
        map.put(SECRET_DATA_KEY_GITHUB_CLIENT_SECRET, githubClientSecret);
        map.put(SECRET_DATA_KEY_GOOGLE_CLIENT_SECRET, googleClientSecret);
        map.put(SECRET_DATA_KEY_EMBRACE_CLIENT_SECRET, embraceClientSecret);
        map.put(SECRET_DATA_KEY_SLACK_CLIENT_SECRET, slackClientSecret);
        map.put(SECRET_DATA_KEY_OKTA_TOKEN_EXCHANGE_CLIENT_SECRET, oktaTokenExchangeClientSecret);
        map.put(SECRET_DATA_KEY_SPLUNK_API_STAGE, splunkApiStage);
        map.put(SECRET_DATA_KEY_SPLUNK_API_PROD, splunkApiProd);
        return map;
    }

    private static String decodeTrimmed(Map<String, byte[]> data, String key) {
        byte[] raw = data.get(key);
        if (raw == null) {
            return "";
        }
        return new String(raw, StandardCharsets.UTF_8).replaceAll("\\r?\\n$", "");
    }

    private @Nullable Map<String, byte[]> getSecretFromApiServer(String pkeySecretName) throws IOException, ApiException {
        ApiClient client = Config.defaultClient();
        Configuration.setDefaultApiClient(client);
        CoreV1Api api = new CoreV1Api();
        V1Secret secret = api.readNamespacedSecret(pkeySecretName, secretNamespace).execute();
        return secret.getData();
    }
}
