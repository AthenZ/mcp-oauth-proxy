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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class K8SSecretsProviderTest {

    @Test
    void credentialsMapFromData_includesSplunkStageAndProd() {
        Map<String, byte[]> data = new HashMap<>();
        data.put(K8SSecretsProvider.SECRET_DATA_KEY_SPLUNK_API_STAGE, "stage-token".getBytes(StandardCharsets.UTF_8));
        data.put(K8SSecretsProvider.SECRET_DATA_KEY_SPLUNK_API_PROD, "prod-token".getBytes(StandardCharsets.UTF_8));

        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(data);

        assertEquals("stage-token", m.get(K8SSecretsProvider.SECRET_DATA_KEY_SPLUNK_API_STAGE));
        assertEquals("prod-token", m.get(K8SSecretsProvider.SECRET_DATA_KEY_SPLUNK_API_PROD));
    }

    @Test
    void credentialsMapFromData_includesSlackClientSecret() {
        Map<String, byte[]> data = new HashMap<>();
        data.put(K8SSecretsProvider.SECRET_DATA_KEY_SLACK_CLIENT_SECRET, "slack-secret".getBytes(StandardCharsets.UTF_8));

        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(data);

        assertEquals("slack-secret", m.get(K8SSecretsProvider.SECRET_DATA_KEY_SLACK_CLIENT_SECRET));
    }

    @Test
    void credentialsMapFromData_includesFigmaClientSecret() {
        Map<String, byte[]> data = new HashMap<>();
        data.put(K8SSecretsProvider.SECRET_DATA_KEY_FIGMA_CLIENT_SECRET,
                "figma-secret".getBytes(StandardCharsets.UTF_8));

        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(data);

        assertEquals("figma-secret", m.get(K8SSecretsProvider.SECRET_DATA_KEY_FIGMA_CLIENT_SECRET));
    }

    @Test
    void credentialsMapFromData_figmaClientSecretAbsent_resolvesToEmpty() {
        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(new HashMap<>());

        assertEquals("", m.get(K8SSecretsProvider.SECRET_DATA_KEY_FIGMA_CLIENT_SECRET));
    }

    @Test
    void credentialsMapFromData_includesRootlyClientSecret() {
        // Rootly confidential client_secret_post. Without this entry the Quarkus OIDC tenant
        // resolves the secret to null and the Vert.x token-exchange call NPEs when adding the
        // client_secret form-body field. Mirrors the figma/oracle/wisdom/airtable tests above.
        Map<String, byte[]> data = new HashMap<>();
        data.put(K8SSecretsProvider.SECRET_DATA_KEY_ROOTLY_CLIENT_SECRET,
                "rootly-secret".getBytes(StandardCharsets.UTF_8));

        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(data);

        assertEquals("rootly-secret", m.get(K8SSecretsProvider.SECRET_DATA_KEY_ROOTLY_CLIENT_SECRET));
    }

    @Test
    void credentialsMapFromData_rootlyClientSecretAbsent_resolvesToEmpty() {
        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(new HashMap<>());

        assertEquals("", m.get(K8SSecretsProvider.SECRET_DATA_KEY_ROOTLY_CLIENT_SECRET));
    }

    @Test
    void credentialsMapFromData_includesOracleEpmClientSecret() {
        // Oracle IDCS confidential client_secret. Without this entry the Quarkus OIDC tenant
        // resolves the secret to null and the Vert.x token-exchange call NPEs when adding the
        // client_secret form-body field. Mirrors the figma test above.
        Map<String, byte[]> data = new HashMap<>();
        data.put(K8SSecretsProvider.SECRET_DATA_KEY_ORACLE_EPM_CLIENT_SECRET,
                "oracle-epm-secret".getBytes(StandardCharsets.UTF_8));

        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(data);

        assertEquals("oracle-epm-secret", m.get(K8SSecretsProvider.SECRET_DATA_KEY_ORACLE_EPM_CLIENT_SECRET));
    }

    @Test
    void credentialsMapFromData_oracleEpmClientSecretAbsent_resolvesToEmpty() {
        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(new HashMap<>());

        assertEquals("", m.get(K8SSecretsProvider.SECRET_DATA_KEY_ORACLE_EPM_CLIENT_SECRET));
    }

    @Test
    void credentialsMapFromData_includesWisdomAiClientSecret() {
        // Descope confidential client_secret. WisdomAI DCR registers public clients but Descope's
        // token endpoint requires a secret on refresh (errorCode E011002). Without this entry the
        // upstream refresh client falls back to the "secret not found" branch and returns null.
        Map<String, byte[]> data = new HashMap<>();
        data.put(K8SSecretsProvider.SECRET_DATA_KEY_WISDOMAI_CLIENT_SECRET,
                "wisdomai-secret".getBytes(StandardCharsets.UTF_8));

        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(data);

        assertEquals("wisdomai-secret", m.get(K8SSecretsProvider.SECRET_DATA_KEY_WISDOMAI_CLIENT_SECRET));
    }

    @Test
    void credentialsMapFromData_wisdomAiClientSecretAbsent_resolvesToEmpty() {
        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(new HashMap<>());

        assertEquals("", m.get(K8SSecretsProvider.SECRET_DATA_KEY_WISDOMAI_CLIENT_SECRET));
    }

    @Test
    void credentialsMapFromData_includesAirtableClientSecret() {
        // Airtable confidential client_secret. Without this entry the Quarkus OIDC tenant
        // resolves the secret to null and the Vert.x token-exchange call NPEs when computing
        // the Basic-auth Authorization header. Mirrors the figma/oracle/wisdom tests above.
        Map<String, byte[]> data = new HashMap<>();
        data.put(K8SSecretsProvider.SECRET_DATA_KEY_AIRTABLE_CLIENT_SECRET,
                "airtable-secret".getBytes(StandardCharsets.UTF_8));

        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(data);

        assertEquals("airtable-secret", m.get(K8SSecretsProvider.SECRET_DATA_KEY_AIRTABLE_CLIENT_SECRET));
    }

    @Test
    void credentialsMapFromData_airtableClientSecretAbsent_resolvesToEmpty() {
        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(new HashMap<>());

        assertEquals("", m.get(K8SSecretsProvider.SECRET_DATA_KEY_AIRTABLE_CLIENT_SECRET));
    }

    @Test
    void credentialsMapFromData_includesGeminiEnterpriseClientSecret() {
        // Gemini Enterprise confidential client_secret (dedicated Google OAuth client). Without
        // this entry the GeminiEnterpriseUpstreamRefreshClient lookup resolves to null and the
        // refresh path hits the "secret not found" branch. Mirrors the figma/oracle tests above.
        Map<String, byte[]> data = new HashMap<>();
        data.put(K8SSecretsProvider.SECRET_DATA_KEY_GEMINI_ENTERPRISE_CLIENT_SECRET,
                "gemini-enterprise-secret".getBytes(StandardCharsets.UTF_8));

        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(data);

        assertEquals("gemini-enterprise-secret",
                m.get(K8SSecretsProvider.SECRET_DATA_KEY_GEMINI_ENTERPRISE_CLIENT_SECRET));
    }

    @Test
    void credentialsMapFromData_geminiEnterpriseClientSecretAbsent_resolvesToEmpty() {
        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(new HashMap<>());

        assertEquals("", m.get(K8SSecretsProvider.SECRET_DATA_KEY_GEMINI_ENTERPRISE_CLIENT_SECRET));
    }

    @Test
    void credentialsMapFromData_includesGrafanaStageAndProd() {
        Map<String, byte[]> data = new HashMap<>();
        data.put(K8SSecretsProvider.SECRET_DATA_KEY_GRAFANA_API_STAGE,
                "grafana-stage".getBytes(StandardCharsets.UTF_8));
        data.put(K8SSecretsProvider.SECRET_DATA_KEY_GRAFANA_API_PROD,
                "grafana-prod".getBytes(StandardCharsets.UTF_8));

        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(data);

        assertEquals("grafana-stage", m.get(K8SSecretsProvider.SECRET_DATA_KEY_GRAFANA_API_STAGE));
        assertEquals("grafana-prod", m.get(K8SSecretsProvider.SECRET_DATA_KEY_GRAFANA_API_PROD));
    }

    @Test
    void credentialsMapFromData_trimsTrailingNewlineOnSplunkKeys() {
        Map<String, byte[]> data = new HashMap<>();
        data.put(
                K8SSecretsProvider.SECRET_DATA_KEY_SPLUNK_API_STAGE,
                "tok\n".getBytes(StandardCharsets.UTF_8));

        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(data);

        assertEquals("tok", m.get(K8SSecretsProvider.SECRET_DATA_KEY_SPLUNK_API_STAGE));
    }
}
