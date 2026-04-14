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
    void credentialsMapFromData_trimsTrailingNewlineOnSplunkKeys() {
        Map<String, byte[]> data = new HashMap<>();
        data.put(
                K8SSecretsProvider.SECRET_DATA_KEY_SPLUNK_API_STAGE,
                "tok\n".getBytes(StandardCharsets.UTF_8));

        Map<String, String> m = K8SSecretsProvider.credentialsMapFromData(data);

        assertEquals("tok", m.get(K8SSecretsProvider.SECRET_DATA_KEY_SPLUNK_API_STAGE));
    }
}
