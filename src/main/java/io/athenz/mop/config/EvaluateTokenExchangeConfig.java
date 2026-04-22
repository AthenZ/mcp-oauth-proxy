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
package io.athenz.mop.config;

import io.smallrye.config.ConfigMapping;
import java.util.List;

/**
 * Configuration for the Evaluate MCP token exchange (Okta id_token -> Athenz id_token via ZTS).
 * The Athenz id_token is returned directly to the MCP client as the bearer access_token; there is no
 * downstream STS layer (unlike GCP Monitoring/Logging). Both {@code audience} and {@code scopes}
 * are passed to the ZTS token-exchange call:
 * <ul>
 *   <li>{@code audience}: ZTS {@code audience} parameter (e.g. {@code evaluateplus.k8s.evaluate-elide-production}).</li>
 *   <li>{@code scopes}: ZTS {@code scope} role-names (e.g. {@code evaluateplus.k8s:role.evaluate-mcp-user}).
 *       {@code openid} is added automatically by {@code openIdIssuer(true)}.</li>
 * </ul>
 */
@ConfigMapping(prefix = "server.token-exchange.evaluate")
public interface EvaluateTokenExchangeConfig {

    String audience();

    List<String> scopes();
}
