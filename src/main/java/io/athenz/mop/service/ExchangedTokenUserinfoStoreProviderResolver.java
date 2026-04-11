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

import io.athenz.mop.config.DatabricksSqlTokenExchangeConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.apache.commons.lang3.StringUtils;

/**
 * Token store / userinfo provider string for exchanged access tokens (audiences that use a dedicated
 * Dynamo row keyed by returned access token hash). Default is YAML {@code audience}; product-specific
 * rules (e.g. per-workspace keys) live here so {@link AuthorizerService} stays generic.
 */
@ApplicationScoped
public class ExchangedTokenUserinfoStoreProviderResolver {

    @Inject
    DatabricksSqlTokenExchangeConfig databricksSqlTokenExchangeConfig;

    /**
     * @param resource MCP resource URI from the token or refresh request
     * @param audience resource mapping audience (e.g. glean, splunk, databricks-sql)
     * @return provider key for {@code storeUserToken}
     */
    public String resolve(String resource, String audience) {
        if (StringUtils.isBlank(audience)) {
            return audience;
        }
        if (AudienceConstants.PROVIDER_DATABRICKS_SQL.equals(audience)) {
            return DatabricksSqlWorkspaceResolver.resolve(resource, databricksSqlTokenExchangeConfig)
                    .map(w -> AudienceConstants.databricksSqlStorageProvider(w.hostname()))
                    .orElse(audience);
        }
        return audience;
    }
}
