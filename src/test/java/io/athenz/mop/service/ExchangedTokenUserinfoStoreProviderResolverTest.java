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
import io.athenz.mop.config.DatabricksVectorSearchTokenExchangeConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

class ExchangedTokenUserinfoStoreProviderResolverTest {

    @Mock
    private DatabricksSqlTokenExchangeConfig databricksSqlTokenExchangeConfig;

    @Mock
    private DatabricksVectorSearchTokenExchangeConfig databricksVectorSearchTokenExchangeConfig;

    @InjectMocks
    private ExchangedTokenUserinfoStoreProviderResolver resolver;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(databricksSqlTokenExchangeConfig.workspaceHostTemplate()).thenReturn("https://%s.cloud.databricks.com");
        when(databricksSqlTokenExchangeConfig.resourcePathPrefix()).thenReturn("/v1/databricks-sql/");
        when(databricksSqlTokenExchangeConfig.workspaceSegmentPattern()).thenReturn("^dbc-[a-zA-Z0-9.-]+$");
        when(databricksSqlTokenExchangeConfig.oauthScope()).thenReturn("sql");

        when(databricksVectorSearchTokenExchangeConfig.workspaceHostTemplate()).thenReturn("https://%s.cloud.databricks.com");
        when(databricksVectorSearchTokenExchangeConfig.resourcePathPrefix()).thenReturn("/v1/databricks-vector-search/");
        when(databricksVectorSearchTokenExchangeConfig.workspaceSegmentPattern()).thenReturn("^dbc-[a-zA-Z0-9.-]+$");
        when(databricksVectorSearchTokenExchangeConfig.oauthScope()).thenReturn("vector-search");
    }

    @Test
    void resolve_databricksSql_prefixesHostname() {
        String p = resolver.resolve(
                "https://gateway.test.example/v1/databricks-sql/dbc-abc/mcp",
                AudienceConstants.PROVIDER_DATABRICKS_SQL);
        assertEquals("databricks-sql-dbc-abc.cloud.databricks.com", p);
    }

    @Test
    void resolve_databricksVectorSearch_prefixesHostname() {
        String p = resolver.resolve(
                "https://gateway.test.example/v1/databricks-vector-search/dbc-xyz/catalog/schema/mcp",
                AudienceConstants.PROVIDER_DATABRICKS_VECTOR_SEARCH);
        assertEquals("databricks-vector-search-dbc-xyz.cloud.databricks.com", p);
    }

    @Test
    void resolve_nonDatabricks_returnsAudience() {
        assertEquals(
                "glean",
                resolver.resolve("https://x/v1/databricks-sql/dbc-a/mcp", "glean"));
    }

    @Test
    void resolve_blankAudience_returnsAsIs() {
        assertNull(resolver.resolve("https://x/v1/databricks-sql/dbc-a/mcp", null));
        assertEquals("", resolver.resolve("https://x", ""));
        assertEquals("   ", resolver.resolve("https://x", "   "));
    }

    @Test
    void resolve_databricksSql_invalidResource_fallsBackToAudience() {
        assertEquals(
                AudienceConstants.PROVIDER_DATABRICKS_SQL,
                resolver.resolve("https://evil.example/not-databricks/mcp", AudienceConstants.PROVIDER_DATABRICKS_SQL));
    }

    @Test
    void resolve_databricksVectorSearch_invalidResource_fallsBackToAudience() {
        assertEquals(
                AudienceConstants.PROVIDER_DATABRICKS_VECTOR_SEARCH,
                resolver.resolve("https://evil.example/not-databricks/mcp", AudienceConstants.PROVIDER_DATABRICKS_VECTOR_SEARCH));
    }

    @Test
    void resolve_evaluate_returnsAudience() {
        assertEquals(
                AudienceConstants.PROVIDER_EVALUATE,
                resolver.resolve("https://mcp-gateway.ouryahoo.com/v1/evaluate/mcp", AudienceConstants.PROVIDER_EVALUATE));
    }

    @Test
    void storesExchangedTokenForUserinfo_includesEvaluate() {
        assertEquals(true, AudienceConstants.storesExchangedTokenForUserinfo(AudienceConstants.PROVIDER_EVALUATE));
    }

    @Test
    void resolve_googleBigQuery_returnsAudience() {
        assertEquals(
                AudienceConstants.PROVIDER_GOOGLE_BIGQUERY,
                resolver.resolve("https://mcp-gateway.ouryahoo.com/v1/gcp-bigquery/mcp", AudienceConstants.PROVIDER_GOOGLE_BIGQUERY));
    }

    @Test
    void storesExchangedTokenForUserinfo_includesGcpWorkforceAudiences() {
        assertEquals(true, AudienceConstants.storesExchangedTokenForUserinfo(AudienceConstants.PROVIDER_GOOGLE_MONITORING));
        assertEquals(true, AudienceConstants.storesExchangedTokenForUserinfo(AudienceConstants.PROVIDER_GOOGLE_LOGGING));
        assertEquals(true, AudienceConstants.storesExchangedTokenForUserinfo(AudienceConstants.PROVIDER_GOOGLE_BIGQUERY));
    }
}
