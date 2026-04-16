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

import io.athenz.mop.config.DatabricksTokenExchangeConfig;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class DatabricksWorkspaceResolverTest {

    private DatabricksTokenExchangeConfig sqlConfig() {
        DatabricksTokenExchangeConfig c = Mockito.mock(DatabricksTokenExchangeConfig.class);
        when(c.workspaceHostTemplate()).thenReturn("https://%s.cloud.databricks.com");
        when(c.resourcePathPrefix()).thenReturn("/v1/databricks-sql/");
        when(c.workspaceSegmentPattern()).thenReturn("^dbc-[a-zA-Z0-9.-]+$");
        when(c.oauthScope()).thenReturn("sql");
        return c;
    }

    private DatabricksTokenExchangeConfig vectorSearchConfig() {
        DatabricksTokenExchangeConfig c = Mockito.mock(DatabricksTokenExchangeConfig.class);
        when(c.workspaceHostTemplate()).thenReturn("https://%s.cloud.databricks.com");
        when(c.resourcePathPrefix()).thenReturn("/v1/databricks-vector-search/");
        when(c.workspaceSegmentPattern()).thenReturn("^dbc-[a-zA-Z0-9.-]+$");
        when(c.oauthScope()).thenReturn("vector-search");
        return c;
    }

    @Test
    void resolve_validGatewayUrl() {
        var r = DatabricksWorkspaceResolver.resolve(
                "https://gateway.test.example/v1/databricks-sql/dbc-44743f95-b8ca/mcp", sqlConfig());
        assertTrue(r.isPresent());
        assertEquals("https://dbc-44743f95-b8ca.cloud.databricks.com", r.get().workspaceBaseUrl());
        assertEquals("dbc-44743f95-b8ca.cloud.databricks.com", r.get().hostname());
    }

    @Test
    void resolve_rejectsInvalidSegment() {
        assertTrue(DatabricksWorkspaceResolver.resolve(
                "https://gateway.test.example/v1/databricks-sql/evil/mcp", sqlConfig()).isEmpty());
        assertTrue(DatabricksWorkspaceResolver.resolve(
                "https://gateway.test.example/v1/databricks-sql/foo-dbc-1/mcp", sqlConfig()).isEmpty());
    }

    @Test
    void normalizePrefix_addsSlashes() {
        assertEquals("/v1/databricks-sql/", DatabricksWorkspaceResolver.normalizePrefix("/v1/databricks-sql"));
        assertEquals("/v1/databricks-sql/", DatabricksWorkspaceResolver.normalizePrefix("/v1/databricks-sql/"));
    }

    @Test
    void normalizePrefix_nullOrEmpty_returnsRoot() {
        assertEquals("/", DatabricksWorkspaceResolver.normalizePrefix(null));
        assertEquals("/", DatabricksWorkspaceResolver.normalizePrefix(""));
    }

    @Test
    void normalizePrefix_prependsSlashWhenMissing() {
        assertEquals("/v1/databricks-sql/", DatabricksWorkspaceResolver.normalizePrefix("v1/databricks-sql"));
    }

    @Test
    void resolve_blankResourceOrNullConfig_returnsEmpty() {
        assertTrue(DatabricksWorkspaceResolver.resolve("", sqlConfig()).isEmpty());
        assertTrue(DatabricksWorkspaceResolver.resolve("   ", sqlConfig()).isEmpty());
        assertTrue(DatabricksWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-a/mcp", null).isEmpty());
    }

    @Test
    void resolve_invalidUri_returnsEmpty() {
        assertTrue(DatabricksWorkspaceResolver.resolve("http://[", sqlConfig()).isEmpty());
    }

    @Test
    void resolve_blankPath_returnsEmpty() {
        assertTrue(DatabricksWorkspaceResolver.resolve("https://hostonly", sqlConfig()).isEmpty());
    }

    @Test
    void resolve_wrongPrefix_returnsEmpty() {
        assertTrue(DatabricksWorkspaceResolver.resolve(
                "https://h/v1/other/dbc-seg/mcp", sqlConfig()).isEmpty());
    }

    @Test
    void resolve_missingMcpSuffix_returnsEmpty() {
        assertTrue(DatabricksWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-seg/extra", sqlConfig()).isEmpty());
    }

    @Test
    void resolve_emptySegment_returnsEmpty() {
        assertTrue(DatabricksWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql//mcp", sqlConfig()).isEmpty());
    }

    @Test
    void resolve_invalidRegex_returnsEmpty() {
        DatabricksTokenExchangeConfig c = Mockito.mock(DatabricksTokenExchangeConfig.class);
        when(c.resourcePathPrefix()).thenReturn("/v1/databricks-sql/");
        when(c.workspaceSegmentPattern()).thenReturn("[");
        when(c.workspaceHostTemplate()).thenReturn("https://%s.cloud.databricks.com");
        assertTrue(DatabricksWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-a/mcp", c).isEmpty());
    }

    @Test
    void resolve_templateWithoutPlaceholder_returnsEmpty() {
        DatabricksTokenExchangeConfig c = Mockito.mock(DatabricksTokenExchangeConfig.class);
        when(c.resourcePathPrefix()).thenReturn("/v1/databricks-sql/");
        when(c.workspaceSegmentPattern()).thenReturn("^dbc-[a-zA-Z0-9.-]+$");
        when(c.workspaceHostTemplate()).thenReturn("https://fixed.databricks.com");
        assertTrue(DatabricksWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-a/mcp", c).isEmpty());
    }

    @Test
    void resolve_templateBlank_returnsEmpty() {
        DatabricksTokenExchangeConfig c = Mockito.mock(DatabricksTokenExchangeConfig.class);
        when(c.resourcePathPrefix()).thenReturn("/v1/databricks-sql/");
        when(c.workspaceSegmentPattern()).thenReturn("^dbc-[a-zA-Z0-9.-]+$");
        when(c.workspaceHostTemplate()).thenReturn("   ");
        assertTrue(DatabricksWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-a/mcp", c).isEmpty());
    }

    @Test
    void resolve_workspaceUrlWithoutHost_returnsEmpty() {
        DatabricksTokenExchangeConfig c = Mockito.mock(DatabricksTokenExchangeConfig.class);
        when(c.resourcePathPrefix()).thenReturn("/v1/databricks-sql/");
        when(c.workspaceSegmentPattern()).thenReturn("^dbc-[a-zA-Z0-9.-]+$");
        when(c.workspaceHostTemplate()).thenReturn("%s");
        assertTrue(DatabricksWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-a/mcp", c).isEmpty());
    }

    @Test
    void resolve_stringFormatThrows_returnsEmpty() {
        DatabricksTokenExchangeConfig c = Mockito.mock(DatabricksTokenExchangeConfig.class);
        when(c.resourcePathPrefix()).thenReturn("/v1/databricks-sql/");
        when(c.workspaceSegmentPattern()).thenReturn("^dbc-[a-zA-Z0-9.-]+$");
        when(c.workspaceHostTemplate()).thenReturn("https://%d.cloud.databricks.com");
        assertTrue(DatabricksWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-a/mcp", c).isEmpty());
    }

    @Test
    void resolve_trimsResourceUri() {
        var r = DatabricksWorkspaceResolver.resolve(
                "  https://local/v1/databricks-sql/dbc-z9/mcp  ", sqlConfig());
        assertTrue(r.isPresent());
        assertEquals("dbc-z9.cloud.databricks.com", r.get().hostname());
    }

    // --- Vector Search tests ---

    @Test
    void resolve_vectorSearch_validUrl_extractsWorkspace() {
        var r = DatabricksWorkspaceResolver.resolve(
                "https://gw.example/v1/databricks-vector-search/dbc-44743f95-b8ca/my_catalog/my_schema/mcp",
                vectorSearchConfig());
        assertTrue(r.isPresent());
        assertEquals("https://dbc-44743f95-b8ca.cloud.databricks.com", r.get().workspaceBaseUrl());
        assertEquals("dbc-44743f95-b8ca.cloud.databricks.com", r.get().hostname());
    }

    @Test
    void resolve_vectorSearch_invalidWorkspaceSegment_returnsEmpty() {
        assertTrue(DatabricksWorkspaceResolver.resolve(
                "https://gw.example/v1/databricks-vector-search/evil/catalog/schema/mcp",
                vectorSearchConfig()).isEmpty());
    }

    @Test
    void resolve_vectorSearch_missingMcpSuffix_returnsEmpty() {
        assertTrue(DatabricksWorkspaceResolver.resolve(
                "https://gw.example/v1/databricks-vector-search/dbc-ws/cat/sch/other",
                vectorSearchConfig()).isEmpty());
    }

    @Test
    void resolve_vectorSearch_wrongPrefix_returnsEmpty() {
        assertTrue(DatabricksWorkspaceResolver.resolve(
                "https://gw.example/v1/databricks-sql/dbc-ws/cat/sch/mcp",
                vectorSearchConfig()).isEmpty());
    }

    @Test
    void resolve_sql_singleSegment_stillWorks() {
        var r = DatabricksWorkspaceResolver.resolve(
                "https://gw.example/v1/databricks-sql/dbc-ws/mcp", sqlConfig());
        assertTrue(r.isPresent());
        assertEquals("dbc-ws.cloud.databricks.com", r.get().hostname());
    }

    @Test
    void resolve_sql_multiSegment_extractsFirstSegmentOnly() {
        DatabricksTokenExchangeConfig c = sqlConfig();
        var r = DatabricksWorkspaceResolver.resolve(
                "https://gw.example/v1/databricks-sql/dbc-ws/extra/segments/mcp", c);
        assertTrue(r.isPresent());
        assertEquals("dbc-ws.cloud.databricks.com", r.get().hostname());
    }
}
