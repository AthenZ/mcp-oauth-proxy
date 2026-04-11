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
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class DatabricksSqlWorkspaceResolverTest {

    private DatabricksSqlTokenExchangeConfig config() {
        DatabricksSqlTokenExchangeConfig c = Mockito.mock(DatabricksSqlTokenExchangeConfig.class);
        when(c.workspaceHostTemplate()).thenReturn("https://%s.cloud.databricks.com");
        when(c.resourcePathPrefix()).thenReturn("/v1/databricks-sql/");
        when(c.workspaceSegmentPattern()).thenReturn("^dbc-[a-zA-Z0-9.-]+$");
        when(c.oauthScope()).thenReturn("sql");
        return c;
    }

    @Test
    void resolve_validGatewayUrl() {
        var r = DatabricksSqlWorkspaceResolver.resolve(
                "https://gateway.test.example/v1/databricks-sql/dbc-44743f95-b8ca/mcp", config());
        assertTrue(r.isPresent());
        assertEquals("https://dbc-44743f95-b8ca.cloud.databricks.com", r.get().workspaceBaseUrl());
        assertEquals("dbc-44743f95-b8ca.cloud.databricks.com", r.get().hostname());
    }

    @Test
    void resolve_rejectsInvalidSegment() {
        assertTrue(DatabricksSqlWorkspaceResolver.resolve(
                "https://gateway.test.example/v1/databricks-sql/evil/mcp", config()).isEmpty());
        assertTrue(DatabricksSqlWorkspaceResolver.resolve(
                "https://gateway.test.example/v1/databricks-sql/foo-dbc-1/mcp", config()).isEmpty());
    }

    @Test
    void normalizePrefix_addsSlashes() {
        assertEquals("/v1/databricks-sql/", DatabricksSqlWorkspaceResolver.normalizePrefix("/v1/databricks-sql"));
        assertEquals("/v1/databricks-sql/", DatabricksSqlWorkspaceResolver.normalizePrefix("/v1/databricks-sql/"));
    }

    @Test
    void normalizePrefix_nullOrEmpty_returnsRoot() {
        assertEquals("/", DatabricksSqlWorkspaceResolver.normalizePrefix(null));
        assertEquals("/", DatabricksSqlWorkspaceResolver.normalizePrefix(""));
    }

    @Test
    void normalizePrefix_prependsSlashWhenMissing() {
        assertEquals("/v1/databricks-sql/", DatabricksSqlWorkspaceResolver.normalizePrefix("v1/databricks-sql"));
    }

    @Test
    void resolve_blankResourceOrNullConfig_returnsEmpty() {
        assertTrue(DatabricksSqlWorkspaceResolver.resolve("", config()).isEmpty());
        assertTrue(DatabricksSqlWorkspaceResolver.resolve("   ", config()).isEmpty());
        assertTrue(DatabricksSqlWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-a/mcp", null).isEmpty());
    }

    @Test
    void resolve_invalidUri_returnsEmpty() {
        assertTrue(DatabricksSqlWorkspaceResolver.resolve("http://[", config()).isEmpty());
    }

    @Test
    void resolve_blankPath_returnsEmpty() {
        assertTrue(DatabricksSqlWorkspaceResolver.resolve("https://hostonly", config()).isEmpty());
    }

    @Test
    void resolve_wrongPrefix_returnsEmpty() {
        assertTrue(DatabricksSqlWorkspaceResolver.resolve(
                "https://h/v1/other/dbc-seg/mcp", config()).isEmpty());
    }

    @Test
    void resolve_missingMcpSuffix_returnsEmpty() {
        assertTrue(DatabricksSqlWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-seg/extra", config()).isEmpty());
    }

    @Test
    void resolve_emptySegment_returnsEmpty() {
        assertTrue(DatabricksSqlWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql//mcp", config()).isEmpty());
    }

    @Test
    void resolve_segmentWithSlash_returnsEmpty() {
        assertTrue(DatabricksSqlWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-a/extra/mcp", config()).isEmpty());
    }

    @Test
    void resolve_invalidRegex_returnsEmpty() {
        DatabricksSqlTokenExchangeConfig c = Mockito.mock(DatabricksSqlTokenExchangeConfig.class);
        when(c.resourcePathPrefix()).thenReturn("/v1/databricks-sql/");
        when(c.workspaceSegmentPattern()).thenReturn("["); // Pattern.compile throws
        when(c.workspaceHostTemplate()).thenReturn("https://%s.cloud.databricks.com");
        assertTrue(DatabricksSqlWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-a/mcp", c).isEmpty());
    }

    @Test
    void resolve_templateWithoutPlaceholder_returnsEmpty() {
        DatabricksSqlTokenExchangeConfig c = Mockito.mock(DatabricksSqlTokenExchangeConfig.class);
        when(c.resourcePathPrefix()).thenReturn("/v1/databricks-sql/");
        when(c.workspaceSegmentPattern()).thenReturn("^dbc-[a-zA-Z0-9.-]+$");
        when(c.workspaceHostTemplate()).thenReturn("https://fixed.databricks.com");
        assertTrue(DatabricksSqlWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-a/mcp", c).isEmpty());
    }

    @Test
    void resolve_templateBlank_returnsEmpty() {
        DatabricksSqlTokenExchangeConfig c = Mockito.mock(DatabricksSqlTokenExchangeConfig.class);
        when(c.resourcePathPrefix()).thenReturn("/v1/databricks-sql/");
        when(c.workspaceSegmentPattern()).thenReturn("^dbc-[a-zA-Z0-9.-]+$");
        when(c.workspaceHostTemplate()).thenReturn("   ");
        assertTrue(DatabricksSqlWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-a/mcp", c).isEmpty());
    }

    @Test
    void resolve_workspaceUrlWithoutHost_returnsEmpty() {
        DatabricksSqlTokenExchangeConfig c = Mockito.mock(DatabricksSqlTokenExchangeConfig.class);
        when(c.resourcePathPrefix()).thenReturn("/v1/databricks-sql/");
        when(c.workspaceSegmentPattern()).thenReturn("^dbc-[a-zA-Z0-9.-]+$");
        when(c.workspaceHostTemplate()).thenReturn("%s"); // URI has no host
        assertTrue(DatabricksSqlWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-a/mcp", c).isEmpty());
    }

    @Test
    void resolve_stringFormatThrows_returnsEmpty() {
        DatabricksSqlTokenExchangeConfig c = Mockito.mock(DatabricksSqlTokenExchangeConfig.class);
        when(c.resourcePathPrefix()).thenReturn("/v1/databricks-sql/");
        when(c.workspaceSegmentPattern()).thenReturn("^dbc-[a-zA-Z0-9.-]+$");
        when(c.workspaceHostTemplate()).thenReturn("https://%d.cloud.databricks.com"); // %d with string arg
        assertTrue(DatabricksSqlWorkspaceResolver.resolve(
                "https://h/v1/databricks-sql/dbc-a/mcp", c).isEmpty());
    }

    @Test
    void resolve_trimsResourceUri() {
        var r = DatabricksSqlWorkspaceResolver.resolve(
                "  https://local/v1/databricks-sql/dbc-z9/mcp  ", config());
        assertTrue(r.isPresent());
        assertEquals("dbc-z9.cloud.databricks.com", r.get().hostname());
    }
}
