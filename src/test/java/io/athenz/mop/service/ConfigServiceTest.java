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

import io.athenz.mop.config.ResourceConfig;
import io.athenz.mop.config.TokenExchangeServersConfig;
import io.athenz.mop.model.ResourceMeta;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ConfigServiceTest {

    /** Fake host for wildcard SQL MCP tests (not a real deployment). */
    private static final String DATABRICKS_SQL_MCP_BASE = "https://databricks-mcp.gateway.test:4444/v1/databricks-sql";

    @Mock
    private ResourceConfig resourceConfig;

    @Mock
    private TokenExchangeServersConfig tokenExchangeServersConfig;

    @InjectMocks
    private ConfigService configService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        configService.defaultIDP = "default-idp";
    }

    @Test
    void testInit_WithResourceMappings() {
        // Create mock resource mappings
        ResourceConfig.ResourceMapping mapping1 = mock(ResourceConfig.ResourceMapping.class);
        ResourceConfig.TokenConfig tokenConfig1 = mock(ResourceConfig.TokenConfig.class);
        ResourceConfig.JAGConfig jagConfig1 = mock(ResourceConfig.JAGConfig.class);

        when(mapping1.uri()).thenReturn("https://api1.example.com");
        when(mapping1.scopes()).thenReturn(Arrays.asList("read", "write"));
        when(mapping1.domain()).thenReturn("domain1");
        when(mapping1.token()).thenReturn(tokenConfig1);
        when(tokenConfig1.idp()).thenReturn("idp1");
        when(tokenConfig1.as()).thenReturn("as1");
        when(tokenConfig1.audience()).thenReturn(Optional.empty());
        when(tokenConfig1.jag()).thenReturn(jagConfig1);
        when(jagConfig1.enabled()).thenReturn(true);
        when(jagConfig1.issuer()).thenReturn("issuer1");

        when(resourceConfig.resourceMapping()).thenReturn(Collections.singletonList(mapping1));

        // Create mock remote server
        TokenExchangeServersConfig.RemoteServer server1 = mock(TokenExchangeServersConfig.RemoteServer.class);
        when(server1.name()).thenReturn("server1");
        when(server1.endpoint()).thenReturn("https://server1.example.com");
        when(server1.usernameClaim()).thenReturn("sub");

        when(tokenExchangeServersConfig.endpoints()).thenReturn(Collections.singletonList(server1));

        // Call init
        configService.init();

        // Verify resource meta is populated
        ResourceMeta meta = configService.getResourceMeta("https://api1.example.com");
        assertNotNull(meta);
        assertEquals(Arrays.asList("read", "write"), meta.scopes());
        assertEquals("domain1", meta.domain());
        assertEquals("idp1", meta.idpServer());
        assertEquals("as1", meta.authorizationServer());
        assertTrue(meta.jagEnabled());
        assertEquals("issuer1", meta.jagIssuer());

        // Verify remote server is populated
        assertEquals("https://server1.example.com", configService.getRemoteServerEndpoint("server1"));
        assertEquals("sub", configService.getRemoteServerUsernameClaim("server1"));
    }

    @Test
    void testInit_WithMultipleResourceMappings() {
        ResourceConfig.ResourceMapping mapping1 = mock(ResourceConfig.ResourceMapping.class);
        ResourceConfig.ResourceMapping mapping2 = mock(ResourceConfig.ResourceMapping.class);
        ResourceConfig.TokenConfig tokenConfig1 = mock(ResourceConfig.TokenConfig.class);
        ResourceConfig.TokenConfig tokenConfig2 = mock(ResourceConfig.TokenConfig.class);
        ResourceConfig.JAGConfig jagConfig1 = mock(ResourceConfig.JAGConfig.class);
        ResourceConfig.JAGConfig jagConfig2 = mock(ResourceConfig.JAGConfig.class);

        when(mapping1.uri()).thenReturn("https://api1.example.com");
        when(mapping1.scopes()).thenReturn(Collections.singletonList("read"));
        when(mapping1.domain()).thenReturn("domain1");
        when(mapping1.token()).thenReturn(tokenConfig1);
        when(tokenConfig1.idp()).thenReturn("idp1");
        when(tokenConfig1.as()).thenReturn("as1");
        when(tokenConfig1.audience()).thenReturn(Optional.empty());
        when(tokenConfig1.jag()).thenReturn(jagConfig1);
        when(jagConfig1.enabled()).thenReturn(false);
        when(jagConfig1.issuer()).thenReturn("issuer1");

        when(mapping2.uri()).thenReturn("https://api2.example.com");
        when(mapping2.scopes()).thenReturn(Arrays.asList("read", "write", "delete"));
        when(mapping2.domain()).thenReturn("domain2");
        when(mapping2.token()).thenReturn(tokenConfig2);
        when(tokenConfig2.idp()).thenReturn("idp2");
        when(tokenConfig2.as()).thenReturn("as2");
        when(tokenConfig2.audience()).thenReturn(Optional.empty());
        when(tokenConfig2.jag()).thenReturn(jagConfig2);
        when(jagConfig2.enabled()).thenReturn(true);
        when(jagConfig2.issuer()).thenReturn("issuer2");

        when(resourceConfig.resourceMapping()).thenReturn(Arrays.asList(mapping1, mapping2));
        when(tokenExchangeServersConfig.endpoints()).thenReturn(Collections.emptyList());

        configService.init();

        ResourceMeta meta1 = configService.getResourceMeta("https://api1.example.com");
        ResourceMeta meta2 = configService.getResourceMeta("https://api2.example.com");

        assertNotNull(meta1);
        assertNotNull(meta2);
        assertEquals("domain1", meta1.domain());
        assertEquals("domain2", meta2.domain());
        assertFalse(meta1.jagEnabled());
        assertTrue(meta2.jagEnabled());
    }

    @Test
    void testGetRemoteServerEndpoint_Exists() {
        TokenExchangeServersConfig.RemoteServer server1 = mock(TokenExchangeServersConfig.RemoteServer.class);
        when(server1.name()).thenReturn("github");
        when(server1.endpoint()).thenReturn("https://github.com/token");
        when(server1.usernameClaim()).thenReturn("login");

        when(resourceConfig.resourceMapping()).thenReturn(Collections.emptyList());
        when(tokenExchangeServersConfig.endpoints()).thenReturn(Collections.singletonList(server1));

        configService.init();

        assertEquals("https://github.com/token", configService.getRemoteServerEndpoint("github"));
    }

    @Test
    void testGetRemoteServerEndpoint_NotExists() {
        when(resourceConfig.resourceMapping()).thenReturn(Collections.emptyList());
        when(tokenExchangeServersConfig.endpoints()).thenReturn(Collections.emptyList());

        configService.init();

        assertNull(configService.getRemoteServerEndpoint("nonexistent"));
    }

    @Test
    void testGetRemoteServerUsernameClaim_Exists() {
        TokenExchangeServersConfig.RemoteServer server1 = mock(TokenExchangeServersConfig.RemoteServer.class);
        when(server1.name()).thenReturn("google");
        when(server1.endpoint()).thenReturn("https://accounts.google.com/token");
        when(server1.usernameClaim()).thenReturn("email");

        when(resourceConfig.resourceMapping()).thenReturn(Collections.emptyList());
        when(tokenExchangeServersConfig.endpoints()).thenReturn(Collections.singletonList(server1));

        configService.init();

        assertEquals("email", configService.getRemoteServerUsernameClaim("google"));
    }

    @Test
    void testGetRemoteServerUsernameClaim_NotExists() {
        when(resourceConfig.resourceMapping()).thenReturn(Collections.emptyList());
        when(tokenExchangeServersConfig.endpoints()).thenReturn(Collections.emptyList());

        configService.init();

        assertNull(configService.getRemoteServerUsernameClaim("nonexistent"));
    }

    @Test
    void testGetResourceMeta_Exists() {
        ResourceConfig.ResourceMapping mapping1 = mock(ResourceConfig.ResourceMapping.class);
        ResourceConfig.TokenConfig tokenConfig1 = mock(ResourceConfig.TokenConfig.class);
        ResourceConfig.JAGConfig jagConfig1 = mock(ResourceConfig.JAGConfig.class);

        when(mapping1.uri()).thenReturn("https://api.example.com");
        when(mapping1.scopes()).thenReturn(Collections.singletonList("admin"));
        when(mapping1.domain()).thenReturn("admin-domain");
        when(mapping1.token()).thenReturn(tokenConfig1);
        when(tokenConfig1.idp()).thenReturn("admin-idp");
        when(tokenConfig1.as()).thenReturn("admin-as");
        when(tokenConfig1.audience()).thenReturn(Optional.empty());
        when(tokenConfig1.jag()).thenReturn(jagConfig1);
        when(jagConfig1.enabled()).thenReturn(true);
        when(jagConfig1.issuer()).thenReturn("admin-issuer");

        when(resourceConfig.resourceMapping()).thenReturn(Collections.singletonList(mapping1));
        when(tokenExchangeServersConfig.endpoints()).thenReturn(Collections.emptyList());

        configService.init();

        ResourceMeta meta = configService.getResourceMeta("https://api.example.com");
        assertNotNull(meta);
        assertEquals("admin-domain", meta.domain());
    }

    @Test
    void testGetResourceMeta_NotExists() {
        when(resourceConfig.resourceMapping()).thenReturn(Collections.emptyList());
        when(tokenExchangeServersConfig.endpoints()).thenReturn(Collections.emptyList());

        configService.init();

        assertNull(configService.getResourceMeta("https://nonexistent.example.com"));
    }

    @Test
    void testGetDefaultIDP() {
        assertEquals("default-idp", configService.getDefaultIDP());
    }

    @Test
    void testGlobToRegex_MatchesDatabricksSqlGatewayPath() {
        Pattern p = ConfigService.globToRegex(DATABRICKS_SQL_MCP_BASE + "/*/mcp");
        String concrete = DATABRICKS_SQL_MCP_BASE + "/dbc-44743f95-b8ca/mcp";
        assertTrue(p.matcher(concrete).matches());
        assertFalse(p.matcher(DATABRICKS_SQL_MCP_BASE + "/dbc-44743f95-b8ca/extra/mcp").matches());
        assertFalse(p.matcher("https://other-mcp.gateway.test:4444/v1/other-sql/foo/mcp").matches());
    }

    @Test
    void testGetResourceMeta_WildcardMapping_ResolvesAndCaches() {
        ResourceConfig.ResourceMapping mapping = mock(ResourceConfig.ResourceMapping.class);
        ResourceConfig.TokenConfig tokenConfig = mock(ResourceConfig.TokenConfig.class);
        ResourceConfig.JAGConfig jagConfig = mock(ResourceConfig.JAGConfig.class);

        when(mapping.uri()).thenReturn(DATABRICKS_SQL_MCP_BASE + "/*/mcp");
        when(mapping.scopes()).thenReturn(Collections.singletonList("s1"));
        when(mapping.domain()).thenReturn("dom-wild");
        when(mapping.token()).thenReturn(tokenConfig);
        when(tokenConfig.idp()).thenReturn("idp-w");
        when(tokenConfig.as()).thenReturn("as-w");
        when(tokenConfig.audience()).thenReturn(Optional.empty());
        when(tokenConfig.jag()).thenReturn(jagConfig);
        when(jagConfig.enabled()).thenReturn(false);
        when(jagConfig.issuer()).thenReturn("issuer-w");

        when(resourceConfig.resourceMapping()).thenReturn(Collections.singletonList(mapping));
        when(tokenExchangeServersConfig.endpoints()).thenReturn(Collections.emptyList());

        configService.init();

        String resource = DATABRICKS_SQL_MCP_BASE + "/dbc-44743f95-b8ca/mcp";
        ResourceMeta first = configService.getResourceMeta(resource);
        ResourceMeta second = configService.getResourceMeta(resource);

        assertNotNull(first);
        assertSame(first, second);
        assertEquals("dom-wild", first.domain());
        assertEquals("idp-w", first.idpServer());
        assertSame(first, configService.getResourceMeta(resource));
    }

    @Test
    void testGetResourceMeta_WildcardMapping_NoMatch() {
        ResourceConfig.ResourceMapping mapping = mock(ResourceConfig.ResourceMapping.class);
        ResourceConfig.TokenConfig tokenConfig = mock(ResourceConfig.TokenConfig.class);
        ResourceConfig.JAGConfig jagConfig = mock(ResourceConfig.JAGConfig.class);

        when(mapping.uri()).thenReturn(DATABRICKS_SQL_MCP_BASE + "/*/mcp");
        when(mapping.scopes()).thenReturn(Collections.emptyList());
        when(mapping.domain()).thenReturn("d");
        when(mapping.token()).thenReturn(tokenConfig);
        when(tokenConfig.idp()).thenReturn("i");
        when(tokenConfig.as()).thenReturn("a");
        when(tokenConfig.audience()).thenReturn(Optional.empty());
        when(tokenConfig.jag()).thenReturn(jagConfig);
        when(jagConfig.enabled()).thenReturn(false);
        when(jagConfig.issuer()).thenReturn("j");

        when(resourceConfig.resourceMapping()).thenReturn(Collections.singletonList(mapping));
        when(tokenExchangeServersConfig.endpoints()).thenReturn(Collections.emptyList());

        configService.init();

        assertNull(configService.getResourceMeta("https://databricks-mcp.gateway.test:4444/v1/other-sql/foo/mcp"));
    }
}
