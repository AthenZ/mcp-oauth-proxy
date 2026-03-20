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

import com.yahoo.athenz.zms.DomainList;
import com.yahoo.athenz.zms.ZMSClient;
import io.athenz.mop.client.ZMSClientProducer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class ZMSServiceImplTest {

    @Mock
    private ZMSClientProducer zmsClientProducer;

    @Mock
    private ZMSClient zmsClient;

    @InjectMocks
    private ZMSServiceImpl zmsService;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        when(zmsClientProducer.getZMSClient()).thenReturn(zmsClient);
        setDefaultGcpRoleName("gcp.fed.mcp.user");
    }

    private void setDefaultGcpRoleName(String value) throws Exception {
        Field f = ZMSServiceImpl.class.getDeclaredField("defaultGcpRoleName");
        f.setAccessible(true);
        f.set(zmsService, value);
    }


    @Test
    void testGetScopeForPrincipal_Success() {
        when(zmsClient.getDomainListByRole("user.foobar", "gcp.fed.mcp.user"))
                .thenReturn(new DomainList().setNames(Arrays.asList("domain1", "domain2")));

        String scope = zmsService.getScopeForPrincipal("user.foobar", "gcp.fed.mcp.user");

        assertEquals("domain1:role.gcp.fed.mcp.user domain2:role.gcp.fed.mcp.user openid", scope);
        verify(zmsClient, times(1)).getDomainListByRole("user.foobar", "gcp.fed.mcp.user");
    }

    @Test
    void testGetScopeForPrincipal_WithExplicitRoleName() {
        when(zmsClient.getDomainListByRole("user.abc", "custom.role"))
                .thenReturn(new DomainList().setNames(Collections.singletonList("msd.stage")));

        String scope = zmsService.getScopeForPrincipal("user.abc", "custom.role");

        assertEquals("msd.stage:role.custom.role openid", scope);
        verify(zmsClient, times(1)).getDomainListByRole("user.abc", "custom.role");
    }

    @Test
    void testGetScopeForPrincipal_NullRoleName_UsesDefault() {
        when(zmsClient.getDomainListByRole("user.x", "gcp.fed.mcp.user"))
                .thenReturn(new DomainList().setNames(Collections.singletonList("dom")));

        String scope = zmsService.getScopeForPrincipal("user.x", null);

        assertEquals("dom:role.gcp.fed.mcp.user openid", scope);
        verify(zmsClient, times(1)).getDomainListByRole("user.x", "gcp.fed.mcp.user");
    }

    @Test
    void testGetScopeForPrincipal_BlankRoleName_UsesDefault() {
        when(zmsClient.getDomainListByRole("user.y", "gcp.fed.mcp.user"))
                .thenReturn(new DomainList().setNames(Collections.singletonList("dom")));

        String scope = zmsService.getScopeForPrincipal("user.y", "   ");

        assertEquals("dom:role.gcp.fed.mcp.user openid", scope);
        verify(zmsClient, times(1)).getDomainListByRole("user.y", "gcp.fed.mcp.user");
    }

    @Test
    void testGetScopeForPrincipal_EmptyDomainList_ReturnsOpenidOnly() {
        when(zmsClient.getDomainListByRole("user.empty", "role"))
                .thenReturn(new DomainList().setNames(Collections.emptyList()));

        String scope = zmsService.getScopeForPrincipal("user.empty", "role");

        assertEquals("openid", scope);
    }

    @Test
    void testGetScopeForPrincipal_NullDomainList_ReturnsOpenidOnly() {
        when(zmsClient.getDomainListByRole("user.null", "role")).thenReturn(null);

        String scope = zmsService.getScopeForPrincipal("user.null", "role");

        assertEquals("openid", scope);
    }

    @Test
    void testGetScopeForPrincipal_ZMSThrows_ReturnsOpenidOnly() {
        when(zmsClient.getDomainListByRole(anyString(), anyString()))
                .thenThrow(new RuntimeException("ZMS unavailable"));

        String scope = zmsService.getScopeForPrincipal("user.fail", "role");

        assertEquals("openid", scope);
    }
}
