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

import io.athenz.mop.client.ZmsAssumeRoleResourceClient;
import io.athenz.mop.model.GcpZmsPrincipalScope;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.Field;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ZMSServiceImplTest {

    @Mock
    private ZmsAssumeRoleResourceClient zmsAssumeRoleResourceClient;

    @InjectMocks
    private ZMSServiceImpl zmsService;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        setDefaultGcpRoleName("gcp.fed.mcp.user");
    }

    private void setDefaultGcpRoleName(String value) throws Exception {
        Field f = ZMSServiceImpl.class.getDeclaredField("defaultGcpRoleName");
        f.setAccessible(true);
        f.set(zmsService, value);
    }

    @Test
    void testGetScopeForPrincipal_Success() {
        String json =
                """
                {"resources":[{"principal":"user.foobar","assertions":[
                  {"role":"domain1:role.gcp.fed.mcp.user","resource":"projects/p-domain1/roles/fed.mcp.user","action":"gcp.assume_role","effect":"ALLOW"},
                  {"role":"domain2:role.gcp.fed.mcp.user","resource":"projects/p-domain2/roles/fed.mcp.user","action":"gcp.assume_role","effect":"ALLOW"}
                ]}]}
                """
                        .replaceAll("\\s+", "");

        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.foobar")).thenReturn(json);

        GcpZmsPrincipalScope r = zmsService.getScopeForPrincipal("user.foobar", "gcp.fed.mcp.user");

        assertEquals("domain1:role.gcp.fed.mcp.user domain2:role.gcp.fed.mcp.user openid", r.scope());
        assertEquals("p-domain1", r.defaultBillingProject());
        verify(zmsAssumeRoleResourceClient, times(1)).getAssumeRoleResourceJson("user.foobar");
    }

    @Test
    void testGetScopeForPrincipal_WithExplicitRoleName() {
        String json =
                "{\"resources\":[{\"assertions\":[{\"role\":\"msd.stage:role.custom.role\","
                        + "\"resource\":\"projects/core-msd-s/roles/fed.mcp.user\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"ALLOW\"}]}]}";

        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.abc")).thenReturn(json);

        GcpZmsPrincipalScope r = zmsService.getScopeForPrincipal("user.abc", "custom.role");

        assertEquals("msd.stage:role.custom.role openid", r.scope());
        assertEquals("core-msd-s", r.defaultBillingProject());
    }

    @Test
    void testGetScopeForPrincipal_NullRoleName_UsesDefault() {
        String json =
                "{\"resources\":[{\"assertions\":[{\"role\":\"dom:role.gcp.fed.mcp.user\","
                        + "\"resource\":\"projects/p1/roles/fed.mcp.user\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"ALLOW\"}]}]}";

        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.x")).thenReturn(json);

        GcpZmsPrincipalScope r = zmsService.getScopeForPrincipal("user.x", null);

        assertEquals("dom:role.gcp.fed.mcp.user openid", r.scope());
        assertEquals("p1", r.defaultBillingProject());
    }

    @Test
    void testGetScopeForPrincipal_BlankRoleName_UsesDefault() {
        String json =
                "{\"resources\":[{\"assertions\":[{\"role\":\"dom:role.gcp.fed.mcp.user\","
                        + "\"resource\":\"projects/p1/roles/fed.mcp.user\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"ALLOW\"}]}]}";

        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.y")).thenReturn(json);

        GcpZmsPrincipalScope r = zmsService.getScopeForPrincipal("user.y", "   ");

        assertEquals("dom:role.gcp.fed.mcp.user openid", r.scope());
    }

    @Test
    void testGetScopeForPrincipal_ExcludesNonMcpRole() {
        String json =
                "{\"resources\":[{\"assertions\":["
                        + "{\"role\":\"calypso.nonprod:role.gcp.fed.power.user\","
                        + "\"resource\":\"projects/gcp-calypso-nonprod/roles/fed.power.user\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"ALLOW\"},"
                        + "{\"role\":\"msd.stage:role.gcp.fed.mcp.user\","
                        + "\"resource\":\"projects/core-msd-s/roles/fed.mcp.user\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"ALLOW\"}"
                        + "]}]}";

        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.z")).thenReturn(json);

        GcpZmsPrincipalScope r = zmsService.getScopeForPrincipal("user.z", "gcp.fed.mcp.user");

        assertEquals("msd.stage:role.gcp.fed.mcp.user openid", r.scope());
        assertEquals("core-msd-s", r.defaultBillingProject());
    }

    @Test
    void testGetScopeForPrincipal_CommaSeparatedRoleNames_MatchesAny() {
        String json =
                """
                {"resources":[{"assertions":[
                  {"role":"dom1:role.gcp.fed.mcp.user","resource":"projects/p-user/roles/r","action":"gcp.assume_role","effect":"ALLOW"},
                  {"role":"dom2:role.gcp.fed.mcp.monitoring.user","resource":"projects/p-mon/roles/r","action":"gcp.assume_role","effect":"ALLOW"}
                ]}]}
                """
                        .replaceAll("\\s+", "");

        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.multi")).thenReturn(json);

        GcpZmsPrincipalScope r =
                zmsService.getScopeForPrincipal("user.multi", "gcp.fed.mcp.user, gcp.fed.mcp.monitoring.user");

        assertTrue(r.scope().contains("dom1:role.gcp.fed.mcp.user"));
        assertTrue(r.scope().contains("dom2:role.gcp.fed.mcp.monitoring.user"));
        assertTrue(r.scope().endsWith(" openid"));
        assertEquals("p-user", r.defaultBillingProject());
    }

    @Test
    void testGetScopeForPrincipal_DefaultCommaSeparated_UsesAnyMatch() throws Exception {
        setDefaultGcpRoleName("gcp.fed.mcp.user, gcp.fed.mcp.monitoring.user");
        String json =
                "{\"resources\":[{\"assertions\":["
                        + "{\"role\":\"dom:role.gcp.fed.mcp.monitoring.user\","
                        + "\"resource\":\"projects/p-m/roles/r\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"ALLOW\"}]}]}";

        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.d")).thenReturn(json);

        GcpZmsPrincipalScope r = zmsService.getScopeForPrincipal("user.d", null);

        assertEquals("dom:role.gcp.fed.mcp.monitoring.user openid", r.scope());
        assertEquals("p-m", r.defaultBillingProject());
    }

    @Test
    void roleMarkersFromRaw_trimsAndSkipsBlanks() {
        assertEquals(List.of("role.a", "role.b"), ZMSServiceImpl.roleMarkersFromRaw(" a , , b "));
        assertTrue(ZMSServiceImpl.roleMarkersFromRaw("").isEmpty());
        assertTrue(ZMSServiceImpl.roleMarkersFromRaw("   ,  ,").isEmpty());
    }

    @Test
    void testGetScopeForPrincipal_WrongActionIgnored() {
        String json =
                "{\"resources\":[{\"assertions\":[{\"role\":\"dom:role.gcp.fed.mcp.user\","
                        + "\"resource\":\"projects/p1/roles/fed.mcp.user\","
                        + "\"action\":\"other.action\",\"effect\":\"ALLOW\"}]}]}";

        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.a")).thenReturn(json);

        GcpZmsPrincipalScope r = zmsService.getScopeForPrincipal("user.a", "gcp.fed.mcp.user");

        assertEquals("openid", r.scope());
        assertNull(r.defaultBillingProject());
    }

    @Test
    void testGetScopeForPrincipal_DenyEffectIgnored() {
        String json =
                "{\"resources\":[{\"assertions\":[{\"role\":\"dom:role.gcp.fed.mcp.user\","
                        + "\"resource\":\"projects/p1/roles/fed.mcp.user\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"DENY\"}]}]}";

        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.b")).thenReturn(json);

        GcpZmsPrincipalScope r = zmsService.getScopeForPrincipal("user.b", "gcp.fed.mcp.user");

        assertEquals("openid", r.scope());
        assertNull(r.defaultBillingProject());
    }

    @Test
    void testGetScopeForPrincipal_DenyOnFirstAssertion_AllowOnSecondStillIncluded() {
        String json =
                "{\"resources\":[{\"assertions\":["
                        + "{\"role\":\"dom1:role.gcp.fed.mcp.user\","
                        + "\"resource\":\"projects/p-deny/roles/r\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"DENY\"},"
                        + "{\"role\":\"dom2:role.gcp.fed.mcp.monitoring.user\","
                        + "\"resource\":\"projects/p-allow/roles/r\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"ALLOW\"}"
                        + "]}]}";

        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.denyThenAllow")).thenReturn(json);

        GcpZmsPrincipalScope r =
                zmsService.getScopeForPrincipal(
                        "user.denyThenAllow", "gcp.fed.mcp.user, gcp.fed.mcp.monitoring.user");

        assertFalse(r.scope().contains("dom1:role.gcp.fed.mcp.user"));
        assertTrue(r.scope().contains("dom2:role.gcp.fed.mcp.monitoring.user"));
        assertEquals("p-allow", r.defaultBillingProject());
    }

    @Test
    void testGetScopeForPrincipal_EmptyMatchingAssertions_ReturnsOpenidOnly() {
        String json = "{\"resources\":[{\"assertions\":[]}]}";

        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.empty")).thenReturn(json);

        GcpZmsPrincipalScope r = zmsService.getScopeForPrincipal("user.empty", "role");

        assertEquals("openid", r.scope());
        assertNull(r.defaultBillingProject());
    }

    @Test
    void testGetScopeForPrincipal_NullJson_ReturnsOpenidOnly() {
        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.null")).thenReturn(null);

        GcpZmsPrincipalScope r = zmsService.getScopeForPrincipal("user.null", "role");

        assertEquals("openid", r.scope());
        assertNull(r.defaultBillingProject());
    }

    @Test
    void testGetScopeForPrincipal_BlankJson_ReturnsOpenidOnly() {
        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.blank")).thenReturn("   \n");

        GcpZmsPrincipalScope r = zmsService.getScopeForPrincipal("user.blank", "role");

        assertEquals("openid", r.scope());
        assertNull(r.defaultBillingProject());
    }

    @Test
    void testGetScopeForPrincipal_InvalidJson_ReturnsOpenidOnly() {
        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.fail")).thenReturn("not-json{");

        GcpZmsPrincipalScope r = zmsService.getScopeForPrincipal("user.fail", "role");

        assertEquals("openid", r.scope());
        assertNull(r.defaultBillingProject());
    }

    @Test
    void testExtractGcpProjectId() {
        assertEquals("core-msd-s", ZMSServiceImpl.extractGcpProjectId("projects/core-msd-s/roles/fed.mcp.user"));
        assertNull(ZMSServiceImpl.extractGcpProjectId(null));
        assertNull(ZMSServiceImpl.extractGcpProjectId("invalid"));
        assertNull(ZMSServiceImpl.extractGcpProjectId(""));
        assertNull(ZMSServiceImpl.extractGcpProjectId("   "));
    }

    @Test
    void testGetScopeForPrincipal_clientThrows_returnsOpenidOnly() {
        when(zmsAssumeRoleResourceClient.getAssumeRoleResourceJson("user.err"))
                .thenThrow(new RuntimeException("ZMS unavailable"));

        GcpZmsPrincipalScope r = zmsService.getScopeForPrincipal("user.err", "gcp.fed.mcp.user");

        assertEquals("openid", r.scope());
        assertNull(r.defaultBillingProject());
    }

    @Test
    void parseAssumeRoleResourceResponse_emptyResourcesArray() throws Exception {
        GcpZmsPrincipalScope r =
                zmsService.parseAssumeRoleResourceResponse("{\"resources\":[]}", List.of("role.gcp.fed.mcp.user"));
        assertEquals("openid", r.scope());
        assertNull(r.defaultBillingProject());
    }

    @Test
    void parseAssumeRoleResourceResponse_missingResourcesKey() throws Exception {
        GcpZmsPrincipalScope r = zmsService.parseAssumeRoleResourceResponse("{}", List.of("role.gcp.fed.mcp.user"));
        assertEquals("openid", r.scope());
    }

    @Test
    void parseAssumeRoleResourceResponse_nullAssertions_skipsEntry() throws Exception {
        String json =
                "{\"resources\":["
                        + "{\"principal\":\"user.p\",\"assertions\":null},"
                        + "{\"assertions\":[{\"role\":\"d:role.gcp.fed.mcp.user\","
                        + "\"resource\":\"projects/p2/roles/fed.mcp.user\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"ALLOW\"}]}"
                        + "]}";
        GcpZmsPrincipalScope r = zmsService.parseAssumeRoleResourceResponse(json, List.of("role.gcp.fed.mcp.user"));
        assertEquals("d:role.gcp.fed.mcp.user openid", r.scope());
        assertEquals("p2", r.defaultBillingProject());
    }

    @Test
    void parseAssumeRoleResourceResponse_billingFromSecondMatchWhenFirstResourceInvalid() throws Exception {
        String json =
                "{\"resources\":[{\"assertions\":["
                        + "{\"role\":\"a:role.gcp.fed.mcp.user\",\"resource\":\"not-a-project-path\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"ALLOW\"},"
                        + "{\"role\":\"b:role.gcp.fed.mcp.user\",\"resource\":\"projects/from-second/roles/fed.mcp.user\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"ALLOW\"}"
                        + "]}]}";
        GcpZmsPrincipalScope r = zmsService.parseAssumeRoleResourceResponse(json, List.of("role.gcp.fed.mcp.user"));
        assertTrue(r.scope().contains("a:role.gcp.fed.mcp.user"));
        assertTrue(r.scope().contains("b:role.gcp.fed.mcp.user"));
        assertEquals("from-second", r.defaultBillingProject());
    }

    @Test
    void parseAssumeRoleResourceResponse_deduplicatesSameRole() throws Exception {
        String json =
                "{\"resources\":[{\"assertions\":["
                        + "{\"role\":\"d:role.gcp.fed.mcp.user\",\"resource\":\"projects/p/roles/r\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"ALLOW\"},"
                        + "{\"role\":\"d:role.gcp.fed.mcp.user\",\"resource\":\"projects/p/roles/r\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"ALLOW\"}"
                        + "]}]}";
        GcpZmsPrincipalScope r = zmsService.parseAssumeRoleResourceResponse(json, List.of("role.gcp.fed.mcp.user"));
        assertEquals("d:role.gcp.fed.mcp.user openid", r.scope());
    }

    @Test
    void parseAssumeRoleResourceResponse_nullActionExcluded() throws Exception {
        String json =
                "{\"resources\":[{\"assertions\":[{\"role\":\"d:role.gcp.fed.mcp.user\","
                        + "\"resource\":\"projects/p/roles/r\",\"effect\":\"ALLOW\"}]}]}";
        GcpZmsPrincipalScope r = zmsService.parseAssumeRoleResourceResponse(json, List.of("role.gcp.fed.mcp.user"));
        assertEquals("openid", r.scope());
    }

    @Test
    void parseAssumeRoleResourceResponse_nullEffectExcluded() throws Exception {
        String json =
                "{\"resources\":[{\"assertions\":[{\"role\":\"d:role.gcp.fed.mcp.user\","
                        + "\"resource\":\"projects/p/roles/r\",\"action\":\"gcp.assume_role\"}]}]}";
        GcpZmsPrincipalScope r = zmsService.parseAssumeRoleResourceResponse(json, List.of("role.gcp.fed.mcp.user"));
        assertEquals("openid", r.scope());
    }

    @Test
    void parseAssumeRoleResourceResponse_multipleMarkers_unionOfMatches() throws Exception {
        String json =
                "{\"resources\":[{\"assertions\":["
                        + "{\"role\":\"x:role.gcp.fed.mcp.user\",\"resource\":\"projects/px/roles/r\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"ALLOW\"},"
                        + "{\"role\":\"y:role.gcp.fed.mcp.monitoring.user\",\"resource\":\"projects/py/roles/r\","
                        + "\"action\":\"gcp.assume_role\",\"effect\":\"ALLOW\"}"
                        + "]}]}";
        GcpZmsPrincipalScope r =
                zmsService.parseAssumeRoleResourceResponse(
                        json, List.of("role.gcp.fed.mcp.user", "role.gcp.fed.mcp.monitoring.user"));
        assertTrue(r.scope().contains("x:role.gcp.fed.mcp.user"));
        assertTrue(r.scope().contains("y:role.gcp.fed.mcp.monitoring.user"));
        assertEquals("px", r.defaultBillingProject());
    }
}
