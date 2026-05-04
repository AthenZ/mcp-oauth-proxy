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
package io.athenz.mop.resource;

import io.athenz.mop.telemetry.OauthProxyMetrics;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

@ExtendWith(MockitoExtension.class)
class AuthorizeErrorResourceTest {

    private static final String IIQ_URL = "https://yo/iiq";
    private static final String SUPPORT_CHANNEL = "#mcp-help";
    private static final String PROVIDER = "okta";

    @Mock
    OauthProxyMetrics metrics;

    private AuthorizeErrorResource resource;

    @BeforeEach
    void setUp() {
        resource = new AuthorizeErrorResource();
        resource.oauthProxyMetrics = metrics;
        resource.providerDefault = PROVIDER;
        resource.iiqUrl = IIQ_URL;
        resource.supportChannel = SUPPORT_CHANNEL;
    }

    @Test
    void classify_oktaUnassignedDescription_returnsNotAssigned() {
        assertEquals(AuthorizeErrorResource.Bucket.NOT_ASSIGNED,
                AuthorizeErrorResource.classify(
                        "access_denied",
                        "User is not assigned to the client application"));
    }

    @Test
    void classify_oktaUnassignedDescriptionMixedCase_returnsNotAssigned() {
        assertEquals(AuthorizeErrorResource.Bucket.NOT_ASSIGNED,
                AuthorizeErrorResource.classify(
                        "access_denied",
                        "USER IS NOT ASSIGNED TO THE CLIENT APPLICATION"));
    }

    @Test
    void classify_accessDeniedOtherDescription_returnsGeneric() {
        assertEquals(AuthorizeErrorResource.Bucket.GENERIC,
                AuthorizeErrorResource.classify("access_denied", "User declined consent"));
    }

    @Test
    void classify_accessDeniedNullDescription_returnsGeneric() {
        assertEquals(AuthorizeErrorResource.Bucket.GENERIC,
                AuthorizeErrorResource.classify("access_denied", null));
    }

    @Test
    void classify_invalidScope_returnsGeneric() {
        assertEquals(AuthorizeErrorResource.Bucket.GENERIC,
                AuthorizeErrorResource.classify("invalid_scope", null));
    }

    @Test
    void classify_allNull_returnsGeneric() {
        assertEquals(AuthorizeErrorResource.Bucket.GENERIC,
                AuthorizeErrorResource.classify(null, null));
    }

    @Test
    void render_notAssignedBucket_returns403WithIiqLinkAndStateInDetails() {
        Response response = resource.render(
                "access_denied",
                "User is not assigned to the client application",
                "abc-123-state");

        assertEquals(403, response.getStatus());
        assertEquals("text/html", response.getMediaType().getType() + "/" + response.getMediaType().getSubtype());
        assertEquals("UTF-8", response.getMediaType().getParameters().get("charset"));
        assertEquals("no-store", response.getHeaderString("Cache-Control"));
        assertEquals("nosniff", response.getHeaderString("X-Content-Type-Options"));

        String html = (String) response.getEntity();
        assertNotNull(html);
        assertTrue(html.contains("Request access via yo/iiq"),
                "yo/iiq CTA should appear on NOT_ASSIGNED page");
        assertTrue(html.contains("href=\"" + IIQ_URL + "\""),
                "yo/iiq button should link to configured iiqUrl");
        assertTrue(html.contains("don&#39;t have access"),
                "heading should be the entitlement-style copy");
        assertTrue(html.contains("abc-123-state"),
                "state should be echoed in the technical-details block");
        assertTrue(html.contains(SUPPORT_CHANNEL),
                "configured Slack channel should appear in the help line");
        assertTrue(html.contains("yahoo-logo.svg"),
                "Yahoo brand logo image should be embedded in the page");
        assertTrue(html.contains("MCP OAuth Proxy"),
                "product label should appear next to the Yahoo brand logo");

        verify(metrics).recordAuthorizeRedirect(PROVIDER, false, "user_not_assigned", "unknown");
        verifyNoMoreInteractions(metrics);
    }

    @Test
    void render_genericBucket_returns401WithoutIiqLink() {
        Response response = resource.render(
                "invalid_scope",
                "scope=foo is not allowed for this client",
                null);

        assertEquals(401, response.getStatus());
        String html = (String) response.getEntity();
        assertFalse(html.contains("Request access via yo/iiq"),
                "yo/iiq CTA should not appear on the generic page");
        assertTrue(html.contains("Sign-in didn&#39;t complete"),
                "heading should be the generic copy");
        assertTrue(html.contains("invalid_scope"),
                "raw error code should be echoed in the technical-details block");

        verify(metrics).recordAuthorizeRedirect(PROVIDER, false, "upstream_error", "unknown");
        verifyNoMoreInteractions(metrics);
    }

    @Test
    void render_xssInDescription_isEscaped() {
        String malicious = "\"><script>alert(1)</script>";
        Response response = resource.render("access_denied", malicious, "s");

        String html = (String) response.getEntity();
        assertFalse(html.contains("<script>"),
                "raw <script> tag must not appear in rendered HTML");
        assertFalse(html.contains("alert(1)</script>"),
                "raw </script> closing tag must not appear in rendered HTML");
        assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
                "<script> payload should be HTML-entity escaped");
    }

    @Test
    void render_xssInState_isEscaped() {
        String malicious = "<img src=x onerror=alert(1)>";
        Response response = resource.render(
                "access_denied",
                "User is not assigned to the client application",
                malicious);

        String html = (String) response.getEntity();
        // The page intentionally embeds an <img> for the Yahoo brand logo, so we cannot assert
        // there is no <img substring at all. Instead assert the attacker-controlled tag is not
        // emitted as a real element (no `<img src=x` -- only `&lt;img src=x`) and that the full
        // payload is present in HTML-escaped form.
        assertFalse(html.contains("<img src=x"),
                "raw attacker <img> tag must not appear unescaped in rendered HTML");
        assertTrue(html.contains("&lt;img src=x onerror=alert(1)&gt;"),
                "state payload should be HTML-entity escaped");
    }

    @Test
    void render_emptyParameters_rendersEmDashPlaceholders() {
        Response response = resource.render(null, null, null);

        String html = (String) response.getEntity();
        assertTrue(html.contains("&mdash;"),
                "missing fields should render as em-dash placeholders, not blank cells");
    }
}
