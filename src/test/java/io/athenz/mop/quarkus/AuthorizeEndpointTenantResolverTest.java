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
package io.athenz.mop.quarkus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.quarkus.oidc.runtime.OidcUtils;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AuthorizeEndpointTenantResolver}.
 *
 * <p>Behavior under test:
 * <ul>
 *   <li>{@code /authorize} resolves to {@link OidcUtils#DEFAULT_TENANT_ID} so Quarkus binds the
 *       request to the primary Okta tenant regardless of which {@code q_session*} cookies are
 *       present. This is the fix for the "Unable to determine user identity" prod bug, where
 *       Quarkus' default cookie-based resolver was binding {@code /authorize} to a named
 *       secondary-login tenant (e.g. slack/github/embrace) whose tokens lack a {@code sub} claim.</li>
 *   <li>All other paths return {@code null} so Quarkus' built-in cookie / tenant-paths resolution
 *       continues to handle the named-tenant secondary-login callback paths
 *       ({@code /slack/authorize/callback}, {@code /github/authorize/callback},
 *       {@code /google-*\/authorize/callback}, ...).</li>
 * </ul>
 */
class AuthorizeEndpointTenantResolverTest {

    private final AuthorizeEndpointTenantResolver resolver = new AuthorizeEndpointTenantResolver();

    @Test
    void resolve_authorizePath_returnsDefaultTenantId() {
        assertEquals(OidcUtils.DEFAULT_TENANT_ID, resolver.resolve(routingContextFor("/authorize")));
    }

    @Test
    void resolve_authorizePathExactMatchOnly_doesNotCaptureCallbackOrSubpaths() {
        // Sanity check: only the exact path "/authorize" is forced to the default tenant.
        // /authorize/callback is the default-tenant Okta callback; Quarkus' own machinery binds
        // it correctly via tenant-paths/cookies, so the resolver must not interfere.
        assertNull(resolver.resolve(routingContextFor("/authorize/callback")));
        assertNull(resolver.resolve(routingContextFor("/authorizers")));
        assertNull(resolver.resolve(routingContextFor("/authorize/extra")));
    }

    @Test
    void resolve_namedTenantSecondaryLoginEntryPaths_returnNull() {
        // Secondary-login entry paths must keep current behavior: Quarkus binds them to their
        // own named tenants via cookies / tenant-paths.
        String[] paths = new String[] {
                "/slack/authorize",
                "/github/authorize",
                "/atlassian/authorize",
                "/embrace/authorize",
                "/google-sheets/authorize",
                "/google-slides/authorize",
                "/google-drive/authorize",
                "/google-docs/authorize",
                "/google-mail/authorize",
                "/google-calendar/authorize",
                "/google-tasks/authorize",
                "/google-chat/authorize",
                "/google-forms/authorize",
                "/google-keep/authorize",
                "/google-meet/authorize",
                "/google-cloud-platform/authorize"
        };
        for (String path : paths) {
            assertNull(resolver.resolve(routingContextFor(path)),
                    "path " + path + " must not be intercepted by AuthorizeEndpointTenantResolver");
        }
    }

    @Test
    void resolve_namedTenantCallbackPaths_returnNull() {
        // Callback paths fired by upstream OAuth providers. Same reasoning as above.
        String[] paths = new String[] {
                "/slack/authorize/callback",
                "/github/authorize/callback",
                "/atlassian/authorize/callback",
                "/embrace/authorize/callback",
                "/google-sheets/authorize/callback",
                "/google-slides/authorize/callback"
        };
        for (String path : paths) {
            assertNull(resolver.resolve(routingContextFor(path)),
                    "path " + path + " must not be intercepted by AuthorizeEndpointTenantResolver");
        }
    }

    @Test
    void resolve_atlassianMcpPath_returnsNullSoCustomTenantConfigResolverHandlesIt() {
        // /atlassian-mcp/* is intentionally handled by the dynamic CustomTenantConfigResolver,
        // not by this static TenantResolver, because the tenant config is per-MCP-client.
        assertNull(resolver.resolve(routingContextFor("/atlassian-mcp/authorize")));
        assertNull(resolver.resolve(routingContextFor("/atlassian-mcp/authorize/callback")));
    }

    @Test
    void resolve_unauthenticatedAndUtilityPaths_returnNull() {
        String[] paths = new String[] {
                "/token",
                "/register",
                "/userinfo",
                "/q/health",
                "/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration",
                "/"
        };
        for (String path : paths) {
            assertNull(resolver.resolve(routingContextFor(path)),
                    "path " + path + " must not be intercepted by AuthorizeEndpointTenantResolver");
        }
    }

    private static RoutingContext routingContextFor(String path) {
        RoutingContext rc = mock(RoutingContext.class);
        HttpServerRequest req = mock(HttpServerRequest.class);
        when(rc.request()).thenReturn(req);
        when(req.path()).thenReturn(path);
        return rc;
    }
}
