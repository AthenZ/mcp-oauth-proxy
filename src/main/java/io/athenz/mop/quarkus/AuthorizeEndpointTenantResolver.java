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

import io.quarkus.oidc.TenantResolver;
import io.quarkus.oidc.runtime.OidcUtils;
import io.vertx.ext.web.RoutingContext;
import jakarta.inject.Singleton;
import java.lang.invoke.MethodHandles;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Quarkus OIDC {@link TenantResolver} that pins the OAuth 2.1 authorization endpoint
 * (<code>/authorize</code>) to the primary (Okta) default tenant.
 *
 * <h2>Why this exists</h2>
 *
 * <p>MoP runs OIDC in two stages per resource:
 * <ol>
 *   <li><b>Primary login</b> against the default Okta tenant. Always required. Establishes the
 *       user's identity (the {@code sub} claim) used by {@code AuthorizeResource}.</li>
 *   <li><b>Secondary login</b> against a named tenant (e.g. {@code slack}, {@code github},
 *       {@code google-sheets}, {@code embrace}, {@code atlassian}). Only triggered when the
 *       user does not yet have an upstream token for the requested resource.</li>
 * </ol>
 *
 * <p>After a secondary login, Quarkus stores its session under a tenant-suffixed cookie name
 * (e.g. {@code q_session_slack}). Subsequent requests to {@code /authorize} carry both the
 * default-tenant cookie ({@code q_session}) and the named-tenant cookie. Quarkus' built-in
 * cookie-based tenant resolution can pick the named-tenant cookie, bind {@code /authorize} to
 * that tenant, and then fail subject extraction in {@code AuthorizeResource} because tenants
 * like {@code slack} do not provide a {@code sub} claim. The user sees
 * {@code server_error: Unable to determine user identity}.
 *
 * <p>This resolver short-circuits that risk by binding {@code /authorize} to the default tenant
 * unconditionally. It is registered as a static {@link TenantResolver} bean and runs ahead of
 * Quarkus' path-/cookie-based fallback resolution. Returning {@link OidcUtils#DEFAULT_TENANT_ID}
 * is the documented way to select the default static tenant.
 *
 * <p>For every other path the resolver returns {@code null}, leaving Quarkus' default resolution
 * intact so the named-tenant secondary-login flows ({@code /slack/authorize/callback},
 * {@code /github/authorize/callback}, {@code /google-*\/authorize/callback}, ...) keep being
 * bound to their own tenants by the existing cookie / tenant-paths logic.
 */
@Singleton
public class AuthorizeEndpointTenantResolver implements TenantResolver {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    /**
     * Exact path of the OAuth 2.1 authorization endpoint (see
     * {@code io.athenz.mop.resource.AuthorizeResource}).
     */
    static final String AUTHORIZE_PATH = "/authorize";

    @Override
    public String resolve(RoutingContext context) {
        String path = context.request().path();
        if (AUTHORIZE_PATH.equals(path)) {
            // Force the primary Okta tenant so a leftover q_session_<tenant> cookie cannot
            // steer this request away from the user's Okta identity.
            log.debug("Pinning {} to the default Okta tenant", path);
            return OidcUtils.DEFAULT_TENANT_ID;
        }
        return null;
    }
}
