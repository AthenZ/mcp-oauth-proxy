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

import io.athenz.mop.telemetry.OauthClientLabel;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.lang.invoke.MethodHandles;
import java.util.Locale;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Public, unauthenticated landing page rendered when Quarkus OIDC's authorization
 * code callback receives an upstream error (RFC 6749 Section 4.1.2.1) instead of a
 * {@code code} parameter. Wired in via {@code quarkus.oidc.authentication.error-path}
 * for the default Okta tenant.
 *
 * <p>Replaces the bare HTTP 401 a user otherwise sees when Okta returns
 * {@code error=access_denied&error_description=User+is+not+assigned+to+the+client+application}
 * with a friendly remediation page that links to yo/iiq.</p>
 *
 * <p>v1 only handles the default Okta tenant. Per-provider error pages
 * ({@code /slack/authorize/error}, {@code /github/authorize/error}, ...) are out of scope
 * for now — when added they should each get their own resource (or share this one with a
 * {@code provider} path/query param) so per-provider remediation copy can diverge.</p>
 */
@Path("/authorize/error")
public class AuthorizeErrorResource {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    /**
     * Substring (lowercased) of the Okta {@code error_description} sent when a user authenticates
     * successfully but the Okta admin has not assigned them to the OIDC client application that
     * MoP uses. Triggers the entitlement-request UX rather than the generic "sign-in failed" page.
     */
    static final String NOT_ASSIGNED_MARKER = "not assigned to the client application";

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @ConfigProperty(name = "server.token-exchange.idp")
    String providerDefault;

    @ConfigProperty(name = "mop.authorize-error.iiq-url", defaultValue = "https://yo/iiq")
    String iiqUrl;

    @ConfigProperty(name = "mop.authorize-error.support-channel", defaultValue = "#mcp-help")
    String supportChannel;

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response render(
            @QueryParam("error") String error,
            @QueryParam("error_description") String description,
            @QueryParam("state") String state) {
        Bucket bucket = classify(error, description);
        log.warn("Rendering /authorize/error bucket={} error={} description={}",
                bucket, error, description);
        oauthProxyMetrics.recordAuthorizeRedirect(
                OauthProviderLabel.normalize(providerDefault),
                false,
                bucket.metricLabel(),
                OauthClientLabel.normalize(null));
        Response.Status status = bucket == Bucket.NOT_ASSIGNED
                ? Response.Status.FORBIDDEN
                : Response.Status.UNAUTHORIZED;
        return Response.status(status)
                .entity(renderHtml(bucket, error, description, state))
                .type(MediaType.TEXT_HTML + ";charset=UTF-8")
                .header("Cache-Control", "no-store")
                .header("X-Content-Type-Options", "nosniff")
                .build();
    }

    static Bucket classify(String error, String description) {
        if ("access_denied".equals(error)
                && description != null
                && description.toLowerCase(Locale.ROOT).contains(NOT_ASSIGNED_MARKER)) {
            return Bucket.NOT_ASSIGNED;
        }
        return Bucket.GENERIC;
    }

    String renderHtml(Bucket bucket, String error, String description, String state) {
        String heading;
        String body;
        String primaryCta;
        if (bucket == Bucket.NOT_ASSIGNED) {
            heading = "You don&#39;t have access to this application yet";
            body = "Your Yahoo Okta account isn&#39;t entitled to MCP-on-Proxy. "
                    + "To request access, open a yo/iiq request for the appropriate Okta application group.";
            primaryCta = "<a class=\"btn primary\" href=\"" + escapeAttr(iiqUrl)
                    + "\" target=\"_blank\" rel=\"noopener noreferrer\">Request access via yo/iiq</a>";
        } else {
            heading = "Sign-in didn&#39;t complete";
            body = "Something went wrong while signing you in. You can try again, or reach out for help if "
                    + "the problem keeps happening.";
            primaryCta = "";
        }

        String safeError = escapeHtml(error);
        String safeDescription = escapeHtml(description);
        String safeState = escapeHtml(state);
        String safeChannel = escapeHtml(supportChannel);

        return "<!DOCTYPE html>\n"
                + "<html lang=\"en\"><head>\n"
                + "<meta charset=\"utf-8\">\n"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
                + "<title>MCP-on-Proxy - Sign-in error</title>\n"
                + "<style>\n"
                + "  :root { color-scheme: light dark; }\n"
                + "  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto,\n"
                + "         \"Helvetica Neue\", Arial, sans-serif; background: #f7f8fa; color: #1f2328;\n"
                + "         display: flex; align-items: center; justify-content: center; min-height: 100vh; }\n"
                + "  @media (prefers-color-scheme: dark) {\n"
                + "    body { background: #0d1117; color: #e6edf3; }\n"
                + "    .card { background: #161b22; border-color: #30363d; }\n"
                + "    .btn.primary { background: #2f81f7; }\n"
                + "    a { color: #58a6ff; }\n"
                + "    details { background: #0d1117; border-color: #30363d; }\n"
                + "  }\n"
                + "  .card { max-width: 520px; width: calc(100% - 32px); padding: 32px;\n"
                + "          background: #ffffff; border: 1px solid #d0d7de; border-radius: 12px;\n"
                + "          box-shadow: 0 1px 3px rgba(0,0,0,0.04); margin: 24px; }\n"
                + "  .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 20px; }\n"
                + "  .brand img { height: 28px; width: auto; display: block; }\n"
                + "  .brand-divider { color: #d0d7de; font-size: 18px; font-weight: 300; }\n"
                + "  .brand-product { font-size: 13px; color: #57606a; font-weight: 500; letter-spacing: 0.2px; }\n"
                + "  h1 { font-size: 22px; margin: 0 0 12px; font-weight: 600; }\n"
                + "  p  { font-size: 15px; line-height: 1.55; margin: 0 0 20px; }\n"
                + "  .actions { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin-bottom: 20px; }\n"
                + "  .btn { display: inline-block; padding: 10px 18px; border-radius: 8px; text-decoration: none;\n"
                + "         font-weight: 600; font-size: 14px; }\n"
                + "  .btn.primary { background: #0969da; color: #ffffff; }\n"
                + "  .btn.primary:hover { filter: brightness(1.05); }\n"
                + "  .help { font-size: 13px; color: #57606a; }\n"
                + "  details { margin-top: 16px; padding: 10px 12px; border: 1px solid #d0d7de; border-radius: 6px;\n"
                + "            background: #f6f8fa; font-size: 12px; }\n"
                + "  summary { cursor: pointer; color: #57606a; }\n"
                + "  dl { margin: 8px 0 0; display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; }\n"
                + "  dt { color: #57606a; }\n"
                + "  dd { margin: 0; word-break: break-word; }\n"
                + "</style>\n"
                + "</head><body>\n"
                + "<main class=\"card\" role=\"main\">\n"
                + "  <div class=\"brand\">\n"
                + "    <img src=\"https://s.yimg.com/cv/apiv2/yahooincsites/images/yahoo-logo.svg\" "
                + "alt=\"Yahoo\" width=\"88\" height=\"28\"/>\n"
                + "    <span class=\"brand-divider\">|</span>\n"
                + "    <span class=\"brand-product\">MCP OAuth Proxy</span>\n"
                + "  </div>\n"
                + "  <h1>" + heading + "</h1>\n"
                + "  <p>" + body + "</p>\n"
                + "  <div class=\"actions\">" + primaryCta + "</div>\n"
                + "  <p class=\"help\">Need help? Reach out on <strong>" + safeChannel + "</strong> on Slack.</p>\n"
                + "  <details>\n"
                + "    <summary>Technical details (share with support)</summary>\n"
                + "    <dl>\n"
                + "      <dt>Code</dt><dd>" + (safeError.isEmpty() ? "&mdash;" : safeError) + "</dd>\n"
                + "      <dt>Detail</dt><dd>" + (safeDescription.isEmpty() ? "&mdash;" : safeDescription) + "</dd>\n"
                + "      <dt>Reference</dt><dd>" + (safeState.isEmpty() ? "&mdash;" : safeState) + "</dd>\n"
                + "    </dl>\n"
                + "  </details>\n"
                + "</main>\n"
                + "</body></html>\n";
    }

    /**
     * HTML-escape every character that has special meaning in element text. Returns
     * an empty string for {@code null} so callers can concatenate without null guards.
     */
    static String escapeHtml(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(raw.length() + 16);
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Same escaping as {@link #escapeHtml(String)} but tuned for double-quoted attribute values:
     * identical output today, kept as a separate name so future changes (e.g. dropping &lt;/&gt;
     * escaping) are localized.
     */
    static String escapeAttr(String raw) {
        return escapeHtml(raw);
    }

    enum Bucket {
        NOT_ASSIGNED,
        GENERIC;

        String metricLabel() {
            return this == NOT_ASSIGNED ? "user_not_assigned" : "upstream_error";
        }
    }
}
