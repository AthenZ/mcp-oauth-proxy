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

import io.athenz.mop.model.AuthorizationCode;
import io.athenz.mop.service.AuthCodeRegionResolver;
import io.athenz.mop.service.AuthorizerService;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.RefreshTokenService;
import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.oidc.OidcSession;
import io.quarkus.oidc.UserInfo;
import io.quarkus.security.Authenticated;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Unified OAuth callback handler for all Google Workspace services.
 * The provider name is extracted from the URL path via {@code @PathParam}.
 */
@Path("/{provider: google-(?:drive|docs|sheets|slides|gmail|calendar|tasks|chat|forms|keep|meet|cloud-platform)}/authorize")
public class GoogleWorkspaceResource extends BaseResource {

    private static final Logger log = LoggerFactory.getLogger(GoogleWorkspaceResource.class);

    @Inject
    AuthorizerService authorizerService;

    @Inject
    AccessTokenCredential accessTokenCredential;

    @Inject
    AuthCodeRegionResolver authCodeRegionResolver;

    @Inject
    UserInfo userInfo;

    @ConfigProperty(name = "server.token-exchange.idp")
    String providerDefault;

    @Inject
    OidcSession oidcSession;

    @Inject
    ConfigService configService;

    @Inject
    RefreshTokenService refreshTokenService;

    @PathParam("provider")
    String provider;

    @GET
    @Authenticated
    @Produces(MediaType.TEXT_HTML)
    public Response authorize(@QueryParam("state") String state) {
        if (state == null || state.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of(
                    "error", "invalid_request",
                    "error_description", "Missing state parameter"))
                .type(MediaType.APPLICATION_JSON)
                .build();
        }
        log.info("{} request to store tokens for user: {}", provider, userInfo.getEmail());
        AuthorizationCode authorizationCode = authCodeRegionResolver.resolve(state, providerDefault).authorizationCode();
        if (authorizationCode == null) {
            log.warn("{} callback: authorization code not found for state (local or cross-region)", provider);
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of(
                    "error", "invalid_grant",
                    "error_description", "Authorization code not found or expired"))
                .type(MediaType.APPLICATION_JSON)
                .build();
        }

        String lookupKey = getUsername(userInfo, configService.getRemoteServerUsernameClaim(provider), null);
        String newAccessToken = accessTokenCredential.getToken();
        String newIdToken = accessTokenCredential.getToken();
        String newRefreshToken = (accessTokenCredential.getRefreshToken() != null)
            ? accessTokenCredential.getRefreshToken().getToken()
            : null;

        // For Google Workspace, Google only returns a refresh_token on the very first consent for a
        // given (client_id, account) pair. When the same Yahoo user later connects this same product
        // (e.g. google-docs) from a *different* MCP client (Cursor vs Claude vs Codex), Google still
        // shows the consent screen but does not mint a new refresh_token. We therefore look up any
        // existing upstream Google refresh for this (provider, user) ignoring client_id, and reuse it
        // for the new client's row. The /token step downstream also performs this same inheritance
        // (TokenResource.handleAuthorizationCodeGrant) when persisting the per-client MoP refresh row.
        String existingUpstreamRefresh = lookupExistingUpstreamRefresh(authorizationCode.getSubject(), lookupKey, provider);

        String refreshTokenToStore;
        if (newRefreshToken != null) {
            refreshTokenToStore = newRefreshToken;
            log.info("{}: Using new refresh token from authorization response", provider);
        } else if (existingUpstreamRefresh != null) {
            refreshTokenToStore = existingUpstreamRefresh;
            log.info("{}: Refresh token not in response, inheriting existing upstream refresh token "
                + "from sibling row for (provider, user) ignoring client_id", provider);
        } else {
            // Truly first time for this (provider, user) AND Google did not mint a refresh_token.
            // This usually means the user previously granted offline access to this Google client_id
            // outside of MoP (or revoked MoP at myaccount.google.com/permissions and the previous
            // upstream refresh got dropped). Render a friendly reconnect page instead of a bare 500.
            log.warn("{}: No refresh token received and none found in storage for subject={} lookupKey={}. "
                + "Rendering reconnect page so the user can re-authorize.",
                provider, authorizationCode.getSubject(), lookupKey);
            logoutFromProvider(provider, oidcSession);
            return buildReconnectPage(provider, state, authorizationCode);
        }
        authorizerService.storeTokens(
            lookupKey,
            authorizationCode.getSubject(),
            newIdToken,
            newAccessToken,
            refreshTokenToStore,
            provider,
            authorizationCode.getClientId());

        logoutFromProvider(provider, oidcSession);
        return buildSuccessRedirect(authorizationCode.getRedirectUri(), state, authorizationCode.getState());
    }

    private String lookupExistingUpstreamRefresh(String subject, String lookupKey, String provider) {
        String value = refreshTokenService.getUpstreamRefreshToken(subject, provider);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        // Defensive secondary lookup: some legacy rows may have been written keyed by lookupKey
        // (email-localpart) rather than the OAuth subject. Try that too before giving up.
        if (lookupKey != null && !lookupKey.equals(subject)) {
            value = refreshTokenService.getUpstreamRefreshToken(lookupKey, provider);
            if (value != null && !value.isEmpty()) {
                log.info("{}: Inherited upstream refresh via lookupKey fallback (subject={}, lookupKey={})",
                    provider, subject, lookupKey);
                return value;
            }
        }
        return null;
    }

    private Response buildReconnectPage(String provider, String state, AuthorizationCode authorizationCode) {
        // Reconnect-only retry URL: just bouncing back through Quarkus OIDC's @Authenticated path
        // sends Google `prompt=none`, so Google silently re-uses the existing consent and again
        // omits `refresh_token` -- looping the user right back here. The only reliable way out is
        // to have the user revoke the OAuth client at Google first, which clears Google-side
        // consent so the next /authorize round trip triggers a true fresh consent + refresh_token.
        // We make "Revoke at Google" the primary CTA and provide the retry only as the explicit
        // step 2 the user takes after revoking.
        String reconnectUrl = "/" + provider + "/authorize?state="
            + java.net.URLEncoder.encode(state, java.nio.charset.StandardCharsets.UTF_8);
        String revokeUrl = "https://myaccount.google.com/permissions";
        String body = "<!DOCTYPE html>\n"
            + "<html lang=\"en\"><head><meta charset=\"utf-8\"/>"
            + "<title>Reconnect Google Workspace</title>"
            + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/>"
            + "<style>"
            + "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
            + "max-width:560px;margin:48px auto;padding:0 24px;color:#202124;line-height:1.5}"
            + "h1{font-size:22px;margin-bottom:8px}"
            + "h2{font-size:16px;margin-top:28px;margin-bottom:6px;color:#202124}"
            + "p{font-size:15px;margin:8px 0}"
            + ".btn{display:inline-block;background:#1a73e8;color:#fff;padding:10px 20px;"
            + "border-radius:6px;text-decoration:none;font-weight:500;margin-top:8px}"
            + ".btn:hover{background:#1765cc}"
            + ".btn-secondary{background:#fff;color:#1a73e8;border:1px solid #1a73e8}"
            + ".btn-secondary:hover{background:#e8f0fe}"
            + ".muted{color:#5f6368;font-size:13px;margin-top:24px}"
            + "code{background:#f1f3f4;padding:1px 6px;border-radius:4px;font-size:13px}"
            + ".step{color:#5f6368;font-size:13px;text-transform:uppercase;letter-spacing:0.5px;"
            + "margin-top:24px;margin-bottom:0}"
            + ".brand{display:flex;align-items:center;gap:10px;margin-bottom:24px}"
            + ".brand img{height:32px;width:auto;display:block}"
            + ".brand-divider{color:#dadce0;font-size:18px;font-weight:300}"
            + ".brand-product{font-size:14px;color:#5f6368;font-weight:500;letter-spacing:0.2px}"
            + "</style></head><body>"
            + "<div class=\"brand\">"
            + "<img src=\"https://s.yimg.com/cv/apiv2/yahooincsites/images/yahoo-logo.svg\" "
            + "alt=\"Yahoo\" width=\"100\" height=\"32\"/>"
            + "<span class=\"brand-divider\">|</span>"
            + "<span class=\"brand-product\">MCP OAuth Proxy</span>"
            + "</div>"
            + "<h1>Reconnect your Google account</h1>"
            + "<p>We could not finish connecting <code>" + escapeHtml(provider) + "</code> "
            + "because Google did not return a refresh token for this session, and we do not have "
            + "one saved for your account.</p>"
            + "<p>This usually happens when your previous authorization for the MoP OAuth proxy "
            + "was revoked or expired (for example, after revoking access in your Google account "
            + "settings, after a long period of inactivity, or after a Workspace admin policy "
            + "change). Simply retrying will keep failing because Google still treats this app as "
            + "already consented and silently skips issuing a new refresh token.</p>"

            + "<p class=\"step\">Step 1</p>"
            + "<h2>Revoke this app at Google</h2>"
            + "<p>Find <strong>MoP OAuth Proxy</strong> (or the equivalent app name in your "
            + "Google account) in the list and click <strong>Remove access</strong>.</p>"
            + "<p><a class=\"btn\" href=\"" + revokeUrl + "\" target=\"_blank\" rel=\"noopener\">"
            + "Open Google Account permissions</a></p>"

            + "<p class=\"step\">Step 2</p>"
            + "<h2>Retry connecting</h2>"
            + "<p>After you have revoked access in Google, click below to start a fresh "
            + "consent flow.</p>"
            + "<p><a class=\"btn btn-secondary\" href=\"" + escapeHtml(reconnectUrl) + "\">"
            + "Retry " + escapeHtml(provider) + "</a></p>"

            + "<p class=\"muted\">If retrying still loops you back here, your Google session "
            + "may be cached in your browser. Open the retry link in a new private/incognito "
            + "window after revoking.</p>"
            + "</body></html>";
        return Response.status(Response.Status.OK)
            .type(MediaType.TEXT_HTML)
            .entity(body)
            .build();
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("\"", "&quot;").replace("'", "&#39;");
    }
}
