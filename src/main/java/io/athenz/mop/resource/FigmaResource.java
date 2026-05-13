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

import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import io.athenz.mop.model.AuthorizationCode;
import io.athenz.mop.service.AuthCodeRegionResolver;
import io.athenz.mop.service.AuthorizerService;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.FigmaCodeExchangeClient;
import io.athenz.mop.service.FigmaPkceStateCache;
import io.athenz.mop.service.FigmaUserInfoClient;
import io.athenz.mop.telemetry.AuthCodeValidationReason;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Custom Figma OAuth callback resource — a deliberate <em>non-Quarkus-OIDC</em> code flow.
 *
 * <p><b>Why this resource exists outside Quarkus OIDC.</b> Quarkus 3.30.6
 * {@code CodeAuthenticationMechanism.generateInternalIdToken} (called whenever the upstream
 * token response carries no {@code id_token}, which is true for Figma) HS256-signs the
 * synthetic internal ID token using {@code OidcCommonUtils.getClientOrJwtSecret(creds)} —
 * which returns the tenant's {@code client_secret} verbatim. jose4j enforces a 256-bit
 * (32-byte) minimum on HS256 keys, and Figma's currently-issued client secret for the MoP
 * OAuth app is 30 ASCII characters (240 bits), so the signing fails with
 * {@code "A key of the same size as the hash output ... MUST be used"} and the callback
 * returns 500. There is no Quarkus property to configure a separate signing key without also
 * rewriting how the upstream call is authenticated, and Figma rotation requires a multi-week
 * approval. So MoP performs the upstream code flow itself for the {@code figma} provider —
 * Quarkus OIDC is bypassed for this tenant only. Every other tenant (Slack, Embrace, Google
 * Workspace, Okta, etc.) is unaffected.
 *
 * <p><b>Flow</b>
 * <ol>
 *   <li>{@code GET /figma/authorize?state=<mopAuthCode>} — entry point. The {@code state}
 *       value is the MoP authorization code that {@link AuthorizeResource} minted before
 *       redirecting here. We generate a fresh PKCE {@code code_verifier} and an unguessable
 *       upstream {@code state}, persist {@code (upstreamState -> {verifier, mopAuthCode})}
 *       in the per-pod {@link FigmaPkceStateCache}, and 302 the browser to
 *       {@code https://www.figma.com/oauth/mcp?...}.</li>
 *   <li>{@code GET /figma/authorize/callback?code=...&state=<upstreamState>} — Figma's
 *       redirect lands here. We atomically pop the cache entry, exchange the code via
 *       {@link FigmaCodeExchangeClient}, fetch {@code /v1/me} via {@link FigmaUserInfoClient}
 *       to resolve the user's email, then call
 *       {@link AuthorizerService#storeTokens(String, String, String, String, String, String, String, Long)}
 *       with the documented 90-day Figma access-token lifetime so the L1 row in
 *       {@code mcp-oauth-proxy-tokens} TTLs to {@code now + 90d + 5m} instead of the global
 *       {@code server.token-store.expiry} cap. Finally we 302 back to the original MCP
 *       client's redirect URI with the MoP authorization code.</li>
 * </ol>
 *
 * <p><b>Reverting to stock Quarkus OIDC.</b> When Figma issues a client secret with
 * {@literal >=} 32 chars, this entire resource and the {@link FigmaPkceStateCache},
 * {@link FigmaCodeExchangeClient}, and {@link FigmaUserInfoClient} helpers can be deleted, the
 * {@code quarkus.oidc.figma} tenant restored to its Slack-style shape, and the {@code figma}
 * HTTP-permission policy flipped back to {@code authenticated}. The {@code FigmaResource}
 * shape would then mirror {@code SlackResource} again.
 */
@Path("/figma")
public class FigmaResource extends BaseResource {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    static final String PROVIDER = "figma";
    /**
     * Documented Figma access-token lifetime (90 days). Pinned here so the L1 row in
     * {@code mcp-oauth-proxy-tokens} is written with TTL = now + 90d + 5m at fresh consent;
     * subsequent refreshes recompute the TTL from the actual {@code expires_in} returned by
     * Figma at refresh time.
     */
    static final long FIGMA_ACCESS_TOKEN_LIFETIME_SECONDS = 7_776_000L;

    private static final String FIGMA_AUTHORIZE_URI = "https://www.figma.com/oauth/mcp";
    private static final String SCOPES = "mcp:connect current_user:read";
    private static final SecureRandom RNG = new SecureRandom();

    @ConfigProperty(name = "server.figma.client-id", defaultValue = "")
    String clientId;

    /**
     * Public-facing redirect URI for the {@code /figma/authorize/callback} endpoint. This
     * MUST exactly match one of the values registered with Figma's OAuth app — Figma rejects
     * the code exchange if the redirect URI on {@code /token} does not byte-equal the one on
     * {@code /authorize}. Currently registered values:
     * <ul>
     *   <li>{@code https://local.sample-token-service.experiments.athenz.ouryahoo.com/figma/authorize/callback} (local dev)</li>
     *   <li>{@code https://stage.mop.athenz.ouryahoo.com/figma/authorize/callback} (stage)</li>
     *   <li>{@code https://mop.athenz.ouryahoo.com/figma/authorize/callback} (prod)</li>
     * </ul>
     * Intentionally has no default — an unset value triggers a loud 500 from {@link #authorize}
     * rather than silently 302'ing the user to a URL Figma will reject.
     */
    @ConfigProperty(name = "server.figma.callback-redirect-uri", defaultValue = "")
    String callbackRedirectUri;

    @Inject
    AuthorizerService authorizerService;

    @Inject
    AuthCodeRegionResolver authCodeRegionResolver;

    @ConfigProperty(name = "server.token-exchange.idp")
    String providerDefault;

    @Inject
    ConfigService configService;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    TelemetryRequestContext telemetryRequestContext;

    @Inject
    FigmaPkceStateCache pkceStateCache;

    @Inject
    FigmaCodeExchangeClient codeExchangeClient;

    @Inject
    FigmaUserInfoClient userInfoClient;

    /**
     * Step 1: receive the MoP-orchestrated redirect from {@link AuthorizeResource}, mint a
     * PKCE verifier + upstream state, and 302 the browser to Figma's authorize endpoint.
     */
    @GET
    @Path("/authorize")
    @Produces(MediaType.TEXT_HTML)
    public Response authorize(@QueryParam("state") String mopAuthCode) {
        telemetryRequestContext.setOauthProvider(OauthProviderLabel.FIGMA);
        if (mopAuthCode == null || mopAuthCode.isEmpty()) {
            log.warn("Figma /authorize called without state (the MoP auth code)");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "invalid_request",
                            "error_description", "Missing state parameter"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        if (clientId == null || clientId.isEmpty()) {
            log.error("Figma /authorize: clientId not configured (server.figma.client-id)");
            return Response.serverError()
                    .entity(Map.of(
                            "error", "server_error",
                            "error_description", "Figma client_id not configured"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        if (callbackRedirectUri == null || callbackRedirectUri.isEmpty()) {
            log.error("Figma /authorize: callback redirect URI not configured (server.figma.callback-redirect-uri)");
            return Response.serverError()
                    .entity(Map.of(
                            "error", "server_error",
                            "error_description", "Figma callback redirect URI not configured"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        // Fresh PKCE pair per flow (Nimbus default = 43-char base64url random).
        CodeVerifier codeVerifier = new CodeVerifier();
        CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);
        // Unguessable upstream state: 32 random bytes (256-bit) base64url-encoded → 43 chars.
        String upstreamState = newRandomState();
        pkceStateCache.put(upstreamState, codeVerifier.getValue(), mopAuthCode);

        String url = FIGMA_AUTHORIZE_URI
                + "?response_type=code"
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&redirect_uri=" + URLEncoder.encode(callbackRedirectUri, StandardCharsets.UTF_8)
                + "&scope=" + URLEncoder.encode(SCOPES, StandardCharsets.UTF_8)
                + "&state=" + URLEncoder.encode(upstreamState, StandardCharsets.UTF_8)
                + "&code_challenge=" + URLEncoder.encode(codeChallenge.getValue(), StandardCharsets.UTF_8)
                + "&code_challenge_method=S256";
        log.info("Figma /authorize redirecting to upstream (state masked) for mop_auth_code masked");
        return Response.seeOther(URI.create(url)).build();
    }

    /**
     * Step 2: handle the redirect back from Figma, exchange the code for tokens, fetch the
     * user's email, persist via {@link AuthorizerService}, and 302 back to the original MCP
     * client's redirect URI with the MoP authorization code.
     */
    @GET
    @Path("/authorize/callback")
    @Produces(MediaType.TEXT_HTML)
    public Response callback(
            @QueryParam("code") String code,
            @QueryParam("state") String upstreamState,
            @QueryParam("error") String upstreamError,
            @QueryParam("error_description") String upstreamErrorDescription) {
        telemetryRequestContext.setOauthProvider(OauthProviderLabel.FIGMA);
        if (upstreamError != null && !upstreamError.isEmpty()) {
            log.warn("Figma callback: upstream returned error={} description={}",
                    upstreamError, upstreamErrorDescription);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", upstreamError,
                            "error_description",
                            upstreamErrorDescription != null ? upstreamErrorDescription : ""))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        if (code == null || code.isEmpty() || upstreamState == null || upstreamState.isEmpty()) {
            log.warn("Figma callback: missing code or state");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "invalid_request",
                            "error_description", "Missing code or state parameter"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        Optional<FigmaPkceStateCache.Entry> entryOpt = pkceStateCache.pop(upstreamState);
        if (entryOpt.isEmpty()) {
            log.warn("Figma callback: no PKCE state entry for upstream state (expired, replayed, or never minted)");
            // Treat as auth-code-style validation failure for telemetry continuity with stock tenants.
            oauthProxyMetrics.recordAuthCodeValidationFailure(
                    OauthProviderLabel.FIGMA, AuthCodeValidationReason.NOT_FOUND);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "invalid_grant",
                            "error_description", "PKCE state not found, expired, or replayed"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        FigmaPkceStateCache.Entry entry = entryOpt.get();
        AuthorizationCode authorizationCode = authCodeRegionResolver
                .resolve(entry.mopAuthCode(), providerDefault).authorizationCode();
        if (authorizationCode == null) {
            log.warn("Figma callback: MoP authorization code not found for popped state");
            oauthProxyMetrics.recordAuthCodeValidationFailure(
                    OauthProviderLabel.FIGMA, AuthCodeValidationReason.NOT_FOUND);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            "error", "invalid_grant",
                            "error_description", "Authorization code not found or expired"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        FigmaCodeExchangeClient.FigmaTokens tokens;
        try {
            tokens = codeExchangeClient.exchange(code, callbackRedirectUri, entry.codeVerifier());
        } catch (FigmaCodeExchangeClient.FigmaCodeExchangeException e) {
            log.error("Figma callback: code exchange failed: {}", e.getMessage());
            return Response.serverError()
                    .entity(Map.of(
                            "error", "server_error",
                            "error_description", "Figma authorization-code exchange failed"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        FigmaUserInfoClient.FigmaUser figmaUser;
        try {
            figmaUser = userInfoClient.fetchMe(tokens.accessToken());
        } catch (FigmaUserInfoClient.FigmaUserInfoException e) {
            log.error("Figma callback: /v1/me lookup failed: {}", e.getMessage());
            return Response.serverError()
                    .entity(Map.of(
                            "error", "server_error",
                            "error_description", "Figma /v1/me lookup failed"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        String usernameClaim = configService.getRemoteServerUsernameClaim(PROVIDER);
        String lookupKey = lookupKeyFor(figmaUser, usernameClaim);
        if (lookupKey == null || lookupKey.isEmpty()) {
            log.error("Figma callback: could not derive lookup key from /v1/me (claim={})", usernameClaim);
            return Response.serverError()
                    .entity(Map.of(
                            "error", "server_error",
                            "error_description", "Figma user has no usable identity claim"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        log.info("Figma callback: storing tokens for user: {}", lookupKey);

        authorizerService.storeTokens(
                lookupKey,
                authorizationCode.getSubject(),
                tokens.accessToken(),
                tokens.accessToken(),
                tokens.refreshToken(),
                PROVIDER,
                authorizationCode.getClientId(),
                FIGMA_ACCESS_TOKEN_LIFETIME_SECONDS);

        return buildSuccessRedirect(
                authorizationCode.getRedirectUri(),
                entry.mopAuthCode(),
                authorizationCode.getState());
    }

    /**
     * Resolves the MoP {@code lookupKey} from the Figma user, applying the same
     * {@code @domain}-stripping convention as {@link BaseResource#getUsername} when the
     * configured username claim is email-like.
     */
    static String lookupKeyFor(FigmaUserInfoClient.FigmaUser user, String usernameClaim) {
        if (user == null) {
            return null;
        }
        String value;
        if (usernameClaim != null && usernameClaim.contains("email")) {
            value = user.email();
        } else if ("handle".equals(usernameClaim)) {
            value = user.handle();
        } else {
            // Default to id (matches the Figma userinfo response shape).
            value = user.id();
        }
        if (value != null && usernameClaim != null && usernameClaim.contains("email")
                && value.contains("@")) {
            value = value.substring(0, value.indexOf('@'));
        }
        return value;
    }

    /** 32-byte (256-bit) base64url random; ~43 chars. Suitable for {@code state} CSRF tokens. */
    private static String newRandomState() {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
