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

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import io.athenz.mop.config.LookerConfig;
import io.athenz.mop.telemetry.UpstreamHttpCallLabels;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link UpstreamRefreshClient} shared by every Looker MCP instance (all L2 promoted).
 *
 * <p>Each Looker instance is its own provider id ({@code looker-ouryahoo}, {@code looker-enterprise},
 * ...). They differ only by host and {@code client_id}; the OAuth shape is identical, so a single
 * client serves all of them. The concrete instance is derived from the {@code provider#sub} prefix
 * of {@code providerUserId}: the token endpoint is {@code https://<host>/api/token} (host resolved
 * via {@link ConfigService#getRemoteServerEndpoint(String)}) and the {@code client_id} comes from
 * {@link LookerConfig}.
 *
 * <p>Looker is a <strong>public PKCE client</strong> ({@code token_endpoint_auth_method=none}): the
 * request body carries {@code client_id} only and there is NO {@code Authorization} header. Do NOT
 * introduce {@code ClientSecretBasic} / {@code ClientSecretPost} — Looker issues no client_secret
 * for these instances and any auth mechanism that requires one would silently break refresh.
 *
 * <p>Looker access tokens last ~1 hour ({@code expires_in=3599/3600}); when the upstream omits
 * {@code expires_in} we fall back to that documented constant. Refresh tokens do
 * <strong>not</strong> rotate — the refresh response returns {@code refresh_token:null}, so we
 * carry forward the prior RT verbatim and never null out the L2 row's
 * {@code encrypted_upstream_refresh_token} (same pattern Datadog uses).
 *
 * <p>Error contract follows {@link UpstreamRefreshClient}: {@code invalid_grant} -&gt;
 * {@link OktaTokenRevokedException}; everything else -&gt; {@link OktaTokenRefreshException}. Reusing
 * the Okta exception types keeps {@link UpstreamRefreshService}'s revoke-on-invalid-grant logic
 * provider-agnostic.
 */
@ApplicationScoped
public class LookerUpstreamRefreshClient implements UpstreamRefreshClient {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    /** Documented Looker access-token lifetime (~1 h); used only when the upstream omits {@code expires_in}. */
    static final long DEFAULT_EXPIRES_IN_SECONDS = 3_600L;

    @Inject
    ConfigService configService;

    @Inject
    LookerConfig lookerConfig;

    @Inject
    TokenClient tokenClient;

    @Override
    public UpstreamRefreshResponse refresh(String providerUserId, String upstreamRefreshToken) {
        if (upstreamRefreshToken == null || upstreamRefreshToken.isBlank()) {
            throw new OktaTokenRefreshException("Looker upstream refresh token is empty");
        }
        String provider = providerOf(providerUserId);
        if (!LookerInstances.isLooker(provider)) {
            throw new OktaTokenRefreshException(
                    "LookerUpstreamRefreshClient invoked for non-Looker provider: " + provider);
        }
        String clientId = lookerConfig.clientId(provider);
        if (clientId == null || clientId.isBlank()) {
            throw new OktaTokenRefreshException(
                    "Looker client_id not configured for provider=" + provider
                            + " (server.token-exchange.looker.client-ids." + provider + ")");
        }
        String tokenEndpoint = LookerInstances.tokenEndpoint(configService.getRemoteServerEndpoint(provider));
        if (tokenEndpoint == null) {
            throw new OktaTokenRefreshException(
                    "Looker token endpoint not configured for provider=" + provider
                            + " (server.token-exchange.remote-servers.endpoints[?name=" + provider + "].endpoint)");
        }
        String trimmedRt = upstreamRefreshToken.trim();
        try {
            AuthorizationGrant refreshGrant = new RefreshTokenGrant(new RefreshToken(trimmedRt));
            // Public PKCE client: TokenRequest(URI, ClientID, AuthorizationGrant, Scope) puts
            // client_id in the form body and sends NO Authorization header.
            TokenRequest tokenRequest = new TokenRequest(
                    URI.create(tokenEndpoint),
                    new ClientID(clientId.trim()),
                    refreshGrant,
                    /* scope */ null);
            TokenResponse tokenResponse;
            try (var ignored = UpstreamHttpCallLabels.withLabels(
                    provider, UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN)) {
                tokenResponse = tokenClient.execute(tokenRequest);
            }
            if (tokenResponse.indicatesSuccess()) {
                AccessTokenResponse success = tokenResponse.toSuccessResponse();
                String newAccessToken = success.getTokens().getAccessToken().getValue();
                RefreshToken newRefreshToken = success.getTokens().getRefreshToken();
                Long lifetime = success.getTokens().getAccessToken().getLifetime();
                long expiresIn = lifetime != null && lifetime > 0L ? lifetime : DEFAULT_EXPIRES_IN_SECONDS;
                // Looker does not rotate the RT (refresh response returns refresh_token:null) —
                // carry forward the prior RT when the response omits a new one so the L2 row's
                // encrypted_upstream_refresh_token is not nulled out.
                String rotatedRt = newRefreshToken != null ? newRefreshToken.getValue() : trimmedRt;
                Object scopeObj = success.getCustomParameters() != null
                        ? success.getCustomParameters().get("scope") : null;
                String scope = scopeObj != null ? scopeObj.toString() : null;
                return new UpstreamRefreshResponse(newAccessToken, rotatedRt, /* idToken */ null,
                        expiresIn, scope);
            }
            TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            String body = UpstreamTokenRefreshErrors.formatTokenError(errorResponse);
            log.error("Looker refresh failed for provider_user_id={} upstream response: {}",
                    providerUserId, body);
            String code = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getCode() : "unknown";
            String desc = errorResponse.getErrorObject() != null
                    ? errorResponse.getErrorObject().getDescription() : "unknown";
            if ("invalid_grant".equals(code)) {
                throw new OktaTokenRevokedException("Looker refresh token invalid or revoked: " + desc);
            }
            throw new OktaTokenRefreshException("Looker token refresh failed: " + code + " - " + desc);
        } catch (OktaTokenRevokedException | OktaTokenRefreshException e) {
            throw e;
        } catch (Exception e) {
            log.error("Looker refresh failed for provider_user_id={} (could not complete token request or parse upstream response)",
                    providerUserId, e);
            throw new OktaTokenRefreshException("Looker token refresh failed: " + e.getMessage(), e);
        }
    }

    /** Extract the {@code provider} prefix from a {@code provider#sub} key, or return as-is. */
    static String providerOf(String providerUserId) {
        if (providerUserId == null || providerUserId.isEmpty()) {
            return "";
        }
        int hash = providerUserId.indexOf('#');
        return hash < 0 ? providerUserId : providerUserId.substring(0, hash);
    }
}
