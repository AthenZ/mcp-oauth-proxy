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

import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.telemetry.ExchangeStep;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import io.athenz.mop.util.JwtUtils;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Token "exchange" for the Yahoo OS MCP: there is no exchange at all. Unlike Glean
 * (Okta access_token -> Okta AS token exchange) or Evaluate (Okta id_token -> Athenz id_token
 * via ZTS), the Yahoo OS MCP server accepts the raw Okta OIDC id_token as its bearer. This impl
 * simply surfaces the Okta {@code id_token} as {@link TokenWrapper#accessToken} so the standard
 * token-response / {@code /userinfo} / refresh plumbing in {@link AuthorizerService} works
 * unchanged.
 *
 * <p>Yahoo OS is Okta-rooted and has no upstream refresh token of its own: refresh is performed
 * via the shared Okta path (the single L2 {@code okta#<sub>} row under
 * {@link UpstreamRefreshService}), exactly like Glean and Evaluate. Accordingly
 * {@link #refreshWithUpstreamToken(String)} returns {@code null} and the provider is intentionally
 * NOT registered in {@link UpstreamProviderClassifier}.
 */
@ApplicationScoped
public class TokenExchangeServiceYahooOsImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    /** Fallback bearer TTL (seconds) when the Okta id_token carries no usable {@code exp} claim. */
    static final long DEFAULT_TTL_SECONDS = 3600L;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    TelemetryRequestContext telemetryRequestContext;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    @Override
    public AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO) {
        throw new UnsupportedOperationException(
                "Yahoo OS exchange uses getAccessTokenFromResourceAuthorizationServer");
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO) {
        String oauthProvider = OauthProviderLabel.YAHOO_OS;
        String oauthClient = telemetryRequestContext.oauthClient();
        String region = metricsRegionProvider.primaryRegion();
        long t0 = System.nanoTime();

        TokenWrapper oktaToken = tokenExchangeDO != null ? tokenExchangeDO.tokenWrapper() : null;
        if (oktaToken == null || StringUtils.isBlank(oktaToken.idToken())) {
            log.warn("Yahoo OS exchange: missing Okta id_token");
            recordStep(oauthProvider, oauthClient, region, t0, false);
            return AuthorizationResultDO.unauthorized("Yahoo OS exchange: missing Okta id_token");
        }

        String idToken = oktaToken.idToken();
        long ttl = ttlFromIdToken(idToken);

        // Surface the Okta id_token as TokenWrapper.accessToken so AuthorizerService returns it to
        // the MCP client as the bearer access_token, and the store-by-audience path in
        // AuthorizerService#storeExchangedTokenByAudienceIfNeeded keys /userinfo off it.
        TokenWrapper out = new TokenWrapper(
                oktaToken.key(),
                tokenExchangeDO.remoteServer(),
                null,
                idToken,
                null,
                ttl);

        recordStep(oauthProvider, oauthClient, region, t0, true);
        return new AuthorizationResultDO(AuthResult.AUTHORIZED, out);
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(
            TokenExchangeDO tokenExchangeDO) {
        throw new UnsupportedOperationException("Yahoo OS exchange does not support client credentials");
    }

    @Override
    public TokenWrapper refreshWithUpstreamToken(String upstreamRefreshToken) {
        // Upstream is Okta; refresh is performed by the shared Okta refresh path (same as
        // Glean / Evaluate / GCP providers).
        return null;
    }

    /**
     * Relative TTL (seconds) derived from the id_token {@code exp} claim, floored at 0 and
     * falling back to {@link #DEFAULT_TTL_SECONDS} when the claim is absent or unparseable.
     */
    private static long ttlFromIdToken(String idToken) {
        Object exp = JwtUtils.getClaimFromToken(idToken, "exp");
        Long expEpoch = toEpochSeconds(exp);
        if (expEpoch == null) {
            return DEFAULT_TTL_SECONDS;
        }
        long remaining = expEpoch - Instant.now().getEpochSecond();
        return Math.max(remaining, 0L);
    }

    private static Long toEpochSeconds(Object exp) {
        if (exp instanceof java.util.Date date) {
            return date.toInstant().getEpochSecond();
        }
        if (exp instanceof Number number) {
            return number.longValue();
        }
        if (exp instanceof String s && StringUtils.isNotBlank(s)) {
            try {
                return Long.parseLong(s.trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private void recordStep(String oauthProvider, String oauthClient, String region,
                            long startNanos, boolean success) {
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        oauthProxyMetrics.recordExchangeStep(ExchangeStep.YAHOO_OS_ID_TOKEN, oauthProvider, success,
                success ? null : "unauthorized", oauthClient, region, seconds);
    }
}
