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
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryProviderResolver;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shared token exchange logic for all Google Workspace services (Drive, Docs, Sheets, etc.).
 *
 * <p>The upstream Google refresh call has been factored out to
 * {@link GoogleWorkspaceUpstreamRefreshClient} and is invoked via
 * {@link UpstreamRefreshService#refreshUpstream(String, String, String)} so promoted providers
 * share the L2 lock and version-CAS write path. This class now only implements the
 * resource-side pass-through needed by {@code AuthorizerService.completeRefreshWithOktaTokens}.
 */
public abstract class TokenExchangeServiceGoogleWorkspaceBase implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(TokenExchangeServiceGoogleWorkspaceBase.class);

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    TelemetryProviderResolver telemetryProviderResolver;

    @Inject
    TelemetryRequestContext telemetryRequestContext;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    private String providerLabel;

    public void setProviderLabel(String providerLabel) {
        this.providerLabel = providerLabel;
    }

    public String getProviderLabel() {
        return providerLabel;
    }

    @Override
    public AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO) {
        long t0 = System.nanoTime();
        String oauthProvider = telemetryProviderResolver.fromResourceUri(tokenExchangeDO.resource());
        double seconds = (System.nanoTime() - t0) / 1_000_000_000.0;
        oauthProxyMetrics.recordExchangeStep(ExchangeStep.PASS_THROUGH, oauthProvider, true, null,
                telemetryRequestContext.oauthClient(), metricsRegionProvider.primaryRegion(), seconds);
        return new AuthorizationResultDO(AuthResult.AUTHORIZED, tokenExchangeDO.tokenWrapper());
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(TokenExchangeDO tokenExchangeDO) {
        throw new RuntimeException("Not implemented yet");
    }

    @Override
    public TokenWrapper refreshWithUpstreamToken(String upstreamRefreshToken) {
        // After Google Workspace providers were promoted to the L2 upstream-tokens table, the
        // refresh path goes through UpstreamRefreshService.refreshUpstream(providerUserId,
        // provider, clientId) which (a) holds the per-(provider, sub) DDB-backed lock so
        // concurrent refreshes from siblings don't race, (b) writes the rotated RT and staged
        // AT atomically with version-CAS, and (c) populates the per-client L0 cell so further
        // same-client calls hit Path B without re-acquiring the lock. The HTTP call itself now
        // lives in GoogleWorkspaceUpstreamRefreshClient.refresh.
        //
        // This method is retained for two reasons:
        //   1. The TokenExchangeService interface contract requires it.
        //   2. AuthorizerService.refreshUpstreamAndGetTokenLocked still has a legacy code path
        //      that calls TokenExchangeService.refreshWithUpstreamToken for native-IdP
        //      providers (slack/github/atlassian/embrace). Promoted-provider dispatch in
        //      TokenResource.handleRefreshTokenGrant short-circuits before reaching that path
        //      for any google-* provider.
        //
        // If we ever land here for a Google provider, it's a code-routing bug — refuse and
        // surface it loudly rather than silently issue a Google call that bypasses the L2
        // lock.
        log.error("Direct Google refresh path invoked for provider={}; this should be unreachable. "
                + "Promoted Google providers must route through UpstreamRefreshService. Returning null.",
                getProviderLabel());
        return null;
    }
}
