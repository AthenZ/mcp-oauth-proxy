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
import jakarta.enterprise.context.Dependent;
import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Token exchange for every Looker MCP instance. Looker instances are public PKCE clients
 * ({@code token_endpoint_auth_method=none}); access tokens last ~1 hour and the refresh token does
 * <strong>not</strong> rotate (the refresh response returns {@code refresh_token:null}).
 *
 * <p>One {@code @Dependent} bean is created per Looker instance by
 * {@link TokenExchangeServiceProducer} and tagged with {@link #setProviderLabel(String)}, mirroring
 * {@link TokenExchangeServiceGoogleWorkspaceBase}. The instances differ only by host and
 * {@code client_id}; the exchange/refresh behavior is identical.
 *
 * <p>With Looker promoted to the L2 model in
 * {@link UpstreamProviderClassifier#isUpstreamPromoted(String)}, the canonical refresh path is
 * {@code UpstreamRefreshService.refreshUpstream("looker-...", ...)} -&gt;
 * {@link LookerUpstreamRefreshClient}, which holds the per-{@code (provider, sub)} L2 lock and
 * carries forward the non-rotating RT. The {@link #refreshWithUpstreamToken(String)} method below
 * is the {@link TokenExchangeService} contract method only; for a promoted provider reaching it is
 * a routing bug, so it refuses loudly rather than issue a Looker call that bypasses the L2 lock.
 */
@Dependent
public class TokenExchangeServiceLookerImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(TokenExchangeServiceLookerImpl.class);

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
        // Looker is L2-promoted: the canonical refresh path is
        // UpstreamRefreshService.refreshUpstream(providerUserId, provider, clientId) ->
        // LookerUpstreamRefreshClient, which holds the per-(provider, sub) DDB-backed lock and
        // carries forward the non-rotating RT. The legacy single-arg path cannot know which Looker
        // instance (host / client_id) this RT belongs to, and bypassing the L2 lock would race
        // sibling refreshes, so we refuse loudly rather than issue a bogus upstream call.
        log.error("Direct Looker refresh path invoked for provider={}; this should be unreachable. "
                + "Promoted Looker instances must route through UpstreamRefreshService. Returning null.",
                getProviderLabel());
        return null;
    }
}
