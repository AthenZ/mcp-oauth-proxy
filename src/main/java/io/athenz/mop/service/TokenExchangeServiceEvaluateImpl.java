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

import io.athenz.mop.config.EvaluateTokenExchangeConfig;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.RequestedZtsTokenType;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.telemetry.ExchangeStep;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Token exchange for the Evaluate MCP: Okta id_token -> Athenz id_token via ZTS
 * ({@link TokenExchangeServiceZTSImpl#getAccessTokenFromResourceAuthorizationServer} with
 * {@code requestedZtsTokenType = ID_TOKEN}). Unlike the GCP Monitoring/Logging flow there is no
 * downstream STS step: the Athenz id_token is returned to the MCP client directly in
 * {@link TokenWrapper#accessToken} so the standard token-response / {@code /userinfo} / refresh
 * plumbing in {@link AuthorizerService} works unchanged.
 */
@ApplicationScoped
public class TokenExchangeServiceEvaluateImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    TokenExchangeServiceProducer tokenExchangeServiceProducer;

    @Inject
    EvaluateTokenExchangeConfig evaluateTokenExchangeConfig;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    TelemetryRequestContext telemetryRequestContext;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    @Override
    public AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO) {
        throw new UnsupportedOperationException(
                "Evaluate exchange uses getAccessTokenFromResourceAuthorizationServer");
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO) {
        TokenWrapper oktaToken = tokenExchangeDO != null ? tokenExchangeDO.tokenWrapper() : null;
        if (oktaToken == null || StringUtils.isBlank(oktaToken.idToken())) {
            log.warn("Evaluate exchange: missing Okta id_token");
            return AuthorizationResultDO.unauthorized("Evaluate exchange: missing Okta id_token");
        }

        String audience = evaluateTokenExchangeConfig.audience();
        List<String> scopes = evaluateTokenExchangeConfig.scopes();
        if (StringUtils.isBlank(audience) || scopes == null || scopes.isEmpty()) {
            log.error("Evaluate exchange: missing audience or scopes config");
            return AuthorizationResultDO.unauthorized("Evaluate exchange: missing audience or scopes config");
        }

        String resource = tokenExchangeDO.resource();
        String oauthProvider = OauthProviderLabel.EVALUATE;
        String oauthClient = telemetryRequestContext.oauthClient();
        String region = metricsRegionProvider.primaryRegion();

        // Delegate to the ZTS id-token exchange. We pass audience via TokenExchangeDO.namespace
        // so TokenExchangeServiceZTSImpl.getAthenzIdTokenViaZts uses it (falling back to the
        // global athenz audience only when blank, which preserves the GCP flow).
        TokenExchangeDO athenzRequest = new TokenExchangeDO(
                scopes,
                resource,
                audience,
                tokenExchangeDO.remoteServer(),
                oktaToken,
                RequestedZtsTokenType.ID_TOKEN);

        TokenExchangeService athenzExchange =
                tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("athenz");

        long t0 = System.nanoTime();
        AuthorizationResultDO athenzResult;
        try {
            athenzResult = athenzExchange.getAccessTokenFromResourceAuthorizationServer(athenzRequest);
        } catch (RuntimeException e) {
            recordEvaluateStep(oauthProvider, oauthClient, region, t0, false);
            throw e;
        }

        boolean athenzOk = athenzResult != null
                && athenzResult.token() != null
                && athenzResult.authResult() == AuthResult.AUTHORIZED;
        if (!athenzOk) {
            log.warn("Evaluate exchange: Athenz id-token exchange failed");
            recordEvaluateStep(oauthProvider, oauthClient, region, t0, false);
            String upstream = athenzResult != null ? athenzResult.errorMessage() : null;
            return AuthorizationResultDO.unauthorized(
                    "Evaluate exchange: Athenz id-token exchange failed"
                            + (upstream != null ? " (" + upstream + ")" : ""));
        }

        String athenzIdToken = athenzResult.token().idToken();
        if (StringUtils.isBlank(athenzIdToken)) {
            log.warn("Evaluate exchange: Athenz id-token exchange returned no id_token");
            recordEvaluateStep(oauthProvider, oauthClient, region, t0, false);
            return AuthorizationResultDO.unauthorized("Evaluate exchange: Athenz id-token exchange returned no id_token");
        }

        recordEvaluateStep(oauthProvider, oauthClient, region, t0, true);

        // Surface the Athenz id_token as TokenWrapper.accessToken so AuthorizerService returns it
        // to the MCP client as the bearer access_token, and the store-by-audience path in
        // AuthorizerService#storeExchangedTokenByAudienceIfNeeded keys /userinfo off it.
        TokenWrapper out = new TokenWrapper(
                oktaToken.key(),
                tokenExchangeDO.remoteServer(),
                null,
                athenzIdToken,
                null,
                athenzResult.token().ttl());
        return new AuthorizationResultDO(AuthResult.AUTHORIZED, out);
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(
            TokenExchangeDO tokenExchangeDO) {
        throw new UnsupportedOperationException("Evaluate exchange does not support client credentials");
    }

    @Override
    public TokenWrapper refreshWithUpstreamToken(String upstreamRefreshToken) {
        // Upstream is Okta; refresh is performed by the Okta token-exchange service (same as
        // Grafana / Splunk / GCP providers).
        return null;
    }

    private void recordEvaluateStep(String oauthProvider, String oauthClient, String region,
                                    long startNanos, boolean success) {
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        oauthProxyMetrics.recordExchangeStep(ExchangeStep.EVALUATE_ATHENZ_ID_TOKEN, oauthProvider, success,
                success ? null : "unauthorized", oauthClient, region, seconds);
    }
}
