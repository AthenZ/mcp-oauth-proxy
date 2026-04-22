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

import io.athenz.mop.config.GrafanaTokenExchangeConfig;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.secret.K8SSecretsProvider;
import io.athenz.mop.util.JwtUtils;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Mints short-lived Grafana Cloud service-account tokens on behalf of a human user identified by
 * {@code short_id} in the upstream Okta {@code id_token}. Every mint uses a fresh, timestamp-suffixed
 * token name ({@code mcp.<short_id>.<unix_ts>}) so repeated mints for the same user never collide with
 * Grafana's {@code ErrTokenAlreadyExists}. Expired tokens are garbage-collected out-of-band by
 * {@link io.athenz.mop.token.sweeper.GrafanaTokenCleaner} running as a Kubernetes CronJob.
 */
@ApplicationScoped
public class TokenExchangeServiceGrafanaImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    static final String REMOTE_SERVER_KEY = "grafana";
    static final String DEFAULT_USERNAME_CLAIM = "short_id";

    @Inject
    GrafanaTokenExchangeConfig grafanaConfig;

    @Inject
    GrafanaManagementClient grafanaManagementClient;

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

    @Inject
    ConfigService configService;

    @Override
    public AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO) {
        throw new UnsupportedOperationException(
                "Grafana exchange uses getAccessTokenFromResourceAuthorizationServer");
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO) {
        TokenWrapper oktaWrap = tokenExchangeDO != null ? tokenExchangeDO.tokenWrapper() : null;
        if (oktaWrap == null || StringUtils.isBlank(oktaWrap.idToken())) {
            log.warn("Grafana exchange: missing Okta id_token");
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }

        String baseUrl = tokenExchangeDO.remoteServer();
        if (StringUtils.isBlank(baseUrl)) {
            baseUrl = configService.getRemoteServerEndpoint(REMOTE_SERVER_KEY);
        }
        if (StringUtils.isBlank(baseUrl)) {
            log.warn("Grafana exchange: missing remote server (Grafana base URL)");
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }

        String saId = configService.getRemoteServerServiceAccountId(REMOTE_SERVER_KEY);
        if (StringUtils.isBlank(saId)) {
            log.warn("Grafana exchange: missing service-account-id for remote server {}", REMOTE_SERVER_KEY);
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }

        String usernameClaim = StringUtils.defaultIfBlank(
                configService.getRemoteServerUsernameClaim(REMOTE_SERVER_KEY), DEFAULT_USERNAME_CLAIM);
        Object claimVal = JwtUtils.getClaimFromToken(oktaWrap.idToken(), usernameClaim);
        String shortId = StringUtils.trimToNull(claimVal != null ? claimVal.toString() : null);
        if (StringUtils.isBlank(shortId)) {
            log.warn("Grafana exchange: missing claim {} in id_token", usernameClaim);
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }

        Map<String, String> creds = k8SSecretsProvider.getCredentials(null);
        String adminBearer = creds != null ? creds.get(grafanaConfig.adminTokenSecretKey()) : null;
        if (StringUtils.isBlank(adminBearer)) {
            log.error("Grafana exchange: admin token not configured in credentials map under key {}",
                    grafanaConfig.adminTokenSecretKey());
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }

        String prefix = StringUtils.defaultIfBlank(grafanaConfig.tokenNamePrefix(), "mcp.");
        long ts = Instant.now().getEpochSecond();
        String tokenName = prefix + shortId + "." + ts;
        long secondsToLive = grafanaConfig.secondsToLive();

        String key = grafanaManagementClient.mintToken(baseUrl, saId, adminBearer, tokenName, secondsToLive);
        if (StringUtils.isBlank(key)) {
            log.warn("Grafana exchange: token mint failed for shortId={}", shortId);
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }

        log.info("Grafana exchange: token mint ok shortId={} tokenName={}", shortId, tokenName);

        TokenWrapper out = new TokenWrapper(null, null, null, key, null, secondsToLive);
        return new AuthorizationResultDO(AuthResult.AUTHORIZED, out);
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(
            TokenExchangeDO tokenExchangeDO) {
        throw new UnsupportedOperationException("Grafana exchange does not support client credentials");
    }

    @Override
    public TokenWrapper refreshWithUpstreamToken(String upstreamRefreshToken) {
        return null;
    }
}
