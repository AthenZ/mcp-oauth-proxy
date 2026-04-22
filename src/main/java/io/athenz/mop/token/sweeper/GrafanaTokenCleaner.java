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
package io.athenz.mop.token.sweeper;

import io.athenz.mop.config.GrafanaTokenExchangeConfig;
import io.athenz.mop.model.grafana.GrafanaTokenInfo;
import io.athenz.mop.secret.K8SSecretsProvider;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.GrafanaManagementClient;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Grafana-specific token garbage collector. Lists all service-account tokens via the Grafana
 * management API and deletes those where {@code hasExpired=true} or {@code isRevoked=true}. Per-token
 * failures are swallowed so one bad request doesn't abandon the entire run; they're counted in the
 * returned {@link CleanupResult#failed()} which drives the Job pod exit code.
 */
@ApplicationScoped
public class GrafanaTokenCleaner implements TokenCleaner {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    static final String REMOTE_SERVER_KEY = "grafana";

    @Inject
    GrafanaTokenExchangeConfig grafanaConfig;

    @Inject
    GrafanaManagementClient grafanaManagementClient;

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

    @Inject
    ConfigService configService;

    @Override
    public String providerId() {
        return REMOTE_SERVER_KEY;
    }

    @Override
    public CleanupResult cleanupOnce() {
        if (!grafanaConfig.cleanupEnabled()) {
            log.info("GrafanaTokenCleaner: cleanup-enabled=false, skipping");
            return CleanupResult.EMPTY;
        }

        String baseUrl = configService.getRemoteServerEndpoint(REMOTE_SERVER_KEY);
        if (StringUtils.isBlank(baseUrl)) {
            log.warn("GrafanaTokenCleaner: missing remote server endpoint for {}", REMOTE_SERVER_KEY);
            return CleanupResult.EMPTY;
        }

        String saId = configService.getRemoteServerServiceAccountId(REMOTE_SERVER_KEY);
        if (StringUtils.isBlank(saId)) {
            log.warn("GrafanaTokenCleaner: missing service-account-id for {}", REMOTE_SERVER_KEY);
            return CleanupResult.EMPTY;
        }

        Map<String, String> creds = k8SSecretsProvider.getCredentials(null);
        String adminBearer = creds != null ? creds.get(grafanaConfig.adminTokenSecretKey()) : null;
        if (StringUtils.isBlank(adminBearer)) {
            log.warn("GrafanaTokenCleaner: admin bearer not configured under key {}",
                    grafanaConfig.adminTokenSecretKey());
            return CleanupResult.EMPTY;
        }

        List<GrafanaTokenInfo> tokens = grafanaManagementClient.listTokens(baseUrl, saId, adminBearer);
        if (tokens == null || tokens.isEmpty()) {
            log.info("GrafanaTokenCleaner: no tokens returned by list");
            return CleanupResult.EMPTY;
        }

        int deleted = 0;
        int failed = 0;
        for (GrafanaTokenInfo t : tokens) {
            if (t == null) {
                continue;
            }
            if (!t.hasExpired() && !t.isRevoked()) {
                continue;
            }
            try {
                boolean ok = grafanaManagementClient.deleteToken(baseUrl, saId, adminBearer, t.id());
                if (ok) {
                    deleted++;
                } else {
                    failed++;
                    log.warn("GrafanaTokenCleaner: deleteToken returned false for id={} name={}",
                            t.id(), t.name());
                }
            } catch (RuntimeException e) {
                failed++;
                log.warn("GrafanaTokenCleaner: deleteToken threw for id={} name={}: {}",
                        t.id(), t.name(), e.getMessage());
            }
        }
        log.info("GrafanaTokenCleaner: cleanup done tokensScanned={} deleted={} failed={}",
                tokens.size(), deleted, failed);
        return new CleanupResult(deleted, failed);
    }
}
