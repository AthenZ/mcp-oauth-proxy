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

import io.athenz.mop.config.SplunkTokenExchangeConfig;
import io.athenz.mop.secret.K8SSecretsProvider;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.SplunkManagementClient;
import io.athenz.mop.service.SplunkManagementClient.SplunkExpiredToken;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Splunk-specific token garbage collector. Lists all authorization tokens via the Splunk management
 * API ({@code GET /services/authorization/tokens?count=0}) and deletes those whose
 * {@code claims.sub} starts with the configured mirror-user prefix and whose {@code claims.exp} is
 * already past. Mirrors {@link GrafanaTokenCleaner}: per-token failures are swallowed so one bad
 * delete doesn't abandon the whole run, but they are logged with the offending token id and
 * counted in {@link CleanupResult#failed()} which drives the Job pod exit code.
 */
@ApplicationScoped
public class SplunkTokenCleaner implements TokenCleaner {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    static final String REMOTE_SERVER_KEY = "splunk";

    @Inject
    SplunkTokenExchangeConfig splunkConfig;

    @Inject
    SplunkManagementClient splunkManagementClient;

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

    @Inject
    ConfigService configService;

    /** Indirection for tests; production uses the system UTC clock. */
    Clock clock = Clock.systemUTC();

    @Override
    public String providerId() {
        return REMOTE_SERVER_KEY;
    }

    @Override
    public CleanupResult cleanupOnce() {
        if (!splunkConfig.cleanupEnabled()) {
            log.info("SplunkTokenCleaner: cleanup-enabled=false, skipping");
            return CleanupResult.EMPTY;
        }

        String baseUrl = configService.getRemoteServerEndpoint(REMOTE_SERVER_KEY);
        if (StringUtils.isBlank(baseUrl)) {
            log.warn("SplunkTokenCleaner: missing remote server endpoint for {}", REMOTE_SERVER_KEY);
            return CleanupResult.EMPTY;
        }

        Map<String, String> creds = k8SSecretsProvider.getCredentials(null);
        String adminBearer = creds != null ? creds.get(splunkConfig.adminTokenSecretKey()) : null;
        if (StringUtils.isBlank(adminBearer)) {
            log.warn("SplunkTokenCleaner: admin bearer not configured under key {}",
                    splunkConfig.adminTokenSecretKey());
            return CleanupResult.EMPTY;
        }

        String prefix = splunkConfig.mirrorUserPrefix();
        if (StringUtils.isBlank(prefix)) {
            log.warn("SplunkTokenCleaner: mirror-user-prefix is blank, refusing to scan Splunk tokens");
            return CleanupResult.EMPTY;
        }

        long now = clock.instant().getEpochSecond();
        List<SplunkExpiredToken> tokens =
                splunkManagementClient.listExpiredMcpTokens(baseUrl, adminBearer, prefix, now);
        if (tokens == null || tokens.isEmpty()) {
            log.info("SplunkTokenCleaner: no expired tokens returned by list (prefix={}, now={})", prefix, now);
            return CleanupResult.EMPTY;
        }

        int deleted = 0;
        int failed = 0;
        for (SplunkExpiredToken t : tokens) {
            if (t == null || StringUtils.isBlank(t.id())) {
                continue;
            }
            try {
                boolean ok = splunkManagementClient.deleteToken(baseUrl, adminBearer, t.id());
                if (ok) {
                    deleted++;
                } else {
                    failed++;
                    log.warn("SplunkTokenCleaner: deleteToken returned false for id={} sub={} exp={}",
                            t.id(), t.sub(), t.exp());
                }
            } catch (RuntimeException e) {
                failed++;
                log.warn("SplunkTokenCleaner: deleteToken threw for id={} sub={}: {}",
                        t.id(), t.sub(), e.getMessage());
            }
        }
        log.info("SplunkTokenCleaner: cleanup done tokensScanned={} deleted={} failed={}",
                tokens.size(), deleted, failed);
        return new CleanupResult(deleted, failed);
    }
}
