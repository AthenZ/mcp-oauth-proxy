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

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dispatcher invoked by {@code MopMain} when the pod is started with {@code CRON_JOB_MODE=1}.
 *
 * <p>Exit code contract (interpreted by Kubernetes CronJob / Job pod status):
 * <ul>
 *   <li>{@code 0} — cleaner ran and reported no failures</li>
 *   <li>{@code 1} — cleaner ran but reported one or more per-token failures</li>
 *   <li>{@code 2} — no {@link TokenCleaner} bean matched the given {@code providerId}</li>
 *   <li>{@code 3} — {@code providerId} was null or blank (misconfigured CronJob)</li>
 * </ul>
 */
@ApplicationScoped
public class TokenCleanupRunner {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    public static final int EXIT_OK = 0;
    public static final int EXIT_PARTIAL_FAILURE = 1;
    public static final int EXIT_UNKNOWN_PROVIDER = 2;
    public static final int EXIT_MISSING_PROVIDER = 3;

    @Inject
    Instance<TokenCleaner> cleaners;

    /**
     * Runs the cleaner whose {@link TokenCleaner#providerId()} equals {@code providerId}. Short-lived Job
     * pods must flush OpenTelemetry batches before exit; that is handled by {@code MopMain} around this
     * call so this method can stay unit-testable without a metrics SDK.
     */
    public int runOnce(String providerId) {
        String normalized = StringUtils.trimToNull(providerId);
        if (normalized == null) {
            log.error("TokenCleanupRunner: CRON_JOB_PROVIDER env var is null or blank");
            return EXIT_MISSING_PROVIDER;
        }

        TokenCleaner match = null;
        for (TokenCleaner c : cleaners) {
            if (normalized.equals(c.providerId())) {
                match = c;
                break;
            }
        }
        if (match == null) {
            log.error("TokenCleanupRunner: no TokenCleaner registered for providerId={}", normalized);
            return EXIT_UNKNOWN_PROVIDER;
        }

        log.info("TokenCleanupRunner: starting cleanup providerId={}", normalized);
        CleanupResult result;
        try {
            result = match.cleanupOnce();
        } catch (RuntimeException e) {
            log.error("TokenCleanupRunner: cleaner providerId={} threw unexpectedly", normalized, e);
            return EXIT_PARTIAL_FAILURE;
        }
        if (result == null) {
            log.warn("TokenCleanupRunner: cleaner providerId={} returned null result (treating as failure)",
                    normalized);
            return EXIT_PARTIAL_FAILURE;
        }

        log.info("TokenCleanupRunner: finished providerId={} deleted={} failed={}",
                normalized, result.deleted(), result.failed());
        return result.isSuccess() ? EXIT_OK : EXIT_PARTIAL_FAILURE;
    }
}
