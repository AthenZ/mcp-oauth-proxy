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
package io.athenz.mop;

import io.athenz.mop.token.sweeper.TokenCleanupRunner;
import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.annotations.QuarkusMain;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Entry point for both the long-lived HTTPS serving process and the short-lived Kubernetes CronJob
 * cleanup process. Dispatch is driven entirely by environment variables so the same Docker image and
 * entrypoint can be reused without argv tricks:
 *
 * <ul>
 *   <li>{@code CRON_JOB_MODE} unset / {@code "0"} / {@code "false"} — boot Quarkus and serve
 *   traffic (equivalent to the pre-existing behavior)</li>
 *   <li>{@code CRON_JOB_MODE=1} (or {@code "true"}, case-insensitive) — invoke
 *   {@link TokenCleanupRunner} with the {@code CRON_JOB_PROVIDER} env var as the provider id, then
 *   exit with the runner's exit code</li>
 * </ul>
 *
 * The {@code %cleanup} Quarkus profile (activated via {@code QUARKUS_PROFILE=...,cleanup} on the
 * CronJob container spec) disables the HTTP listener so Job pods don't waste time binding a port.
 */
@QuarkusMain
public class MopMain implements QuarkusApplication {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    static final String ENV_CRON_JOB_MODE = "CRON_JOB_MODE";
    static final String ENV_CRON_JOB_PROVIDER = "CRON_JOB_PROVIDER";

    @Inject
    TokenCleanupRunner cleanupRunner;

    @Override
    public int run(String... args) throws Exception {
        if (isCronJobMode(System.getenv(ENV_CRON_JOB_MODE))) {
            String providerId = System.getenv(ENV_CRON_JOB_PROVIDER);
            log.info("MopMain: starting in cleanup mode providerId={}", providerId);
            return cleanupRunner.runOnce(providerId);
        }
        log.info("MopMain: starting in serve mode");
        Quarkus.waitForExit();
        return 0;
    }

    /**
     * Accepts {@code "1"} as a deliberate alias for {@code "true"} so operators can use the same
     * on/off convention as other env vars in the fleet, while also delegating to
     * {@link Boolean#parseBoolean(String)} for the standard {@code "true"}/{@code "false"} pair
     * (case-insensitive). Null, blank, {@code "0"}, and every other value map to {@code false}.
     *
     * <p>Package-private for unit testing; also injected via {@code System.getenv(...)} in
     * {@link #run(String...)} so a test harness can exercise the parsing without mutating real env.
     */
    static boolean isCronJobMode(String rawEnvValue) {
        if (rawEnvValue == null) {
            return false;
        }
        String trimmed = rawEnvValue.trim();
        if (trimmed.isEmpty()) {
            return false;
        }
        return "1".equals(trimmed) || Boolean.parseBoolean(trimmed);
    }
}
