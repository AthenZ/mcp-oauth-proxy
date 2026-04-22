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

/**
 * Provider-agnostic contract for one-shot token garbage collection, invoked by
 * {@link TokenCleanupRunner} in a Kubernetes CronJob pod. Each implementation encapsulates the calls
 * to a specific provider's management API (list + delete) and returns an aggregate result that drives
 * the Job pod exit code so K8s can count successful vs failed schedule ticks.
 */
public interface TokenCleaner {

    /**
     * Case-sensitive id matched against the {@code CRON_JOB_PROVIDER} env var. Should equal the same
     * string used for {@code remote-servers.endpoints[?].name} and {@code cleanup.jobs[?].name} so ops
     * never have to translate between the three.
     */
    String providerId();

    /**
     * Runs a single cleanup pass end-to-end. Implementations must swallow per-item failures and count
     * them in the returned {@link CleanupResult} so a handful of bad tokens don't abandon a whole run.
     */
    CleanupResult cleanupOnce();
}
