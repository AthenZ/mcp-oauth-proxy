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

import jakarta.enterprise.context.ApplicationScoped;
import java.util.Set;

/**
 * Classifies which upstream IdP providers participate in the L2 upstream-tokens canonical-RT
 * model (one DDB row per {@code provider#sub}, version-CAS lock, staged AT for cross-client
 * coalescing).
 *
 * <p>The allow-list is hardcoded. Adding or removing a promoted provider is a code change so it
 * goes through normal review — the L2 model carries non-trivial schema and write-path
 * implications and we never want it controlled by config drift.
 *
 * <p>Today the allow-list contains:
 * <ul>
 *   <li>{@code okta} — original L2 user (Okta-rooted refresh).</li>
 *   <li>The 12 Google Workspace providers — promoted to L2 to fix the sibling-inheritance trap
 *       that bit us when a poisoned upstream RT in an "ACTIVE" sibling row poisoned every fresh
 *       login. With the canonical-row model there are no siblings, only the L2 row.</li>
 * </ul>
 *
 * <p>Native-IdP providers like Slack/GitHub/Atlassian/Embrace stay on the legacy per-client
 * refresh-tokens row model: they don't suffer from the same Google-style RT-rotation-on-every-refresh
 * pressure, so the simpler model is fine for them.
 */
@ApplicationScoped
public class UpstreamProviderClassifier {

    /**
     * The 12 google-workspace providers that share the L2 + per-client L0 cache machinery.
     * Exposed publicly so telemetry can pre-register zero-counters for each (provider, outcome)
     * tuple at metric-bean init, which keeps Prometheus/OTLP scrapes stable when no traffic has
     * hit a given provider yet.
     */
    public static final Set<String> GOOGLE_WORKSPACE_PROVIDERS = Set.of(
            "google-drive",
            "google-docs",
            "google-sheets",
            "google-slides",
            "google-gmail",
            "google-calendar",
            "google-tasks",
            "google-chat",
            "google-forms",
            "google-keep",
            "google-meet",
            "google-cloud-platform"
    );

    private static final Set<String> PROMOTED_PROVIDERS;
    static {
        Set<String> all = new java.util.HashSet<>(GOOGLE_WORKSPACE_PROVIDERS);
        all.add(AudienceConstants.PROVIDER_OKTA);
        PROMOTED_PROVIDERS = Set.copyOf(all);
    }

    /**
     * Returns true when the provider participates in the L2 canonical upstream-RT model.
     *
     * <p>Callers use this to decide whether to seed {@link UpstreamTokenStore} on consent,
     * whether to use {@link UpstreamRefreshService#refreshUpstream} on refresh, and whether
     * to populate the per-client AT cache. Unknown / blank inputs always return false so the
     * legacy code path stays the safe default.
     */
    public boolean isUpstreamPromoted(String provider) {
        if (provider == null || provider.isEmpty()) {
            return false;
        }
        return PROMOTED_PROVIDERS.contains(provider);
    }

    /**
     * True for any of the 12 google-workspace providers. Useful where the surrounding code
     * already knows it's not Okta but still needs to disambiguate Google from native-IdP
     * providers (e.g. when picking the right {@code UpstreamRefreshClient}).
     */
    public boolean isGoogleWorkspace(String provider) {
        if (provider == null || provider.isEmpty() || AudienceConstants.PROVIDER_OKTA.equals(provider)) {
            return false;
        }
        return PROMOTED_PROVIDERS.contains(provider);
    }
}
