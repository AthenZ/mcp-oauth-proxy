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
import jakarta.inject.Inject;
import java.util.Optional;
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
 *   <li>{@code figma} — promoted to L2 so the bare {@code (subject, figma)} row in
 *       {@code mcp-oauth-proxy-tokens} honors the real 90-day Figma access-token lifetime
 *       instead of the global ~8h {@code server.token-store.expiry} cap. Without promotion the
 *       row would evict 8h after consent regardless of the real AT lifetime.</li>
 *   <li>{@code datadog} — promoted to L2 so the canonical upstream RT is stored once and
 *       amortized across MCP-client windows. Datadog access tokens are 1h and the refresh
 *       token does not rotate; the L2 row TTL is capped at 6 months (operator-tunable via
 *       {@code server.upstream-token.expiry-seconds-by-provider.datadog}) to bound row sprawl.
 *       Datadog is a public PKCE client (DCR returns no client_secret), and the
 *       {@link DatadogUpstreamRefreshClient} reflects that — see the resolver below.</li>
 *   <li>{@code linear} — promoted to L2 for the same amortization reasons. Linear access
 *       tokens are ~24h ({@code expires_in=86399}) and the refresh token <strong>rotates</strong>
 *       on every refresh, with a documented 30-min replay-grace window for retry safety. L2 row
 *       TTL is capped at 6 months (operator-tunable via
 *       {@code server.upstream-token.expiry-seconds-by-provider.linear}) since Linear's RT
 *       lifetime is otherwise unbounded. Linear is a public PKCE client today; see
 *       {@link LinearUpstreamRefreshClient} for the public-client wiring and the
 *       {@code TODO(linear-confidential)} hook for a future client_secret rollout.</li>
 *   <li>{@code oracle-epm} — promoted to L2 for cross-client AT coalescing. Oracle IDCS
 *       access tokens are 1h ({@code expires_in=3600}) and the refresh token <strong>rotates</strong>
 *       on every refresh. L2 row TTL is capped at 30 days (operator-tunable via
 *       {@code server.upstream-token.expiry-seconds-by-provider.oracle-epm}); matches the
 *       global default since Oracle's RT TTL is operator-tunable upstream. Oracle is a
 *       confidential client (client_secret_post); see {@link OracleEpmUpstreamRefreshClient}
 *       for the wiring.</li>
 * </ul>
 *
 * <p>Other native-IdP providers like Slack/GitHub/Atlassian/Embrace stay on the legacy
 * per-client refresh-tokens row model: their access-token lifetimes are short enough that the
 * 8h bare-row TTL is not painful.
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

    public static final long GOOGLE_WORKSPACE_EXPIRY_SECONDS_FLOOR = 15_552_000L; // 6 months in seconds (180 days)

    /** Provider id for Figma (90-day access-token lifetime, L2 promoted). */
    public static final String FIGMA_PROVIDER = "figma";

    /** Provider id for Datadog (1h access-token lifetime, non-rotating RT, L2 promoted). */
    public static final String DATADOG_PROVIDER = "datadog";

    /** Provider id for Linear (~24h access-token lifetime, rotating RT with 30-min replay grace, L2 promoted). */
    public static final String LINEAR_PROVIDER = "linear";

    /** Provider id for Oracle EPM (1h access-token lifetime, rotating RT, L2 promoted). */
    public static final String ORACLE_EPM_PROVIDER = "oracle-epm";

    private static final Set<String> PROMOTED_PROVIDERS;
    static {
        Set<String> all = new java.util.HashSet<>(GOOGLE_WORKSPACE_PROVIDERS);
        all.add(AudienceConstants.PROVIDER_OKTA);
        all.add(FIGMA_PROVIDER);
        all.add(DATADOG_PROVIDER);
        all.add(LINEAR_PROVIDER);
        all.add(ORACLE_EPM_PROVIDER);
        PROMOTED_PROVIDERS = Set.copyOf(all);
    }

    @Inject
    GoogleWorkspaceUpstreamRefreshClient googleWorkspaceUpstreamRefreshClient;

    @Inject
    FigmaUpstreamRefreshClient figmaUpstreamRefreshClient;

    @Inject
    DatadogUpstreamRefreshClient datadogUpstreamRefreshClient;

    @Inject
    LinearUpstreamRefreshClient linearUpstreamRefreshClient;

    @Inject
    OracleEpmUpstreamRefreshClient oracleEpmUpstreamRefreshClient;

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
     * already knows it's not Okta but still needs to disambiguate Google from other promoted
     * providers (e.g. Figma) when picking telemetry labels or downstream behavior.
     */
    public boolean isGoogleWorkspace(String provider) {
        if (provider == null || provider.isEmpty()) {
            return false;
        }
        return GOOGLE_WORKSPACE_PROVIDERS.contains(provider);
    }

    /**
     * Resolves the {@link UpstreamRefreshClient} for non-Okta promoted providers. Returns
     * {@link Optional#empty()} for Okta (callers handle Okta via the legacy single-arg path) and
     * for unknown providers. Centralising the dispatch here keeps {@code UpstreamRefreshService.clientFor}
     * to a single delegating call and makes adding a new promoted provider a one-file change.
     */
    public Optional<UpstreamRefreshClient> resolveRefreshTokenClient(String provider) {
        if (provider == null || provider.isEmpty() || AudienceConstants.PROVIDER_OKTA.equals(provider)) {
            return Optional.empty();
        }
        if (isGoogleWorkspace(provider)) {
            return Optional.of(googleWorkspaceUpstreamRefreshClient);
        }
        if (FIGMA_PROVIDER.equals(provider)) {
            return Optional.of(figmaUpstreamRefreshClient);
        }
        if (DATADOG_PROVIDER.equals(provider)) {
            return Optional.of(datadogUpstreamRefreshClient);
        }
        if (LINEAR_PROVIDER.equals(provider)) {
            return Optional.of(linearUpstreamRefreshClient);
        }
        if (ORACLE_EPM_PROVIDER.equals(provider)) {
            return Optional.of(oracleEpmUpstreamRefreshClient);
        }
        return Optional.empty();
    }
}
