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
package io.athenz.mop.config;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for {@link UpstreamTokenConfig#expirySecondsForProvider(String)}.
 *
 * <p>The interface is implemented as an in-test fake here so we can exercise the {@code default}
 * resolution method without dragging in SmallRye Config / Quarkus startup. Production wiring is
 * separately covered by {@code UpstreamTokenStoreDynamoDbImplTest} and
 * {@code UpstreamRefreshServiceTest}, which mock the interface and stub
 * {@code expirySecondsForProvider(...)} directly.
 */
class UpstreamTokenConfigTest {

    private static final long DEFAULT_30D = 2_592_000L;
    private static final long OKTA_24H = 86_400L;
    private static final long GOOGLE_180D = 15_552_000L;
    private static final long FIGMA_90D = 7_776_000L;

    private static UpstreamTokenConfig configWith(Map<String, Long> map) {
        return new FakeConfig(DEFAULT_30D, map);
    }

    @Test
    void exactMatchOverride_winsOverDefault() {
        Map<String, Long> map = new HashMap<>();
        map.put("okta", OKTA_24H);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(OKTA_24H, cfg.expirySecondsForProvider("okta"));
        assertEquals(OKTA_24H, cfg.expirySecondsForProvider("okta#abc-123"));
    }

    @Test
    void unknownProvider_fallsBackToDefault() {
        UpstreamTokenConfig cfg = configWith(new HashMap<>());

        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("github"));
        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("github#sub"));
        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("atlassian"));
    }

    @Test
    void googleWorkspaceProviders_clampedToFloorEvenWithoutMapEntry() {
        // No Google entry in map → default would be 30d, but the hardcoded floor on
        // UpstreamProviderClassifier must lift it to 6 months for every member of the
        // authoritative GOOGLE_WORKSPACE_PROVIDERS set. This is the safety net that keeps
        // Google rows alive across operator misconfiguration. Iterating the canonical set
        // means new Google variants automatically inherit the floor the moment they're added
        // to the classifier.
        UpstreamTokenConfig cfg = configWith(new HashMap<>());

        for (String provider : io.athenz.mop.service.UpstreamProviderClassifier.GOOGLE_WORKSPACE_PROVIDERS) {
            assertEquals(GOOGLE_180D, cfg.expirySecondsForProvider(provider),
                    "bare provider id should be floored: " + provider);
            assertEquals(GOOGLE_180D, cfg.expirySecondsForProvider(provider + "#user@example.com"),
                    "provider#sub should be floored: " + provider);
        }
    }

    @Test
    void googleWorkspaceProvider_floorAppliedEvenWhenMapValueIsLower() {
        // Operator typo / regression: someone sets google-docs to 5 minutes. The floor must
        // save us. Pick one canonical member; the iteration test above covers full membership.
        Map<String, Long> map = new HashMap<>();
        map.put("google-docs", 300L);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(GOOGLE_180D, cfg.expirySecondsForProvider("google-docs"));
        assertEquals(GOOGLE_180D, cfg.expirySecondsForProvider("google-docs#u"));
    }

    @Test
    void googleWorkspaceProvider_mapValueAboveFloor_winsAsConfigured() {
        // Operators can extend Google upward (e.g. 1 year). The floor only enforces the lower
        // bound; values larger than the floor pass through unchanged.
        long oneYear = 31_536_000L;
        Map<String, Long> map = new HashMap<>();
        map.put("google-drive", oneYear);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(oneYear, cfg.expirySecondsForProvider("google-drive#u"));
    }

    @Test
    void googleWorkspaceGroupKey_appliesToEveryWorkspaceProvider() {
        // The `google-workspace` group key is the operator's single knob for all 12 Google
        // Workspace providers. Setting it should make every member of GOOGLE_WORKSPACE_PROVIDERS
        // resolve to that value (subject to the floor).
        long elevenMonths = 28_512_000L;  // 330d — well above the 180d floor
        Map<String, Long> map = new HashMap<>();
        map.put(UpstreamTokenConfig.GOOGLE_WORKSPACE_GROUP_KEY, elevenMonths);
        UpstreamTokenConfig cfg = configWith(map);

        for (String provider : io.athenz.mop.service.UpstreamProviderClassifier.GOOGLE_WORKSPACE_PROVIDERS) {
            assertEquals(elevenMonths, cfg.expirySecondsForProvider(provider + "#u"),
                    "group key should apply to: " + provider);
        }
    }

    @Test
    void googleWorkspaceGroupKey_doesNotAffectNonWorkspaceProviders() {
        // The group key MUST NOT leak to non-Workspace providers — okta, github, atlassian
        // etc. should still go through the default-or-exact-override path. This is the
        // boundary that protects the "Workforce vs Workspace" split (google-monitoring,
        // google-logging, google-bigquery — those are Workforce, not Workspace).
        Map<String, Long> map = new HashMap<>();
        map.put(UpstreamTokenConfig.GOOGLE_WORKSPACE_GROUP_KEY, 31_536_000L);  // 1 year
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("github#u"));
        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("atlassian#u"));
        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("google-monitoring#u"));
        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("google-bigquery#u"));
    }

    @Test
    void exactMatch_winsOverGroupKey_forSingleProviderOverride() {
        // When both the group key and an exact-match key are set, the exact-match key wins.
        // This is how an operator would tune one Google provider differently from the others
        // (e.g. extend just Drive to 1 year while leaving the rest at 6 months).
        long sixMonths = GOOGLE_180D;
        long oneYear = 31_536_000L;
        Map<String, Long> map = new HashMap<>();
        map.put(UpstreamTokenConfig.GOOGLE_WORKSPACE_GROUP_KEY, sixMonths);
        map.put("google-drive", oneYear);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(oneYear, cfg.expirySecondsForProvider("google-drive#u"));
        assertEquals(sixMonths, cfg.expirySecondsForProvider("google-docs#u"));
        assertEquals(sixMonths, cfg.expirySecondsForProvider("google-gmail#u"));
    }

    @Test
    void googleWorkspaceGroupKey_belowFloor_stillClampedUp() {
        // Even when set via the group key, a too-low value still gets clamped to the floor.
        // Operator can't accidentally evict every Google row by setting `google-workspace`
        // to 5 minutes.
        Map<String, Long> map = new HashMap<>();
        map.put(UpstreamTokenConfig.GOOGLE_WORKSPACE_GROUP_KEY, 300L);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(GOOGLE_180D, cfg.expirySecondsForProvider("google-drive#u"));
        assertEquals(GOOGLE_180D, cfg.expirySecondsForProvider("google-gmail#u"));
    }

    @Test
    void googlePrefix_butNotInWorkspaceSet_doesNotGetFloor() {
        // Critical negative test: the floor only applies to providers in the authoritative
        // GOOGLE_WORKSPACE_PROVIDERS set, NOT to anything that happens to start with "google".
        // The Workforce providers (google-monitoring/logging/bigquery) and any typo'd id like
        // "google-mail" (canonical is "google-gmail") fall through to the default. This is
        // the whole point of binding the floor to the curated set instead of a string prefix.
        UpstreamTokenConfig cfg = configWith(new HashMap<>());

        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("google-monitoring#u"));
        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("google-logging#u"));
        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("google-bigquery#u"));
        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("google-mail#u"));
        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("google#u"));
    }

    @Test
    void nullOrEmptyInput_treatedAsUnknownProvider() {
        UpstreamTokenConfig cfg = configWith(new HashMap<>());

        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider(null));
        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider(""));
    }

    @Test
    void inputWithoutHash_treatedAsBareProviderId() {
        Map<String, Long> map = new HashMap<>();
        map.put("okta", OKTA_24H);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(OKTA_24H, cfg.expirySecondsForProvider("okta"));
    }

    @Test
    void figma_exactMatchOverride_returnsConfiguredLifetime() {
        // Figma is L2 promoted but NOT in GOOGLE_WORKSPACE_PROVIDERS, so the floor does not
        // apply. The exact-match key must yield the configured 90 d AT lifetime.
        Map<String, Long> map = new HashMap<>();
        map.put("figma", FIGMA_90D);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(FIGMA_90D, cfg.expirySecondsForProvider("figma"));
        assertEquals(FIGMA_90D, cfg.expirySecondsForProvider("figma#1318454437468440704"));
    }

    @Test
    void figma_unconfigured_fallsBackToDefault() {
        // Without an exact-match key Figma falls through to the global default (30 d). This
        // mirrors how the production deployments configure it: chart values.yaml and the env
        // overrides set figma=7776000 explicitly. If that value is dropped, this test
        // demonstrates the fallback (which is shorter than the real 90 d AT — operators must
        // set the override).
        UpstreamTokenConfig cfg = configWith(new HashMap<>());

        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("figma#1234"));
    }

    @Test
    void figma_groupKeyDoesNotApplyToFigma() {
        // The google-workspace group key is scoped to Workspace providers only. Figma must NOT
        // accidentally inherit a Google-tier expiry just because the group key is set.
        Map<String, Long> map = new HashMap<>();
        map.put(UpstreamTokenConfig.GOOGLE_WORKSPACE_GROUP_KEY, GOOGLE_180D);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("figma#u"));
    }

    @Test
    void datadog_exactMatchOverride_returnsConfiguredLifetime() {
        // Datadog is L2 promoted but NOT in GOOGLE_WORKSPACE_PROVIDERS, so the floor does not
        // apply. The exact-match key must yield the configured cap (6 months by default).
        long sixMonths = GOOGLE_180D;
        Map<String, Long> map = new HashMap<>();
        map.put("datadog", sixMonths);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(sixMonths, cfg.expirySecondsForProvider("datadog"));
        assertEquals(sixMonths, cfg.expirySecondsForProvider("datadog#user-uuid"));
    }

    @Test
    void datadog_unconfigured_fallsBackToDefault() {
        // Without an exact-match key Datadog falls through to the global default (30 d). This
        // mirrors how production is configured: chart values.yaml + env overrides set
        // datadog=15552000 (6 months) explicitly. If the override is dropped this test
        // demonstrates the fallback. Datadog's RT does not expire upstream so the only effect is
        // unnecessary re-consents — no data loss.
        UpstreamTokenConfig cfg = configWith(new HashMap<>());

        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("datadog#user-uuid"));
    }

    @Test
    void datadog_groupKeyDoesNotApplyToDatadog() {
        // The google-workspace group key is scoped to Workspace providers only. Datadog must NOT
        // accidentally inherit a Google-tier expiry just because the group key is set.
        Map<String, Long> map = new HashMap<>();
        map.put(UpstreamTokenConfig.GOOGLE_WORKSPACE_GROUP_KEY, GOOGLE_180D);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("datadog#u"));
    }

    @Test
    void linear_exactMatchOverride_returnsConfiguredLifetime() {
        // Linear is L2 promoted but NOT in GOOGLE_WORKSPACE_PROVIDERS, so the floor does not
        // apply. The exact-match key must yield the configured cap (6 months by default).
        long sixMonths = GOOGLE_180D;
        Map<String, Long> map = new HashMap<>();
        map.put("linear", sixMonths);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(sixMonths, cfg.expirySecondsForProvider("linear"));
        assertEquals(sixMonths, cfg.expirySecondsForProvider("linear#user-uuid"));
    }

    @Test
    void linear_unconfigured_fallsBackToDefault() {
        // Without an exact-match key Linear falls through to the global default (30 d). Production
        // sets linear=15552000 (6 months) explicitly via chart values.yaml + env overrides; if
        // that override is dropped this test demonstrates the fallback. Linear's RT lifetime is
        // unbounded upstream so the only effect is unnecessary re-consents — no data loss.
        UpstreamTokenConfig cfg = configWith(new HashMap<>());

        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("linear#user-uuid"));
    }

    @Test
    void linear_groupKeyDoesNotApplyToLinear() {
        // The google-workspace group key is scoped to Workspace providers only. Linear must NOT
        // accidentally inherit a Google-tier expiry just because the group key is set.
        Map<String, Long> map = new HashMap<>();
        map.put(UpstreamTokenConfig.GOOGLE_WORKSPACE_GROUP_KEY, GOOGLE_180D);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("linear#u"));
    }

    @Test
    void oracleEpm_exactMatchOverride_returnsConfiguredLifetime() {
        // Oracle EPM is L2 promoted but NOT in GOOGLE_WORKSPACE_PROVIDERS, so the floor does
        // not apply. The exact-match key must yield the configured cap (30 days by default).
        Map<String, Long> map = new HashMap<>();
        map.put("oracle-epm", DEFAULT_30D);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("oracle-epm"));
        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("oracle-epm#yosrixp@yahooinc.com"));
    }

    @Test
    void oracleEpm_unconfigured_fallsBackToDefault() {
        // Without an exact-match key Oracle EPM falls through to the global default (30 d).
        // Production sets oracle-epm=2592000 (30 days) explicitly via chart values.yaml + env
        // overrides; if the override is dropped this test demonstrates the fallback (which is
        // the same value, so no behavioral difference for default config).
        UpstreamTokenConfig cfg = configWith(new HashMap<>());

        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("oracle-epm#user-uuid"));
    }

    @Test
    void oracleEpm_groupKeyDoesNotApplyToOracleEpm() {
        // The google-workspace group key is scoped to Workspace providers only. Oracle EPM must
        // NOT accidentally inherit a Google-tier expiry just because the group key is set.
        Map<String, Long> map = new HashMap<>();
        map.put(UpstreamTokenConfig.GOOGLE_WORKSPACE_GROUP_KEY, GOOGLE_180D);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("oracle-epm#u"));
    }

    @Test
    void zeroOrNegativeMapValue_ignoredInFavorOfDefault() {
        // Zero/negative is treated as "unset" — falls back to the default. This catches a
        // malformed values.yaml gracefully rather than writing a row with 0s TTL.
        Map<String, Long> map = new HashMap<>();
        map.put("github", 0L);
        UpstreamTokenConfig cfg = configWith(map);

        assertEquals(DEFAULT_30D, cfg.expirySecondsForProvider("github#u"));
    }

    /**
     * Minimal in-test impl that returns just the two methods consumed by the {@code default}
     * resolver. All other interface methods are stubbed with sensible no-op values so any
     * accidental future call shows up as a compile error rather than silently returning null.
     */
    private static final class FakeConfig implements UpstreamTokenConfig {
        private final long defaultSeconds;
        private final Map<String, Long> overrides;

        FakeConfig(long defaultSeconds, Map<String, Long> overrides) {
            this.defaultSeconds = defaultSeconds;
            this.overrides = overrides;
        }

        @Override public String tableName() { return "test-upstream"; }
        @Override public long expirySecondsDefault() { return defaultSeconds; }
        @Override public Map<String, Long> expirySecondsByProvider() { return overrides; }
        @Override public int ttlBufferDays() { return 3; }
        @Override public int revokedRetentionDays() { return 14; }
        @Override public long l2AtReuseGraceSeconds() { return 30L; }
        @Override public long l2AtReuseMinRemainingSeconds() { return 60L; }
        @Override public long replicationWaitMillis() { return 750L; }
    }
}
