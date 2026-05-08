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

import io.athenz.mop.service.UpstreamProviderClassifier;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;
import java.util.Map;

@ConfigMapping(prefix = "server.upstream-token")
public interface UpstreamTokenConfig {

    @WithName("table-name")
    String tableName();

    /**
     * Default upstream-row {@code expiry_seconds} used when the provider id (parsed from the
     * {@code provider#sub} partition key) has no entry in {@link #expirySecondsByProvider()}
     * and no built-in floor applies. Default 30 days.
     */
    @WithName("expiry-seconds-default")
    @WithDefault("2592000") // 30 days in seconds (30 * 24 * 60 * 60)
    long expirySecondsDefault();

    /**
     * Per-provider override map. Keys are provider ids used as the prefix of
     * {@code provider_user_id} (e.g. {@code okta}, {@code google-docs}, {@code github}).
     *
     * <p>Special key {@link #GOOGLE_WORKSPACE_GROUP_KEY} (= {@code "google-workspace"}) acts
     * as a single knob covering every member of
     * {@link UpstreamProviderClassifier#GOOGLE_WORKSPACE_PROVIDERS}. It exists so operators
     * can change the Google Workspace expiry per env without listing all 12 providers.
     *
     * <p>Resolution precedence (see {@link #expirySecondsForProvider(String)}):
     * <ol>
     *   <li>Exact-match key for the provider id (e.g. {@code google-drive: "31536000"}).</li>
     *   <li>Group key {@code google-workspace} for any member of
     *       {@link UpstreamProviderClassifier#GOOGLE_WORKSPACE_PROVIDERS}.</li>
     *   <li>{@link #expirySecondsDefault()}.</li>
     * </ol>
     *
     * <p>After the lookup, any Google Workspace provider is additionally clamped UP to
     * {@link UpstreamProviderClassifier#GOOGLE_WORKSPACE_EXPIRY_SECONDS_FLOOR}. Operators can
     * extend Google upward via the map but cannot accidentally shorten it below the floor —
     * losing a Google Workspace L2 row forces a re-consent we cannot afford.
     *
     * <p>Example values.yaml:
     * <pre>
     *   expirySecondsByProvider:
     *     okta:             "86400"      # 24h
     *     google-workspace: "15552000"   # 6 months (covers all 12 Google Workspace providers)
     *     # Optional per-provider override on top of the group key:
     *     # google-drive:   "31536000"   # 1 year, just for Drive
     * </pre>
     */
    @WithName("expiry-seconds-by-provider")
    Map<String, Long> expirySecondsByProvider();

    /**
     * Group key in {@link #expirySecondsByProvider()} that maps to every member of
     * {@link UpstreamProviderClassifier#GOOGLE_WORKSPACE_PROVIDERS}. Lets a single YAML
     * entry express "this is the value for all Google Workspace providers" without listing
     * each of the 12 individually.
     */
    String GOOGLE_WORKSPACE_GROUP_KEY = "google-workspace";

    @WithName("ttl-buffer-days")
    @WithDefault("3")
    int ttlBufferDays();

    @WithName("revoked-retention-days")
    @WithDefault("14")
    int revokedRetentionDays();

    @WithName("l2-at-reuse-grace-seconds")
    @WithDefault("30")
    long l2AtReuseGraceSeconds();

    @WithName("l2-at-reuse-min-remaining-seconds")
    @WithDefault("60")
    long l2AtReuseMinRemainingSeconds();

    @WithName("replication-wait-millis")
    @WithDefault("750")
    long replicationWaitMillis();

    default long expirySecondsForProvider(String providerOrProviderUserId) {
        String provider = extractProvider(providerOrProviderUserId);
        Map<String, Long> map = expirySecondsByProvider();
        boolean isGoogleWorkspace = UpstreamProviderClassifier.GOOGLE_WORKSPACE_PROVIDERS.contains(provider);

        long resolved;
        Long exactOverride = map != null ? map.get(provider) : null;
        if (exactOverride != null && exactOverride > 0L) {
            resolved = exactOverride;
        } else if (isGoogleWorkspace && map != null) {
            Long groupOverride = map.get(GOOGLE_WORKSPACE_GROUP_KEY);
            resolved = (groupOverride != null && groupOverride > 0L)
                    ? groupOverride
                    : expirySecondsDefault();
        } else {
            resolved = expirySecondsDefault();
        }

        if (isGoogleWorkspace) {
            resolved = Math.max(resolved, UpstreamProviderClassifier.GOOGLE_WORKSPACE_EXPIRY_SECONDS_FLOOR);
        }
        return resolved;
    }

    /** Extract the {@code provider} prefix from a {@code provider#sub} key, or return as-is. */
    private static String extractProvider(String providerOrProviderUserId) {
        if (providerOrProviderUserId == null || providerOrProviderUserId.isEmpty()) {
            return "";
        }
        int hash = providerOrProviderUserId.indexOf('#');
        return hash < 0 ? providerOrProviderUserId : providerOrProviderUserId.substring(0, hash);
    }
}
