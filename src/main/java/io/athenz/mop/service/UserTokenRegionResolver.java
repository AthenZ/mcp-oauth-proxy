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

import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.store.TokenStore;
import io.athenz.mop.store.impl.aws.CrossRegionTokenStoreFallback;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * Resolves per-user token rows from the local store first, then the configured cross-region DynamoDB peer
 * (if enabled). Mirrors {@link AuthCodeRegionResolver} for auth codes. Used by every read of a per-user
 * token row so that DynamoDB Global Tables replication lag between regions does not surface as
 * {@code authn expired} 401s on /token, /authorize, /userinfo and IdP callback paths.
 *
 * Writes (storeUserToken / deleteUserToken) intentionally remain local; replication propagates them.
 */
@ApplicationScoped
public class UserTokenRegionResolver {

    public static final String CALL_SITE_AUTHORIZE_USER_TOKEN = "authorize_user_token";
    public static final String CALL_SITE_AUTHORIZER_GET_USER_TOKEN = "authorizer_get_user_token";
    public static final String CALL_SITE_USERINFO_TOKEN_LOOKUP = "userinfo_token_lookup";
    public static final String CALL_SITE_USERINFO_OKTA_LOOKUP = "userinfo_okta_lookup";

    @Inject
    TokenStore tokenStore;

    @Inject
    CrossRegionTokenStoreFallback crossRegionFallback;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    @ConfigProperty(name = "server.cross-region-fallback.region")
    Optional<String> fallbackRegionConfig;

    /**
     * Resolve a token by (user, provider). Tries local first; on miss, consults the peer region when the
     * fallback bean is active. Emits {@code recordCrossRegionFallbackTriggered} on a peer hit and
     * {@code recordCrossRegionFallbackExhausted} when both regions miss (only when fallback is active).
     */
    public UserTokenResolution resolveByUserProvider(String user, String provider, String callSite) {
        TokenWrapper local = tokenStore.getUserToken(user, provider);
        if (local != null) {
            return new UserTokenResolution(local, false);
        }
        if (!crossRegionFallback.isActive()) {
            return new UserTokenResolution(null, false);
        }
        TokenWrapper peer = crossRegionFallback.getUserToken(user, provider);
        String providerLabel = OauthProviderLabel.normalize(provider);
        if (peer != null) {
            recordTriggered(providerLabel, callSite);
            return new UserTokenResolution(peer, true);
        }
        recordExhausted(providerLabel, callSite);
        return new UserTokenResolution(null, false);
    }

    /**
     * Resolve a token by access-token hash. Tries local first; on miss, consults the peer region when the
     * fallback bean is active. Provider label is unknown until a row is found, so triggered/exhausted
     * metrics use {@code "unknown"} for {@code oauth_provider} on this path (matches the existing inline
     * behavior in {@code UserInfoResource}).
     */
    public UserTokenResolution resolveByAccessTokenHash(String accessTokenHash, String callSite) {
        TokenWrapper local = tokenStore.getUserTokenByAccessTokenHash(accessTokenHash);
        if (local != null) {
            return new UserTokenResolution(local, false);
        }
        if (!crossRegionFallback.isActive()) {
            return new UserTokenResolution(null, false);
        }
        TokenWrapper peer = crossRegionFallback.getUserTokenByAccessTokenHash(accessTokenHash);
        if (peer != null) {
            String providerLabel = OauthProviderLabel.normalize(peer.provider());
            recordTriggered(providerLabel, callSite);
            return new UserTokenResolution(peer, true);
        }
        recordExhausted("unknown", callSite);
        return new UserTokenResolution(null, false);
    }

    private void recordTriggered(String providerLabel, String callSite) {
        String primary = metricsRegionProvider.primaryRegion();
        String fallback = fallbackRegionConfig.map(String::trim).filter(s -> !s.isEmpty()).orElse("unknown");
        oauthProxyMetrics.recordCrossRegionFallbackTriggered(providerLabel, callSite, primary, fallback);
    }

    private void recordExhausted(String providerLabel, String callSite) {
        String primary = metricsRegionProvider.primaryRegion();
        String fallback = fallbackRegionConfig.map(String::trim).filter(s -> !s.isEmpty()).orElse("unknown");
        oauthProxyMetrics.recordCrossRegionFallbackExhausted(providerLabel, callSite, primary, fallback,
                401, "not_found");
    }
}
