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

import io.athenz.mop.model.AuthorizationCodeTokensDO;
import io.athenz.mop.store.TokenStoreAsync;
import io.athenz.mop.store.impl.aws.CrossRegionTokenStoreFallback;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves the {@code auth_tokens_json} row in the user-tokens table from local first, then the
 * configured cross-region peer (if enabled). Returns a {@link Uni} so it slots into the existing
 * Quarkus OIDC token-state-manager pipeline. Used by {@code CustomTokenStateManager.getTokens}.
 *
 * <p>The local read may complete with a {@code null} item, throw a {@link RuntimeException}
 * ("No auth code tokens found"), or surface a JSON unmarshal error. Any of those triggers a peer
 * lookup when the fallback bean is active. Writes (create/delete) stay local.
 */
@ApplicationScoped
public class AuthCodeTokensRegionResolver {

    private static final Logger log = LoggerFactory.getLogger(AuthCodeTokensRegionResolver.class);

    public static final String CALL_SITE_AUTH_CODE_TOKENS_GET = "auth_code_tokens_get";

    @Inject
    TokenStoreAsync tokenStoreAsync;

    @Inject
    CrossRegionTokenStoreFallback crossRegionFallback;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    MetricsRegionProvider metricsRegionProvider;

    @ConfigProperty(name = "server.cross-region-fallback.region")
    Optional<String> fallbackRegionConfig;

    /**
     * Resolve the auth-code-tokens row for {@code (id, provider)}. On local hit, returns the row.
     * On local miss/failure, consults the peer region when the fallback is active. Emits triggered
     * on peer hit and exhausted when both regions miss.
     *
     * <p>The returned {@link Uni} fails with the original local exception when both the local and
     * the peer paths produce nothing — preserving today's downstream behavior of mapping that into
     * an {@link io.quarkus.security.AuthenticationFailedException} in {@code CustomTokenStateManager}.
     */
    public Uni<AuthorizationCodeTokensDO> resolve(String id, String provider) {
        return tokenStoreAsync.getTokenAsync(id, provider)
                .onFailure().recoverWithUni(failure -> peerOrFail(id, provider, failure))
                .onItem().ifNull().switchTo(() -> peerOrFail(id, provider, null));
    }

    private Uni<AuthorizationCodeTokensDO> peerOrFail(String id, String provider, Throwable localFailure) {
        if (!crossRegionFallback.isActive()) {
            return failed(id, provider, localFailure);
        }
        return Uni.createFrom().item(() -> crossRegionFallback.getTokenAsync(id, provider))
                .onItem().transformToUni(peer -> {
                    String providerLabel = OauthProviderLabel.normalize(provider);
                    if (peer != null) {
                        log.info("Recovered auth code tokens from peer region for id={} provider={}", id, provider);
                        recordTriggered(providerLabel);
                        return Uni.createFrom().item(peer);
                    }
                    recordExhausted(providerLabel);
                    return failed(id, provider, localFailure);
                })
                .onFailure().recoverWithUni(peerFailure -> {
                    log.warn("Peer region getTokenAsync threw for id={} provider={}: {}", id, provider, peerFailure.getMessage());
                    return failed(id, provider, localFailure);
                });
    }

    private static Uni<AuthorizationCodeTokensDO> failed(String id, String provider, Throwable localFailure) {
        if (localFailure != null) {
            return Uni.createFrom().failure(localFailure);
        }
        return Uni.createFrom().failure(new RuntimeException(
                "No auth code tokens found for id " + id + " provider " + provider));
    }

    private void recordTriggered(String providerLabel) {
        String primary = metricsRegionProvider.primaryRegion();
        String fallback = fallbackRegionConfig.map(String::trim).filter(s -> !s.isEmpty()).orElse("unknown");
        oauthProxyMetrics.recordCrossRegionFallbackTriggered(
                providerLabel, CALL_SITE_AUTH_CODE_TOKENS_GET, primary, fallback);
    }

    private void recordExhausted(String providerLabel) {
        String primary = metricsRegionProvider.primaryRegion();
        String fallback = fallbackRegionConfig.map(String::trim).filter(s -> !s.isEmpty()).orElse("unknown");
        oauthProxyMetrics.recordCrossRegionFallbackExhausted(
                providerLabel, CALL_SITE_AUTH_CODE_TOKENS_GET, primary, fallback,
                401, "not_found");
    }
}
