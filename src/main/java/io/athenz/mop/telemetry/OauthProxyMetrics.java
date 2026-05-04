/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import io.athenz.mop.service.UpstreamProviderClassifier;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.metrics.DoubleHistogram;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.LongUpDownCounter;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.api.metrics.ObservableLongGauge;
import io.quarkus.runtime.StartupEvent;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

@ApplicationScoped
public class OauthProxyMetrics {

    private static final List<Double> HISTOGRAM_BUCKETS = List.of(
            0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0);

    private static final AttributeKey<String> HTTP_METHOD = AttributeKey.stringKey("http_request_method");
    private static final AttributeKey<String> HTTP_ROUTE = AttributeKey.stringKey("http_route");
    private static final AttributeKey<String> HTTP_STATUS = AttributeKey.stringKey("http_response_status_code");
    private static final AttributeKey<String> ERROR_TYPE = AttributeKey.stringKey("error_type");
    private static final AttributeKey<String> OAUTH_PROVIDER = AttributeKey.stringKey("oauth_provider");
    private static final AttributeKey<String> OAUTH_CLIENT = AttributeKey.stringKey("oauth_client");
    private static final AttributeKey<String> OAUTH_GRANT_TYPE = AttributeKey.stringKey("oauth_grant_type");
    private static final AttributeKey<String> OUTCOME = AttributeKey.stringKey("outcome");
    private static final AttributeKey<String> OAUTH_OPERATION = AttributeKey.stringKey("oauth_operation");
    private static final AttributeKey<String> PRIMARY_REGION = AttributeKey.stringKey("primary_region");
    private static final AttributeKey<String> FALLBACK_REGION = AttributeKey.stringKey("fallback_region");
    private static final AttributeKey<String> REGION = AttributeKey.stringKey("region");
    private static final AttributeKey<String> EXCHANGE_STEP = AttributeKey.stringKey("exchange_step");
    private static final AttributeKey<String> UPSTREAM_ENDPOINT = AttributeKey.stringKey("upstream_endpoint");
    private static final AttributeKey<String> RETRY_REASON = AttributeKey.stringKey("retry_reason");
    private static final AttributeKey<String> ENDPOINT = AttributeKey.stringKey("endpoint");
    private static final AttributeKey<String> OPERATION = AttributeKey.stringKey("operation");
    private static final AttributeKey<String> USERINFO_FAILURE_REASON = AttributeKey.stringKey("userinfo_failure_reason");
    private static final AttributeKey<String> REASON = AttributeKey.stringKey("reason");

    /**
     * Outcomes emitted from {@code UpstreamRefreshService.refreshUpstream} when the shared Okta
     * upstream session cache is enabled. Tracks where a refresh request was satisfied so we can
     * tune sizes/TTLs and report Okta load reduction.
     */
    public static final List<String> UPSTREAM_OKTA_CACHE_OUTCOMES = List.of(
            "l0_hit", "l1_hit", "hit_post_lock", "miss_refreshed");

    /**
     * Outcomes emitted from {@code UpstreamRefreshService.refreshUpstreamPromoted} for any
     * provider that goes through the L2 promotion + per-client L0 cache path (today: every
     * google-* provider). Same observable shape as {@link #UPSTREAM_OKTA_CACHE_OUTCOMES} but the
     * counter additionally carries a {@code provider} label so the dashboard can break out
     * google-docs vs google-slides vs google-drive vs … without aggregating across sub-products.
     * The {@code reuse_within_grace} outcome is the Path E hit (cached AT staged on the L2 row by
     * a recently-refreshed sibling client).
     */
    public static final List<String> UPSTREAM_PROMOTED_CACHE_OUTCOMES = List.of(
            "l0_hit", "hit_post_lock", "reuse_within_grace", "miss_refreshed");

    /**
     * Outcomes emitted from {@code UserInfoResource.serveUserinfo} when the shared Okta upstream
     * session cache is enabled. {@code stale_claims_served} is the safety-net path: refresh
     * failed but the cache still held a (now-expired) parseable id_token whose claims are
     * stable across refreshes — we serve them rather than 401 a request whose upstream-provider
     * bearer is still valid.
     */
    public static final List<String> USERINFO_OKTA_CACHE_OUTCOMES = List.of(
            "fresh_hit", "expired_refreshed", "absent_refreshed", "stale_claims_served");

    private static final List<String> OKTA_SESSION_CACHE_EVICTION_REASONS = List.of(
            "size", "expired_write", "explicit", "collected");

    private static final List<String> CROSS_REGION_FALLBACK_CALL_SITES = List.of(
            "authorize_user_token",
            "authorizer_get_user_token",
            "userinfo_token_lookup",
            "userinfo_okta_lookup",
            "userinfo_bearer_lookup",
            "upstream_okta_cache_lookup",
            "refresh_token_validate",
            "refresh_token_get_pk",
            "refresh_token_get_upstream",
            "upstream_token_get",
            "auth_code_tokens_get");

    /**
     * Outcomes emitted from the bearer-index lookup path
     * ({@link io.athenz.mop.service.BearerIndexRegionResolver#resolveByHash(String)} and the
     * /userinfo read site that consumes it).
     * <ul>
     *   <li>{@code hit} — local bearer-index row present and not yet TTL-evicted.</li>
     *   <li>{@code from_fallback} — local miss but the cross-region peer table had the row
     *       (Global Tables replication lag).</li>
     *   <li>{@code miss} — both regions missed; /userinfo will return 401 and the MCP client's
     *       refresh grant will mint a new bearer.</li>
     * </ul>
     */
    public static final List<String> BEARER_INDEX_LOOKUP_OUTCOMES = List.of(
            "hit", "from_fallback", "miss");

    /**
     * Outcomes emitted from every bearer-index write call site (login, token-exchange,
     * refresh-grant rotation, /userinfo's internal Okta refresh, warm-cache mint).
     */
    public static final List<String> BEARER_INDEX_WRITE_OUTCOMES = List.of(
            "success", "failure");

    public static final List<List<String>> TOKEN_RESOURCE_VALIDATION_OUTCOMES = List.of(
            List.of("accepted", "known_mapped"),
            List.of("rejected", "unknown_resource"));

    private Meter meter;
    private LongCounter httpErrors4xx;
    private LongCounter httpErrors5xx;
    private LongCounter errorsTotal;
    private LongCounter tokenIssuanceTotal;
    private LongCounter authCodeExchangeTotal;
    private LongCounter refreshTokenExchangeTotal;
    private LongCounter userinfoRequestsTotal;
    private LongCounter crossRegionFallbackTriggeredTotal;
    private LongCounter crossRegionFallbackExhaustedTotal;
    private DoubleHistogram tokenExchangeDurationSeconds;
    private LongUpDownCounter httpRequestsInflight;
    private DoubleHistogram upstreamRequestDurationSeconds;
    private LongCounter retryAttemptsTotal;
    private LongCounter tokenExchangeStepTotal;
    private DoubleHistogram tokenExchangeStepDurationSeconds;
    private LongCounter dynamicClientRegistrationTotal;
    private LongCounter oidcDiscoveryRequestsTotal;
    private LongCounter crossRegionDynamodbFailuresTotal;
    private LongCounter clientCredentialsGrantTotal;
    private LongCounter authorizeRedirectTotal;
    private DoubleHistogram userinfoDurationSeconds;
    private LongCounter authCodeValidationTotal;
    private LongCounter upstreamTokenCasAbortedPeerNewerTotal;
    private LongCounter upstreamTokenReplicationWaitTotal;
    private LongCounter upstreamOktaRevokedTotal;
    private LongCounter refreshTokenInflightLockTotal;
    private LongCounter refreshTokenInflightCacheServedTotal;
    private LongCounter refreshTokenGraceServedTotal;
    private LongCounter refreshTokenReplayRevokedTotal;
    private DoubleHistogram refreshTokenInflightLockWaitSeconds;
    private DoubleHistogram refreshTokenRotateHoldSeconds;
    private LongCounter upstreamOktaCacheTotal;
    private LongCounter upstreamPromotedCacheTotal;
    private LongCounter userinfoOktaCacheTotal;
    private LongCounter oktaSessionCacheEvictionsTotal;
    private LongCounter bearerIndexLookupTotal;
    private LongCounter bearerIndexWriteTotal;
    private LongCounter tokenResourceValidationTotal;
    private final AtomicReference<LongSupplier> oktaSessionCacheSizeSupplier = new AtomicReference<>(() -> 0L);
    /** Held to keep the asynchronous gauge alive (otherwise it can be GC'd by the SDK). */
    @SuppressWarnings("unused")
    private ObservableLongGauge oktaSessionCacheSizeGauge;

    @PostConstruct
    void init() {
        meter = GlobalOpenTelemetry.get().getMeter("mcp-oauth-proxy");

        httpErrors4xx = meter.counterBuilder("mop_http_errors_4xx").build();
        httpErrors5xx = meter.counterBuilder("mop_http_errors_5xx").build();
        errorsTotal = meter.counterBuilder("mop_errors_total").build();
        tokenIssuanceTotal = meter.counterBuilder("mop_token_issuance_total").build();
        authCodeExchangeTotal = meter.counterBuilder("mop_auth_code_exchange_total").build();
        refreshTokenExchangeTotal = meter.counterBuilder("mop_refresh_token_exchange_total").build();
        userinfoRequestsTotal = meter.counterBuilder("mop_userinfo_requests_total").build();
        crossRegionFallbackTriggeredTotal = meter.counterBuilder("mop_crossregion_fallback_triggered_total").build();
        crossRegionFallbackExhaustedTotal = meter.counterBuilder("mop_crossregion_fallback_exhausted_total").build();

        tokenExchangeDurationSeconds = meter.histogramBuilder("mop_token_exchange_duration_seconds")
                .setUnit("s")
                .setExplicitBucketBoundariesAdvice(HISTOGRAM_BUCKETS)
                .build();

        httpRequestsInflight = meter.upDownCounterBuilder("mop_http_requests_inflight").build();

        upstreamRequestDurationSeconds = meter.histogramBuilder("mop_upstream_request_duration_seconds")
                .setUnit("s")
                .setExplicitBucketBoundariesAdvice(HISTOGRAM_BUCKETS)
                .build();

        retryAttemptsTotal = meter.counterBuilder("mop_retry_attempts_total").build();
        tokenExchangeStepTotal = meter.counterBuilder("mop_token_exchange_step_total").build();
        tokenExchangeStepDurationSeconds = meter.histogramBuilder("mop_token_exchange_step_duration_seconds")
                .setUnit("s")
                .setExplicitBucketBoundariesAdvice(HISTOGRAM_BUCKETS)
                .build();

        dynamicClientRegistrationTotal = meter.counterBuilder("mop_dynamic_client_registration_total").build();
        oidcDiscoveryRequestsTotal = meter.counterBuilder("mop_oidc_discovery_requests_total").build();
        crossRegionDynamodbFailuresTotal = meter.counterBuilder("mop_cross_region_dynamodb_failures_total").build();
        clientCredentialsGrantTotal = meter.counterBuilder("mop_client_credentials_grant_total").build();
        authorizeRedirectTotal = meter.counterBuilder("mop_authorize_redirect_total").build();

        userinfoDurationSeconds = meter.histogramBuilder("mop_userinfo_duration_seconds")
                .setUnit("s")
                .setExplicitBucketBoundariesAdvice(HISTOGRAM_BUCKETS)
                .build();

        authCodeValidationTotal = meter.counterBuilder("mop_auth_code_validation_total").build();

        upstreamTokenCasAbortedPeerNewerTotal = meter
                .counterBuilder("mop_upstream_token_cas_aborted_peer_newer_total")
                .build();
        upstreamTokenReplicationWaitTotal = meter
                .counterBuilder("mop_upstream_token_replication_wait_total")
                .build();
        upstreamOktaRevokedTotal = meter
                .counterBuilder("mop_upstream_okta_revoked_total")
                .setDescription("Centralized Okta upstream-token rows soft-deleted (status flipped from ACTIVE) "
                        + "after Okta returned invalid_grant. Labels: reason=REVOKED_INVALID_GRANT|...")
                .build();

        refreshTokenInflightLockTotal = meter
                .counterBuilder("mop_refresh_token_inflight_lock_total")
                .setDescription("Per-RT distributed-lock attempts for the refresh-token rotate path")
                .build();
        refreshTokenInflightCacheServedTotal = meter
                .counterBuilder("mop_refresh_token_inflight_cache_served_total")
                .setDescription("Refresh-token rotate calls served from the per-pod in-flight result cache (singleflight hit)")
                .build();
        refreshTokenGraceServedTotal = meter
                .counterBuilder("mop_refresh_token_grace_served_total")
                .setDescription("Refresh-token validate() calls that hit ROTATED inside the grace window and were served from the family successor instead of revoking")
                .build();
        refreshTokenReplayRevokedTotal = meter
                .counterBuilder("mop_refresh_token_replay_revoked_total")
                .setDescription("Refresh-token replays that fell outside the grace window and triggered a family revoke (genuine stolen-RT defense)")
                .build();
        refreshTokenInflightLockWaitSeconds = meter
                .histogramBuilder("mop_refresh_token_inflight_lock_wait_seconds")
                .setUnit("s")
                .setDescription("Time spent waiting for the per-RT distributed lock (acquire returned acquired/timeout/interrupted)")
                .setExplicitBucketBoundariesAdvice(HISTOGRAM_BUCKETS)
                .build();
        refreshTokenRotateHoldSeconds = meter
                .histogramBuilder("mop_refresh_token_rotate_hold_seconds")
                .setUnit("s")
                .setDescription("Time the per-RT lock was held (acquire to release) inside RefreshTokenServiceImpl.rotate()")
                .setExplicitBucketBoundariesAdvice(HISTOGRAM_BUCKETS)
                .build();

        upstreamOktaCacheTotal = meter
                .counterBuilder("mop_upstream_okta_cache_total")
                .setDescription("Outcome of refreshUpstream() when the shared Okta upstream session cache is enabled. "
                        + "Labels: outcome=l0_hit|l1_hit|hit_post_lock|miss_refreshed.")
                .build();
        upstreamPromotedCacheTotal = meter
                .counterBuilder("mop_upstream_promoted_cache_total")
                .setDescription("Outcome of refreshUpstreamPromoted() for any provider on the L2 promotion path "
                        + "(google-* providers today). Labels: provider=<google-docs|google-slides|...>, "
                        + "outcome=l0_hit|hit_post_lock|reuse_within_grace|miss_refreshed.")
                .build();
        userinfoOktaCacheTotal = meter
                .counterBuilder("mop_userinfo_okta_cache_total")
                .setDescription("Outcome of /userinfo's id_token freshness branch when the shared Okta upstream "
                        + "session cache is enabled. Labels: outcome=fresh_hit|expired_refreshed|absent_refreshed|"
                        + "stale_claims_served.")
                .build();
        oktaSessionCacheEvictionsTotal = meter
                .counterBuilder("mop_okta_session_cache_evictions_total")
                .setDescription("Caffeine RemovalListener events on the per-pod Okta upstream session cache. "
                        + "Labels: reason=size|expired_write|explicit|collected.")
                .build();
        bearerIndexLookupTotal = meter
                .counterBuilder("mop_bearer_index_lookup_total")
                .setDescription("Outcome of /userinfo bearer-index lookups against the "
                        + "mcp-oauth-proxy-bearer-index DynamoDB table (and optional cross-region peer). "
                        + "Labels: outcome=hit|from_fallback|miss.")
                .build();
        bearerIndexWriteTotal = meter
                .counterBuilder("mop_bearer_index_write_total")
                .setDescription("Outcome of bearer-index writes from the five mint sites (login, "
                        + "token-exchange, refresh-grant rotation, warm-cache mint, /userinfo's Okta refresh). "
                        + "Labels: outcome=success|failure.")
                .build();
        tokenResourceValidationTotal = meter
                .counterBuilder("mop_token_resource_validation_total")
                .setDescription("Outcome of the RFC 8707 resource-indicator validation gate in "
                        + "TokenResource.generateTokenOAuth2 (the perimeter that rejects unknown "
                        + "resources with 400 invalid_target before any DB lookup, RT validation, "
                        + "or upstream call). Labels: "
                        + "outcome=accepted|rejected, reason=known_mapped|unknown_resource, "
                        + "oauth_grant_type=authorization_code|client_credentials|refresh_token|unknown, "
                        + "oauth_client. Absent/blank resource is not observed by design.")
                .build();
        oktaSessionCacheSizeGauge = meter
                .gaugeBuilder("mop_okta_session_cache_size")
                .ofLongs()
                .setDescription("Approximate per-pod entry count for the shared Okta upstream session cache (L0).")
                .buildWithCallback(measurement ->
                        measurement.record(oktaSessionCacheSizeSupplier.get().getAsLong(), Attributes.empty()));
    }

    /**
     * Registers initial zero samples so instruments and common label combinations appear in collectors
     * (e.g. Prometheus) before the first real event.
     */
    void onStartup(@Observes StartupEvent ignored) {
        bootstrapZeroSeries();
    }

    private void bootstrapZeroSeries() {
        Attributes empty = Attributes.empty();

        httpErrors4xx.add(0, empty);
        httpErrors5xx.add(0, empty);
        errorsTotal.add(0, empty);
        authCodeExchangeTotal.add(0, empty);
        refreshTokenExchangeTotal.add(0, empty);
        userinfoRequestsTotal.add(0, empty);
        crossRegionFallbackTriggeredTotal.add(0, empty);
        crossRegionFallbackExhaustedTotal.add(0, empty);

        tokenExchangeDurationSeconds.record(0.0, empty);

        upstreamRequestDurationSeconds.record(0.0, empty);

        retryAttemptsTotal.add(0, empty);
        tokenExchangeStepTotal.add(0, empty);
        tokenExchangeStepDurationSeconds.record(0.0, empty);

        dynamicClientRegistrationTotal.add(0, empty);
        oidcDiscoveryRequestsTotal.add(0, empty);
        crossRegionDynamodbFailuresTotal.add(0, empty);
        clientCredentialsGrantTotal.add(0, empty);
        authorizeRedirectTotal.add(0, empty);

        userinfoDurationSeconds.record(0.0, empty);

        authCodeValidationTotal.add(0, empty);
        upstreamTokenCasAbortedPeerNewerTotal.add(0, empty);

        Attributes replWaitSucceeded = Attributes.builder().put(OUTCOME, "succeeded").build();
        Attributes replWaitStillStale = Attributes.builder().put(OUTCOME, "still_stale").build();
        upstreamTokenReplicationWaitTotal.add(0, replWaitSucceeded);
        upstreamTokenReplicationWaitTotal.add(0, replWaitStillStale);

        upstreamOktaRevokedTotal.add(0, Attributes.builder()
                .put(REASON, "REVOKED_INVALID_GRANT").build());

        for (String outcome : List.of("acquired", "wait_succeeded", "timeout", "interrupted")) {
            refreshTokenInflightLockTotal.add(0, Attributes.builder().put(OUTCOME, outcome).build());
        }
        refreshTokenInflightCacheServedTotal.add(0, Attributes.empty());
        for (String path : List.of("token_age_only", "family_idle_validated", "family_idle_exceeded", "successor_unavailable")) {
            refreshTokenGraceServedTotal.add(0, Attributes.builder().put("grace_path", path).build());
        }
        refreshTokenReplayRevokedTotal.add(0, Attributes.empty());
        for (String outcome : List.of("acquired", "timeout", "interrupted")) {
            refreshTokenInflightLockWaitSeconds.record(0.0, Attributes.builder().put(OUTCOME, outcome).build());
        }
        for (String outcome : List.of("rotated_internal", "rotated_grace", "cache_hit_after_lock", "null_result")) {
            refreshTokenRotateHoldSeconds.record(0.0, Attributes.builder().put(OUTCOME, outcome).build());
        }

        for (String callSite : CROSS_REGION_FALLBACK_CALL_SITES) {
            Attributes triggeredAttrs = Attributes.builder()
                    .put(OAUTH_PROVIDER, OauthProviderLabel.UNKNOWN)
                    .put(OAUTH_OPERATION, callSite)
                    .put(PRIMARY_REGION, "")
                    .put(FALLBACK_REGION, "")
                    .build();
            crossRegionFallbackTriggeredTotal.add(0, triggeredAttrs);
            Attributes exhaustedAttrs = Attributes.builder()
                    .put(OAUTH_PROVIDER, OauthProviderLabel.UNKNOWN)
                    .put(OAUTH_OPERATION, callSite)
                    .put(PRIMARY_REGION, "")
                    .put(FALLBACK_REGION, "")
                    .put(HTTP_STATUS, "401")
                    .put(ERROR_TYPE, "not_found")
                    .build();
            crossRegionFallbackExhaustedTotal.add(0, exhaustedAttrs);
        }

        for (ExchangeStep step : ExchangeStep.values()) {
            Attributes stepAttrs = Attributes.builder()
                    .put(EXCHANGE_STEP, step.value())
                    .put(OAUTH_PROVIDER, "")
                    .put(OUTCOME, "success")
                    .put(OAUTH_CLIENT, "")
                    .put(REGION, "")
                    .build();
            tokenExchangeStepTotal.add(0, stepAttrs);
            tokenExchangeStepDurationSeconds.record(0.0, stepAttrs);
        }

        for (String reason : AuthCodeValidationReason.allFailureReasons()) {
            authCodeValidationTotal.add(0, Attributes.of(
                    OAUTH_PROVIDER, OauthProviderLabel.UNKNOWN,
                    ERROR_TYPE, reason));
        }

        for (String outcome : UPSTREAM_OKTA_CACHE_OUTCOMES) {
            upstreamOktaCacheTotal.add(0, Attributes.builder().put(OUTCOME, outcome).build());
        }
        for (String provider : UpstreamProviderClassifier.GOOGLE_WORKSPACE_PROVIDERS) {
            for (String outcome : UPSTREAM_PROMOTED_CACHE_OUTCOMES) {
                upstreamPromotedCacheTotal.add(0, Attributes.builder()
                        .put(OAUTH_PROVIDER, provider)
                        .put(OUTCOME, outcome)
                        .build());
            }
        }
        for (String outcome : USERINFO_OKTA_CACHE_OUTCOMES) {
            userinfoOktaCacheTotal.add(0, Attributes.builder().put(OUTCOME, outcome).build());
        }
        for (String reason : OKTA_SESSION_CACHE_EVICTION_REASONS) {
            oktaSessionCacheEvictionsTotal.add(0, Attributes.builder().put(REASON, reason).build());
        }
        for (String outcome : BEARER_INDEX_LOOKUP_OUTCOMES) {
            bearerIndexLookupTotal.add(0, Attributes.builder().put(OUTCOME, outcome).build());
        }
        for (String outcome : BEARER_INDEX_WRITE_OUTCOMES) {
            bearerIndexWriteTotal.add(0, Attributes.builder().put(OUTCOME, outcome).build());
        }
        for (List<String> outcomeReason : TOKEN_RESOURCE_VALIDATION_OUTCOMES) {
            for (String grant : List.of("authorization_code", "client_credentials", "refresh_token")) {
                tokenResourceValidationTotal.add(0, Attributes.builder()
                        .put(OUTCOME, outcomeReason.get(0))
                        .put(REASON, outcomeReason.get(1))
                        .put(OAUTH_GRANT_TYPE, grant)
                        .put(OAUTH_CLIENT, "")
                        .build());
            }
        }
    }

    public void recordHttp4xx(String method, String route, int status, String errorType,
                              String oauthProvider, String oauthClient) {
        httpErrors4xx.add(1, Attributes.of(
                HTTP_METHOD, nullToEmpty(method),
                HTTP_ROUTE, nullToEmpty(route),
                HTTP_STATUS, String.valueOf(status),
                ERROR_TYPE, nullToEmpty(errorType),
                OAUTH_PROVIDER, nullToEmpty(oauthProvider),
                OAUTH_CLIENT, nullToEmpty(oauthClient)));
    }

    public void recordHttp5xx(String method, String route, int status, String errorType,
                              String oauthProvider, String oauthClient) {
        httpErrors5xx.add(1, Attributes.of(
                HTTP_METHOD, nullToEmpty(method),
                HTTP_ROUTE, nullToEmpty(route),
                HTTP_STATUS, String.valueOf(status),
                ERROR_TYPE, nullToEmpty(errorType),
                OAUTH_PROVIDER, nullToEmpty(oauthProvider),
                OAUTH_CLIENT, nullToEmpty(oauthClient)));
    }

    public void recordErrorsTotal(String route, String errorType, int status,
                                  String oauthProvider, String oauthClient) {
        errorsTotal.add(1, Attributes.of(
                HTTP_ROUTE, nullToEmpty(route),
                ERROR_TYPE, nullToEmpty(errorType),
                HTTP_STATUS, String.valueOf(status),
                OAUTH_PROVIDER, nullToEmpty(oauthProvider),
                OAUTH_CLIENT, nullToEmpty(oauthClient)));
    }

    public void recordTokenIssuance(String oauthProvider, String oauthGrantType, boolean success,
                                    String errorType, String oauthClient) {
        String grant = (oauthGrantType == null || oauthGrantType.isBlank())
                ? OauthProviderLabel.UNKNOWN
                : oauthGrantType.trim();
        AttributesBuilder b = Attributes.builder()
                .put(OAUTH_PROVIDER, OauthProviderLabel.normalize(oauthProvider))
                .put(OAUTH_GRANT_TYPE, grant)
                .put(OUTCOME, success ? "success" : "failure")
                .put(OAUTH_CLIENT, OauthClientLabel.normalize(oauthClient));
        if (!success && errorType != null && !errorType.isEmpty()) {
            b.put(ERROR_TYPE, errorType);
        }
        tokenIssuanceTotal.add(1, b.build());
    }

    public void recordAuthCodeExchange(String oauthProvider, boolean success, int httpStatus,
                                       String errorType, String oauthClient) {
        AttributesBuilder b = Attributes.builder()
                .put(OAUTH_PROVIDER, nullToEmpty(oauthProvider))
                .put(OUTCOME, success ? "success" : "failure")
                .put(HTTP_STATUS, String.valueOf(httpStatus))
                .put(OAUTH_CLIENT, nullToEmpty(oauthClient));
        if (!success && errorType != null && !errorType.isEmpty()) {
            b.put(ERROR_TYPE, errorType);
        }
        authCodeExchangeTotal.add(1, b.build());
    }

    public void recordRefreshTokenExchange(String oauthProvider, boolean success, int httpStatus,
                                           String errorType, String oauthClient) {
        AttributesBuilder b = Attributes.builder()
                .put(OAUTH_PROVIDER, nullToEmpty(oauthProvider))
                .put(OUTCOME, success ? "success" : "failure")
                .put(HTTP_STATUS, String.valueOf(httpStatus))
                .put(OAUTH_CLIENT, nullToEmpty(oauthClient));
        if (!success && errorType != null && !errorType.isEmpty()) {
            b.put(ERROR_TYPE, errorType);
        }
        refreshTokenExchangeTotal.add(1, b.build());
    }

    public void recordUserinfoRequest(String oauthProvider, boolean success, int httpStatus,
                                      String errorType, String userinfoFailureReason) {
        AttributesBuilder b = Attributes.builder()
                .put(OAUTH_PROVIDER, nullToEmpty(oauthProvider))
                .put(OUTCOME, success ? "success" : "failure")
                .put(HTTP_STATUS, String.valueOf(httpStatus));
        if (!success && errorType != null && !errorType.isEmpty()) {
            b.put(ERROR_TYPE, errorType);
        }
        if (!success && userinfoFailureReason != null && !userinfoFailureReason.isEmpty()) {
            b.put(USERINFO_FAILURE_REASON, userinfoFailureReason);
        }
        userinfoRequestsTotal.add(1, b.build());
    }

    public void recordCrossRegionFallbackTriggered(String oauthProvider, String oauthOperation,
                                                   String primaryRegion, String fallbackRegion) {
        crossRegionFallbackTriggeredTotal.add(1, Attributes.of(
                OAUTH_PROVIDER, nullToEmpty(oauthProvider),
                OAUTH_OPERATION, nullToEmpty(oauthOperation),
                PRIMARY_REGION, nullToEmpty(primaryRegion),
                FALLBACK_REGION, nullToEmpty(fallbackRegion)));
    }

    public void recordCrossRegionFallbackExhausted(String oauthProvider, String oauthOperation,
                                                   String primaryRegion, String fallbackRegion,
                                                   int httpStatus, String errorType) {
        crossRegionFallbackExhaustedTotal.add(1, Attributes.of(
                OAUTH_PROVIDER, nullToEmpty(oauthProvider),
                OAUTH_OPERATION, nullToEmpty(oauthOperation),
                PRIMARY_REGION, nullToEmpty(primaryRegion),
                FALLBACK_REGION, nullToEmpty(fallbackRegion),
                HTTP_STATUS, String.valueOf(httpStatus),
                ERROR_TYPE, nullToEmpty(errorType)));
    }

    public void recordTokenExchangeDurationE2E(String oauthProvider, String oauthGrantType, boolean success,
                                               String oauthClient, String region, double seconds) {
        Attributes attrs = Attributes.builder()
                .put(OAUTH_PROVIDER, nullToEmpty(oauthProvider))
                .put(OAUTH_GRANT_TYPE, nullToEmpty(oauthGrantType))
                .put(OUTCOME, success ? "success" : "failure")
                .put(OAUTH_CLIENT, nullToEmpty(oauthClient))
                .put(REGION, nullToEmpty(region))
                .build();
        tokenExchangeDurationSeconds.record(seconds, attrs);
    }

    public void incHttpInflight(String route) {
        httpRequestsInflight.add(1, Attributes.of(HTTP_ROUTE, nullToEmpty(route)));
    }

    public void decHttpInflight(String route) {
        httpRequestsInflight.add(-1, Attributes.of(HTTP_ROUTE, nullToEmpty(route)));
    }

    public void recordUpstreamRequest(String oauthProvider, String upstreamEndpoint, int httpStatus,
                                      String region, double seconds) {
        upstreamRequestDurationSeconds.record(seconds, Attributes.of(
                OAUTH_PROVIDER, nullToEmpty(oauthProvider),
                UPSTREAM_ENDPOINT, nullToEmpty(upstreamEndpoint),
                HTTP_STATUS, String.valueOf(httpStatus),
                REGION, nullToEmpty(region)));
    }

    public void recordRetryAttempt(String oauthProvider, String oauthOperation, String region, String retryReason) {
        retryAttemptsTotal.add(1, Attributes.of(
                OAUTH_PROVIDER, nullToEmpty(oauthProvider),
                OAUTH_OPERATION, nullToEmpty(oauthOperation),
                REGION, nullToEmpty(region),
                RETRY_REASON, nullToEmpty(retryReason)));
    }

    public void recordExchangeStep(ExchangeStep step, String oauthProvider, boolean success,
                                   String errorType, String oauthClient, String region, double seconds) {
        AttributesBuilder b = Attributes.builder()
                .put(EXCHANGE_STEP, step.value())
                .put(OAUTH_PROVIDER, nullToEmpty(oauthProvider))
                .put(OUTCOME, success ? "success" : "failure")
                .put(OAUTH_CLIENT, nullToEmpty(oauthClient))
                .put(REGION, nullToEmpty(region));
        if (!success && errorType != null && !errorType.isEmpty()) {
            b.put(ERROR_TYPE, errorType);
        }
        Attributes attrs = b.build();
        tokenExchangeStepTotal.add(1, attrs);
        tokenExchangeStepDurationSeconds.record(seconds, attrs);
    }

    public void recordDynamicClientRegistration(boolean success, String errorType, String oauthClient) {
        AttributesBuilder b = Attributes.builder()
                .put(OUTCOME, success ? "success" : "failure")
                .put(OAUTH_CLIENT, nullToEmpty(oauthClient));
        if (!success && errorType != null && !errorType.isEmpty()) {
            b.put(ERROR_TYPE, errorType);
        }
        dynamicClientRegistrationTotal.add(1, b.build());
    }

    public void recordOidcDiscovery(String endpoint, boolean success, String errorType) {
        AttributesBuilder b = Attributes.builder()
                .put(ENDPOINT, nullToEmpty(endpoint))
                .put(OUTCOME, success ? "success" : "failure");
        if (!success && errorType != null && !errorType.isEmpty()) {
            b.put(ERROR_TYPE, errorType);
        }
        oidcDiscoveryRequestsTotal.add(1, b.build());
    }

    public void recordCrossRegionDynamoFailure(String operation, String errorType, String oauthProvider) {
        crossRegionDynamodbFailuresTotal.add(1, Attributes.of(
                OPERATION, nullToEmpty(operation),
                ERROR_TYPE, nullToEmpty(errorType),
                OAUTH_PROVIDER, nullToEmpty(oauthProvider)));
    }

    public void recordClientCredentialsGrant(boolean success, String errorType, String oauthClient) {
        AttributesBuilder b = Attributes.builder()
                .put(OUTCOME, success ? "success" : "failure")
                .put(OAUTH_CLIENT, nullToEmpty(oauthClient));
        if (!success && errorType != null && !errorType.isEmpty()) {
            b.put(ERROR_TYPE, errorType);
        }
        clientCredentialsGrantTotal.add(1, b.build());
    }

    public void recordAuthorizeRedirect(String oauthProvider, boolean success, String errorType, String oauthClient) {
        AttributesBuilder b = Attributes.builder()
                .put(OAUTH_PROVIDER, nullToEmpty(oauthProvider))
                .put(OUTCOME, success ? "success" : "failure")
                .put(OAUTH_CLIENT, nullToEmpty(oauthClient));
        if (!success && errorType != null && !errorType.isEmpty()) {
            b.put(ERROR_TYPE, errorType);
        }
        authorizeRedirectTotal.add(1, b.build());
    }

    public void recordUserinfoDuration(String oauthProvider, boolean success,
                                       String userinfoFailureReason, double seconds) {
        AttributesBuilder b = Attributes.builder()
                .put(OAUTH_PROVIDER, nullToEmpty(oauthProvider))
                .put(OUTCOME, success ? "success" : "failure");
        if (!success && userinfoFailureReason != null && !userinfoFailureReason.isEmpty()) {
            b.put(USERINFO_FAILURE_REASON, userinfoFailureReason);
        }
        userinfoDurationSeconds.record(seconds, b.build());
    }

    /**
     * Increment when {@code UpstreamRefreshService} aborts the local centralized-Okta-refresh CAS
     * write because the cross-region peer carries a newer {@code version}, or because the row is
     * only present in the peer region. The local pod skips both the Okta refresh call and the
     * local CAS in this case; replication is expected to catch up before the next /token call.
     */
    public void recordUpstreamTokenCasAbortedPeerNewer(String providerUserId) {
        upstreamTokenCasAbortedPeerNewerTotal.add(1, Attributes.empty());
    }

    /**
     * Record the outcome of an in-process replication wait performed by
     * {@code UpstreamRefreshService} when it detects the peer region has a newer view of the
     * upstream-token row. {@code outcome} should be {@code "succeeded"} (peer caught up locally
     * after the sleep) or {@code "still_stale"} (we still see the peer ahead and abort transient).
     */
    public void recordUpstreamTokenReplicationWait(String outcome) {
        upstreamTokenReplicationWaitTotal.add(1, Attributes.builder().put(OUTCOME, outcome).build());
    }

    /**
     * Records every soft-delete of a centralized Okta upstream-token row. Today fires only on
     * Okta {@code invalid_grant} responses (with {@code reason="REVOKED_INVALID_GRANT"}); the
     * label is left open so future revoke causes (admin revoke, scheduled cleanup, etc.) can be
     * distinguished without a new counter.
     *
     * @param reason a {@code STATUS_REVOKED_*} constant from {@code UpstreamTokenRecord}
     */
    public void recordUpstreamOktaRevoked(String reason) {
        upstreamOktaRevokedTotal.add(1, Attributes.builder().put(REASON, nullToEmpty(reason)).build());
    }

    /**
     * Outcome of trying to take the per-RT distributed lock guarding the rotate path.
     * {@code outcome} is one of: {@code acquired} (this caller won and rotated),
     * {@code wait_succeeded} (lost the race; waited and reused another caller's result),
     * {@code timeout} (could not get the lock after retries — surface as transient),
     * {@code interrupted} (thread interrupted while waiting).
     */
    public void recordRefreshTokenInflightLock(String outcome) {
        refreshTokenInflightLockTotal.add(1, Attributes.builder().put(OUTCOME, nullToEmpty(outcome)).build());
    }

    /**
     * Increments when a concurrent caller presenting the same RT was served from the per-pod
     * in-flight result cache (singleflight hit). Pure win: avoided one DDB transactWrite.
     */
    public void recordRefreshTokenInflightCacheServed() {
        refreshTokenInflightCacheServedTotal.add(1, Attributes.empty());
    }

    /**
     * Increments when {@code validate()} hit a {@code ROTATED} row and resolved against the
     * grace path. {@code path} values:
     * <ul>
     *   <li>{@code token_age_only} — token-age predicate passed, family-idle gate disabled
     *       ({@code familyIdleGraceSeconds=0}). Caller will be served from the family successor.</li>
     *   <li>{@code family_idle_validated} — both predicates passed (token-age AND family-idle).
     *       Caller will be served from the family successor. This is the safer "post-Paranoids"
     *       configuration.</li>
     *   <li>{@code family_idle_exceeded} — token-age passed but family-idle gate failed; the
     *       family appears abandoned. Caller falls through to {@code ROTATED_REPLAY} → revoke.</li>
     *   <li>{@code successor_unavailable} — grace would apply but no live ACTIVE successor was
     *       found in the family (e.g. all leaves revoked/expired). Falls through to revoke.</li>
     * </ul>
     */
    public void recordRefreshTokenGraceServed(String path) {
        refreshTokenGraceServedTotal.add(1, Attributes.builder().put("grace_path", nullToEmpty(path)).build());
    }

    /**
     * Increments when a refresh-token replay fell outside the grace window and triggered the
     * family revoke. This is the genuine stolen-RT defense path; it should be near zero in a
     * healthy fleet.
     */
    public void recordRefreshTokenReplayRevoked() {
        refreshTokenReplayRevokedTotal.add(1, Attributes.empty());
    }

    /**
     * Wall-clock time spent inside {@code tryAcquirePerRtLock} (across all backoff sleeps and
     * DDB conditional-write attempts) until the loop terminated. {@code outcome} mirrors the
     * label values used by {@link #recordRefreshTokenInflightLock(String)} for the terminal
     * states (acquired, timeout, interrupted). Use this to size {@code inflight-lock-max-retries}
     * and {@code inflight-lock-initial-backoff-ms}: the {@code acquired} p99 should be well
     * inside the configured retry budget.
     */
    public void recordRefreshTokenInflightLockWait(String outcome, double seconds) {
        refreshTokenInflightLockWaitSeconds.record(seconds, Attributes.builder()
                .put(OUTCOME, nullToEmpty(outcome)).build());
    }

    /**
     * Wall-clock time the per-RT lock was actually held by {@code rotate()} — from successful
     * acquire through the {@code finally} block that releases it. This is the work the lock
     * protects (read row, validate, TransactWriteItems, populate cache). Compare its p99 to
     * {@code inflight-lock-ttl-seconds}: there should be a comfortable margin so the lock
     * never expires mid-rotation under DDB throttling. {@code outcome} values:
     * <ul>
     *   <li>{@code rotated_internal} — full rotate completed and returned a new RT.</li>
     *   <li>{@code rotated_grace} — re-check found another caller's cached result; returned that.</li>
     *   <li>{@code cache_hit_after_lock} — same as {@code rotated_grace} but emphasizes the cache hit.</li>
     *   <li>{@code null_result} — rotateInternal returned null (e.g. row not found, validation failed).</li>
     * </ul>
     */
    public void recordRefreshTokenRotateHold(String outcome, double seconds) {
        refreshTokenRotateHoldSeconds.record(seconds, Attributes.builder()
                .put(OUTCOME, nullToEmpty(outcome)).build());
    }

    /**
     * Authorization code validate/consume failures (missing code, replay, PKCE, binding, etc.).
     * {@code failureReason} should be a {@link AuthCodeValidationReason} constant.
     */
    public void recordAuthCodeValidationFailure(String oauthProvider, String failureReason) {
        authCodeValidationTotal.add(1, Attributes.of(
                OAUTH_PROVIDER, OauthProviderLabel.normalize(oauthProvider),
                ERROR_TYPE, nullToEmpty(failureReason)));
    }

    /**
     * Records the outcome of a single {@code UpstreamRefreshService.refreshUpstream(...)} call
     * when the shared Okta upstream session cache is enabled.
     *
     * @param outcome one of {@code l0_hit}, {@code l1_hit}, {@code hit_post_lock}, {@code miss_refreshed}.
     */
    public void recordUpstreamOktaCacheOutcome(String outcome) {
        upstreamOktaCacheTotal.add(1, Attributes.builder().put(OUTCOME, nullToEmpty(outcome)).build());
    }

    /**
     * Records the outcome of {@code refreshUpstreamPromoted} for any provider on the L2 path.
     * Counterpart to {@link #recordUpstreamOktaCacheOutcome(String)} but with a {@code provider}
     * label so dashboards can break down per-google-workspace-product cache effectiveness.
     *
     * @param provider one of the google-workspace provider strings (see
     *                 {@link UpstreamProviderClassifier#GOOGLE_WORKSPACE_PROVIDERS}).
     * @param outcome  one of {@code l0_hit}, {@code hit_post_lock}, {@code reuse_within_grace},
     *                 {@code miss_refreshed}.
     */
    public void recordUpstreamPromotedCacheOutcome(String provider, String outcome) {
        upstreamPromotedCacheTotal.add(1, Attributes.builder()
                .put(OAUTH_PROVIDER, nullToEmpty(provider))
                .put(OUTCOME, nullToEmpty(outcome))
                .build());
    }

    /**
     * Records the outcome of {@code /userinfo}'s id_token freshness branch when the shared
     * Okta upstream session cache is enabled.
     *
     * @param outcome one of {@code fresh_hit}, {@code expired_refreshed}, {@code absent_refreshed},
     *                {@code stale_claims_served}.
     */
    public void recordUserinfoOktaCacheOutcome(String outcome) {
        userinfoOktaCacheTotal.add(1, Attributes.builder().put(OUTCOME, nullToEmpty(outcome)).build());
    }

    /**
     * Records a Caffeine eviction event from the per-pod Okta upstream session cache.
     *
     * @param reason one of {@code size}, {@code expired_write}, {@code explicit}, {@code collected}.
     */
    public void recordOktaSessionCacheEviction(String reason) {
        oktaSessionCacheEvictionsTotal.add(1, Attributes.builder().put(REASON, nullToEmpty(reason)).build());
    }

    /**
     * Wires the per-pod Okta upstream session cache into the {@code mop_okta_session_cache_size}
     * observable gauge. Called once at cache initialization. Replacing the supplier is safe;
     * the gauge always reads the latest registered supplier.
     */
    public void registerOktaSessionCacheSizeGauge(LongSupplier supplier) {
        if (supplier != null) {
            oktaSessionCacheSizeSupplier.set(supplier);
        }
    }

    /**
     * Records the outcome of a bearer-index lookup performed by /userinfo against the new
     * {@code mcp-oauth-proxy-bearer-index} table (with optional cross-region peer fallback).
     *
     * @param outcome one of {@code hit}, {@code from_fallback}, {@code miss}
     */
    public void recordBearerIndexLookup(String outcome) {
        bearerIndexLookupTotal.add(1, Attributes.builder().put(OUTCOME, nullToEmpty(outcome)).build());
    }

    /**
     * Records the outcome of a bearer-index write attempt at one of the five mint sites.
     *
     * @param success {@code true} when the put returned without throwing; {@code false} when the
     *                bearer-index write threw and was swallowed by the caller (the bearer is still
     *                returned to the MCP client; /userinfo will 401 once and the client refresh
     *                will repopulate).
     */
    public void recordBearerIndexWrite(boolean success) {
        bearerIndexWriteTotal.add(1, Attributes.builder()
                .put(OUTCOME, success ? "success" : "failure")
                .build());
    }

    /**
     * Records the outcome of the RFC 8707 §2 resource-indicator validation gate in
     * {@code TokenResource.generateTokenOAuth2}. Emit one sample per /token request whose wire
     * {@code resource} parameter was non-blank (absent/blank is intentionally not observed).
     *
     * @param accepted {@code true} when the resource resolved to a known {@code ResourceMeta}
     *                 (proceeds to per-grant handler); {@code false} when it did not (rejected
     *                 with 400 {@code invalid_target}).
     * @param reason   classification: {@code known_mapped} for accepted, {@code unknown_resource}
     *                 for rejected. The label is kept open so future failure shapes
     *                 (e.g. {@code malformed_uri}) can be added without a new counter.
     * @param oauthGrantType wire {@code grant_type}, or {@code "unknown"} if missing.
     * @param oauthClient    normalized client id (empty string if absent).
     */
    public void recordTokenResourceValidation(boolean accepted, String reason,
                                              String oauthGrantType, String oauthClient) {
        tokenResourceValidationTotal.add(1, Attributes.builder()
                .put(OUTCOME, accepted ? "accepted" : "rejected")
                .put(REASON, nullToEmpty(reason))
                .put(OAUTH_GRANT_TYPE, nullToEmpty(oauthGrantType))
                .put(OAUTH_CLIENT, nullToEmpty(oauthClient))
                .build());
    }

    private static String nullToEmpty(String s) {
        return s != null ? s : "";
    }
}
