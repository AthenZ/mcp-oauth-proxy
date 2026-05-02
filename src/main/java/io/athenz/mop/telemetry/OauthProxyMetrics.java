/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.metrics.DoubleHistogram;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.LongUpDownCounter;
import io.opentelemetry.api.metrics.Meter;
import io.quarkus.runtime.StartupEvent;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import java.util.List;

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

    private static final List<String> CROSS_REGION_FALLBACK_CALL_SITES = List.of(
            "authorize_user_token",
            "authorizer_get_user_token",
            "userinfo_token_lookup",
            "userinfo_okta_lookup",
            "refresh_token_validate",
            "refresh_token_get_pk",
            "refresh_token_get_upstream",
            "upstream_token_get",
            "auth_code_tokens_get");

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
    private LongCounter refreshTokenInflightLockTotal;
    private LongCounter refreshTokenInflightCacheServedTotal;
    private LongCounter refreshTokenGraceServedTotal;
    private LongCounter refreshTokenReplayRevokedTotal;
    private DoubleHistogram refreshTokenInflightLockWaitSeconds;
    private DoubleHistogram refreshTokenRotateHoldSeconds;

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

    private static String nullToEmpty(String s) {
        return s != null ? s : "";
    }
}
