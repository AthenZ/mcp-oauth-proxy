/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Uses the JVM's existing {@link io.opentelemetry.api.GlobalOpenTelemetry} (Quarkus initializes it once).
 * Does not call {@code GlobalOpenTelemetry.set}, which is only allowed once per process.
 */
class OauthProxyMetricsTest {

    @Test
    void init_bootstrap_andRecord_doNotThrow() {
        OauthProxyMetrics m = new OauthProxyMetrics();
        assertDoesNotThrow(() -> {
            m.init();
            m.onStartup(null);
            m.recordAuthCodeValidationFailure(OauthProviderLabel.OKTA, AuthCodeValidationReason.EXPIRED);
            m.recordHttp4xx("GET", "/token", 400, "bad_request", "okta", "c1");
            m.recordTokenIssuance("okta", "authorization_code", true, null, "c1");
            // RFC 8707 resource-validation gate: both label permutations + the absent-resource
            // contract (the gate caller never invokes this for absent/blank resource).
            m.recordTokenResourceValidation(true, "known_mapped", "refresh_token", "c1");
            m.recordTokenResourceValidation(false, "unknown_resource", "refresh_token", "c1");
            m.recordTokenResourceValidation(false, "unknown_resource", "authorization_code", "c1");
            m.recordTokenResourceValidation(false, "unknown_resource", "client_credentials", "c1");
        });
    }
}
