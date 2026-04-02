/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.metrics.impl.OpenTelemetryMetric;
import io.opentelemetry.api.GlobalOpenTelemetry;
import jakarta.enterprise.context.ApplicationScoped;

/**
 * B2B-style factory: Athenz {@link OpenTelemetryMetric} bound to the same {@link GlobalOpenTelemetry}
 * instance as {@link OauthProxyMetrics} (meter name {@code mcp-oauth-proxy}).
 */
@ApplicationScoped
public class MopOtelMetricFactory {

    public Metric create() {
        return new OpenTelemetryMetric(GlobalOpenTelemetry.get(), "mcp-oauth-proxy", false, false, false, false);
    }
}
