/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Logs OpenTelemetry configuration once at startup so operators can confirm MoP is configured to
 * export metrics (and that {@code quarkus.otel.metrics.enabled} is on — it defaults to false in Quarkus).
 */
@ApplicationScoped
public class OtelTelemetryDiagnostics {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    @ConfigProperty(name = "quarkus.otel.enabled", defaultValue = "false")
    boolean otelEnabled;

    @Inject
    @ConfigProperty(name = "quarkus.otel.metrics.enabled", defaultValue = "false")
    boolean otelMetricsEnabled;

    @Inject
    @ConfigProperty(name = "quarkus.otel.exporter.otlp.endpoint")
    Optional<String> otlpEndpoint;

    @Inject
    @ConfigProperty(name = "quarkus.otel.exporter.otlp.metrics.endpoint")
    Optional<String> otlpMetricsEndpoint;

    void onStartup(@Observes StartupEvent ignored) {
        String meterProvider = GlobalOpenTelemetry.get().getMeterProvider().getClass().getName();
        log.info(
                "MoP OpenTelemetry diagnostics: quarkus.otel.enabled={} quarkus.otel.metrics.enabled={} "
                        + "otlp.endpoint={} otlp.metrics.endpoint={} GlobalOpenTelemetry.meterProvider={} "
                        + "(custom metrics use meter \"mcp-oauth-proxy\", names prefixed mop_; "
                        + "for export failures set log category io.opentelemetry.exporter.internal.http to DEBUG)",
                otelEnabled,
                otelMetricsEnabled,
                otlpEndpoint.orElse(""),
                otlpMetricsEndpoint.orElse("(same as otlp.endpoint)"),
                meterProvider);
    }
}
