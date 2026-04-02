/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.quarkus;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.OpenTelemetry;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import java.lang.invoke.MethodHandles;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Confirms OpenTelemetry is available at runtime (Quarkus uses JBoss LogManager; log correlation
 * uses {@code quarkus.otel} logs exporter when enabled, not Logback {@code OpenTelemetryAppender}).
 */
@ApplicationScoped
public class OtelStartupObserver {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    void onStart(@Observes StartupEvent ev) {
        OpenTelemetry otel = GlobalOpenTelemetry.get();
        log.info("OpenTelemetry GlobalOpenTelemetry initialized: class={}", otel.getClass().getName());
    }
}
