/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import jakarta.enterprise.context.ApplicationScoped;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class MetricsRegionProvider {

    @ConfigProperty(name = "server.metrics.region")
    Optional<String> configuredRegion;

    public String primaryRegion() {
        return configuredRegion
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .orElseGet(() -> {
                    String env = System.getenv("AWS_REGION");
                    return env != null && !env.isEmpty() ? env : "unknown";
                });
    }
}
