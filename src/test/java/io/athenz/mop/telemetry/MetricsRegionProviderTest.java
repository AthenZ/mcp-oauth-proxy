/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import java.lang.reflect.Field;
import java.util.Optional;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MetricsRegionProviderTest {

    @Test
    void primaryRegion_usesConfiguredValueTrimmed() throws Exception {
        MetricsRegionProvider p = new MetricsRegionProvider();
        Field f = MetricsRegionProvider.class.getDeclaredField("configuredRegion");
        f.setAccessible(true);
        f.set(p, Optional.of("  us-east-1  "));
        assertEquals("us-east-1", p.primaryRegion());
    }

    @Test
    void primaryRegion_blankOptional_fallsBackToEnvOrUnknown() throws Exception {
        MetricsRegionProvider p = new MetricsRegionProvider();
        Field f = MetricsRegionProvider.class.getDeclaredField("configuredRegion");
        f.setAccessible(true);
        f.set(p, Optional.of("   "));
        String region = p.primaryRegion();
        String env = System.getenv("AWS_REGION");
        if (env != null && !env.isEmpty()) {
            assertEquals(env, region);
        } else {
            assertEquals("unknown", region);
        }
    }
}
