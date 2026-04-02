/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import com.yahoo.athenz.common.metrics.Metric;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class MopOtelMetricFactoryTest {

    @Test
    void create_returnsMetric() {
        MopOtelMetricFactory factory = new MopOtelMetricFactory();
        Metric metric = factory.create();
        assertNotNull(metric);
    }
}
