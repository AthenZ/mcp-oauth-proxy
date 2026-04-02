/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ExchangeStepTest {

    @Test
    void everyStep_hasNonEmptyValue() {
        for (ExchangeStep s : ExchangeStep.values()) {
            assertNotNull(s.value());
            assertFalse(s.value().isEmpty());
        }
    }
}
