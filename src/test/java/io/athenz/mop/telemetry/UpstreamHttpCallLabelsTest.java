/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class UpstreamHttpCallLabelsTest {

    @Test
    void withLabels_setsThreadLocalsAndClearsOnClose() {
        assertNull(UpstreamHttpCallLabels.oauthProvider());
        assertNull(UpstreamHttpCallLabels.upstreamEndpoint());

        try (var ignored = UpstreamHttpCallLabels.withLabels("okta", UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN)) {
            assertEquals("okta", UpstreamHttpCallLabels.oauthProvider());
            assertEquals(UpstreamHttpCallLabels.ENDPOINT_OAUTH_TOKEN, UpstreamHttpCallLabels.upstreamEndpoint());
        }

        assertNull(UpstreamHttpCallLabels.oauthProvider());
        assertNull(UpstreamHttpCallLabels.upstreamEndpoint());
    }

    @Test
    void nestedScopes_innerCloseClearsThreadLocals_doesNotRestoreOuter() {
        try (var outer = UpstreamHttpCallLabels.withLabels("a", "ep1")) {
            assertEquals("a", UpstreamHttpCallLabels.oauthProvider());
            try (var inner = UpstreamHttpCallLabels.withLabels("b", "ep2")) {
                assertEquals("b", UpstreamHttpCallLabels.oauthProvider());
                assertEquals("ep2", UpstreamHttpCallLabels.upstreamEndpoint());
            }
            // Current implementation: single ThreadLocal; inner close() clears both.
            assertNull(UpstreamHttpCallLabels.oauthProvider());
            assertNull(UpstreamHttpCallLabels.upstreamEndpoint());
        }
        assertNull(UpstreamHttpCallLabels.oauthProvider());
    }
}
