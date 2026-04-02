/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TelemetryRequestContextTest {

    private TelemetryRequestContext ctx;

    @BeforeEach
    void setUp() {
        ctx = new TelemetryRequestContext();
    }

    @Test
    void defaults() {
        assertEquals(OauthProviderLabel.UNKNOWN, ctx.oauthProvider());
        assertEquals(OauthProviderLabel.UNKNOWN, ctx.oauthClient());
        assertEquals("/", ctx.normalizedRoute());
    }

    @Test
    void setOauthProvider_nullOrEmpty_becomesUnknown() {
        ctx.setOauthProvider(null);
        assertEquals(OauthProviderLabel.UNKNOWN, ctx.oauthProvider());
        ctx.setOauthProvider("");
        assertEquals(OauthProviderLabel.UNKNOWN, ctx.oauthProvider());
        ctx.setOauthProvider("okta");
        assertEquals("okta", ctx.oauthProvider());
    }

    @Test
    void setOauthClient_nullOrEmpty_becomesUnknown() {
        ctx.setOauthClient(null);
        assertEquals(OauthProviderLabel.UNKNOWN, ctx.oauthClient());
        ctx.setOauthClient("");
        assertEquals(OauthProviderLabel.UNKNOWN, ctx.oauthClient());
        ctx.setOauthClient("cid");
        assertEquals("cid", ctx.oauthClient());
    }

    @Test
    void setNormalizedRoute_nullOrEmpty_becomesSlash() {
        ctx.setNormalizedRoute(null);
        assertEquals("/", ctx.normalizedRoute());
        ctx.setNormalizedRoute("");
        assertEquals("/", ctx.normalizedRoute());
        ctx.setNormalizedRoute("/token");
        assertEquals("/token", ctx.normalizedRoute());
    }
}
