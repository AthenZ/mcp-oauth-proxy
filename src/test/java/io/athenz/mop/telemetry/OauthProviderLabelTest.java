/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class OauthProviderLabelTest {

    @Test
    void normalize_nullOrBlank_returnsUnknown() {
        assertEquals(OauthProviderLabel.UNKNOWN, OauthProviderLabel.normalize(null));
        assertEquals(OauthProviderLabel.UNKNOWN, OauthProviderLabel.normalize(""));
        assertEquals(OauthProviderLabel.UNKNOWN, OauthProviderLabel.normalize("  "));
    }

    @Test
    void normalize_knownProviders_preservedLowercase() {
        assertEquals(OauthProviderLabel.OKTA, OauthProviderLabel.normalize("OKTA"));
        assertEquals(OauthProviderLabel.GITHUB, OauthProviderLabel.normalize(" github "));
        assertEquals(OauthProviderLabel.GOOGLE_MONITORING, OauthProviderLabel.normalize("Google-Monitoring"));
    }

    @Test
    void normalize_unlistedProvider_returnsTrimmedLowercase() {
        assertEquals("custom-idp", OauthProviderLabel.normalize("custom-idp"));
        assertEquals("my_tenant_okta", OauthProviderLabel.normalize("  MY_TENANT_OKTA  "));
    }
}
