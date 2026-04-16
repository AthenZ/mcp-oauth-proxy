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
        assertEquals(OauthProviderLabel.EMBRACE, OauthProviderLabel.normalize("EMBRACE"));
        assertEquals(OauthProviderLabel.GOOGLE_DRIVE, OauthProviderLabel.normalize("Google-Drive"));
        assertEquals(OauthProviderLabel.GOOGLE_CLOUD_PLATFORM, OauthProviderLabel.normalize("Google-Cloud-Platform"));
        assertEquals(OauthProviderLabel.GOOGLE_MONITORING, OauthProviderLabel.normalize("Google-Monitoring"));
    }

    @Test
    void normalize_googleWorkspaceProviders_preservedLowercase() {
        assertEquals(OauthProviderLabel.GOOGLE_DOCS, OauthProviderLabel.normalize("Google-Docs"));
        assertEquals(OauthProviderLabel.GOOGLE_SHEETS, OauthProviderLabel.normalize("Google-Sheets"));
        assertEquals(OauthProviderLabel.GOOGLE_SLIDES, OauthProviderLabel.normalize("Google-Slides"));
        assertEquals(OauthProviderLabel.GOOGLE_GMAIL, OauthProviderLabel.normalize("Google-Gmail"));
        assertEquals(OauthProviderLabel.GOOGLE_CALENDAR, OauthProviderLabel.normalize("Google-Calendar"));
        assertEquals(OauthProviderLabel.GOOGLE_TASKS, OauthProviderLabel.normalize("Google-Tasks"));
        assertEquals(OauthProviderLabel.GOOGLE_CHAT, OauthProviderLabel.normalize("Google-Chat"));
        assertEquals(OauthProviderLabel.GOOGLE_FORMS, OauthProviderLabel.normalize("Google-Forms"));
        assertEquals(OauthProviderLabel.GOOGLE_KEEP, OauthProviderLabel.normalize("Google-Keep"));
        assertEquals(OauthProviderLabel.GOOGLE_MEET, OauthProviderLabel.normalize("Google-Meet"));
    }

    @Test
    void normalize_gcpPathSlugs_mapToGoogleAudienceNames() {
        assertEquals(OauthProviderLabel.GOOGLE_MONITORING, OauthProviderLabel.normalize("gcp-monitoring"));
        assertEquals(OauthProviderLabel.GOOGLE_LOGGING, OauthProviderLabel.normalize("gcp-logging"));
    }

    @Test
    void normalize_databricksProviders_preservedLowercase() {
        assertEquals(OauthProviderLabel.DATABRICKS_SQL, OauthProviderLabel.normalize("Databricks-Sql"));
        assertEquals(OauthProviderLabel.DATABRICKS_VECTOR_SEARCH, OauthProviderLabel.normalize("Databricks-Vector-Search"));
        assertEquals(OauthProviderLabel.DATABRICKS_VECTOR_SEARCH, OauthProviderLabel.normalize("DATABRICKS-VECTOR-SEARCH"));
    }

    @Test
    void normalize_unlistedProvider_returnsTrimmedLowercase() {
        assertEquals("custom-idp", OauthProviderLabel.normalize("custom-idp"));
        assertEquals("my_tenant_okta", OauthProviderLabel.normalize("  MY_TENANT_OKTA  "));
    }
}
