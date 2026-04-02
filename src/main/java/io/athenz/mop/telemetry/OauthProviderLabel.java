/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import java.util.Locale;

/**
 * Normalizes provider strings for the {@code oauth_provider} metric label: trim + lowercase.
 * Known IdPs map to canonical names; any other non-blank value is passed through (watch label cardinality).
 */
public final class OauthProviderLabel {

    public static final String UNKNOWN = "unknown";
    public static final String OKTA = "okta";
    public static final String GLEAN = "glean";
    public static final String GITHUB = "github";
    public static final String GOOGLE = "google";
    public static final String ATLASSIAN = "atlassian";
    public static final String ATHENZ = "athenz";
    public static final String GOOGLE_MONITORING = "google-monitoring";
    public static final String GOOGLE_LOGGING = "google-logging";

    private OauthProviderLabel() {
    }

    public static String normalize(String raw) {
        if (raw == null || raw.isBlank()) {
            return UNKNOWN;
        }
        String s = raw.trim().toLowerCase(Locale.ROOT);
        return switch (s) {
            case OKTA, GLEAN, GITHUB, GOOGLE, ATLASSIAN, ATHENZ, GOOGLE_MONITORING, GOOGLE_LOGGING -> s;
            default -> s;
        };
    }
}
