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
 * <p>
 * GCP Monitoring/Logging/BigQuery MCPs use URL paths like {@code .../v1/gcp-monitoring/mcp}, but metrics
 * use the configured resource {@code audience} values {@code google-monitoring}, {@code google-logging},
 * and {@code google-bigquery}. Path-style {@code gcp-monitoring} / {@code gcp-logging} /
 * {@code gcp-bigquery} inputs are aliased to those canonical names.
 */
public final class OauthProviderLabel {

    public static final String UNKNOWN = "unknown";
    public static final String OKTA = "okta";
    public static final String GLEAN = "glean";
    public static final String GITHUB = "github";
    public static final String EMBRACE = "embrace";
    public static final String GOOGLE_DRIVE = "google-drive";
    public static final String GOOGLE_DOCS = "google-docs";
    public static final String GOOGLE_SHEETS = "google-sheets";
    public static final String GOOGLE_SLIDES = "google-slides";
    public static final String GOOGLE_GMAIL = "google-gmail";
    public static final String GOOGLE_CALENDAR = "google-calendar";
    public static final String GOOGLE_TASKS = "google-tasks";
    public static final String GOOGLE_CHAT = "google-chat";
    public static final String GOOGLE_FORMS = "google-forms";
    public static final String GOOGLE_KEEP = "google-keep";
    public static final String GOOGLE_MEET = "google-meet";
    public static final String GOOGLE_CLOUD_PLATFORM = "google-cloud-platform";
    public static final String ATLASSIAN = "atlassian";
    public static final String ATHENZ = "athenz";
    public static final String GOOGLE_MONITORING = "google-monitoring";
    public static final String GOOGLE_LOGGING = "google-logging";
    public static final String GOOGLE_BIGQUERY = "google-bigquery";
    public static final String DATABRICKS_SQL = "databricks-sql";
    public static final String DATABRICKS_VECTOR_SEARCH = "databricks-vector-search";
    public static final String SLACK = "slack";
    public static final String FIGMA = "figma";
    public static final String ROOTLY = "rootly";
    public static final String DATADOG = "datadog";
    public static final String LINEAR = "linear";
    public static final String ORACLE_EPM = "oracle-epm";
    public static final String WISDOMAI = "wisdomai";
    public static final String AIRTABLE = "airtable";
    public static final String GRAFANA = "grafana";
    public static final String EVALUATE = "evaluate";
    public static final String YAHOO_OS = "yahoo-os";
    public static final String YAHOO_SYNAPSE = "yahoo-synapse";
    public static final String UDS = "uds";
    public static final String LOOKER_MAW = "looker-maw";
    public static final String LOOKER_OURYAHOO = "looker-ouryahoo";
    public static final String LOOKER_FINANCE = "looker-finance";
    public static final String LOOKER_HR = "looker-hr";
    public static final String LOOKER_SEARCH = "looker-search";
    public static final String LOOKER_ENTERPRISE = "looker-enterprise";
    public static final String LOOKER_PRISM_MAIL = "looker-prism-mail";

    private OauthProviderLabel() {
    }

    public static String normalize(String raw) {
        if (raw == null || raw.isBlank()) {
            return UNKNOWN;
        }
        String s = raw.trim().toLowerCase(Locale.ROOT);
        return switch (s) {
            case OKTA, GLEAN, GITHUB, EMBRACE, GOOGLE_DRIVE, GOOGLE_DOCS, GOOGLE_SHEETS,
                    GOOGLE_SLIDES, GOOGLE_GMAIL, GOOGLE_CALENDAR, GOOGLE_TASKS, GOOGLE_CHAT, GOOGLE_FORMS,
                    GOOGLE_KEEP, GOOGLE_MEET, GOOGLE_CLOUD_PLATFORM, ATLASSIAN, ATHENZ, GOOGLE_MONITORING,
                    GOOGLE_LOGGING, GOOGLE_BIGQUERY, DATABRICKS_SQL, DATABRICKS_VECTOR_SEARCH, SLACK, FIGMA,
                    ROOTLY, DATADOG, LINEAR, ORACLE_EPM, WISDOMAI, AIRTABLE, GRAFANA, EVALUATE, YAHOO_OS,
                    YAHOO_SYNAPSE, UDS, LOOKER_MAW, LOOKER_OURYAHOO, LOOKER_FINANCE, LOOKER_HR, LOOKER_SEARCH,
                    LOOKER_ENTERPRISE, LOOKER_PRISM_MAIL -> s;
            case "gcp-monitoring" -> GOOGLE_MONITORING;
            case "gcp-logging" -> GOOGLE_LOGGING;
            case "gcp-bigquery" -> GOOGLE_BIGQUERY;
            case "wisdom-ai", "wisdom_ai" -> WISDOMAI;
            default -> s;
        };
    }
}
