/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.athenz.mop.service;

import org.apache.commons.lang3.StringUtils;

/**
 * Audience / provider names used for token storage and token exchange routing.
 * Same style as PROVIDER_GLEAN used in resource-mapping token.audience.
 */
public final class AudienceConstants {

    private AudienceConstants() {
    }

    /** Default upstream IdP provider id (token store, refresh table, token exchange routing key). */
    public static final String PROVIDER_OKTA = "okta";

    public static final String PROVIDER_GLEAN = "glean";
    public static final String PROVIDER_GOOGLE_MONITORING = "google-monitoring";
    public static final String PROVIDER_GOOGLE_LOGGING = "google-logging";
    public static final String PROVIDER_SPLUNK = "splunk";

    /** Databricks SQL MCP resource mapping {@code token.audience} / {@code token.as} routing id. */
    public static final String PROVIDER_DATABRICKS_SQL = "databricks-sql";

    /**
     * DynamoDB / userinfo provider column for a Databricks SQL workspace (prefix + workspace hostname).
     */
    public static String databricksSqlStorageProvider(String hostname) {
        if (StringUtils.isBlank(hostname)) {
            return PROVIDER_DATABRICKS_SQL;
        }
        return PROVIDER_DATABRICKS_SQL + "-" + hostname.trim();
    }

    /** Exchanged access token stored by audience so {@code GET /userinfo} can resolve Okta profile from Splunk/Glean/GCP tokens. */
    public static boolean storesExchangedTokenForUserinfo(String audience) {
        if (StringUtils.isBlank(audience)) {
            return false;
        }
        return PROVIDER_GLEAN.equals(audience)
                || PROVIDER_GOOGLE_MONITORING.equals(audience)
                || PROVIDER_GOOGLE_LOGGING.equals(audience)
                || PROVIDER_SPLUNK.equals(audience)
                || PROVIDER_DATABRICKS_SQL.equals(audience);
    }
}
