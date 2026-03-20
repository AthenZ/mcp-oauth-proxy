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
}
