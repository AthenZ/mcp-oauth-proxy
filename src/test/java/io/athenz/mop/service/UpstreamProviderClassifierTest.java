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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the {@link UpstreamProviderClassifier} allow-list. Adding/removing a promoted provider
 * is a code change with non-trivial schema and write-path implications, so this test exists to
 * make any drift in the set explicit (and to catch typos in provider names).
 */
class UpstreamProviderClassifierTest {

    private final UpstreamProviderClassifier classifier = new UpstreamProviderClassifier();

    @ParameterizedTest
    @ValueSource(strings = {
            "okta",
            "google-drive", "google-docs", "google-sheets", "google-slides",
            "google-gmail", "google-calendar", "google-tasks", "google-chat",
            "google-forms", "google-keep", "google-meet", "google-cloud-platform"
    })
    void isUpstreamPromoted_returnsTrueForPromotedProviders(String provider) {
        assertTrue(classifier.isUpstreamPromoted(provider),
                "provider expected to be promoted: " + provider);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "slack", "github", "atlassian", "embrace", "splunk", "grafana",
            "evaluate", "databricks-sql", "google", "google-unknown", "Google-Drive"
    })
    void isUpstreamPromoted_returnsFalseForNonPromotedOrTypoProviders(String provider) {
        assertFalse(classifier.isUpstreamPromoted(provider),
                "provider must NOT be promoted: " + provider);
    }

    @Test
    void isUpstreamPromoted_falseForNullOrEmpty() {
        assertFalse(classifier.isUpstreamPromoted(null));
        assertFalse(classifier.isUpstreamPromoted(""));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "google-drive", "google-docs", "google-sheets", "google-slides",
            "google-gmail", "google-calendar", "google-tasks", "google-chat",
            "google-forms", "google-keep", "google-meet", "google-cloud-platform"
    })
    void isGoogleWorkspace_returnsTrueForGoogleProviders(String provider) {
        assertTrue(classifier.isGoogleWorkspace(provider));
    }

    @Test
    void isGoogleWorkspace_falseForOkta() {
        assertFalse(classifier.isGoogleWorkspace("okta"),
                "Okta is promoted but is NOT google-workspace; classifier must distinguish them");
    }

    @Test
    void isGoogleWorkspace_falseForNullEmptyAndNonGoogle() {
        assertFalse(classifier.isGoogleWorkspace(null));
        assertFalse(classifier.isGoogleWorkspace(""));
        assertFalse(classifier.isGoogleWorkspace("slack"));
        assertFalse(classifier.isGoogleWorkspace("github"));
    }
}
