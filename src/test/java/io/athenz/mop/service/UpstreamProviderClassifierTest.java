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

import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the {@link UpstreamProviderClassifier} allow-list. Adding/removing a promoted provider
 * is a code change with non-trivial schema and write-path implications, so this test exists to
 * make any drift in the set explicit (and to catch typos in provider names).
 */
class UpstreamProviderClassifierTest {

    private UpstreamProviderClassifier classifier;

    @Mock
    private GoogleWorkspaceUpstreamRefreshClient googleWorkspaceUpstreamRefreshClient;

    @Mock
    private FigmaUpstreamRefreshClient figmaUpstreamRefreshClient;

    @Mock
    private RootlyUpstreamRefreshClient rootlyUpstreamRefreshClient;

    @Mock
    private DatadogUpstreamRefreshClient datadogUpstreamRefreshClient;

    @Mock
    private LinearUpstreamRefreshClient linearUpstreamRefreshClient;

    @Mock
    private OracleEpmUpstreamRefreshClient oracleEpmUpstreamRefreshClient;

    @Mock
    private WisdomAiUpstreamRefreshClient wisdomAiUpstreamRefreshClient;

    @Mock
    private AirtableUpstreamRefreshClient airtableUpstreamRefreshClient;

    @Mock
    private LookerUpstreamRefreshClient lookerUpstreamRefreshClient;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        classifier = new UpstreamProviderClassifier();
        classifier.googleWorkspaceUpstreamRefreshClient = googleWorkspaceUpstreamRefreshClient;
        classifier.figmaUpstreamRefreshClient = figmaUpstreamRefreshClient;
        classifier.rootlyUpstreamRefreshClient = rootlyUpstreamRefreshClient;
        classifier.datadogUpstreamRefreshClient = datadogUpstreamRefreshClient;
        classifier.linearUpstreamRefreshClient = linearUpstreamRefreshClient;
        classifier.oracleEpmUpstreamRefreshClient = oracleEpmUpstreamRefreshClient;
        classifier.wisdomAiUpstreamRefreshClient = wisdomAiUpstreamRefreshClient;
        classifier.airtableUpstreamRefreshClient = airtableUpstreamRefreshClient;
        classifier.lookerUpstreamRefreshClient = lookerUpstreamRefreshClient;
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "okta",
            "google-drive", "google-docs", "google-sheets", "google-slides",
            "google-gmail", "google-calendar", "google-tasks", "google-chat",
            "google-forms", "google-keep", "google-meet", "google-cloud-platform",
            "figma",
            "rootly",
            "datadog",
            "linear",
            "oracle-epm",
            "wisdomai",
            "airtable",
            "looker-maw", "looker-ouryahoo", "looker-finance", "looker-hr",
            "looker-search", "looker-enterprise", "looker-prism-mail"
    })
    void isUpstreamPromoted_returnsTrueForPromotedProviders(String provider) {
        assertTrue(classifier.isUpstreamPromoted(provider),
                "provider expected to be promoted: " + provider);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "slack", "github", "atlassian", "embrace", "splunk", "grafana",
            "evaluate", "databricks-sql", "google", "google-unknown", "Google-Drive",
            "Figma", "Datadog", "datadoghq", "Linear", "linears",
            "Oracle-Epm", "oracleepm", "oracle",
            "WisdomAi", "wisdom-ai", "wisdom_ai", "wisdom",
            "Airtable", "AIRTABLE", "air-table", "air_table", "airtables",
            "looker", "Looker-Ouryahoo", "looker_ouryahoo", "looker-unknown"
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
    void isGoogleWorkspace_falseForFigma() {
        assertFalse(classifier.isGoogleWorkspace("figma"),
                "Figma is promoted but is NOT google-workspace; classifier must distinguish them");
    }

    @Test
    void isGoogleWorkspace_falseForRootly() {
        assertFalse(classifier.isGoogleWorkspace("rootly"),
                "Rootly is promoted but is NOT google-workspace; classifier must distinguish them");
    }

    @Test
    void isGoogleWorkspace_falseForDatadog() {
        assertFalse(classifier.isGoogleWorkspace("datadog"),
                "Datadog is promoted but is NOT google-workspace; classifier must distinguish them");
    }

    @Test
    void isGoogleWorkspace_falseForLinear() {
        assertFalse(classifier.isGoogleWorkspace("linear"),
                "Linear is promoted but is NOT google-workspace; classifier must distinguish them");
    }

    @Test
    void isGoogleWorkspace_falseForOracleEpm() {
        assertFalse(classifier.isGoogleWorkspace("oracle-epm"),
                "Oracle EPM is promoted but is NOT google-workspace; classifier must distinguish them");
    }

    @Test
    void isGoogleWorkspace_falseForWisdomAi() {
        assertFalse(classifier.isGoogleWorkspace("wisdomai"),
                "WisdomAI is promoted but is NOT google-workspace; classifier must distinguish them");
    }

    @Test
    void isGoogleWorkspace_falseForAirtable() {
        assertFalse(classifier.isGoogleWorkspace("airtable"),
                "Airtable is promoted but is NOT google-workspace; classifier must distinguish them");
    }

    @Test
    void isGoogleWorkspace_falseForLooker() {
        assertFalse(classifier.isGoogleWorkspace("looker-ouryahoo"),
                "Looker is promoted but is NOT google-workspace; classifier must distinguish them");
    }

    @Test
    void isGoogleWorkspace_falseForNullEmptyAndNonGoogle() {
        assertFalse(classifier.isGoogleWorkspace(null));
        assertFalse(classifier.isGoogleWorkspace(""));
        assertFalse(classifier.isGoogleWorkspace("slack"));
        assertFalse(classifier.isGoogleWorkspace("github"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "google-drive", "google-docs", "google-sheets", "google-slides",
            "google-gmail", "google-calendar", "google-tasks", "google-chat",
            "google-forms", "google-keep", "google-meet", "google-cloud-platform"
    })
    void resolveRefreshTokenClient_returnsGoogleClientForGoogleWorkspaceProviders(String provider) {
        Optional<UpstreamRefreshClient> resolved = classifier.resolveRefreshTokenClient(provider);
        assertTrue(resolved.isPresent(), "Google Workspace provider should resolve to a client: " + provider);
        assertSame(googleWorkspaceUpstreamRefreshClient, resolved.get());
    }

    @Test
    void resolveRefreshTokenClient_returnsFigmaClientForFigma() {
        Optional<UpstreamRefreshClient> resolved = classifier.resolveRefreshTokenClient("figma");
        assertTrue(resolved.isPresent(), "Figma should resolve to the Figma client");
        assertSame(figmaUpstreamRefreshClient, resolved.get());
    }

    @Test
    void resolveRefreshTokenClient_returnsRootlyClientForRootly() {
        Optional<UpstreamRefreshClient> resolved = classifier.resolveRefreshTokenClient("rootly");
        assertTrue(resolved.isPresent(), "Rootly should resolve to the Rootly client");
        assertSame(rootlyUpstreamRefreshClient, resolved.get());
    }

    @Test
    void resolveRefreshTokenClient_returnsDatadogClientForDatadog() {
        Optional<UpstreamRefreshClient> resolved = classifier.resolveRefreshTokenClient("datadog");
        assertTrue(resolved.isPresent(), "Datadog should resolve to the Datadog client");
        assertSame(datadogUpstreamRefreshClient, resolved.get());
    }

    @Test
    void resolveRefreshTokenClient_returnsLinearClientForLinear() {
        Optional<UpstreamRefreshClient> resolved = classifier.resolveRefreshTokenClient("linear");
        assertTrue(resolved.isPresent(), "Linear should resolve to the Linear client");
        assertSame(linearUpstreamRefreshClient, resolved.get());
    }

    @Test
    void resolveRefreshTokenClient_returnsOracleEpmClientForOracleEpm() {
        Optional<UpstreamRefreshClient> resolved = classifier.resolveRefreshTokenClient("oracle-epm");
        assertTrue(resolved.isPresent(), "Oracle EPM should resolve to the Oracle EPM client");
        assertSame(oracleEpmUpstreamRefreshClient, resolved.get());
    }

    @Test
    void resolveRefreshTokenClient_returnsWisdomAiClientForWisdomAi() {
        Optional<UpstreamRefreshClient> resolved = classifier.resolveRefreshTokenClient("wisdomai");
        assertTrue(resolved.isPresent(), "WisdomAI should resolve to the WisdomAI client");
        assertSame(wisdomAiUpstreamRefreshClient, resolved.get());
    }

    @Test
    void resolveRefreshTokenClient_returnsAirtableClientForAirtable() {
        Optional<UpstreamRefreshClient> resolved = classifier.resolveRefreshTokenClient("airtable");
        assertTrue(resolved.isPresent(), "Airtable should resolve to the Airtable client");
        assertSame(airtableUpstreamRefreshClient, resolved.get());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "looker-maw", "looker-ouryahoo", "looker-finance", "looker-hr",
            "looker-search", "looker-enterprise", "looker-prism-mail"
    })
    void resolveRefreshTokenClient_returnsLookerClientForLookerInstances(String provider) {
        Optional<UpstreamRefreshClient> resolved = classifier.resolveRefreshTokenClient(provider);
        assertTrue(resolved.isPresent(), "Looker instance should resolve to the Looker client: " + provider);
        assertSame(lookerUpstreamRefreshClient, resolved.get());
    }

    @Test
    void resolveRefreshTokenClient_emptyForOkta() {
        // Okta is intentionally NOT resolved here — UpstreamRefreshService.clientFor handles
        // Okta with a service-local lambda over OktaTokenClient, which we deliberately do not
        // leak into the classifier.
        assertTrue(classifier.resolveRefreshTokenClient("okta").isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "slack", "github", "atlassian", "embrace", "splunk", "grafana", "evaluate",
            "databricks-sql", "unknown", "Figma", "Google-Drive", "Datadog", "datadoghq",
            "Linear", "linears", "Oracle-Epm", "oracleepm", "oracle",
            "WisdomAi", "wisdom-ai", "wisdom_ai", "wisdom",
            "Airtable", "AIRTABLE", "air-table", "air_table", "airtables",
            "looker", "Looker-Ouryahoo", "looker_ouryahoo", "looker-unknown"
    })
    void resolveRefreshTokenClient_emptyForNonPromotedOrTypoProviders(String provider) {
        assertTrue(classifier.resolveRefreshTokenClient(provider).isEmpty(),
                "Non-promoted (or typo) provider must NOT resolve to a client: " + provider);
    }

    @Test
    void resolveRefreshTokenClient_emptyForNullOrEmpty() {
        assertTrue(classifier.resolveRefreshTokenClient(null).isEmpty());
        assertTrue(classifier.resolveRefreshTokenClient("").isEmpty());
    }
}
