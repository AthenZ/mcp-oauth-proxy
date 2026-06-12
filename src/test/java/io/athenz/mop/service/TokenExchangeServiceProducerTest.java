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

import io.athenz.mop.config.DatabricksSqlTokenExchangeConfig;
import io.athenz.mop.config.DatabricksVectorSearchTokenExchangeConfig;
import jakarta.enterprise.inject.Instance;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TokenExchangeServiceProducerTest {

    @Mock
    private TokenExchangeServiceZTSImpl tokenExchangeServiceZTSImpl;

    @Mock
    private TokenExchangeServiceOktaImpl tokenExchangeServiceOktaImpl;

    @Mock
    private TokenExchangeServiceAtlassianImpl tokenExchangeServiceAtlassianImpl;

    @Mock
    private TokenExchangeServiceGithubImpl tokenExchangeServiceGithubImpl;

    @Mock
    private TokenExchangeServiceEmbraceImpl tokenExchangeServiceEmbraceImpl;

    @Mock
    private TokenExchangeServiceGcpWorkforceImpl tokenExchangeServiceGcpWorkforceImpl;

    @Mock
    private TokenExchangeServiceSplunkImpl tokenExchangeServiceSplunkImpl;

    @Mock
    private TokenExchangeServiceGrafanaImpl tokenExchangeServiceGrafanaImpl;

    @Mock
    private TokenExchangeServiceSlackImpl tokenExchangeServiceSlackImpl;

    @Mock
    private TokenExchangeServiceFigmaImpl tokenExchangeServiceFigmaImpl;

    @Mock
    private TokenExchangeServiceRootlyImpl tokenExchangeServiceRootlyImpl;

    @Mock
    private TokenExchangeServiceDatadogImpl tokenExchangeServiceDatadogImpl;

    @Mock
    private TokenExchangeServiceLinearImpl tokenExchangeServiceLinearImpl;

    @Mock
    private TokenExchangeServiceWisdomAiImpl tokenExchangeServiceWisdomAiImpl;

    @Mock
    private TokenExchangeServiceOracleEpmImpl tokenExchangeServiceOracleEpmImpl;

    @Mock
    private TokenExchangeServiceAirtableImpl tokenExchangeServiceAirtableImpl;

    @Mock
    private TokenExchangeServiceEvaluateImpl tokenExchangeServiceEvaluateImpl;

    @Mock
    private TokenExchangeServiceYahooOsImpl tokenExchangeServiceYahooOsImpl;

    @Mock
    private Instance<TokenExchangeServiceGoogleWorkspaceImpl> googleWorkspaceProvider;

    @Mock
    private Instance<TokenExchangeServiceLookerImpl> lookerProvider;

    @Mock
    private Instance<TokenExchangeServiceDatabricksImpl> databricksProvider;

    @Mock
    private DatabricksSqlTokenExchangeConfig databricksSqlConfig;

    @Mock
    private DatabricksVectorSearchTokenExchangeConfig databricksVectorSearchConfig;

    @InjectMocks
    private TokenExchangeServiceProducer tokenExchangeServiceProducer;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(googleWorkspaceProvider.get()).thenAnswer(invocation -> {
            TokenExchangeServiceGoogleWorkspaceImpl impl = new TokenExchangeServiceGoogleWorkspaceImpl();
            return impl;
        });
        when(databricksProvider.get()).thenAnswer(invocation -> new TokenExchangeServiceDatabricksImpl());
        when(lookerProvider.get()).thenAnswer(invocation -> new TokenExchangeServiceLookerImpl());
        tokenExchangeServiceProducer.init();
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Atlassian() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("atlassian");
        assertNotNull(result);
        assertSame(tokenExchangeServiceAtlassianImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Github() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("github");
        assertNotNull(result);
        assertSame(tokenExchangeServiceGithubImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Embrace() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("embrace");
        assertNotNull(result);
        assertSame(tokenExchangeServiceEmbraceImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Okta() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_OKTA);
        assertNotNull(result);
        assertSame(tokenExchangeServiceOktaImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Athenz() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("athenz");
        assertNotNull(result);
        assertSame(tokenExchangeServiceZTSImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_GoogleMonitoring() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("google-monitoring");
        assertNotNull(result);
        assertSame(tokenExchangeServiceGcpWorkforceImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_GoogleLogging() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("google-logging");
        assertNotNull(result);
        assertSame(tokenExchangeServiceGcpWorkforceImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_GoogleBigQuery() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("google-bigquery");
        assertNotNull(result);
        assertSame(tokenExchangeServiceGcpWorkforceImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_GcpWorkforceAudiences_SameInstance() {
        TokenExchangeService monitoring = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("google-monitoring");
        TokenExchangeService logging = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("google-logging");
        TokenExchangeService bigquery = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("google-bigquery");
        assertSame(monitoring, logging);
        assertSame(monitoring, bigquery);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Splunk() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("splunk");
        assertNotNull(result);
        assertSame(tokenExchangeServiceSplunkImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Grafana() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("grafana");
        assertNotNull(result);
        assertSame(tokenExchangeServiceGrafanaImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_DatabricksSql() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("databricks-sql");
        assertNotNull(result);
        assertInstanceOf(TokenExchangeServiceDatabricksImpl.class, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_DatabricksVectorSearch() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("databricks-vector-search");
        assertNotNull(result);
        assertInstanceOf(TokenExchangeServiceDatabricksImpl.class, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_DatabricksSqlAndVectorSearch_areDistinctInstances() {
        TokenExchangeService sql = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("databricks-sql");
        TokenExchangeService vs = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("databricks-vector-search");
        assertNotSame(sql, vs);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_DatabricksSql_cachedInstance() {
        TokenExchangeService first = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("databricks-sql");
        TokenExchangeService second = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("databricks-sql");
        assertSame(first, second);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_DatabricksVectorSearch_cachedInstance() {
        TokenExchangeService first = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("databricks-vector-search");
        TokenExchangeService second = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("databricks-vector-search");
        assertSame(first, second);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Slack() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("slack");
        assertNotNull(result);
        assertSame(tokenExchangeServiceSlackImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Figma() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("figma");
        assertNotNull(result);
        assertSame(tokenExchangeServiceFigmaImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Rootly() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("rootly");
        assertNotNull(result);
        assertSame(tokenExchangeServiceRootlyImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Datadog() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("datadog");
        assertNotNull(result);
        assertSame(tokenExchangeServiceDatadogImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Linear() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("linear");
        assertNotNull(result);
        assertSame(tokenExchangeServiceLinearImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_WisdomAi() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("wisdomai");
        assertNotNull(result);
        assertSame(tokenExchangeServiceWisdomAiImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_OracleEpm() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("oracle-epm");
        assertNotNull(result);
        assertSame(tokenExchangeServiceOracleEpmImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Airtable() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("airtable");
        assertNotNull(result);
        assertSame(tokenExchangeServiceAirtableImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Evaluate() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("evaluate");
        assertNotNull(result);
        assertSame(tokenExchangeServiceEvaluateImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_YahooOs() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("yahoo-os");
        assertNotNull(result);
        assertSame(tokenExchangeServiceYahooOsImpl, result);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testGetTokenExchangeServiceImplementation_GoogleWorkspaceProviders(String provider) {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(provider);
        assertNotNull(result);
        assertInstanceOf(TokenExchangeServiceGoogleWorkspaceImpl.class, result);
        assertEquals(provider, ((TokenExchangeServiceGoogleWorkspaceImpl) result).getProviderLabel());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testGetTokenExchangeServiceImplementation_GoogleWorkspaceProviders_ReturnDistinctInstances(String provider) {
        TokenExchangeService first = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(provider);
        TokenExchangeService second = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(provider);
        assertSame(first, second, "Same provider should return the same cached instance");
    }

    @Test
    void testGetTokenExchangeServiceImplementation_GoogleWorkspaceProviders_AllDistinct() {
        TokenExchangeService drive = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("google-drive");
        TokenExchangeService docs = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("google-docs");
        assertNotSame(drive, docs, "Different providers should return different instances");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "looker-maw", "looker-ouryahoo", "looker-finance", "looker-hr",
        "looker-search", "looker-enterprise", "looker-prism-mail"
    })
    void testGetTokenExchangeServiceImplementation_LookerProviders(String provider) {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(provider);
        assertNotNull(result);
        assertInstanceOf(TokenExchangeServiceLookerImpl.class, result);
        assertEquals(provider, ((TokenExchangeServiceLookerImpl) result).getProviderLabel());
    }

    @Test
    void testGetTokenExchangeServiceImplementation_LookerProviders_AllDistinct() {
        TokenExchangeService ouryahoo = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("looker-ouryahoo");
        TokenExchangeService enterprise = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("looker-enterprise");
        assertNotSame(ouryahoo, enterprise, "Different Looker instances should return different instances");
    }

    @Test
    void testGetTokenExchangeServiceImplementation_LookerProvider_cachedInstance() {
        TokenExchangeService first = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("looker-ouryahoo");
        TokenExchangeService second = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("looker-ouryahoo");
        assertSame(first, second);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_UnsupportedType() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("unsupported")
        );
        assertEquals("Unsupported IDP type: unsupported", exception.getMessage());
    }

    @Test
    void testGetTokenExchangeServiceImplementation_NullType() {
        assertThrows(
                NullPointerException.class,
                () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(null)
        );
    }

    @Test
    void testGetTokenExchangeServiceImplementation_EmptyType() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("")
        );
        assertEquals("Unsupported IDP type: ", exception.getMessage());
    }

    @Test
    void testGetTokenExchangeServiceImplementation_CaseSensitive() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("OKTA")
        );
        assertEquals("Unsupported IDP type: OKTA", exception.getMessage());
    }

    @Test
    void testGetTokenExchangeServiceImplementation_MultipleCallsSameType() {
        TokenExchangeService result1 = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_OKTA);
        TokenExchangeService result2 = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(AudienceConstants.PROVIDER_OKTA);
        assertSame(result1, result2);
        assertSame(tokenExchangeServiceOktaImpl, result1);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_RandomUnsupportedValues() {
        String[] unsupportedTypes = {
                "aws", "azure", "facebook", "twitter", "linkedin",
                "salesforce", "microsoft", "apple", "amazon"
        };

        for (String type : unsupportedTypes) {
            IllegalArgumentException exception = assertThrows(
                    IllegalArgumentException.class,
                    () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(type),
                    "Expected exception for type: " + type
            );
            assertEquals("Unsupported IDP type: " + type, exception.getMessage());
        }
    }
}
