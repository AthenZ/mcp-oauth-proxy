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
    private TokenExchangeServiceDatabricksSqlImpl tokenExchangeServiceDatabricksSqlImpl;

    @Mock
    private TokenExchangeServiceSlackImpl tokenExchangeServiceSlackImpl;

    @Mock
    private Instance<TokenExchangeServiceGoogleWorkspaceImpl> googleWorkspaceProvider;

    @InjectMocks
    private TokenExchangeServiceProducer tokenExchangeServiceProducer;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(googleWorkspaceProvider.get()).thenAnswer(invocation -> {
            TokenExchangeServiceGoogleWorkspaceImpl impl = new TokenExchangeServiceGoogleWorkspaceImpl();
            return impl;
        });
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
    void testGetTokenExchangeServiceImplementation_Splunk() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("splunk");
        assertNotNull(result);
        assertSame(tokenExchangeServiceSplunkImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_DatabricksSql() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("databricks-sql");
        assertNotNull(result);
        assertSame(tokenExchangeServiceDatabricksSqlImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Slack() {
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("slack");
        assertNotNull(result);
        assertSame(tokenExchangeServiceSlackImpl, result);
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
