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

import io.athenz.mop.service.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;

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
    private TokenExchangeServiceGoogleImpl tokenExchangeServiceGoogleImpl;

    @InjectMocks
    private TokenExchangeServiceProducer tokenExchangeServiceProducer;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Atlassian() {
        // When
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("atlassian");

        // Then
        assertNotNull(result);
        assertSame(tokenExchangeServiceAtlassianImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Github() {
        // When
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("github");

        // Then
        assertNotNull(result);
        assertSame(tokenExchangeServiceGithubImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Google() {
        // When
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("google");

        // Then
        assertNotNull(result);
        assertSame(tokenExchangeServiceGoogleImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Okta() {
        // When
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("okta");

        // Then
        assertNotNull(result);
        assertSame(tokenExchangeServiceOktaImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_Athenz() {
        // When
        TokenExchangeService result = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("athenz");

        // Then
        assertNotNull(result);
        assertSame(tokenExchangeServiceZTSImpl, result);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_UnsupportedType() {
        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("unsupported")
        );

        assertEquals("Unsupported IDP type: unsupported", exception.getMessage());
    }

    @Test
    void testGetTokenExchangeServiceImplementation_NullType() {
        // When & Then
        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(null)
        );
    }

    @Test
    void testGetTokenExchangeServiceImplementation_EmptyType() {
        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("")
        );

        assertEquals("Unsupported IDP type: ", exception.getMessage());
    }

    @Test
    void testGetTokenExchangeServiceImplementation_CaseSensitive() {
        // When & Then - Verify case sensitivity
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("OKTA")
        );

        assertEquals("Unsupported IDP type: OKTA", exception.getMessage());
    }

    @Test
    void testGetTokenExchangeServiceImplementation_CaseSensitiveGithub() {
        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("GitHub")
        );

        assertEquals("Unsupported IDP type: GitHub", exception.getMessage());
    }

    @Test
    void testGetTokenExchangeServiceImplementation_CaseSensitiveAtlassian() {
        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("Atlassian")
        );

        assertEquals("Unsupported IDP type: Atlassian", exception.getMessage());
    }

    @Test
    void testGetTokenExchangeServiceImplementation_CaseSensitiveGoogle() {
        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("Google")
        );

        assertEquals("Unsupported IDP type: Google", exception.getMessage());
    }

    @Test
    void testGetTokenExchangeServiceImplementation_CaseSensitiveAthenz() {
        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("Athenz")
        );

        assertEquals("Unsupported IDP type: Athenz", exception.getMessage());
    }

    @Test
    void testGetTokenExchangeServiceImplementation_WithWhitespace() {
        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(" okta ")
        );

        assertEquals("Unsupported IDP type:  okta ", exception.getMessage());
    }

    @Test
    void testGetTokenExchangeServiceImplementation_MultipleCallsSameType() {
        // When - Call multiple times with the same type
        TokenExchangeService result1 = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("okta");
        TokenExchangeService result2 = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("okta");

        // Then - Should return the same instance each time
        assertSame(result1, result2);
        assertSame(tokenExchangeServiceOktaImpl, result1);
        assertSame(tokenExchangeServiceOktaImpl, result2);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_AllProvidersDifferent() {
        // When - Get all implementations
        TokenExchangeService atlassian = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("atlassian");
        TokenExchangeService github = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("github");
        TokenExchangeService google = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("google");
        TokenExchangeService okta = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("okta");
        TokenExchangeService athenz = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("athenz");

        // Then - All should be different instances
        assertNotSame(atlassian, github);
        assertNotSame(atlassian, google);
        assertNotSame(atlassian, okta);
        assertNotSame(atlassian, athenz);
        assertNotSame(github, google);
        assertNotSame(github, okta);
        assertNotSame(github, athenz);
        assertNotSame(google, okta);
        assertNotSame(google, athenz);
        assertNotSame(okta, athenz);
    }

    @Test
    void testGetTokenExchangeServiceImplementation_RandomUnsupportedValues() {
        // Test various unsupported values
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

    @Test
    void testGetTokenExchangeServiceImplementation_SpecialCharacters() {
        // When & Then - Test with special characters
        String[] specialTypes = {"okta!", "github@", "google#", "athenz$", "atlassian%"};

        for (String type : specialTypes) {
            IllegalArgumentException exception = assertThrows(
                    IllegalArgumentException.class,
                    () -> tokenExchangeServiceProducer.getTokenExchangeServiceImplementation(type),
                    "Expected exception for type: " + type
            );
            assertEquals("Unsupported IDP type: " + type, exception.getMessage());
        }
    }
}
