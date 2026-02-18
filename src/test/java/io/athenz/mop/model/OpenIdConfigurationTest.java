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
package io.athenz.mop.model;

import io.athenz.mop.model.OpenIdConfiguration;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

class OpenIdConfigurationTest {

    @Test
    void testRecordConstruction() {
        OpenIdConfiguration config = new OpenIdConfiguration(
                "https://issuer.example.com",
                "https://issuer.example.com/authorize",
                "https://issuer.example.com/token",
                "https://issuer.example.com/register",
                "https://issuer.example.com/userinfo",
                Arrays.asList("code", "token"),
                Collections.singletonList("public"),
                Collections.singletonList("ES256"),
                Arrays.asList("openid", "profile", "email"),
                Arrays.asList("client_secret_basic", "client_secret_post"),
                Arrays.asList("sub", "iss", "aud"),
                Arrays.asList("authorization_code", "client_credentials"),
                Collections.singletonList("S256")
        );

        assertEquals("https://issuer.example.com", config.issuer());
        assertEquals("https://issuer.example.com/authorize", config.authorizationEndpoint());
        assertEquals("https://issuer.example.com/token", config.tokenEndpoint());
        assertEquals("https://issuer.example.com/register", config.registrationEndpoint());
        assertEquals(2, config.responseTypesSupported().size());
        assertTrue(config.responseTypesSupported().contains("code"));
        assertEquals(1, config.subjectTypesSupported().size());
        assertEquals("public", config.subjectTypesSupported().get(0));
        assertEquals(1, config.idTokenSigningAlgValuesSupported().size());
        assertEquals("ES256", config.idTokenSigningAlgValuesSupported().get(0));
        assertEquals(3, config.scopesSupported().size());
        assertTrue(config.scopesSupported().contains("openid"));
        assertEquals(2, config.tokenEndpointAuthMethodsSupported().size());
        assertEquals(3, config.claimsSupported().size());
        assertEquals(2, config.grantTypesSupported().size());
        assertEquals(1, config.codeChallengeMethodsSupported().size());
        assertEquals("S256", config.codeChallengeMethodsSupported().get(0));
    }

    @Test
    void testRecordEquality() {
        OpenIdConfiguration config1 = new OpenIdConfiguration(
                "https://issuer.example.com",
                "https://issuer.example.com/authorize",
                "https://issuer.example.com/token",
                "https://issuer.example.com/register",
                "https://issuer.example.com/userinfo",
                Collections.singletonList("code"),
                Collections.singletonList("public"),
                Collections.singletonList("ES256"),
                Collections.singletonList("openid"),
                Collections.singletonList("client_secret_basic"),
                Collections.singletonList("sub"),
                Collections.singletonList("authorization_code"),
                Collections.singletonList("S256")
        );

        OpenIdConfiguration config2 = new OpenIdConfiguration(
                "https://issuer.example.com",
                "https://issuer.example.com/authorize",
                "https://issuer.example.com/token",
                "https://issuer.example.com/register",
                "https://issuer.example.com/userinfo",
                Collections.singletonList("code"),
                Collections.singletonList("public"),
                Collections.singletonList("ES256"),
                Collections.singletonList("openid"),
                Collections.singletonList("client_secret_basic"),
                Collections.singletonList("sub"),
                Collections.singletonList("authorization_code"),
                Collections.singletonList("S256")
        );

        assertEquals(config1, config2);
        assertEquals(config1.hashCode(), config2.hashCode());
    }

    @Test
    void testRecordInequality_DifferentIssuer() {
        OpenIdConfiguration config1 = new OpenIdConfiguration(
                "https://issuer1.example.com",
                "https://issuer.example.com/authorize",
                "https://issuer.example.com/token",
                "https://issuer.example.com/register",
                "https://issuer.example.com/userinfo",
                Collections.singletonList("code"),
                Collections.singletonList("public"),
                Collections.singletonList("ES256"),
                Collections.singletonList("openid"),
                Collections.singletonList("client_secret_basic"),
                Collections.singletonList("sub"),
                Collections.singletonList("authorization_code"),
                Collections.singletonList("S256")
        );

        OpenIdConfiguration config2 = new OpenIdConfiguration(
                "https://issuer2.example.com",
                "https://issuer.example.com/authorize",
                "https://issuer.example.com/token",
                "https://issuer.example.com/register",
                "https://issuer.example.com/userinfo",
                Collections.singletonList("code"),
                Collections.singletonList("public"),
                Collections.singletonList("ES256"),
                Collections.singletonList("openid"),
                Collections.singletonList("client_secret_basic"),
                Collections.singletonList("sub"),
                Collections.singletonList("authorization_code"),
                Collections.singletonList("S256")
        );

        assertNotEquals(config1, config2);
    }

    @Test
    void testToString() {
        OpenIdConfiguration config = new OpenIdConfiguration(
                "https://issuer.example.com",
                "https://issuer.example.com/authorize",
                "https://issuer.example.com/token",
                "https://issuer.example.com/register",
                "https://issuer.example.com/userinfo",
                Collections.singletonList("code"),
                Collections.singletonList("public"),
                Collections.singletonList("ES256"),
                Collections.singletonList("openid"),
                Collections.singletonList("client_secret_basic"),
                Collections.singletonList("sub"),
                Collections.singletonList("authorization_code"),
                Collections.singletonList("S256")
        );

        String toString = config.toString();
        assertTrue(toString.contains("issuer.example.com"));
        assertTrue(toString.contains("ES256"));
        assertTrue(toString.contains("S256"));
    }

    @Test
    void testMultipleScopesSupported() {
        OpenIdConfiguration config = new OpenIdConfiguration(
                "https://issuer.example.com",
                "https://issuer.example.com/authorize",
                "https://issuer.example.com/token",
                "https://issuer.example.com/register",
                "https://issuer.example.com/userinfo",
                Collections.singletonList("code"),
                Collections.singletonList("public"),
                Collections.singletonList("ES256"),
                Arrays.asList("openid", "profile", "email", "address", "phone"),
                Collections.singletonList("client_secret_basic"),
                Collections.singletonList("sub"),
                Collections.singletonList("authorization_code"),
                Collections.singletonList("S256")
        );

        assertEquals(5, config.scopesSupported().size());
        assertTrue(config.scopesSupported().contains("openid"));
        assertTrue(config.scopesSupported().contains("profile"));
        assertTrue(config.scopesSupported().contains("email"));
        assertTrue(config.scopesSupported().contains("address"));
        assertTrue(config.scopesSupported().contains("phone"));
    }

    @Test
    void testMultipleAlgorithmsSupported() {
        OpenIdConfiguration config = new OpenIdConfiguration(
                "https://issuer.example.com",
                "https://issuer.example.com/authorize",
                "https://issuer.example.com/token",
                "https://issuer.example.com/register",
                "https://issuer.example.com/userinfo",
                Collections.singletonList("code"),
                Collections.singletonList("public"),
                Arrays.asList("ES256", "ES384", "ES512", "RS256"),
                Collections.singletonList("openid"),
                Collections.singletonList("client_secret_basic"),
                Collections.singletonList("sub"),
                Collections.singletonList("authorization_code"),
                Collections.singletonList("S256")
        );

        assertEquals(4, config.idTokenSigningAlgValuesSupported().size());
        assertTrue(config.idTokenSigningAlgValuesSupported().contains("ES256"));
        assertTrue(config.idTokenSigningAlgValuesSupported().contains("RS256"));
    }
}
