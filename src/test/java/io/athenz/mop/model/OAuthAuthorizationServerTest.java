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

import io.athenz.mop.model.OAuthAuthorizationServer;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

class OAuthAuthorizationServerTest {

    @Test
    void testRecordConstruction() {
        OAuthAuthorizationServer server = new OAuthAuthorizationServer(
                "https://auth.example.com",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token",
                "https://auth.example.com/register",
                Arrays.asList("code", "token"),
                Arrays.asList("authorization_code", "client_credentials"),
                Arrays.asList("client_secret_basic", "client_secret_post"),
                Collections.singletonList("ES256"),
                Collections.singletonList("S256")
        );

        assertEquals("https://auth.example.com", server.issuer());
        assertEquals("https://auth.example.com/authorize", server.authorizationEndpoint());
        assertEquals("https://auth.example.com/token", server.tokenEndpoint());
        assertEquals("https://auth.example.com/register", server.registrationEndpoint());
        assertEquals(2, server.responseTypesSupported().size());
        assertTrue(server.responseTypesSupported().contains("code"));
        assertEquals(2, server.grantTypesSupported().size());
        assertTrue(server.grantTypesSupported().contains("authorization_code"));
        assertEquals(2, server.tokenEndpointAuthMethodsSupported().size());
        assertEquals(1, server.tokenEndpointAuthSigningAlgValuesSupported().size());
        assertEquals("ES256", server.tokenEndpointAuthSigningAlgValuesSupported().get(0));
        assertEquals(1, server.codeChallengeMethodsSupported().size());
        assertEquals("S256", server.codeChallengeMethodsSupported().get(0));
    }

    @Test
    void testRecordEquality() {
        OAuthAuthorizationServer server1 = new OAuthAuthorizationServer(
                "https://auth.example.com",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token",
                "https://auth.example.com/register",
                Collections.singletonList("code"),
                Collections.singletonList("authorization_code"),
                Collections.singletonList("client_secret_basic"),
                Collections.singletonList("ES256"),
                Collections.singletonList("S256")
        );

        OAuthAuthorizationServer server2 = new OAuthAuthorizationServer(
                "https://auth.example.com",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token",
                "https://auth.example.com/register",
                Collections.singletonList("code"),
                Collections.singletonList("authorization_code"),
                Collections.singletonList("client_secret_basic"),
                Collections.singletonList("ES256"),
                Collections.singletonList("S256")
        );

        assertEquals(server1, server2);
        assertEquals(server1.hashCode(), server2.hashCode());
    }

    @Test
    void testRecordInequality_DifferentIssuer() {
        OAuthAuthorizationServer server1 = new OAuthAuthorizationServer(
                "https://auth1.example.com",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token",
                "https://auth.example.com/register",
                Collections.singletonList("code"),
                Collections.singletonList("authorization_code"),
                Collections.singletonList("client_secret_basic"),
                Collections.singletonList("ES256"),
                Collections.singletonList("S256")
        );

        OAuthAuthorizationServer server2 = new OAuthAuthorizationServer(
                "https://auth2.example.com",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token",
                "https://auth.example.com/register",
                Collections.singletonList("code"),
                Collections.singletonList("authorization_code"),
                Collections.singletonList("client_secret_basic"),
                Collections.singletonList("ES256"),
                Collections.singletonList("S256")
        );

        assertNotEquals(server1, server2);
    }

    @Test
    void testToString() {
        OAuthAuthorizationServer server = new OAuthAuthorizationServer(
                "https://auth.example.com",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token",
                "https://auth.example.com/register",
                Collections.singletonList("code"),
                Collections.singletonList("authorization_code"),
                Collections.singletonList("client_secret_basic"),
                Collections.singletonList("ES256"),
                Collections.singletonList("S256")
        );

        String toString = server.toString();
        assertTrue(toString.contains("auth.example.com"));
        assertTrue(toString.contains("ES256"));
        assertTrue(toString.contains("S256"));
    }

    @Test
    void testMultipleGrantTypesSupported() {
        OAuthAuthorizationServer server = new OAuthAuthorizationServer(
                "https://auth.example.com",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token",
                "https://auth.example.com/register",
                Collections.singletonList("code"),
                Arrays.asList("authorization_code", "client_credentials", "refresh_token"),
                Collections.singletonList("client_secret_basic"),
                Collections.singletonList("ES256"),
                Collections.singletonList("S256")
        );

        assertEquals(3, server.grantTypesSupported().size());
        assertTrue(server.grantTypesSupported().contains("authorization_code"));
        assertTrue(server.grantTypesSupported().contains("client_credentials"));
        assertTrue(server.grantTypesSupported().contains("refresh_token"));
    }

    @Test
    void testMultipleAuthMethodsSupported() {
        OAuthAuthorizationServer server = new OAuthAuthorizationServer(
                "https://auth.example.com",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token",
                "https://auth.example.com/register",
                Collections.singletonList("code"),
                Collections.singletonList("authorization_code"),
                Arrays.asList("client_secret_basic", "client_secret_post", "tls_client_auth"),
                Collections.singletonList("ES256"),
                Collections.singletonList("S256")
        );

        assertEquals(3, server.tokenEndpointAuthMethodsSupported().size());
        assertTrue(server.tokenEndpointAuthMethodsSupported().contains("client_secret_basic"));
        assertTrue(server.tokenEndpointAuthMethodsSupported().contains("client_secret_post"));
        assertTrue(server.tokenEndpointAuthMethodsSupported().contains("tls_client_auth"));
    }

    @Test
    void testMultipleSigningAlgorithmsSupported() {
        OAuthAuthorizationServer server = new OAuthAuthorizationServer(
                "https://auth.example.com",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token",
                "https://auth.example.com/register",
                Collections.singletonList("code"),
                Collections.singletonList("authorization_code"),
                Collections.singletonList("client_secret_basic"),
                Arrays.asList("ES256", "ES384", "ES512", "RS256", "RS384", "RS512"),
                Collections.singletonList("S256")
        );

        assertEquals(6, server.tokenEndpointAuthSigningAlgValuesSupported().size());
        assertTrue(server.tokenEndpointAuthSigningAlgValuesSupported().contains("ES256"));
        assertTrue(server.tokenEndpointAuthSigningAlgValuesSupported().contains("RS256"));
        assertTrue(server.tokenEndpointAuthSigningAlgValuesSupported().contains("ES512"));
    }

    @Test
    void testResponseTypesSupported() {
        OAuthAuthorizationServer server = new OAuthAuthorizationServer(
                "https://auth.example.com",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token",
                "https://auth.example.com/register",
                Arrays.asList("code", "token", "id_token", "code token", "code id_token"),
                Collections.singletonList("authorization_code"),
                Collections.singletonList("client_secret_basic"),
                Collections.singletonList("ES256"),
                Collections.singletonList("S256")
        );

        assertEquals(5, server.responseTypesSupported().size());
        assertTrue(server.responseTypesSupported().contains("code"));
        assertTrue(server.responseTypesSupported().contains("token"));
        assertTrue(server.responseTypesSupported().contains("code token"));
    }
}
