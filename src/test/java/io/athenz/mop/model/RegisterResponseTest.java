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

import io.athenz.mop.model.RegisterResponse;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RegisterResponseTest {

    @Test
    void testRecordConstruction() {
        List<String> redirectUris = Arrays.asList(
                "https://app.example.com/callback",
                "https://app.example.com/callback2"
        );

        RegisterResponse response = new RegisterResponse(
                "client-id-123",
                "My Application",
                redirectUris
        );

        assertEquals("client-id-123", response.clientId());
        assertEquals("My Application", response.clientName());
        assertEquals(redirectUris, response.redirectUris());
    }

    @Test
    void testRecordConstruction_SingleRedirectUri() {
        List<String> redirectUris = Collections.singletonList("https://app.example.com/callback");

        RegisterResponse response = new RegisterResponse(
                "client-456",
                "Single App",
                redirectUris
        );

        assertEquals("client-456", response.clientId());
        assertEquals("Single App", response.clientName());
        assertEquals(1, response.redirectUris().size());
        assertEquals("https://app.example.com/callback", response.redirectUris().get(0));
    }

    @Test
    void testRecordConstruction_EmptyRedirectUris() {
        List<String> redirectUris = Collections.emptyList();

        RegisterResponse response = new RegisterResponse(
                "client-789",
                "Empty Redirects App",
                redirectUris
        );

        assertEquals("client-789", response.clientId());
        assertEquals("Empty Redirects App", response.clientName());
        assertTrue(response.redirectUris().isEmpty());
    }

    @Test
    void testRecordEquality() {
        List<String> uris = Arrays.asList("https://app.com/cb1", "https://app.com/cb2");

        RegisterResponse response1 = new RegisterResponse("client-1", "App", uris);
        RegisterResponse response2 = new RegisterResponse("client-1", "App", uris);

        assertEquals(response1, response2);
        assertEquals(response1.hashCode(), response2.hashCode());
    }

    @Test
    void testRecordInequality_DifferentClientId() {
        List<String> uris = Collections.singletonList("https://app.com/callback");

        RegisterResponse response1 = new RegisterResponse("client-1", "App", uris);
        RegisterResponse response2 = new RegisterResponse("client-2", "App", uris);

        assertNotEquals(response1, response2);
    }

    @Test
    void testRecordInequality_DifferentClientName() {
        List<String> uris = Collections.singletonList("https://app.com/callback");

        RegisterResponse response1 = new RegisterResponse("client-1", "App One", uris);
        RegisterResponse response2 = new RegisterResponse("client-1", "App Two", uris);

        assertNotEquals(response1, response2);
    }

    @Test
    void testRecordInequality_DifferentRedirectUris() {
        RegisterResponse response1 = new RegisterResponse(
                "client-1",
                "App",
                Collections.singletonList("https://app1.com/cb")
        );

        RegisterResponse response2 = new RegisterResponse(
                "client-1",
                "App",
                Collections.singletonList("https://app2.com/cb")
        );

        assertNotEquals(response1, response2);
    }

    @Test
    void testToString() {
        List<String> uris = Arrays.asList("https://app.com/cb1", "https://app.com/cb2");
        RegisterResponse response = new RegisterResponse("client-123", "Test App", uris);

        String toString = response.toString();
        assertTrue(toString.contains("client-123"));
        assertTrue(toString.contains("Test App"));
        assertTrue(toString.contains("app.com"));
    }

    @Test
    void testRecordWithMultipleRedirectUris() {
        List<String> uris = Arrays.asList(
                "https://app.example.com/callback",
                "https://app.example.com/oauth/callback",
                "https://staging.example.com/callback"
        );

        RegisterResponse response = new RegisterResponse("client-multi", "Multi Redirect App", uris);

        assertEquals("client-multi", response.clientId());
        assertEquals(3, response.redirectUris().size());
        assertTrue(response.redirectUris().contains("https://app.example.com/callback"));
        assertTrue(response.redirectUris().contains("https://staging.example.com/callback"));
    }

    @Test
    void testRecordWithNullValues() {
        RegisterResponse response = new RegisterResponse(null, null, null);

        assertNull(response.clientId());
        assertNull(response.clientName());
        assertNull(response.redirectUris());
    }
}
