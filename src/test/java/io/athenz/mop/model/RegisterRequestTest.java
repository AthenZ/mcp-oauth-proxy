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

import io.athenz.mop.model.RegisterRequest;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RegisterRequestTest {

    @Test
    void testRecordConstruction() {
        List<String> redirectUris = Arrays.asList(
                "https://app.example.com/callback",
                "https://app.example.com/callback2"
        );

        RegisterRequest request = new RegisterRequest(redirectUris, "My Application");

        assertEquals(redirectUris, request.redirectUris());
        assertEquals("My Application", request.clientName());
    }

    @Test
    void testRecordConstruction_SingleRedirectUri() {
        List<String> redirectUris = Collections.singletonList("https://app.example.com/callback");

        RegisterRequest request = new RegisterRequest(redirectUris, "Single Redirect App");

        assertEquals(1, request.redirectUris().size());
        assertEquals("https://app.example.com/callback", request.redirectUris().get(0));
        assertEquals("Single Redirect App", request.clientName());
    }

    @Test
    void testRecordConstruction_NullClientName() {
        List<String> redirectUris = Collections.singletonList("https://app.example.com/callback");

        RegisterRequest request = new RegisterRequest(redirectUris, null);

        assertEquals(redirectUris, request.redirectUris());
        assertNull(request.clientName());
    }

    @Test
    void testRecordConstruction_EmptyRedirectUris() {
        List<String> redirectUris = Collections.emptyList();

        RegisterRequest request = new RegisterRequest(redirectUris, "Empty Redirect App");

        assertTrue(request.redirectUris().isEmpty());
        assertEquals("Empty Redirect App", request.clientName());
    }

    @Test
    void testRecordEquality() {
        List<String> uris = Arrays.asList("https://app.com/callback1", "https://app.com/callback2");

        RegisterRequest request1 = new RegisterRequest(uris, "App Name");
        RegisterRequest request2 = new RegisterRequest(uris, "App Name");

        assertEquals(request1, request2);
        assertEquals(request1.hashCode(), request2.hashCode());
    }

    @Test
    void testRecordInequality_DifferentRedirectUris() {
        RegisterRequest request1 = new RegisterRequest(
                Collections.singletonList("https://app1.com/callback"),
                "App"
        );

        RegisterRequest request2 = new RegisterRequest(
                Collections.singletonList("https://app2.com/callback"),
                "App"
        );

        assertNotEquals(request1, request2);
    }

    @Test
    void testRecordInequality_DifferentClientName() {
        List<String> uris = Collections.singletonList("https://app.com/callback");

        RegisterRequest request1 = new RegisterRequest(uris, "App One");
        RegisterRequest request2 = new RegisterRequest(uris, "App Two");

        assertNotEquals(request1, request2);
    }

    @Test
    void testToString() {
        List<String> uris = Arrays.asList("https://app.com/cb1", "https://app.com/cb2");
        RegisterRequest request = new RegisterRequest(uris, "Test App");

        String toString = request.toString();
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

        RegisterRequest request = new RegisterRequest(uris, "Multi Redirect App");

        assertEquals(3, request.redirectUris().size());
        assertTrue(request.redirectUris().contains("https://app.example.com/callback"));
        assertTrue(request.redirectUris().contains("https://staging.example.com/callback"));
    }
}
