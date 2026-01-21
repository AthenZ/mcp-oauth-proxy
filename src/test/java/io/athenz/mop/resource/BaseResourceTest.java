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
package io.athenz.mop.resource;

import io.quarkus.oidc.OidcSession;
import io.quarkus.oidc.UserInfo;
import io.smallrye.mutiny.Uni;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class BaseResourceTest {

    private TestBaseResource baseResource;

    @Mock
    private UserInfo userInfo;

    @Mock
    private OidcSession oidcSession;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        baseResource = new TestBaseResource();
    }

    // Concrete implementation for testing
    static class TestBaseResource extends BaseResource {
    }

    @Test
    void testBuildSuccessRedirect_NoQueryParams() {
        Response response = baseResource.buildSuccessRedirect(
                "https://app.example.com/callback",
                "auth-code-123",
                "state-xyz"
        );

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        URI location = (URI) response.getMetadata().getFirst("Location");
        assertNotNull(location);
        assertTrue(location.toString().contains("code=auth-code-123"));
        assertTrue(location.toString().contains("state=state-xyz"));
        assertTrue(location.toString().startsWith("https://app.example.com/callback?"));
    }

    @Test
    void testBuildSuccessRedirect_WithExistingQueryParams() {
        Response response = baseResource.buildSuccessRedirect(
                "https://app.example.com/callback?existing=param",
                "auth-code-456",
                "state-abc"
        );

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        URI location = (URI) response.getMetadata().getFirst("Location");
        assertNotNull(location);
        assertTrue(location.toString().contains("&code=auth-code-456"));
        assertTrue(location.toString().contains("&state=state-abc"));
    }

    @Test
    void testBuildSuccessRedirect_WithoutState() {
        Response response = baseResource.buildSuccessRedirect(
                "https://app.example.com/callback",
                "auth-code-789",
                null
        );

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        URI location = (URI) response.getMetadata().getFirst("Location");
        assertNotNull(location);
        assertTrue(location.toString().contains("code=auth-code-789"));
        assertFalse(location.toString().contains("state="));
    }

    @Test
    void testBuildSuccessRedirect_WithEmptyState() {
        Response response = baseResource.buildSuccessRedirect(
                "https://app.example.com/callback",
                "auth-code-000",
                ""
        );

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        URI location = (URI) response.getMetadata().getFirst("Location");
        assertNotNull(location);
        assertTrue(location.toString().contains("code=auth-code-000"));
        assertFalse(location.toString().contains("state="));
    }

    @Test
    void testBuildSuccessRedirect_EncodesSpecialCharacters() {
        Response response = baseResource.buildSuccessRedirect(
                "https://app.example.com/callback",
                "code with spaces",
                "state&special=chars"
        );

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        URI location = (URI) response.getMetadata().getFirst("Location");
        assertNotNull(location);
        assertTrue(location.toString().contains("code=code+with+spaces"));
        assertTrue(location.toString().contains("state=state%26special%3Dchars"));
    }

    @Test
    void testBuildErrorRedirect_Basic() {
        Response response = baseResource.buildErrorRedirect(
                "https://app.example.com/callback",
                "state-xyz",
                "access_denied",
                "User denied access"
        );

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        URI location = (URI) response.getMetadata().getFirst("Location");
        assertNotNull(location);
        assertTrue(location.toString().contains("error=access_denied"));
        assertTrue(location.toString().contains("error_description=User+denied+access"));
        assertTrue(location.toString().contains("state=state-xyz"));
    }

    @Test
    void testBuildErrorRedirect_WithoutDescription() {
        Response response = baseResource.buildErrorRedirect(
                "https://app.example.com/callback",
                "state-123",
                "invalid_request",
                null
        );

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        URI location = (URI) response.getMetadata().getFirst("Location");
        assertNotNull(location);
        assertTrue(location.toString().contains("error=invalid_request"));
        assertFalse(location.toString().contains("error_description="));
    }

    @Test
    void testBuildErrorRedirect_WithoutState() {
        Response response = baseResource.buildErrorRedirect(
                "https://app.example.com/callback",
                null,
                "server_error",
                "Internal server error"
        );

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        URI location = (URI) response.getMetadata().getFirst("Location");
        assertNotNull(location);
        assertTrue(location.toString().contains("error=server_error"));
        assertFalse(location.toString().contains("state="));
    }

    @Test
    void testBuildRedirect_Basic() {
        Response response = baseResource.buildRedirect(
                "https://app.example.com/callback",
                "state-789"
        );

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        URI location = (URI) response.getMetadata().getFirst("Location");
        assertNotNull(location);
        assertTrue(location.toString().contains("state=state-789"));
    }

    @Test
    void testBuildRedirect_WithoutState() {
        Response response = baseResource.buildRedirect(
                "https://app.example.com/callback",
                null
        );

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        URI location = (URI) response.getMetadata().getFirst("Location");
        assertNotNull(location);
    }

    @Test
    void testGetUserNameFromUserInfo_WithCustomClaim() {
        when(userInfo.get("email")).thenReturn("user@example.com");
        when(userInfo.getSubject()).thenReturn("sub-123");

        String userName = baseResource.getUserNameFromUserInfo(userInfo, "email");

        assertEquals("user@example.com", userName);
        verify(userInfo, times(2)).get("email"); // Called twice: null check and value retrieval
        verify(userInfo, never()).getSubject();
    }

    @Test
    void testGetUserNameFromUserInfo_FallbackToSubject() {
        when(userInfo.get("email")).thenReturn(null);
        when(userInfo.getSubject()).thenReturn("subject-456");

        String userName = baseResource.getUserNameFromUserInfo(userInfo, "email");

        assertEquals("subject-456", userName);
        verify(userInfo).get("email");
        verify(userInfo).getSubject();
    }

    @Test
    void testGetUserNameFromUserInfo_WithQuotes() {
        when(userInfo.get("username")).thenReturn("\"quoted-user\"");

        String userName = baseResource.getUserNameFromUserInfo(userInfo, "username");

        assertEquals("quoted-user", userName);
    }

    @Test
    void testGetUsername_WithUserInfo() {
        when(userInfo.get("login")).thenReturn("testuser");

        String userName = baseResource.getUsername(userInfo, "login", null);

        assertEquals("testuser", userName);
    }

    @Test
    void testGetUsername_WithEmailClaim_ExtractsLocalPart() {
        when(userInfo.get("email")).thenReturn("john.doe@example.com");

        String userName = baseResource.getUsername(userInfo, "email", null);

        assertEquals("john.doe", userName);
    }

    @Test
    void testGetUsername_WithEmailClaim_NoAtSign() {
        when(userInfo.get("email")).thenReturn("username");

        String userName = baseResource.getUsername(userInfo, "email", null);

        assertEquals("username", userName);
    }

    @Test
    void testGetUsername_FromToken() {
        // Create a simple JWT token for testing
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        String userName = baseResource.getUsername(null, "name", token);

        assertEquals("John Doe", userName);
    }

    @Test
    void testGetUsername_NullUserInfo_NullToken() {
        // When both userInfo and token are null, JwtUtils.getClaimFromToken throws NullPointerException
        assertThrows(NullPointerException.class, () -> {
            baseResource.getUsername(null, "sub", null);
        });
    }

    @Test
    void testLogoutFromProvider() {
        Uni<Void> logoutUni = Uni.createFrom().voidItem();
        when(oidcSession.logout()).thenReturn(logoutUni);

        baseResource.logoutFromProvider("github", oidcSession);

        verify(oidcSession).logout();
    }
}
