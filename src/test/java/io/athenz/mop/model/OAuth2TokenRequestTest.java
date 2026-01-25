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

import io.athenz.mop.model.OAuth2TokenRequest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OAuth2TokenRequestTest {

    @Test
    void testDefaultConstructor() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        assertNotNull(request);
        assertNull(request.getGrantType());
        assertNull(request.getScope());
        assertNull(request.getResource());
        assertNull(request.getCode());
        assertNull(request.getRedirectUri());
        assertNull(request.getCodeVerifier());
        assertNull(request.getClientId());
    }

    @Test
    void testSettersAndGetters() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();

        request.setGrantType("authorization_code");
        request.setScope("openid profile");
        request.setResource("https://api.example.com");
        request.setCode("auth-code-123");
        request.setRedirectUri("https://example.com/callback");
        request.setCodeVerifier("verifier-abc");
        request.setClientId("client-456");

        assertEquals("authorization_code", request.getGrantType());
        assertEquals("openid profile", request.getScope());
        assertEquals("https://api.example.com", request.getResource());
        assertEquals("auth-code-123", request.getCode());
        assertEquals("https://example.com/callback", request.getRedirectUri());
        assertEquals("verifier-abc", request.getCodeVerifier());
        assertEquals("client-456", request.getClientId());
    }

    @Test
    void testSetGrantType() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("client_credentials");
        assertEquals("client_credentials", request.getGrantType());
    }

    @Test
    void testSetScope_SingleScope() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setScope("read");
        assertEquals("read", request.getScope());
    }

    @Test
    void testSetScope_MultipleScopes() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setScope("read write delete");
        assertEquals("read write delete", request.getScope());
    }

    @Test
    void testSetResource() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setResource("https://resource.example.com/api/v1");
        assertEquals("https://resource.example.com/api/v1", request.getResource());
    }

    @Test
    void testSetCode() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setCode("authorization-code-xyz");
        assertEquals("authorization-code-xyz", request.getCode());
    }

    @Test
    void testSetRedirectUri() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setRedirectUri("https://app.example.com/oauth/callback");
        assertEquals("https://app.example.com/oauth/callback", request.getRedirectUri());
    }

    @Test
    void testSetCodeVerifier() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setCodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assertEquals("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", request.getCodeVerifier());
    }

    @Test
    void testSetClientId() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setClientId("my-application");
        assertEquals("my-application", request.getClientId());
    }

    @Test
    void testAuthorizationCodeGrant() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("authorization_code");
        request.setCode("abc123");
        request.setRedirectUri("https://app.com/callback");
        request.setCodeVerifier("verifier123");
        request.setClientId("client-id");

        assertEquals("authorization_code", request.getGrantType());
        assertEquals("abc123", request.getCode());
        assertEquals("https://app.com/callback", request.getRedirectUri());
        assertEquals("verifier123", request.getCodeVerifier());
        assertEquals("client-id", request.getClientId());
    }

    @Test
    void testClientCredentialsGrant() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("client_credentials");
        request.setScope("api:read api:write");
        request.setResource("https://api.example.com");

        assertEquals("client_credentials", request.getGrantType());
        assertEquals("api:read api:write", request.getScope());
        assertEquals("https://api.example.com", request.getResource());
        assertNull(request.getCode());
        assertNull(request.getRedirectUri());
        assertNull(request.getCodeVerifier());
    }

    @Test
    void testNullValues() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType(null);
        request.setScope(null);
        request.setResource(null);
        request.setCode(null);
        request.setRedirectUri(null);
        request.setCodeVerifier(null);
        request.setClientId(null);

        assertNull(request.getGrantType());
        assertNull(request.getScope());
        assertNull(request.getResource());
        assertNull(request.getCode());
        assertNull(request.getRedirectUri());
        assertNull(request.getCodeVerifier());
        assertNull(request.getClientId());
    }

    @Test
    void testEmptyStrings() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("");
        request.setScope("");
        request.setResource("");
        request.setCode("");
        request.setRedirectUri("");
        request.setCodeVerifier("");
        request.setClientId("");

        assertEquals("", request.getGrantType());
        assertEquals("", request.getScope());
        assertEquals("", request.getResource());
        assertEquals("", request.getCode());
        assertEquals("", request.getRedirectUri());
        assertEquals("", request.getCodeVerifier());
        assertEquals("", request.getClientId());
    }
}
