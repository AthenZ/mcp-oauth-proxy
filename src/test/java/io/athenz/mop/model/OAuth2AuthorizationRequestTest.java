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

import io.athenz.mop.model.OAuth2AuthorizationRequest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OAuth2AuthorizationRequestTest {

    @Test
    void testDefaultConstructor() {
        OAuth2AuthorizationRequest request = new OAuth2AuthorizationRequest();
        assertNotNull(request);
        assertNull(request.getResponseType());
        assertNull(request.getClientId());
        assertNull(request.getRedirectUri());
        assertNull(request.getScope());
        assertNull(request.getState());
        assertNull(request.getCodeChallenge());
        assertNull(request.getCodeChallengeMethod());
        assertNull(request.getResource());
    }

    @Test
    void testSettersAndGetters() {
        OAuth2AuthorizationRequest request = new OAuth2AuthorizationRequest();

        request.setResponseType("code");
        request.setClientId("client-123");
        request.setRedirectUri("https://example.com/callback");
        request.setScope("openid profile email");
        request.setState("state-xyz");
        request.setCodeChallenge("challenge-abc");
        request.setCodeChallengeMethod("S256");
        request.setResource("https://api.example.com");

        assertEquals("code", request.getResponseType());
        assertEquals("client-123", request.getClientId());
        assertEquals("https://example.com/callback", request.getRedirectUri());
        assertEquals("openid profile email", request.getScope());
        assertEquals("state-xyz", request.getState());
        assertEquals("challenge-abc", request.getCodeChallenge());
        assertEquals("S256", request.getCodeChallengeMethod());
        assertEquals("https://api.example.com", request.getResource());
    }

    @Test
    void testSetResponseType() {
        OAuth2AuthorizationRequest request = new OAuth2AuthorizationRequest();
        request.setResponseType("code");
        assertEquals("code", request.getResponseType());
    }

    @Test
    void testSetClientId() {
        OAuth2AuthorizationRequest request = new OAuth2AuthorizationRequest();
        request.setClientId("my-client");
        assertEquals("my-client", request.getClientId());
    }

    @Test
    void testSetRedirectUri() {
        OAuth2AuthorizationRequest request = new OAuth2AuthorizationRequest();
        request.setRedirectUri("https://redirect.example.com");
        assertEquals("https://redirect.example.com", request.getRedirectUri());
    }

    @Test
    void testSetScope_SingleScope() {
        OAuth2AuthorizationRequest request = new OAuth2AuthorizationRequest();
        request.setScope("openid");
        assertEquals("openid", request.getScope());
    }

    @Test
    void testSetScope_MultipleScopes() {
        OAuth2AuthorizationRequest request = new OAuth2AuthorizationRequest();
        request.setScope("openid profile email");
        assertEquals("openid profile email", request.getScope());
    }

    @Test
    void testSetState() {
        OAuth2AuthorizationRequest request = new OAuth2AuthorizationRequest();
        request.setState("random-state-123");
        assertEquals("random-state-123", request.getState());
    }

    @Test
    void testSetCodeChallenge() {
        OAuth2AuthorizationRequest request = new OAuth2AuthorizationRequest();
        request.setCodeChallenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", request.getCodeChallenge());
    }

    @Test
    void testSetCodeChallengeMethod() {
        OAuth2AuthorizationRequest request = new OAuth2AuthorizationRequest();
        request.setCodeChallengeMethod("S256");
        assertEquals("S256", request.getCodeChallengeMethod());
    }

    @Test
    void testSetResource() {
        OAuth2AuthorizationRequest request = new OAuth2AuthorizationRequest();
        request.setResource("https://resource.example.com/api");
        assertEquals("https://resource.example.com/api", request.getResource());
    }

    @Test
    void testNullValues() {
        OAuth2AuthorizationRequest request = new OAuth2AuthorizationRequest();
        request.setResponseType(null);
        request.setClientId(null);
        request.setRedirectUri(null);
        request.setScope(null);
        request.setState(null);
        request.setCodeChallenge(null);
        request.setCodeChallengeMethod(null);
        request.setResource(null);

        assertNull(request.getResponseType());
        assertNull(request.getClientId());
        assertNull(request.getRedirectUri());
        assertNull(request.getScope());
        assertNull(request.getState());
        assertNull(request.getCodeChallenge());
        assertNull(request.getCodeChallengeMethod());
        assertNull(request.getResource());
    }

    @Test
    void testEmptyStrings() {
        OAuth2AuthorizationRequest request = new OAuth2AuthorizationRequest();
        request.setResponseType("");
        request.setClientId("");
        request.setRedirectUri("");
        request.setScope("");
        request.setState("");
        request.setCodeChallenge("");
        request.setCodeChallengeMethod("");
        request.setResource("");

        assertEquals("", request.getResponseType());
        assertEquals("", request.getClientId());
        assertEquals("", request.getRedirectUri());
        assertEquals("", request.getScope());
        assertEquals("", request.getState());
        assertEquals("", request.getCodeChallenge());
        assertEquals("", request.getCodeChallengeMethod());
        assertEquals("", request.getResource());
    }
}
