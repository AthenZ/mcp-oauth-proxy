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

import jakarta.validation.constraints.NotBlank;
import jakarta.ws.rs.QueryParam;

/**
 * OAuth 2.1 authorization request parameters (RFC 6749 Section 4.1.1 + PKCE RFC 7636)
 * OAuth 2.1 mandates PKCE for all authorization code flows
 */
public class OAuth2AuthorizationRequest {

    @QueryParam("response_type")
    @NotBlank(message = "response_type is required")
    private String responseType;

    @QueryParam("client_id")
    @NotBlank(message = "client_id is required")
    private String clientId;

    @QueryParam("redirect_uri")
    @NotBlank(message = "redirect_uri is required")
    private String redirectUri;

    @QueryParam("scope")
    private String scope;

    @QueryParam("state")
    private String state;

    /**
     * PKCE code challenge (required in OAuth 2.1)
     * Base64-URL encoded SHA256 hash of code_verifier
     */
    @QueryParam("code_challenge")
    @NotBlank(message = "code_challenge is required (PKCE)")
    private String codeChallenge;

    /**
     * PKCE code challenge method (required in OAuth 2.1)
     * Must be "S256" (plain is deprecated)
     */
    @QueryParam("code_challenge_method")
    @NotBlank(message = "code_challenge_method is required")
    private String codeChallengeMethod;

    /**
     * Resource parameter (RFC 8807) - required by MCP specification
     * Must be a canonical URI identifying the MCP server where the token will be used
     */
    @QueryParam("resource")
    private String resource;

    public OAuth2AuthorizationRequest() {
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public void setCodeChallenge(String codeChallenge) {
        this.codeChallenge = codeChallenge;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public void setCodeChallengeMethod(String codeChallengeMethod) {
        this.codeChallengeMethod = codeChallengeMethod;
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }
}
