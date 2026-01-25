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
import jakarta.ws.rs.FormParam;

/**
 * OAuth 2.0/2.1 token request as per RFC 6749
 * Supports:
 * - Section 4.4.2: client_credentials grant
 * - Section 4.1.3: authorization_code grant with PKCE (RFC 7636)
 *
 * Uses form parameters for application/x-www-form-urlencoded content type
 */
public class OAuth2TokenRequest {

    @FormParam("grant_type")
    @NotBlank(message = "grant_type is required")
    private String grantType;

    @FormParam("scope")
    private String scope;

    /**
     * Resource parameter (RFC 8707) - required by MCP specification
     * Must be a canonical URI identifying the MCP server where the token will be used
     */
    @FormParam("resource")
    private String resource;

    // Authorization code grant parameters (RFC 6749 Section 4.1.3)

    /**
     * Authorization code (required for authorization_code grant)
     */
    @FormParam("code")
    private String code;

    /**
     * Redirect URI (required for authorization_code grant, must match the one used in authorization request)
     */
    @FormParam("redirect_uri")
    private String redirectUri;

    /**
     * PKCE code verifier (required for authorization_code grant in OAuth 2.1)
     */
    @FormParam("code_verifier")
    private String codeVerifier;

    /**
     * Client ID (optional for mTLS, required for other auth methods)
     */
    @FormParam("client_id")
    private String clientId;

    public OAuth2TokenRequest() {
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getCodeVerifier() {
        return codeVerifier;
    }

    public void setCodeVerifier(String codeVerifier) {
        this.codeVerifier = codeVerifier;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
}
