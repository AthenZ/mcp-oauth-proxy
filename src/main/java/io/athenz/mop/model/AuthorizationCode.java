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


import java.time.Instant;

/**
 * Represents a secure, one-time use OAuth 2.1 authorization code
 * Includes PKCE parameters for secure code exchange
 */
public class AuthorizationCode {
    private String code;
    private String clientId;
    private String subject;
    private String redirectUri;
    private String scope;
    private String resource;
    private String codeChallenge;
    private String codeChallengeMethod;
    private Instant expiresAt;
    private boolean used;
    private String state;

    public AuthorizationCode() {
    }
    public AuthorizationCode(String code, String clientId, String subject, String redirectUri,
                             String scope, String resource, String codeChallenge,
                             String codeChallengeMethod, Instant expiresAt, String state) {
        this.code = code;
        this.clientId = clientId;
        this.subject = subject;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.resource = resource;
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.expiresAt = expiresAt;
        this.used = false;
        this.state = state;
    }

    public String getCode() {
        return code;
    }

    public String getClientId() {
        return clientId;
    }

    public String getSubject() {
        return subject;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public String getResource() {
        return resource;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public String getState() {
        return state;
    }

    public boolean isUsed() {
        return used;
    }

    public void markAsUsed() {
        this.used = true;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isValid() {
        return !used && !isExpired();
    }

    public void setCode(String code) {
        this.code = code;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public void setCodeChallenge(String codeChallenge) {
        this.codeChallenge = codeChallenge;
    }

    public void setCodeChallengeMethod(String codeChallengeMethod) {
        this.codeChallengeMethod = codeChallengeMethod;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public void setUsed(boolean used) {
        this.used = used;
    }

    public void setState(String state) {
        this.state = state;
    }
}
