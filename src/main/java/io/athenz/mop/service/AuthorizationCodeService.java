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
package io.athenz.mop.service;

import io.athenz.mop.model.AuthorizationCode;
import io.athenz.mop.store.AuthCodeStore;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service for generating, storing, and validating OAuth 2.1 authorization codes
 * Implements one-time use, short-lived authorization codes with PKCE validation
 */
@ApplicationScoped
public class AuthorizationCodeService {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    // OAuth 2.1 recommends 10-minute maximum lifetime for authorization codes
    private static final Duration CODE_EXPIRY = Duration.ofMinutes(10);

    // 32 bytes = 256 bits of entropy for authorization code
    private static final int CODE_LENGTH = 32;

    private final SecureRandom secureRandom = new SecureRandom();

    @Inject
    AuthCodeStore authCodeStore;

    @ConfigProperty(name = "server.token-exchange.idp")
    String providerDefault;

    /**
     * Generate a secure authorization code
     *
     * @param clientId the OAuth client ID
     * @param subject the authenticated subject
     * @param redirectUri the redirect URI for this authorization
     * @param scope the requested scope
     * @param resource the target resource URI (RFC 8707)
     * @param codeChallenge the PKCE code challenge
     * @param codeChallengeMethod the PKCE code challenge method
     * @return the generated authorization code string
     */
    public String generateCode(String clientId, String subject, String redirectUri,
                               String scope, String resource, String codeChallenge,
                               String codeChallengeMethod, String state) {

        // Generate cryptographically secure random code
        byte[] codeBytes = new byte[CODE_LENGTH];
        secureRandom.nextBytes(codeBytes);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(codeBytes);

        Instant expiresAt = Instant.now().plus(CODE_EXPIRY);

        // This is a default scope for the authorization code if the user does not provide a scope
        // and is not used for any upstream IDP authorization code flow
        if (scope == null || scope.isEmpty()) {
            scope = "default";  
        }

        AuthorizationCode authCode = new AuthorizationCode(
                code, clientId, subject, redirectUri, scope, resource,
                codeChallenge, codeChallengeMethod, expiresAt, state
        );

        authCodeStore.storeAuthCode(code, providerDefault, authCode);

        log.info("Generated authorization code for client: {}, subject: {}, expires at: {}",
                clientId, subject, expiresAt);

        return code;
    }

    /**
     * Validate and consume an authorization code
     * This implements one-time use - the code is marked as used and cannot be reused
     *
     * @param code the authorization code to validate
     * @param clientId the client ID attempting to use the code
     * @param redirectUri the redirect URI for validation
     * @param codeVerifier the PKCE code verifier
     * @return the AuthorizationCode if valid, null otherwise
     */
    public AuthorizationCode validateAndConsume(String code, String clientId,
                                                String redirectUri, String codeVerifier) {
        if (code == null || code.isEmpty()) {
            log.warn("Empty authorization code provided");
            return null;
        }

        AuthorizationCode authCode = authCodeStore.getAuthCode(code, providerDefault);

        String codePrefixForLog = code.substring(0, Math.min(8, code.length()));
        if (authCode == null) {
            log.warn("Authorization code not found or expired: {}", codePrefixForLog);
            return null;
        }

        // Check if already used (prevents replay attacks)
        if (authCode.isUsed()) {
            log.error("Authorization code already used: {}", codePrefixForLog);
            // RFC 6749 Section 4.1.2: If code is used twice, revoke all tokens issued with it
            authCodeStore.deleteAuthCode(code, providerDefault);
            return null;
        }

        // Check expiration
        if (authCode.isExpired()) {
            log.warn("Authorization code expired: {}", codePrefixForLog);
            authCodeStore.deleteAuthCode(code, providerDefault);
            return null;
        }

        // Validate client_id matches
        if (!authCode.getClientId().equals(clientId)) {
            log.error("Client ID mismatch for authorization code. Expected: {}, Got: {}",
                    authCode.getClientId(), clientId);
            return null;
        }

        // Validate redirect_uri matches (REQUIRED per RFC 6749)
        if (!authCode.getRedirectUri().equals(redirectUri)) {
            log.error("Redirect URI mismatch for authorization code. Expected: {}, Got: {}",
                    authCode.getRedirectUri(), redirectUri);
            return null;
        }

        // Validate PKCE code_verifier (OAuth 2.1 requirement)
        if (!validatePKCE(authCode.getCodeChallenge(), authCode.getCodeChallengeMethod(), codeVerifier)) {
            log.error("PKCE validation failed for authorization code");
            return null;
        }

        // Mark as used (one-time use enforcement)
        authCode.markAsUsed();
        // delete code from store
        authCodeStore.deleteAuthCode(code, providerDefault);

        log.info("Authorization code validated and consumed for client: {}, subject: {}",
                clientId, authCode.getSubject());

        return authCode;
    }

    /**
     * Validate PKCE code_verifier against code_challenge
     * OAuth 2.1 mandates PKCE for all authorization code flows
     *
     * @param codeChallenge the stored code challenge
     * @param codeChallengeMethod the challenge method (S256)
     * @param codeVerifier the code verifier to validate
     * @return true if PKCE validation passes
     */
    private boolean validatePKCE(String codeChallenge, String codeChallengeMethod, String codeVerifier) {
        if (codeChallenge == null || codeVerifier == null) {
            log.error("Missing PKCE parameters");
            return false;
        }

        try {
            String computedChallenge;

            if ("S256".equals(codeChallengeMethod)) {
                // Compute SHA256 hash of code_verifier
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                computedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            } else {
                log.error("Unsupported code_challenge_method: {}", codeChallengeMethod);
                return false;
            }

            boolean valid = computedChallenge.equals(codeChallenge);
            if (!valid) {
                log.error("PKCE validation failed. Challenge mismatch.");
            }
            return valid;

        } catch (Exception e) {
            log.error("Error validating PKCE", e);
            return false;
        }
    }
}
