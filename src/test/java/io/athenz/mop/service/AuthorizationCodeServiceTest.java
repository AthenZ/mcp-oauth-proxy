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
import io.athenz.mop.service.AuthorizationCodeService;
import io.athenz.mop.store.AuthCodeStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthorizationCodeServiceTest {

    @Mock
    private AuthCodeStore authCodeStore;

    @InjectMocks
    private AuthorizationCodeService authorizationCodeService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        authorizationCodeService.providerDefault = "okta";
    }

    @Test
    void testGenerateCode_Success() {
        // Given
        String clientId = "test-client-id";
        String subject = "test-subject";
        String redirectUri = "https://example.com/callback";
        String scope = "openid profile";
        String resource = "https://api.example.com";
        String codeChallenge = "test-challenge";
        String codeChallengeMethod = "S256";
        String state = "test-state";

        // When
        String code = authorizationCodeService.generateCode(
                clientId, subject, redirectUri, scope, resource,
                codeChallenge, codeChallengeMethod, state
        );

        // Then
        assertNotNull(code);
        assertFalse(code.isEmpty());
        assertTrue(code.length() > 0);

        // Verify that the code was stored
        ArgumentCaptor<AuthorizationCode> authCodeCaptor = ArgumentCaptor.forClass(AuthorizationCode.class);
        verify(authCodeStore).storeAuthCode(eq(code), eq("okta"), authCodeCaptor.capture());

        AuthorizationCode capturedAuthCode = authCodeCaptor.getValue();
        assertEquals(code, capturedAuthCode.getCode());
        assertEquals(clientId, capturedAuthCode.getClientId());
        assertEquals(subject, capturedAuthCode.getSubject());
        assertEquals(redirectUri, capturedAuthCode.getRedirectUri());
        assertEquals(scope, capturedAuthCode.getScope());
        assertEquals(resource, capturedAuthCode.getResource());
        assertEquals(codeChallenge, capturedAuthCode.getCodeChallenge());
        assertEquals(codeChallengeMethod, capturedAuthCode.getCodeChallengeMethod());
        assertEquals(state, capturedAuthCode.getState());
        assertNotNull(capturedAuthCode.getExpiresAt());
        assertTrue(capturedAuthCode.getExpiresAt().isAfter(Instant.now()));
        assertFalse(capturedAuthCode.isUsed());
    }

    @Test
    void testGenerateCode_WithNullScope() {
        // Given
        String clientId = "test-client-id";
        String subject = "test-subject";
        String redirectUri = "https://example.com/callback";
        String scope = null;
        String resource = "https://api.example.com";
        String codeChallenge = "test-challenge";
        String codeChallengeMethod = "S256";
        String state = "test-state";

        // When
        String code = authorizationCodeService.generateCode(
                clientId, subject, redirectUri, scope, resource,
                codeChallenge, codeChallengeMethod, state
        );

        // Then
        assertNotNull(code);

        // Verify that default scope was set
        ArgumentCaptor<AuthorizationCode> authCodeCaptor = ArgumentCaptor.forClass(AuthorizationCode.class);
        verify(authCodeStore).storeAuthCode(eq(code), eq("okta"), authCodeCaptor.capture());

        AuthorizationCode capturedAuthCode = authCodeCaptor.getValue();
        assertEquals("default", capturedAuthCode.getScope());
    }

    @Test
    void testGenerateCode_WithEmptyScope() {
        // Given
        String clientId = "test-client-id";
        String subject = "test-subject";
        String redirectUri = "https://example.com/callback";
        String scope = "";
        String resource = "https://api.example.com";
        String codeChallenge = "test-challenge";
        String codeChallengeMethod = "S256";
        String state = "test-state";

        // When
        String code = authorizationCodeService.generateCode(
                clientId, subject, redirectUri, scope, resource,
                codeChallenge, codeChallengeMethod, state
        );

        // Then
        assertNotNull(code);

        // Verify that default scope was set
        ArgumentCaptor<AuthorizationCode> authCodeCaptor = ArgumentCaptor.forClass(AuthorizationCode.class);
        verify(authCodeStore).storeAuthCode(eq(code), eq("okta"), authCodeCaptor.capture());

        AuthorizationCode capturedAuthCode = authCodeCaptor.getValue();
        assertEquals("default", capturedAuthCode.getScope());
    }

    @Test
    void testGenerateCode_UniqueCodesGenerated() {
        // Given
        String clientId = "test-client-id";
        String subject = "test-subject";
        String redirectUri = "https://example.com/callback";
        String scope = "openid";
        String resource = "https://api.example.com";
        String codeChallenge = "test-challenge";
        String codeChallengeMethod = "S256";
        String state = "test-state";

        // When - Generate multiple codes
        String code1 = authorizationCodeService.generateCode(
                clientId, subject, redirectUri, scope, resource,
                codeChallenge, codeChallengeMethod, state
        );
        String code2 = authorizationCodeService.generateCode(
                clientId, subject, redirectUri, scope, resource,
                codeChallenge, codeChallengeMethod, state
        );

        // Then - Codes should be unique
        assertNotEquals(code1, code2);
    }

    @Test
    void testValidateAndConsume_Success() throws Exception {
        // Given
        String code = "valid-test-code";
        String clientId = "test-client-id";
        String subject = "test-subject";
        String redirectUri = "https://example.com/callback";
        String scope = "openid";
        String resource = "https://api.example.com";
        String codeVerifier = "test-verifier";

        // Compute code challenge
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

        AuthorizationCode authCode = new AuthorizationCode(
                code, clientId, subject, redirectUri, scope, resource,
                codeChallenge, "S256", Instant.now().plusSeconds(600), "test-state"
        );

        when(authCodeStore.getAuthCode(code, "okta")).thenReturn(authCode);

        // When
        AuthorizationCode result = authorizationCodeService.validateAndConsume(
                code, clientId, redirectUri, codeVerifier
        );

        // Then
        assertNotNull(result);
        assertEquals(clientId, result.getClientId());
        assertEquals(subject, result.getSubject());
        assertEquals(redirectUri, result.getRedirectUri());
        assertTrue(result.isUsed());

        // Verify code was deleted from store
        verify(authCodeStore).deleteAuthCode(code, "okta");
    }

    @Test
    void testValidateAndConsume_NullCode() {
        // When
        AuthorizationCode result = authorizationCodeService.validateAndConsume(
                null, "client-id", "https://example.com/callback", "verifier"
        );

        // Then
        assertNull(result);
        verify(authCodeStore, never()).getAuthCode(anyString(), anyString());
    }

    @Test
    void testValidateAndConsume_EmptyCode() {
        // When
        AuthorizationCode result = authorizationCodeService.validateAndConsume(
                "", "client-id", "https://example.com/callback", "verifier"
        );

        // Then
        assertNull(result);
        verify(authCodeStore, never()).getAuthCode(anyString(), anyString());
    }

    @Test
    void testValidateAndConsume_CodeNotFound() {
        // Given
        String code = "non-existent-code";
        when(authCodeStore.getAuthCode(code, "okta")).thenReturn(null);

        // When
        AuthorizationCode result = authorizationCodeService.validateAndConsume(
                code, "client-id", "https://example.com/callback", "verifier"
        );

        // Then
        assertNull(result);
        verify(authCodeStore).getAuthCode(code, "okta");
        verify(authCodeStore, never()).deleteAuthCode(anyString(), anyString());
    }

    @Test
    void testValidateAndConsume_CodeAlreadyUsed() {
        // Given
        String code = "used-code";
        String clientId = "test-client-id";
        String redirectUri = "https://example.com/callback";

        AuthorizationCode authCode = new AuthorizationCode(
                code, clientId, "subject", redirectUri, "openid", "resource",
                "challenge", "S256", Instant.now().plusSeconds(600), "state"
        );
        authCode.markAsUsed();

        when(authCodeStore.getAuthCode(code, "okta")).thenReturn(authCode);

        // When
        AuthorizationCode result = authorizationCodeService.validateAndConsume(
                code, clientId, redirectUri, "verifier"
        );

        // Then
        assertNull(result);
        verify(authCodeStore).deleteAuthCode(code, "okta");
    }

    @Test
    void testValidateAndConsume_CodeExpired() {
        // Given
        String code = "expired-code";
        String clientId = "test-client-id";
        String redirectUri = "https://example.com/callback";

        AuthorizationCode authCode = new AuthorizationCode(
                code, clientId, "subject", redirectUri, "openid", "resource",
                "challenge", "S256", Instant.now().minusSeconds(600), "state"
        );

        when(authCodeStore.getAuthCode(code, "okta")).thenReturn(authCode);

        // When
        AuthorizationCode result = authorizationCodeService.validateAndConsume(
                code, clientId, redirectUri, "verifier"
        );

        // Then
        assertNull(result);
        verify(authCodeStore).deleteAuthCode(code, "okta");
    }

    @Test
    void testValidateAndConsume_ClientIdMismatch() throws Exception {
        // Given
        String code = "valid-code";
        String clientId = "test-client-id";
        String wrongClientId = "wrong-client-id";
        String redirectUri = "https://example.com/callback";
        String codeVerifier = "test-verifier";

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

        AuthorizationCode authCode = new AuthorizationCode(
                code, clientId, "subject", redirectUri, "openid", "resource",
                codeChallenge, "S256", Instant.now().plusSeconds(600), "state"
        );

        when(authCodeStore.getAuthCode(code, "okta")).thenReturn(authCode);

        // When
        AuthorizationCode result = authorizationCodeService.validateAndConsume(
                code, wrongClientId, redirectUri, codeVerifier
        );

        // Then
        assertNull(result);
        verify(authCodeStore, never()).deleteAuthCode(anyString(), anyString());
    }

    @Test
    void testValidateAndConsume_RedirectUriMismatch() throws Exception {
        // Given
        String code = "valid-code";
        String clientId = "test-client-id";
        String redirectUri = "https://example.com/callback";
        String wrongRedirectUri = "https://evil.com/callback";
        String codeVerifier = "test-verifier";

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

        AuthorizationCode authCode = new AuthorizationCode(
                code, clientId, "subject", redirectUri, "openid", "resource",
                codeChallenge, "S256", Instant.now().plusSeconds(600), "state"
        );

        when(authCodeStore.getAuthCode(code, "okta")).thenReturn(authCode);

        // When
        AuthorizationCode result = authorizationCodeService.validateAndConsume(
                code, clientId, wrongRedirectUri, codeVerifier
        );

        // Then
        assertNull(result);
        verify(authCodeStore, never()).deleteAuthCode(anyString(), anyString());
    }

    @Test
    void testValidateAndConsume_PKCEValidationFailed() {
        // Given
        String code = "valid-code";
        String clientId = "test-client-id";
        String redirectUri = "https://example.com/callback";
        String codeVerifier = "wrong-verifier";
        String codeChallenge = "expected-challenge";

        AuthorizationCode authCode = new AuthorizationCode(
                code, clientId, "subject", redirectUri, "openid", "resource",
                codeChallenge, "S256", Instant.now().plusSeconds(600), "state"
        );

        when(authCodeStore.getAuthCode(code, "okta")).thenReturn(authCode);

        // When
        AuthorizationCode result = authorizationCodeService.validateAndConsume(
                code, clientId, redirectUri, codeVerifier
        );

        // Then
        assertNull(result);
        verify(authCodeStore, never()).deleteAuthCode(anyString(), anyString());
    }

    @Test
    void testValidateAndConsume_MissingCodeChallenge() {
        // Given
        String code = "valid-code";
        String clientId = "test-client-id";
        String redirectUri = "https://example.com/callback";
        String codeVerifier = "test-verifier";

        AuthorizationCode authCode = new AuthorizationCode(
                code, clientId, "subject", redirectUri, "openid", "resource",
                null, "S256", Instant.now().plusSeconds(600), "state"
        );

        when(authCodeStore.getAuthCode(code, "okta")).thenReturn(authCode);

        // When
        AuthorizationCode result = authorizationCodeService.validateAndConsume(
                code, clientId, redirectUri, codeVerifier
        );

        // Then
        assertNull(result);
        verify(authCodeStore, never()).deleteAuthCode(anyString(), anyString());
    }

    @Test
    void testValidateAndConsume_MissingCodeVerifier() throws Exception {
        // Given
        String code = "valid-code";
        String clientId = "test-client-id";
        String redirectUri = "https://example.com/callback";
        String codeVerifier = null;

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest("test-verifier".getBytes(StandardCharsets.US_ASCII));
        String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

        AuthorizationCode authCode = new AuthorizationCode(
                code, clientId, "subject", redirectUri, "openid", "resource",
                codeChallenge, "S256", Instant.now().plusSeconds(600), "state"
        );

        when(authCodeStore.getAuthCode(code, "okta")).thenReturn(authCode);

        // When
        AuthorizationCode result = authorizationCodeService.validateAndConsume(
                code, clientId, redirectUri, codeVerifier
        );

        // Then
        assertNull(result);
        verify(authCodeStore, never()).deleteAuthCode(anyString(), anyString());
    }

    @Test
    void testValidateAndConsume_UnsupportedChallengeMethod() throws Exception {
        // Given
        String code = "valid-code";
        String clientId = "test-client-id";
        String redirectUri = "https://example.com/callback";
        String codeVerifier = "test-verifier";

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

        AuthorizationCode authCode = new AuthorizationCode(
                code, clientId, "subject", redirectUri, "openid", "resource",
                codeChallenge, "plain", Instant.now().plusSeconds(600), "state"
        );

        when(authCodeStore.getAuthCode(code, "okta")).thenReturn(authCode);

        // When
        AuthorizationCode result = authorizationCodeService.validateAndConsume(
                code, clientId, redirectUri, codeVerifier
        );

        // Then
        assertNull(result);
        verify(authCodeStore, never()).deleteAuthCode(anyString(), anyString());
    }

    @Test
    void testValidateAndConsume_ShortCode() {
        // Given
        String code = "short";
        when(authCodeStore.getAuthCode(code, "okta")).thenReturn(null);

        // When
        AuthorizationCode result = authorizationCodeService.validateAndConsume(
                code, "client-id", "https://example.com/callback", "verifier"
        );

        // Then
        assertNull(result);
        verify(authCodeStore).getAuthCode(code, "okta");
    }
}
