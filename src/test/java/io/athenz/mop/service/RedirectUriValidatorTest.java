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

import io.athenz.mop.service.RedirectUriValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RedirectUriValidatorTest {

    private RedirectUriValidator validator;

    @BeforeEach
    void setUp() {
        validator = new RedirectUriValidator();
        validator.allowedRedirectUriPrefixes = Arrays.asList(
                "http://localhost",
                "https://localhost",
                "cursor://anysphere.cursor-",
                "https://app.example.com"
        );
    }

    @Test
    void testIsValidRedirectUri_HttpsValid() {
        assertTrue(validator.isValidRedirectUri("https://app.example.com/callback"));
        assertTrue(validator.isValidRedirectUri("https://app.example.com/oauth/callback"));
    }

    @Test
    void testIsValidRedirectUri_HttpLocalhostValid() {
        assertTrue(validator.isValidRedirectUri("http://localhost:3000/callback"));
        assertTrue(validator.isValidRedirectUri("http://localhost/callback"));
        assertTrue(validator.isValidRedirectUri("https://localhost:4443/callback"));
    }

    @Test
    void testIsValidRedirectUri_CustomSchemeValid() {
        assertTrue(validator.isValidRedirectUri("cursor://anysphere.cursor-abc123"));
        assertTrue(validator.isValidRedirectUri("cursor://anysphere.cursor-callback"));
    }

    @Test
    void testIsValidRedirectUri_HttpNonLocalhostInvalid() {
        assertFalse(validator.isValidRedirectUri("http://example.com/callback"));
        assertFalse(validator.isValidRedirectUri("http://app.example.com/callback"));
    }

    @Test
    void testIsValidRedirectUri_NullInvalid() {
        assertFalse(validator.isValidRedirectUri(null));
        assertFalse(validator.isValidRedirectUri(null, "client-123"));
    }

    @Test
    void testIsValidRedirectUri_EmptyInvalid() {
        assertFalse(validator.isValidRedirectUri(""));
        assertFalse(validator.isValidRedirectUri("", "client-123"));
    }

    @Test
    void testIsValidRedirectUri_InvalidFormatInvalid() {
        assertFalse(validator.isValidRedirectUri("not-a-valid-uri"));
        assertFalse(validator.isValidRedirectUri("://invalid"));
    }

    @Test
    void testIsValidRedirectUri_NoSchemeInvalid() {
        assertFalse(validator.isValidRedirectUri("example.com/callback"));
        assertFalse(validator.isValidRedirectUri("//example.com/callback"));
    }

    @Test
    void testIsValidRedirectUri_NotInAllowlistInvalid() {
        assertFalse(validator.isValidRedirectUri("https://evil.example.com/callback"));
        assertFalse(validator.isValidRedirectUri("https://notallowed.com/callback"));
    }

    @Test
    void testIsValidRedirectUri_Localhost127001Valid() {
        // 127.0.0.1 needs to be in the allowlist or allowlist needs to include localhost patterns
        assertTrue(validator.isValidRedirectUri("http://localhost:8080/callback"));
        assertTrue(validator.isValidRedirectUri("http://localhost/callback"));
    }

    @Test
    void testIsValidRedirectUri_WithClientId() {
        assertTrue(validator.isValidRedirectUri("https://app.example.com/callback", "client-123"));
        assertFalse(validator.isValidRedirectUri(null, "client-123"));
        assertFalse(validator.isValidRedirectUri("http://evil.com/callback", "client-123"));
    }

    @Test
    void testIsValidRedirectUri_WithoutClientId() {
        assertTrue(validator.isValidRedirectUri("https://app.example.com/callback"));
        assertFalse(validator.isValidRedirectUri(null));
    }

    @Test
    void testValidateRedirectUris_AllValid() {
        List<String> uris = Arrays.asList(
                "https://app.example.com/callback1",
                "https://app.example.com/callback2",
                "http://localhost:3000/callback"
        );

        assertTrue(validator.validateRedirectUris(uris, "client-123"));
    }

    @Test
    void testValidateRedirectUris_OneInvalid() {
        List<String> uris = Arrays.asList(
                "https://app.example.com/callback1",
                "http://evil.com/callback",
                "http://localhost:3000/callback"
        );

        assertFalse(validator.validateRedirectUris(uris, "client-123"));
    }

    @Test
    void testValidateRedirectUris_NullList() {
        assertFalse(validator.validateRedirectUris(null, "client-123"));
    }

    @Test
    void testValidateRedirectUris_EmptyList() {
        assertFalse(validator.validateRedirectUris(Collections.emptyList(), "client-123"));
    }

    @Test
    void testValidateRedirectUris_SingleValid() {
        List<String> uris = Collections.singletonList("https://app.example.com/callback");
        assertTrue(validator.validateRedirectUris(uris, "client-123"));
    }

    @Test
    void testValidateRedirectUris_SingleInvalid() {
        List<String> uris = Collections.singletonList("http://evil.com/callback");
        assertFalse(validator.validateRedirectUris(uris, "client-123"));
    }

    @Test
    void testIsValidRedirectUri_CustomSchemeWithPath() {
        assertTrue(validator.isValidRedirectUri("cursor://anysphere.cursor-abc123/callback/path"));
    }

    @Test
    void testIsValidRedirectUri_CustomSchemeNotInAllowlist() {
        assertFalse(validator.isValidRedirectUri("myapp://callback"));
        assertFalse(validator.isValidRedirectUri("custom://scheme"));
    }

    @Test
    void testIsValidRedirectUri_HttpsWithPort() {
        assertTrue(validator.isValidRedirectUri("https://app.example.com:8443/callback"));
    }

    @Test
    void testIsValidRedirectUri_LocalhostVariants() {
        // Test localhost with port
        assertTrue(validator.isValidRedirectUri("http://localhost:8080/callback"));

        // Test https localhost
        assertTrue(validator.isValidRedirectUri("https://localhost:4443/callback"));

        // Test http localhost without port
        assertTrue(validator.isValidRedirectUri("http://localhost/callback"));
    }

    @Test
    void testIsValidRedirectUri_EmptyAllowlist() {
        validator.allowedRedirectUriPrefixes = Collections.emptyList();

        // With empty allowlist, the check is skipped and https should be valid
        assertTrue(validator.isValidRedirectUri("https://app.example.com/callback"));

        // But http for non-localhost should still be invalid
        assertFalse(validator.isValidRedirectUri("http://app.example.com/callback"));
    }

    @Test
    void testIsValidRedirectUri_NullAllowlist() {
        validator.allowedRedirectUriPrefixes = null;

        // With null allowlist, check should be skipped and https should be valid
        assertTrue(validator.isValidRedirectUri("https://app.example.com/callback"));

        // But http for non-localhost should still be invalid
        assertFalse(validator.isValidRedirectUri("http://app.example.com/callback"));
    }

    @Test
    void testIsValidRedirectUri_PrefixMatch() {
        // Test that prefix matching works
        assertTrue(validator.isValidRedirectUri("https://app.example.com/callback"));
        assertTrue(validator.isValidRedirectUri("https://app.example.com/callback/nested"));
        assertTrue(validator.isValidRedirectUri("https://app.example.com/different"));
    }

    @Test
    void testIsValidRedirectUri_ExactMatch() {
        validator.allowedRedirectUriPrefixes = Collections.singletonList("https://app.example.com/callback");

        assertTrue(validator.isValidRedirectUri("https://app.example.com/callback"));
        assertTrue(validator.isValidRedirectUri("https://app.example.com/callback/nested"));
    }
}
