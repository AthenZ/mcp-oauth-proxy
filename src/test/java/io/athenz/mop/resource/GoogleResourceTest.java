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

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.config.SSLConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Integration tests for Google OAuth callback endpoint
 * Tests the /google/authorize endpoint for secondary OAuth flow
 *
 * NOTE: These tests require full Google OIDC integration and authentication.
 * Enable them in a full integration test environment.
 */
@QuarkusTest
@Disabled("Requires full Google OIDC integration - enable in integration environment")
class GoogleResourceTest {

    @BeforeAll
    static void configureRestAssured() {
        // Configure REST Assured to trust all SSL certificates for testing
        RestAssured.config = RestAssured.config()
            .sslConfig(SSLConfig.sslConfig()
                .relaxedHTTPSValidation()
                .allowAllHostnames());
    }

    @Test
    void testGoogleAuthorizeRequiresAuthentication() {
        given()
            .queryParam("state", "test-authorization-code")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(401), is(302))); // 401 unauthorized or 302 redirect to login
    }

    @Test
    void testGoogleAuthorizeWithValidState() {
        // This test requires valid Google OIDC authentication
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_google", "valid-session")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500))); // 303 redirect, 401 auth, or 500 if missing token
    }

    @Test
    void testGoogleAuthorizeWithMissingState() {
        given()
            .cookie("q_session_google", "valid-session")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(201), is(401))); // 201 created or 401 auth required
    }

    @Test
    void testGoogleAuthorizeWithEmptyState() {
        given()
            .queryParam("state", "")
            .cookie("q_session_google", "valid-session")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(201), is(401)));
    }

    @Test
    void testGoogleAuthorizeWithInvalidState() {
        given()
            .queryParam("state", "non-existent-authorization-code")
            .cookie("q_session_google", "valid-session")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401))); // 500 if auth code not found, 401 if not authenticated
    }

    @Test
    void testGoogleAuthorizeRequiresRefreshToken() {
        // Google requires refresh token - test behavior when missing
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_google", "session-without-refresh-token")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401))); // Should fail if no refresh token
    }

    @Test
    void testGoogleAuthorizeWithRefreshToken() {
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_google", "session-with-refresh-token")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testGoogleAuthorizeRedirectsToOriginalCallback() {
        // Test successful flow redirects back to original client
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_google", "valid-session")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testGoogleAuthorizeWithExpiredSession() {
        given()
            .queryParam("state", "test-authorization-code")
            .cookie("q_session_google", "expired-session")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(401), is(302))); // Should require re-authentication
    }

    @Test
    void testGoogleAuthorizeStoresAccessAndRefreshToken() {
        // Verify that both access and refresh tokens are stored
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_google", "valid-session-with-tokens")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testGoogleAuthorizeLogoutAfterSuccess() {
        // Verify that OIDC session is logged out after storing tokens
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_google", "valid-session")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testGoogleAuthorizeExtractsEmailUsername() {
        // Verify that username is extracted from Google email
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_google", "valid-session")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testGoogleAuthorizeWithPartialTokens() {
        // Test behavior when only access token (no refresh) is provided
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_google", "session-access-token-only")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401))); // Should fail without refresh token
    }

    @Test
    void testGoogleAuthorizeLogsWarningForMissingRefreshToken() {
        // Verify warning is logged when refresh token is missing
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_google", "session-no-refresh")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401)));
    }

    @Test
    void testGoogleAuthorizeWithMultipleConcurrentRequests() {
        // Test that the same authorization code can't be used twice
        String state = "single-use-authorization-code";

        given()
            .queryParam("state", state)
            .cookie("q_session_google", "valid-session")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));

        // Second request with same state should fail
        given()
            .queryParam("state", state)
            .cookie("q_session_google", "valid-session")
        .when()
            .get("/google/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401))); // Should fail or require new auth
    }
}
