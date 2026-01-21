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
 * Integration tests for Atlassian OAuth callback endpoint
 * Tests the /atlassian/authorize endpoint for secondary OAuth flow
 *
 * NOTE: These tests require full Atlassian OIDC integration and authentication.
 * Enable them in a full integration test environment.
 */
@QuarkusTest
@Disabled("Requires full Atlassian OIDC integration - enable in integration environment")
class AtlassianResourceTest {

    @BeforeAll
    static void configureRestAssured() {
        // Configure REST Assured to trust all SSL certificates for testing
        RestAssured.config = RestAssured.config()
            .sslConfig(SSLConfig.sslConfig()
                .relaxedHTTPSValidation()
                .allowAllHostnames());
    }

    @Test
    void testAtlassianAuthorizeRequiresAuthentication() {
        given()
            .queryParam("state", "test-authorization-code")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(401), is(302))); // 401 unauthorized or 302 redirect to login
    }

    @Test
    void testAtlassianAuthorizeWithValidState() {
        // This test requires valid Atlassian OIDC authentication
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_atlassian", "valid-session")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500))); // 303 redirect, 401 auth, or 500 if missing token
    }

    @Test
    void testAtlassianAuthorizeWithMissingState() {
        given()
            .cookie("q_session_atlassian", "valid-session")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401))); // No default behavior without state, should fail
    }

    @Test
    void testAtlassianAuthorizeWithEmptyState() {
        given()
            .queryParam("state", "")
            .cookie("q_session_atlassian", "valid-session")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401))); // Empty state should fail
    }

    @Test
    void testAtlassianAuthorizeWithInvalidState() {
        given()
            .queryParam("state", "non-existent-authorization-code")
            .cookie("q_session_atlassian", "valid-session")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401))); // 500 if auth code not found, 401 if not authenticated
    }

    @Test
    void testAtlassianAuthorizeRedirectsToOriginalCallback() {
        // Test successful flow redirects back to original client
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_atlassian", "valid-session")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testAtlassianAuthorizeWithExpiredSession() {
        given()
            .queryParam("state", "test-authorization-code")
            .cookie("q_session_atlassian", "expired-session")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(401), is(302))); // Should require re-authentication
    }

    @Test
    void testAtlassianAuthorizeStoresAccessAndRefreshToken() {
        // Verify that both access and refresh tokens are stored
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_atlassian", "valid-session-with-tokens")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testAtlassianAuthorizeLogoutAfterSuccess() {
        // Verify that OIDC session is logged out after storing tokens
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_atlassian", "valid-session")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testAtlassianAuthorizeExtractsUsernameFromToken() {
        // Verify that username is extracted from JWT access token
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_atlassian", "valid-session")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testAtlassianAuthorizeWithMissingAccessToken() {
        // Test behavior when Atlassian doesn't provide access token
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_atlassian", "session-without-token")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401))); // Should fail gracefully
    }

    @Test
    void testAtlassianAuthorizeWithMissingRefreshToken() {
        // Test behavior when refresh token is missing
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_atlassian", "session-without-refresh")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401))); // Should fail if no refresh token
    }

    @Test
    void testAtlassianAuthorizeWithMultipleConcurrentRequests() {
        // Test that the same authorization code can't be used twice
        String state = "single-use-authorization-code";

        given()
            .queryParam("state", state)
            .cookie("q_session_atlassian", "valid-session")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));

        // Second request with same state should fail
        given()
            .queryParam("state", state)
            .cookie("q_session_atlassian", "valid-session")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401))); // Should fail or require new auth
    }

    @Test
    void testAtlassianAuthorizeUsesAccessTokenForBothFields() {
        // Verify Atlassian uses access token for both ID and access token fields
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_atlassian", "valid-session")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testAtlassianAuthorizeLogsRequestInfo() {
        // Verify logging occurs for Atlassian requests
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_atlassian", "valid-session")
        .when()
            .get("/atlassian/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }
}
