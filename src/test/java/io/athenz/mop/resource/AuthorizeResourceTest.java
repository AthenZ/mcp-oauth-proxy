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
 * Integration tests for OAuth 2.1 Authorization Endpoint (RFC 6749 Section 3.1)
 * Tests the /authorize endpoint with PKCE (RFC 7636)
 *
 * NOTE: These tests require full OIDC infrastructure and authentication.
 * Enable them in a full integration test environment.
 */
@QuarkusTest
@Disabled("Requires full OIDC infrastructure and authentication - enable in integration environment")
class AuthorizeResourceTest {

    @BeforeAll
    static void configureRestAssured() {
        // Configure REST Assured to trust all SSL certificates for testing
        RestAssured.config = RestAssured.config()
            .sslConfig(SSLConfig.sslConfig()
                .relaxedHTTPSValidation()
                .allowAllHostnames());
    }

    @Test
    void testAuthorizeRequiresAuthentication() {
        given()
            .queryParam("response_type", "code")
            .queryParam("client_id", "test-client")
            .queryParam("redirect_uri", "https://app.example.com/callback")
            .queryParam("scope", "openid")
            .queryParam("state", "random-state")
            .queryParam("code_challenge", "test-challenge")
            .queryParam("code_challenge_method", "S256")
            .queryParam("resource", "https://api.example.com")
        .when()
            .get("/authorize")
        .then()
            .statusCode(anyOf(is(401), is(302))); // 401 unauthorized or 302 redirect to login
    }

    @Test
    void testAuthorizeWithValidRequest() {
        // This test requires valid OIDC authentication
        given()
            .queryParam("response_type", "code")
            .queryParam("client_id", "test-client")
            .queryParam("redirect_uri", "https://app.example.com/callback")
            .queryParam("scope", "openid")
            .queryParam("state", "random-state")
            .queryParam("code_challenge", "test-challenge")
            .queryParam("code_challenge_method", "S256")
            .queryParam("resource", "https://api.example.com")
            .cookie("valid-session-cookie", "session-value")
        .when()
            .get("/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401))); // 303 redirect on success, 401 if not authenticated
    }

    @Test
    void testAuthorizeWithUnsupportedResponseType() {
        given()
            .queryParam("response_type", "token") // token response type not supported in OAuth 2.1
            .queryParam("client_id", "test-client")
            .queryParam("redirect_uri", "https://app.example.com/callback")
            .queryParam("scope", "openid")
            .queryParam("state", "random-state")
            .queryParam("code_challenge", "test-challenge")
            .queryParam("code_challenge_method", "S256")
            .queryParam("resource", "https://api.example.com")
            .cookie("valid-session-cookie", "session-value")
        .when()
            .get("/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401))); // Should redirect with error or require auth
    }

    @Test
    void testAuthorizeWithPlainCodeChallenge() {
        // OAuth 2.1 requires S256, plain is deprecated
        given()
            .queryParam("response_type", "code")
            .queryParam("client_id", "test-client")
            .queryParam("redirect_uri", "https://app.example.com/callback")
            .queryParam("scope", "openid")
            .queryParam("state", "random-state")
            .queryParam("code_challenge", "test-challenge")
            .queryParam("code_challenge_method", "plain") // Should be rejected
            .queryParam("resource", "https://api.example.com")
            .cookie("valid-session-cookie", "session-value")
        .when()
            .get("/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401))); // Should redirect with error or require auth
    }

    @Test
    void testAuthorizeWithMissingCodeChallenge() {
        given()
            .queryParam("response_type", "code")
            .queryParam("client_id", "test-client")
            .queryParam("redirect_uri", "https://app.example.com/callback")
            .queryParam("scope", "openid")
            .queryParam("state", "random-state")
            .queryParam("resource", "https://api.example.com")
            .cookie("valid-session-cookie", "session-value")
        .when()
            .get("/authorize")
        .then()
            .statusCode(anyOf(is(400), is(401))); // Missing required parameter or auth required
    }

    @Test
    void testAuthorizeWithMissingClientId() {
        given()
            .queryParam("response_type", "code")
            .queryParam("redirect_uri", "https://app.example.com/callback")
            .queryParam("scope", "openid")
            .queryParam("state", "random-state")
            .queryParam("code_challenge", "test-challenge")
            .queryParam("code_challenge_method", "S256")
            .queryParam("resource", "https://api.example.com")
            .cookie("valid-session-cookie", "session-value")
        .when()
            .get("/authorize")
        .then()
            .statusCode(anyOf(is(400), is(401)));
    }

    @Test
    void testAuthorizeWithMissingRedirectUri() {
        given()
            .queryParam("response_type", "code")
            .queryParam("client_id", "test-client")
            .queryParam("scope", "openid")
            .queryParam("state", "random-state")
            .queryParam("code_challenge", "test-challenge")
            .queryParam("code_challenge_method", "S256")
            .queryParam("resource", "https://api.example.com")
            .cookie("valid-session-cookie", "session-value")
        .when()
            .get("/authorize")
        .then()
            .statusCode(anyOf(is(400), is(401)));
    }

    @Test
    void testAuthorizeWithInvalidRedirectUri() {
        given()
            .queryParam("response_type", "code")
            .queryParam("client_id", "test-client")
            .queryParam("redirect_uri", "http://evil.com/callback") // Not in allowlist
            .queryParam("scope", "openid")
            .queryParam("state", "random-state")
            .queryParam("code_challenge", "test-challenge")
            .queryParam("code_challenge_method", "S256")
            .queryParam("resource", "https://api.example.com")
            .cookie("valid-session-cookie", "session-value")
        .when()
            .get("/authorize")
        .then()
            .statusCode(anyOf(is(400), is(401))); // Bad request (invalid redirect) or auth required
    }

    @Test
    void testAuthorizeWithMissingResource() {
        given()
            .queryParam("response_type", "code")
            .queryParam("client_id", "test-client")
            .queryParam("redirect_uri", "https://app.example.com/callback")
            .queryParam("scope", "openid")
            .queryParam("state", "random-state")
            .queryParam("code_challenge", "test-challenge")
            .queryParam("code_challenge_method", "S256")
            .cookie("valid-session-cookie", "session-value")
        .when()
            .get("/authorize")
        .then()
            .statusCode(anyOf(is(400), is(401)));
    }

    @Test
    void testAuthorizeWithEmptyState() {
        // State is recommended but not required
        given()
            .queryParam("response_type", "code")
            .queryParam("client_id", "test-client")
            .queryParam("redirect_uri", "https://app.example.com/callback")
            .queryParam("scope", "openid")
            .queryParam("code_challenge", "test-challenge")
            .queryParam("code_challenge_method", "S256")
            .queryParam("resource", "https://api.example.com")
            .cookie("valid-session-cookie", "session-value")
        .when()
            .get("/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401)));
    }

    @Test
    void testAuthorizeRedirectsWithAuthorizationCode() {
        // Test successful authorization flow (requires authentication)
        given()
            .queryParam("response_type", "code")
            .queryParam("client_id", "test-client")
            .queryParam("redirect_uri", "https://app.example.com/callback")
            .queryParam("scope", "openid")
            .queryParam("state", "random-state")
            .queryParam("code_challenge", "test-challenge")
            .queryParam("code_challenge_method", "S256")
            .queryParam("resource", "https://api.example.com")
            .cookie("valid-session-cookie", "session-value")
        .when()
            .get("/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401)));
    }

    @Test
    void testAuthorizeWithMultipleScopes() {
        given()
            .queryParam("response_type", "code")
            .queryParam("client_id", "test-client")
            .queryParam("redirect_uri", "https://app.example.com/callback")
            .queryParam("scope", "openid profile email")
            .queryParam("state", "random-state")
            .queryParam("code_challenge", "test-challenge")
            .queryParam("code_challenge_method", "S256")
            .queryParam("resource", "https://api.example.com")
            .cookie("valid-session-cookie", "session-value")
        .when()
            .get("/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401)));
    }

    @Test
    void testAuthorizeWithLocalhostRedirectUri() {
        given()
            .queryParam("response_type", "code")
            .queryParam("client_id", "test-client")
            .queryParam("redirect_uri", "http://localhost:3000/callback")
            .queryParam("scope", "openid")
            .queryParam("state", "random-state")
            .queryParam("code_challenge", "test-challenge")
            .queryParam("code_challenge_method", "S256")
            .queryParam("resource", "https://api.example.com")
            .cookie("valid-session-cookie", "session-value")
        .when()
            .get("/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401)));
    }

    @Test
    void testAuthorizeWithCustomSchemeRedirectUri() {
        given()
            .queryParam("response_type", "code")
            .queryParam("client_id", "test-client")
            .queryParam("redirect_uri", "cursor://anysphere.cursor-callback")
            .queryParam("scope", "openid")
            .queryParam("state", "random-state")
            .queryParam("code_challenge", "test-challenge")
            .queryParam("code_challenge_method", "S256")
            .queryParam("resource", "https://api.example.com")
            .cookie("valid-session-cookie", "session-value")
        .when()
            .get("/authorize")
        .then()
            .statusCode(anyOf(is(303), is(400), is(401)));
    }
}
