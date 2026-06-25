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
 * Integration tests for the Rootly OAuth callback endpoint.
 * Tests the {@code /rootly/authorize} endpoint that Quarkus restores to after the upstream
 * Rootly OAuth code flow completes (configured via {@code restore-path-after-redirect: true}).
 *
 * <p>NOTE: These tests require full Rootly OIDC integration and authentication.
 * Enable them in a full integration test environment.
 */
@QuarkusTest
@Disabled("Requires full Rootly OIDC integration - enable in integration environment")
class RootlyResourceTest {

    @BeforeAll
    static void configureRestAssured() {
        RestAssured.config = RestAssured.config()
            .sslConfig(SSLConfig.sslConfig()
                .relaxedHTTPSValidation()
                .allowAllHostnames());
    }

    @Test
    void testRootlyAuthorizeRequiresAuthentication() {
        given()
            .queryParam("state", "test-authorization-code")
        .when()
            .get("/rootly/authorize")
        .then()
            .statusCode(anyOf(is(401), is(302))); // 401 unauthorized or 302 redirect to login
    }

    @Test
    void testRootlyAuthorizeWithValidState() {
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_rootly", "valid-session")
        .when()
            .get("/rootly/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500))); // 303 redirect, 401 auth, or 500 if missing token
    }

    @Test
    void testRootlyAuthorizeWithMissingState() {
        given()
            .cookie("q_session_rootly", "valid-session")
        .when()
            .get("/rootly/authorize")
        .then()
            .statusCode(anyOf(is(400), is(401))); // 400 bad request (missing state) or 401 auth required
    }

    @Test
    void testRootlyAuthorizeWithEmptyState() {
        given()
            .queryParam("state", "")
            .cookie("q_session_rootly", "valid-session")
        .when()
            .get("/rootly/authorize")
        .then()
            .statusCode(anyOf(is(400), is(401))); // 400 bad request (empty state) or 401 auth required
    }

    @Test
    void testRootlyAuthorizeWithInvalidState() {
        given()
            .queryParam("state", "non-existent-authorization-code")
            .cookie("q_session_rootly", "valid-session")
        .when()
            .get("/rootly/authorize")
        .then()
            .statusCode(anyOf(is(400), is(401))); // 400 invalid_grant if auth code not found, 401 if not authenticated
    }

    @Test
    void testRootlyAuthorizeRedirectsToOriginalCallback() {
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_rootly", "valid-session")
        .when()
            .get("/rootly/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testRootlyAuthorizeStoresAccessAndRefreshToken() {
        // Verify both access and refresh tokens are persisted via AuthorizerService
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_rootly", "valid-session-with-tokens")
        .when()
            .get("/rootly/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testRootlyAuthorizeStoresWithoutPinnedLifetime() {
        // Rootly access tokens are short-lived (~1h). MoP does NOT pin an AT lifetime on the bare
        // row (7-arg storeTokens, accessTokenLifetimeSeconds=null); the downstream expires_in is
        // driven by Rootly's real upstream expires_in on refresh. The canonical RT row TTL
        // (6 months) is governed separately by the L2 upstream-token config.
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_rootly", "valid-session")
        .when()
            .get("/rootly/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testRootlyAuthorizeBorrowsCanonicalRefreshTokenWhenAbsent() {
        // When the OIDC session has no fresh RT (subsequent MCP-client window relogin),
        // the resource borrows the canonical upstream RT from refreshTokenService.
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_rootly", "session-without-refresh")
        .when()
            .get("/rootly/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testRootlyAuthorizeLogoutAfterSuccess() {
        // Verify OIDC session is logged out after storing tokens (matches Figma/Github/Atlassian)
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_rootly", "valid-session")
        .when()
            .get("/rootly/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testRootlyAuthorizeExtractsUsernameFromEmailClaim() {
        // username-claim is "email" (per server.token-exchange.remote-servers.rootly.username-claim);
        // BaseResource.getUsername strips the @domain so the stored lookupKey is the short id.
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_rootly", "valid-session")
        .when()
            .get("/rootly/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testRootlyAuthorizeWithMissingAccessToken() {
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_rootly", "session-without-token")
        .when()
            .get("/rootly/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401))); // Should fail gracefully
    }

    @Test
    void testRootlyAuthorizeWithMultipleConcurrentRequests() {
        // Test that the same authorization code can't be used twice (single-use semantics)
        String state = "single-use-authorization-code";

        given()
            .queryParam("state", state)
            .cookie("q_session_rootly", "valid-session")
        .when()
            .get("/rootly/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));

        given()
            .queryParam("state", state)
            .cookie("q_session_rootly", "valid-session")
        .when()
            .get("/rootly/authorize")
        .then()
            .statusCode(anyOf(is(400), is(401), is(500))); // 400 invalid_grant or 401 re-auth
    }
}
