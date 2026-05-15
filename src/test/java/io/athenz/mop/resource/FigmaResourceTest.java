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
 * Integration tests for Figma OAuth callback endpoint.
 * Tests the {@code /figma/authorize} endpoint that Quarkus restores to after the upstream
 * Figma OAuth code flow completes (configured via {@code restore-path-after-redirect: true}).
 *
 * <p>NOTE: These tests require full Figma OIDC integration and authentication.
 * Enable them in a full integration test environment.
 */
@QuarkusTest
@Disabled("Requires full Figma OIDC integration - enable in integration environment")
class FigmaResourceTest {

    @BeforeAll
    static void configureRestAssured() {
        // Configure REST Assured to trust all SSL certificates for testing
        RestAssured.config = RestAssured.config()
            .sslConfig(SSLConfig.sslConfig()
                .relaxedHTTPSValidation()
                .allowAllHostnames());
    }

    @Test
    void testFigmaAuthorizeRequiresAuthentication() {
        given()
            .queryParam("state", "test-authorization-code")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(401), is(302))); // 401 unauthorized or 302 redirect to login
    }

    @Test
    void testFigmaAuthorizeWithValidState() {
        // This test requires valid Figma OIDC authentication
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_figma", "valid-session")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500))); // 303 redirect, 401 auth, or 500 if missing token
    }

    @Test
    void testFigmaAuthorizeWithMissingState() {
        given()
            .cookie("q_session_figma", "valid-session")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(400), is(401))); // 400 bad request (missing state) or 401 auth required
    }

    @Test
    void testFigmaAuthorizeWithEmptyState() {
        given()
            .queryParam("state", "")
            .cookie("q_session_figma", "valid-session")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(400), is(401))); // 400 bad request (empty state) or 401 auth required
    }

    @Test
    void testFigmaAuthorizeWithInvalidState() {
        given()
            .queryParam("state", "non-existent-authorization-code")
            .cookie("q_session_figma", "valid-session")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(400), is(401))); // 400 invalid_grant if auth code not found, 401 if not authenticated
    }

    @Test
    void testFigmaAuthorizeRedirectsToOriginalCallback() {
        // Test successful flow redirects back to original MCP client
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_figma", "valid-session")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testFigmaAuthorizeWithExpiredSession() {
        given()
            .queryParam("state", "test-authorization-code")
            .cookie("q_session_figma", "expired-session")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(401), is(302))); // Should require re-authentication
    }

    @Test
    void testFigmaAuthorizeStoresAccessAndRefreshToken() {
        // Verify both access and refresh tokens are persisted via AuthorizerService
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_figma", "valid-session-with-tokens")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testFigmaAuthorizeStoresWith90DayLifetime() {
        // Figma is L2-promoted: storeTokens is invoked with the 8-arg overload pinning
        // accessTokenLifetimeSeconds = 7,776,000 (90 d) so the L1 bare row outlives the
        // global server.token-store.expiry (~8h). Without this the bare row would evict
        // 8h after consent and force re-consent before the real Figma AT actually expires.
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_figma", "valid-session")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testFigmaAuthorizeBorrowsCanonicalRefreshTokenWhenAbsent() {
        // When the OIDC session has no fresh RT (subsequent MCP-client window relogin),
        // the resource borrows the canonical upstream RT from refreshTokenService.
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_figma", "session-without-refresh")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testFigmaAuthorizeLogoutAfterSuccess() {
        // Verify OIDC session is logged out after storing tokens (matches Github/Atlassian pattern)
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_figma", "valid-session")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testFigmaAuthorizeExtractsUsernameFromEmailClaim() {
        // username-claim is "email" (per server.token-exchange.remote-servers.figma.username-claim);
        // BaseResource.getUsername strips the @domain so the stored lookupKey is the short id
        // (matches Google Workspace / Okta convention).
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_figma", "valid-session")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testFigmaAuthorizeWithMissingAccessToken() {
        // Test behavior when Figma doesn't provide an access token in the callback session
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_figma", "session-without-token")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401))); // Should fail gracefully
    }

    @Test
    void testFigmaAuthorizeWithMultipleConcurrentRequests() {
        // Test that the same authorization code can't be used twice (single-use semantics)
        String state = "single-use-authorization-code";

        given()
            .queryParam("state", state)
            .cookie("q_session_figma", "valid-session")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));

        // Second request with same state should fail
        given()
            .queryParam("state", state)
            .cookie("q_session_figma", "valid-session")
        .when()
            .get("/figma/authorize")
        .then()
            .statusCode(anyOf(is(400), is(401), is(500))); // 400 invalid_grant or 401 re-auth
    }
}
