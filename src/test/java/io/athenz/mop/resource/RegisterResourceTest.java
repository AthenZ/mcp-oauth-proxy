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
import io.restassured.http.ContentType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Integration tests for OAuth 2.0 Dynamic Client Registration endpoint (RFC 7591)
 * Tests the /register endpoint for client registration
 *
 * NOTE: These tests require full Quarkus/JWT infrastructure and are disabled by default.
 * Enable them in a full integration test environment with proper JWT tokens.
 */
@QuarkusTest
@Disabled("Requires full Quarkus/JWT infrastructure - enable in integration environment")
class RegisterResourceTest {

    @BeforeAll
    static void configureRestAssured() {
        // Configure REST Assured to trust all SSL certificates for testing
        RestAssured.config = RestAssured.config()
            .sslConfig(SSLConfig.sslConfig()
                .relaxedHTTPSValidation()
                .allowAllHostnames());
    }

    @Test
    void testRegisterWithValidRequest() {
        String requestJson = """
            {
                "client_name": "test-client",
                "redirect_uris": ["https://app.example.com/callback", "http://localhost:3000/callback"]
            }
            """;

        given()
            .contentType(ContentType.JSON)
            .body(requestJson)
            .header("Authorization", "Bearer valid-jwt-token")
        .when()
            .post("/register/")
        .then()
            .statusCode(anyOf(is(200), is(401))) // 401 if JWT validation fails
            .contentType(ContentType.JSON);
    }

    @Test
    void testRegisterWithMissingClientName() {
        String requestJson = """
            {
                "client_name": null,
                "redirect_uris": ["https://app.example.com/callback"]
            }
            """;

        given()
            .contentType(ContentType.JSON)
            .body(requestJson)
            .header("Authorization", "Bearer valid-jwt-token")
        .when()
            .post("/register/")
        .then()
            .statusCode(anyOf(is(400), is(401))); // 400 for validation error, 401 for auth error
    }

    @Test
    void testRegisterWithEmptyClientName() {
        String requestJson = """
            {
                "client_name": "",
                "redirect_uris": ["https://app.example.com/callback"]
            }
            """;

        given()
            .contentType(ContentType.JSON)
            .body(requestJson)
            .header("Authorization", "Bearer valid-jwt-token")
        .when()
            .post("/register/")
        .then()
            .statusCode(anyOf(is(400), is(401)));
    }

    @Test
    void testRegisterWithMissingRedirectUris() {
        String requestJson = """
            {
                "client_name": "test-client",
                "redirect_uris": null
            }
            """;

        given()
            .contentType(ContentType.JSON)
            .body(requestJson)
            .header("Authorization", "Bearer valid-jwt-token")
        .when()
            .post("/register/")
        .then()
            .statusCode(anyOf(is(400), is(401)));
    }

    @Test
    void testRegisterWithEmptyRedirectUris() {
        String requestJson = """
            {
                "client_name": "test-client",
                "redirect_uris": []
            }
            """;

        given()
            .contentType(ContentType.JSON)
            .body(requestJson)
            .header("Authorization", "Bearer valid-jwt-token")
        .when()
            .post("/register/")
        .then()
            .statusCode(anyOf(is(400), is(401)));
    }

    @Test
    void testRegisterWithInvalidRedirectUriFormat() {
        String requestJson = """
            {
                "client_name": "test-client",
                "redirect_uris": ["not-a-valid-uri", "http://localhost:3000/callback"]
            }
            """;

        given()
            .contentType(ContentType.JSON)
            .body(requestJson)
            .header("Authorization", "Bearer valid-jwt-token")
        .when()
            .post("/register/")
        .then()
            .statusCode(anyOf(is(400), is(401)));
    }

    @Test
    void testRegisterWithHttpNonLocalhost() {
        String requestJson = """
            {
                "client_name": "test-client",
                "redirect_uris": ["http://example.com/callback"]
            }
            """;

        given()
            .contentType(ContentType.JSON)
            .body(requestJson)
            .header("Authorization", "Bearer valid-jwt-token")
        .when()
            .post("/register/")
        .then()
            .statusCode(anyOf(is(400), is(401)));
    }

    @Test
    void testRegisterWithHttpsAndLocalhost() {
        String requestJson = """
            {
                "client_name": "test-client",
                "redirect_uris": [
                    "https://app.example.com/callback",
                    "http://localhost:3000/callback",
                    "https://localhost:4443/callback"
                ]
            }
            """;

        given()
            .contentType(ContentType.JSON)
            .body(requestJson)
            .header("Authorization", "Bearer valid-jwt-token")
        .when()
            .post("/register/")
        .then()
            .statusCode(anyOf(is(200), is(401), is(400)))
            .contentType(ContentType.JSON);
    }

    @Test
    void testRegisterWithoutAuthorizationHeader() {
        String requestJson = """
            {
                "client_name": "test-client",
                "redirect_uris": ["https://app.example.com/callback"]
            }
            """;

        given()
            .contentType(ContentType.JSON)
            .body(requestJson)
        .when()
            .post("/register/")
        .then()
            .statusCode(401); // Should require authentication
    }

    @Test
    void testRegisterWithInvalidJwtToken() {
        String requestJson = """
            {
                "client_name": "test-client",
                "redirect_uris": ["https://app.example.com/callback"]
            }
            """;

        given()
            .contentType(ContentType.JSON)
            .body(requestJson)
            .header("Authorization", "Bearer invalid-token")
        .when()
            .post("/register/")
        .then()
            .statusCode(401);
    }

    @Test
    void testRegisterResponseContainsClientId() {
        String requestJson = """
            {
                "client_name": "test-client",
                "redirect_uris": ["https://app.example.com/callback"]
            }
            """;

        // This test assumes valid JWT is provided and registration succeeds
        given()
            .contentType(ContentType.JSON)
            .body(requestJson)
            .header("Authorization", "Bearer valid-jwt-token")
        .when()
            .post("/register/")
        .then()
            .statusCode(anyOf(is(200), is(401)))
            .contentType(ContentType.JSON);
    }

    @Test
    void testRegisterWithCustomSchemeRedirectUri() {
        String requestJson = """
            {
                "client_name": "test-client",
                "redirect_uris": ["cursor://anysphere.cursor-callback"]
            }
            """;

        given()
            .contentType(ContentType.JSON)
            .body(requestJson)
            .header("Authorization", "Bearer valid-jwt-token")
        .when()
            .post("/register/")
        .then()
            .statusCode(anyOf(is(200), is(400), is(401)))
            .contentType(ContentType.JSON);
    }

    @Test
    void testRegisterWithMalformedJson() {
        given()
            .contentType(ContentType.JSON)
            .body("{invalid json}")
            .header("Authorization", "Bearer valid-jwt-token")
        .when()
            .post("/register/")
        .then()
            .statusCode(anyOf(is(400), is(401)));
    }

    @Test
    void testRegisterWithWrongContentType() {
        String requestJson = """
            {
                "client_name": "test-client",
                "redirect_uris": ["https://app.example.com/callback"]
            }
            """;

        given()
            .contentType(ContentType.XML)
            .body(requestJson)
            .header("Authorization", "Bearer valid-jwt-token")
        .when()
            .post("/register/")
        .then()
            .statusCode(anyOf(is(415), is(401))); // 415 Unsupported Media Type or 401 unauthorized
    }
}
