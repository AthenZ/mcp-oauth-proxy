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

import io.athenz.mop.model.OAuth2ErrorResponse;
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
 * Integration tests for RFC 6749 compliant OAuth 2.0 token endpoint
 * Tests the form-urlencoded endpoint with client_credentials grant type
 *
 * NOTE: These tests require full Kubernetes/OIDC infrastructure and are disabled by default.
 * Enable them in a full integration test environment.
 */
@QuarkusTest
@Disabled("Requires full Kubernetes/OIDC infrastructure - enable in integration environment")
class TokenResourceOAuth2Test {

    @BeforeAll
    static void configureRestAssured() {
        // Configure REST Assured to trust all SSL certificates for testing
        RestAssured.config = RestAssured.config()
            .sslConfig(SSLConfig.sslConfig()
                .relaxedHTTPSValidation()
                .allowAllHostnames());
    }

    @Test
    void testUnsupportedGrantType() {
        given()
            .contentType(ContentType.URLENC)
            .formParam("grant_type", "password")  // password grant is not supported
            .formParam("resource", "https://test.example.com")
        .when()
            .post("/token/")
        .then()
            .statusCode(400)
            .body("error", equalTo(OAuth2ErrorResponse.ErrorCode.UNSUPPORTED_GRANT_TYPE))
            .body("error_description", containsString("authorization_code, client_credentials"));
    }

    @Test
    void testMissingGrantType() {
        given()
            .contentType(ContentType.URLENC)
            .formParam("resource", "https://test.example.com")
        .when()
            .post("/token/")
        .then()
            .statusCode(400);
    }

    @Test
    void testMissingResource() {
        given()
            .contentType(ContentType.URLENC)
            .formParam("grant_type", "client_credentials")
        .when()
            .post("/token/")
        .then()
            .statusCode(400)
            .body("error", equalTo(OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST))
            .body("error_description", containsString("resource"));
    }

    @Test
    void testAuthorizationCodeGrantMissingCode() {
        given()
            .contentType(ContentType.URLENC)
            .formParam("grant_type", "authorization_code")
            .formParam("redirect_uri", "https://example.com/callback")
            .formParam("code_verifier", "test-verifier")
        .when()
            .post("/token/")
        .then()
            .statusCode(400)
            .body("error", equalTo(OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST))
            .body("error_description", containsString("code"));
    }

    @Test
    void testAuthorizationCodeGrantMissingRedirectUri() {
        given()
            .contentType(ContentType.URLENC)
            .formParam("grant_type", "authorization_code")
            .formParam("code", "test-code")
            .formParam("code_verifier", "test-verifier")
        .when()
            .post("/token/")
        .then()
            .statusCode(400)
            .body("error", equalTo(OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST))
            .body("error_description", containsString("redirect_uri"));
    }

    @Test
    void testAuthorizationCodeGrantMissingCodeVerifier() {
        given()
            .contentType(ContentType.URLENC)
            .formParam("grant_type", "authorization_code")
            .formParam("code", "test-code")
            .formParam("redirect_uri", "https://example.com/callback")
        .when()
            .post("/token/")
        .then()
            .statusCode(400)
            .body("error", equalTo(OAuth2ErrorResponse.ErrorCode.INVALID_REQUEST))
            .body("error_description", containsString("code_verifier"));
    }

    @Test
    void testValidRequestWithoutCertificate() {
        // This test expects failure due to missing client certificate
        // In production, this would be enforced at TLS layer
        given()
            .contentType(ContentType.URLENC)
            .formParam("grant_type", "client_credentials")
            .formParam("resource", "https://test.example.com")
        .when()
            .post("/token/")
        .then()
            .statusCode(401);
    }

    @Test
    void testContentTypeApplicationJson() {
        // Test that JSON format still works for backward compatibility
        given()
            .contentType(ContentType.JSON)
            .body("{\"subject\":\"test-subject\",\"resource\":\"https://test.example.com\"}")
        .when()
            .post("/token/")
        .then()
            .statusCode(anyOf(is(200), is(401), is(403))); // Depends on auth/authz
    }

    @Test
    void testWellKnownMetadataIncludesTlsClientAuth() {
        given()
        .when()
            .get("/.well-known/oauth-authorization-server")
        .then()
            .statusCode(200)
            .body("grant_types_supported", hasItem("client_credentials"))
            .body("grant_types_supported", hasItem("authorization_code"))
            .body("response_types_supported", hasItem("code"))
            .body("token_endpoint_auth_methods_supported", hasItem("tls_client_auth"))
            .body("token_endpoint_auth_methods_supported", not(hasItem("client_secret_basic")))
            .body("token_endpoint_auth_methods_supported", not(hasItem("client_secret_post")));
    }

    @Test
    void testOpenIdConfigurationIncludesTlsClientAuth() {
        given()
        .when()
            .get("/.well-known/openid-configuration")
        .then()
            .statusCode(200)
            .body("grant_types_supported", hasItem("client_credentials"))
            .body("grant_types_supported", hasItem("authorization_code"))
            .body("response_types_supported", hasItem("code"))
            .body("token_endpoint_auth_methods_supported", hasItem("tls_client_auth"))
            .body("token_endpoint_auth_methods_supported", not(hasItem("client_secret_basic")))
            .body("token_endpoint_auth_methods_supported", not(hasItem("client_secret_post")));
    }

    @Test
    void testErrorResponseFormat() {
        // Verify error responses follow RFC 6749 Section 5.2 format
        given()
            .contentType(ContentType.URLENC)
            .formParam("grant_type", "password")
            .formParam("resource", "https://test.example.com")
        .when()
            .post("/token/")
        .then()
            .statusCode(400)
            .contentType(ContentType.JSON)
            .body("error", notNullValue())
            .body("error_description", notNullValue())
            .body("error", is(OAuth2ErrorResponse.ErrorCode.UNSUPPORTED_GRANT_TYPE));
    }
}
