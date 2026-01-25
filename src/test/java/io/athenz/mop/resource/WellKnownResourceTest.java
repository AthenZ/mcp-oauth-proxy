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
 * Integration tests for OAuth 2.0/OpenID Connect discovery endpoints
 * Tests RFC 8414 and OpenID Connect Discovery metadata endpoints
 *
 * NOTE: These tests require full Quarkus infrastructure and are disabled by default.
 * Enable them in a full integration test environment.
 */
@QuarkusTest
@Disabled("Requires full Quarkus infrastructure - enable in integration environment")
class WellKnownResourceTest {

    @BeforeAll
    static void configureRestAssured() {
        // Configure REST Assured to trust all SSL certificates for testing
        RestAssured.config = RestAssured.config()
            .sslConfig(SSLConfig.sslConfig()
                .relaxedHTTPSValidation()
                .allowAllHostnames());
    }

    @Test
    void testOpenIdConfigurationEndpoint() {
        given()
        .when()
            .get("/.well-known/openid-configuration")
        .then()
            .statusCode(200)
            .contentType("application/json")
            .body("issuer", notNullValue())
            .body("authorization_endpoint", notNullValue())
            .body("token_endpoint", notNullValue())
            .body("registration_endpoint", notNullValue());
    }

    @Test
    void testOpenIdConfigurationContainsRequiredScopes() {
        given()
        .when()
            .get("/.well-known/openid-configuration")
        .then()
            .statusCode(200)
            .body("scopes_supported", hasItem("openid"))
            .body("scopes_supported", hasItem("offline_access"));
    }

    @Test
    void testOpenIdConfigurationSupportedGrantTypes() {
        given()
        .when()
            .get("/.well-known/openid-configuration")
        .then()
            .statusCode(200)
            .body("grant_types_supported", hasItem("client_credentials"))
            .body("grant_types_supported", hasItem("authorization_code"));
    }

    @Test
    void testOpenIdConfigurationSupportedResponseTypes() {
        given()
        .when()
            .get("/.well-known/openid-configuration")
        .then()
            .statusCode(200)
            .body("response_types_supported", hasItem("code"))
            .body("response_types_supported", hasItem("token"))
            .body("response_types_supported", hasItem("id_token token"));
    }

    @Test
    void testOpenIdConfigurationTokenAuthMethods() {
        given()
        .when()
            .get("/.well-known/openid-configuration")
        .then()
            .statusCode(200)
            .body("token_endpoint_auth_methods_supported", hasItem("tls_client_auth"))
            .body("token_endpoint_auth_methods_supported", hasItem("none"));
    }

    @Test
    void testOpenIdConfigurationIdTokenSigningAlgorithms() {
        given()
        .when()
            .get("/.well-known/openid-configuration")
        .then()
            .statusCode(200)
            .body("id_token_signing_alg_values_supported", hasItem("ES256"));
    }

    @Test
    void testOpenIdConfigurationClaimsSupported() {
        given()
        .when()
            .get("/.well-known/openid-configuration")
        .then()
            .statusCode(200)
            .body("claims_supported", hasItems("sub", "aud", "iss", "exp", "iat"));
    }

    @Test
    void testOpenIdConfigurationPKCESupport() {
        given()
        .when()
            .get("/.well-known/openid-configuration")
        .then()
            .statusCode(200)
            .body("code_challenge_methods_supported", hasItem("S256"));
    }

    @Test
    void testOAuthAuthorizationServerEndpoint() {
        given()
        .when()
            .get("/.well-known/oauth-authorization-server")
        .then()
            .statusCode(200)
            .contentType("application/json")
            .body("issuer", notNullValue())
            .body("authorization_endpoint", notNullValue())
            .body("token_endpoint", notNullValue())
            .body("registration_endpoint", notNullValue());
    }

    @Test
    void testOAuthAuthorizationServerGrantTypes() {
        given()
        .when()
            .get("/.well-known/oauth-authorization-server")
        .then()
            .statusCode(200)
            .body("grant_types_supported", hasItem("client_credentials"))
            .body("grant_types_supported", hasItem("authorization_code"));
    }

    @Test
    void testOAuthAuthorizationServerResponseTypes() {
        given()
        .when()
            .get("/.well-known/oauth-authorization-server")
        .then()
            .statusCode(200)
            .body("response_types_supported", hasItem("code"))
            .body("response_types_supported", hasItem("token"))
            .body("response_types_supported", hasItem("id_token token"));
    }

    @Test
    void testOAuthAuthorizationServerTokenAuthMethods() {
        given()
        .when()
            .get("/.well-known/oauth-authorization-server")
        .then()
            .statusCode(200)
            .body("token_endpoint_auth_methods_supported", hasItem("tls_client_auth"))
            .body("token_endpoint_auth_methods_supported", hasItem("none"));
    }

    @Test
    void testOAuthAuthorizationServerSigningAlgorithms() {
        given()
        .when()
            .get("/.well-known/oauth-authorization-server")
        .then()
            .statusCode(200)
            .body("token_endpoint_auth_signing_alg_values_supported", hasItem("ES256"));
    }

    @Test
    void testOAuthAuthorizationServerPKCESupport() {
        given()
        .when()
            .get("/.well-known/oauth-authorization-server")
        .then()
            .statusCode(200)
            .body("code_challenge_methods_supported", hasItem("S256"));
    }

    @Test
    void testBothEndpointsReturnConsistentData() {
        String oidcIssuer = given()
            .when()
                .get("/.well-known/openid-configuration")
            .then()
                .statusCode(200)
                .extract().path("issuer");

        String oauthIssuer = given()
            .when()
                .get("/.well-known/oauth-authorization-server")
            .then()
                .statusCode(200)
                .extract().path("issuer");

        assert oidcIssuer.equals(oauthIssuer) : "Issuers should match between discovery endpoints";
    }

    @Test
    void testEndpointUrlsAreHTTPS() {
        given()
        .when()
            .get("/.well-known/openid-configuration")
        .then()
            .statusCode(200)
            .body("authorization_endpoint", startsWith("https://"))
            .body("token_endpoint", startsWith("https://"))
            .body("registration_endpoint", startsWith("https://"));
    }
}
