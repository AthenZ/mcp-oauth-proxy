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
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.is;

@QuarkusTest
@Disabled("Requires full Embrace OIDC integration - enable in integration environment")
class EmbraceResourceTest {

    @BeforeAll
    static void configureRestAssured() {
        RestAssured.config = RestAssured.config()
                .sslConfig(SSLConfig.sslConfig()
                        .relaxedHTTPSValidation()
                        .allowAllHostnames());
    }

    @Test
    void testEmbraceAuthorizeRequiresAuthentication() {
        given()
                .queryParam("state", "test-authorization-code")
                .when()
                .get("/embrace/authorize")
                .then()
                .statusCode(anyOf(is(401), is(302)));
    }

    @Test
    void testEmbraceAuthorizeWithValidState() {
        given()
                .queryParam("state", "valid-authorization-code")
                .cookie("q_session_embrace", "valid-session")
                .when()
                .get("/embrace/authorize")
                .then()
                .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @Test
    void testEmbraceAuthorizeWithMissingState() {
        given()
                .cookie("q_session_embrace", "valid-session")
                .when()
                .get("/embrace/authorize")
                .then()
                .statusCode(anyOf(is(201), is(401)));
    }
}
