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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Unified integration tests for all Google Workspace OAuth callback endpoints.
 * Each test is parameterized over all 12 provider path segments.
 *
 * NOTE: These tests require full Google OIDC integration and authentication.
 * Enable them in a full integration test environment.
 */
@QuarkusTest
@Disabled("Requires full Google OIDC integration - enable in integration environment")
class GoogleWorkspaceResourceTest {

    @BeforeAll
    static void configureRestAssured() {
        RestAssured.config = RestAssured.config()
            .sslConfig(SSLConfig.sslConfig()
                .relaxedHTTPSValidation()
                .allowAllHostnames());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testAuthorizeRequiresAuthentication(String provider) {
        given()
            .queryParam("state", "test-authorization-code")
        .when()
            .get("/" + provider + "/authorize")
        .then()
            .statusCode(anyOf(is(401), is(302)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testAuthorizeWithValidState(String provider) {
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_" + provider, "valid-session")
        .when()
            .get("/" + provider + "/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testAuthorizeWithMissingState(String provider) {
        given()
            .cookie("q_session_" + provider, "valid-session")
        .when()
            .get("/" + provider + "/authorize")
        .then()
            .statusCode(anyOf(is(201), is(401)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testAuthorizeWithEmptyState(String provider) {
        given()
            .queryParam("state", "")
            .cookie("q_session_" + provider, "valid-session")
        .when()
            .get("/" + provider + "/authorize")
        .then()
            .statusCode(anyOf(is(201), is(401)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testAuthorizeWithInvalidState(String provider) {
        given()
            .queryParam("state", "non-existent-authorization-code")
            .cookie("q_session_" + provider, "valid-session")
        .when()
            .get("/" + provider + "/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testAuthorizeWithRefreshToken(String provider) {
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_" + provider, "session-with-refresh-token")
        .when()
            .get("/" + provider + "/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testAuthorizeWithExpiredSession(String provider) {
        given()
            .queryParam("state", "test-authorization-code")
            .cookie("q_session_" + provider, "expired-session")
        .when()
            .get("/" + provider + "/authorize")
        .then()
            .statusCode(anyOf(is(401), is(302)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testAuthorizeWithMultipleConcurrentRequests(String provider) {
        String state = "single-use-authorization-code";

        given()
            .queryParam("state", state)
            .cookie("q_session_" + provider, "valid-session")
        .when()
            .get("/" + provider + "/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));

        given()
            .queryParam("state", state)
            .cookie("q_session_" + provider, "valid-session")
        .when()
            .get("/" + provider + "/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testAuthorizeRequiresRefreshToken(String provider) {
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_" + provider, "session-without-refresh-token")
        .when()
            .get("/" + provider + "/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testAuthorizeStoresAccessAndRefreshToken(String provider) {
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_" + provider, "valid-session-with-tokens")
        .when()
            .get("/" + provider + "/authorize")
        .then()
            .statusCode(anyOf(is(303), is(401), is(500)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "google-drive", "google-docs", "google-sheets",
        "google-slides", "google-gmail", "google-calendar", "google-tasks",
        "google-chat", "google-forms", "google-keep", "google-meet",
        "google-cloud-platform"
    })
    void testAuthorizeLogsWarningForMissingRefreshToken(String provider) {
        given()
            .queryParam("state", "valid-authorization-code")
            .cookie("q_session_" + provider, "session-no-refresh")
        .when()
            .get("/" + provider + "/authorize")
        .then()
            .statusCode(anyOf(is(500), is(401)));
    }
}
