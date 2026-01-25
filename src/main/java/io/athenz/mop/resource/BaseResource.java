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

import io.athenz.mop.util.JwtUtils;
import io.quarkus.oidc.OidcSession;
import io.quarkus.oidc.UserInfo;
import jakarta.ws.rs.core.Response;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class BaseResource {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    /**
     * Build success redirect with authorization code
     * RFC 6749 Section 4.1.2
     */
    Response buildSuccessRedirect(String redirectUri, String code, String state) {
        try {
            StringBuilder locationBuilder = new StringBuilder(redirectUri);

            // Add separator (? or & depending on existing query params)
            locationBuilder.append(redirectUri.contains("?") ? "&" : "?");

            // Add code parameter
            locationBuilder.append("code=").append(URLEncoder.encode(code, StandardCharsets.UTF_8));

            // Add state if provided (RECOMMENDED for CSRF protection)
            if (state != null && !state.isEmpty()) {
                locationBuilder.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
            }

            log.info("Redirecting to: {}", locationBuilder.toString().replaceAll("code=[^&]+", "code=***"));

            return Response.seeOther(URI.create(locationBuilder.toString())).build();

        } catch (Exception e) {
            log.error("Error building code redirect", e);
            return Response.serverError().build();
        }
    }

    /**
     * Build error redirect
     * RFC 6749 Section 4.1.2.1
     */
    Response buildErrorRedirect(String redirectUri, String state, String error, String errorDescription) {
        try {
            StringBuilder locationBuilder = new StringBuilder(redirectUri);

            locationBuilder.append(redirectUri.contains("?") ? "&" : "?");
            locationBuilder.append("error=").append(URLEncoder.encode(error, StandardCharsets.UTF_8));

            if (errorDescription != null && !errorDescription.isEmpty()) {
                locationBuilder.append("&error_description=")
                        .append(URLEncoder.encode(errorDescription, StandardCharsets.UTF_8));
            }

            if (state != null && !state.isEmpty()) {
                locationBuilder.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
            }

            log.warn("Redirecting with error: {}", error);

            return Response.seeOther(URI.create(locationBuilder.toString())).build();

        } catch (Exception e) {
            log.error("Error building error redirect", e);
            return Response.serverError().build();
        }
    }

    Response buildRedirect(String redirectUri, String state) {
        try {
            StringBuilder locationBuilder = new StringBuilder(redirectUri);

            // Add separator (? or & depending on existing query params)
            locationBuilder.append(redirectUri.contains("?") ? "&" : "?");

            if (state != null && !state.isEmpty()) {
                locationBuilder.append("state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
            }
            return Response.seeOther(URI.create(locationBuilder.toString())).build();

        } catch (Exception e) {
            log.error("Error building redirect", e);
            return Response.serverError().build();
        }
    }

    String getUserNameFromUserInfo(UserInfo userInfo, String userNameClaim) {
        String userName = null;
        if (userInfo.get(userNameClaim) != null) {
            userName = userInfo.get(userNameClaim).toString();
        }
        if (userName == null || userName.isEmpty()) {
            userName = userInfo.getSubject();
        }
        if (userName != null) {
            userName = trimQuotes(userName);
        }
        return userName;
    }

    private static String trimQuotes(String userName) {
        if (userName != null && userName.contains("\"")) {
            userName = userName.replaceAll("\"", "");
        }
        return userName;
    }

    String getUsername(UserInfo userInfo, String userNameClaim, String token) {
        String userName = null;
        if (userInfo != null) {
            userName = getUserNameFromUserInfo(userInfo, userNameClaim);
        } else {
            Object userNameFromTokenObj = JwtUtils.getClaimFromToken(token, userNameClaim);
            if (userNameFromTokenObj != null) {
                userName = userNameFromTokenObj.toString();
                userName = trimQuotes(userName);
            }
        }
        if (userName != null && userNameClaim.contains("email") && userName.contains("@")) {
            int atIndex = userName.indexOf('@');
            userName = userName.substring(0, atIndex);
        }
        return userName;
    }

    void logoutFromProvider(String provider, OidcSession oidcSession) {
        log.info("Logging out of {} OIDC session", provider);
        oidcSession.logout().await().indefinitely();
    }
}
