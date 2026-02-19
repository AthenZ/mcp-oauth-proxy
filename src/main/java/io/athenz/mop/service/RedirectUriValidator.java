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
package io.athenz.mop.service;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.enterprise.context.ApplicationScoped;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

@ApplicationScoped
public class RedirectUriValidator {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @ConfigProperty(
            name = "server.allowed-redirect-uri-prefixes",
            defaultValue = "http://localhost,https://localhost,cursor://anysphere.cursor-")
    List<String> allowedRedirectUriPrefixes;

    /**
     * Validate a redirect URI against security requirements and allowlist
     *
     * @param redirectUri the redirect URI to validate
     * @param clientId optional client ID for logging purposes
     * @return true if the redirect URI is valid, false otherwise
     */
    public boolean isValidRedirectUri(String redirectUri, String clientId) {
        if (redirectUri == null || redirectUri.isEmpty()) {
            log.warn("Redirect URI is null or empty for client: {}", clientId);
            return false;
        }

        // Validate URI format
        URI uri;
        try {
            uri = URI.create(redirectUri);
        } catch (Exception e) {
            log.error("Invalid redirect_uri format: {} for client: {}", redirectUri, clientId, e);
            return false;
        }

        String scheme = uri.getScheme();
        if (scheme == null) {
            log.error("redirect_uri missing scheme: {} for client: {}", redirectUri, clientId);
            return false;
        }

        if (uri.getUserInfo() != null) {
            log.error("redirect_uri contains userinfo: {} for client: {}", redirectUri, clientId);
            return false;
        }

        if ("http".equals(scheme) || "https".equals(scheme)) {
            if (containsAtSymbol(uri)) {
                log.error("redirect_uri contains '@' in HTTP/HTTPS URL: {} for client: {}",
                        redirectUri, clientId);
                return false;
            }
        }

        String host = uri.getHost();

        if (!"https".equals(scheme)) {
            if ("http".equals(scheme) && isLocalhost(host)) {
            } else if (!"http".equals(scheme)) {
            } else {
                log.error("redirect_uri must use HTTPS (except localhost): {} for client: {}",
                        redirectUri, clientId);
                return false;
            }
        }

        // Check against allowlist
        if (allowedRedirectUriPrefixes != null && !allowedRedirectUriPrefixes.isEmpty()) {
            boolean isAllowed = allowedRedirectUriPrefixes.stream()
                    .anyMatch(allowed -> matchesPattern(uri, allowed));
            if (!isAllowed) {
                log.error("redirect_uri not in allowlist: {} for client: {}", redirectUri, clientId);
                return false;
            }
        }

        return true;
    }

    /**
     * Validate a redirect URI (without client ID context)
     *
     * @param redirectUri the redirect URI to validate
     * @return true if the redirect URI is valid, false otherwise
     */
    public boolean isValidRedirectUri(String redirectUri) {
        return isValidRedirectUri(redirectUri, null);
    }

    /**
     * Validate multiple redirect URIs (used during client registration)
     *
     * @param redirectUris list of redirect URIs to validate
     * @param clientId optional client ID for logging purposes
     * @return true if all redirect URIs are valid, false otherwise
     */
    public boolean validateRedirectUris(List<String> redirectUris, String clientId) {
        if (redirectUris == null || redirectUris.isEmpty()) {
            log.warn("No redirect URIs provided for client: {}", clientId);
            return false;
        }

        for (String uri : redirectUris) {
            if (!isValidRedirectUri(uri, clientId)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if host is localhost
     */
    private boolean isLocalhost(String host) {
        return host != null &&
                (host.equals("localhost") ||
                 host.equals("127.0.0.1") ||
                 host.equals("::1"));
    }

    private boolean containsAtSymbol(URI uri) {
        return contains(uri.getRawAuthority()) ||
               contains(uri.getRawPath()) ||
               contains(uri.getRawQuery()) ||
               contains(uri.getRawFragment());
    }

    private boolean contains(String value) {
        return value != null && value.contains("@");
    }

    private boolean matchesPattern(URI redirect, String allowedPattern) {
        try {
            URI allowed = URI.create(allowedPattern);

            if (!Objects.equals(redirect.getScheme(), allowed.getScheme())) {
                return false;
            }

            String scheme = redirect.getScheme();

            if (!"http".equals(scheme) && !"https".equals(scheme)) {
                return redirect.toString().startsWith(allowedPattern);
            }

            if (!Objects.equals(redirect.getHost(), allowed.getHost())) {
                return false;
            }

            int allowedPort = normalizePort(allowed);
            int redirectPort = normalizePort(redirect);

            if (allowed.getPort() != -1 && allowedPort != redirectPort) {
                return false;
            }

            String allowedPath = Optional.ofNullable(allowed.getPath()).orElse("");
            String redirectPath = Optional.ofNullable(redirect.getPath()).orElse("");

            if (!redirectPath.startsWith(allowedPath)) {
                return false;
            }

            if (!allowedPath.endsWith("/") &&
                redirectPath.length() > allowedPath.length() &&
                redirectPath.charAt(allowedPath.length()) != '/') {
                return false;
            }

            return true;

        } catch (Exception e) {
            return false;
        }
    }

    private int normalizePort(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }

        if ("https".equals(uri.getScheme())) {
            return 443;
        }

        if ("http".equals(uri.getScheme())) {
            return 80;
        }

        return -1;
    }
}
