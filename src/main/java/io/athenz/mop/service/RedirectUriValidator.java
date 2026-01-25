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

import jakarta.enterprise.context.ApplicationScoped;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.util.List;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service for validating OAuth 2.1 redirect URIs
 * Provides centralized validation logic for authorization and registration endpoints
 */
@ApplicationScoped
public class RedirectUriValidator {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @ConfigProperty(name = "server.allowed-redirect-uri-prefixes",
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

        String host = uri.getHost();

        // Security check: redirect_uri should use HTTPS (with exceptions)
        if (!"https".equals(scheme)) {
            // Allow http only for localhost in development
            if ("http".equals(scheme) && isLocalhost(host)) {
                log.debug("Allowing http for localhost: {}", redirectUri);
            }
            // Allow custom URI schemes (e.g., cursor://, myapp://)
            else if (!scheme.equals("http")) {
                log.debug("Allowing custom URI scheme: {} for client: {}", scheme, clientId);
            }
            // Reject http for non-localhost
            else {
                log.error("redirect_uri must use HTTPS (except localhost): {} for client: {}",
                        redirectUri, clientId);
                return false;
            }
        }

        // Check against allowlist
        if (allowedRedirectUriPrefixes != null && !allowedRedirectUriPrefixes.isEmpty()) {
            boolean isAllowed = allowedRedirectUriPrefixes.stream()
                    .anyMatch(allowed -> matchesPattern(redirectUri, allowed));
            if (!isAllowed) {
                log.error("redirect_uri not in allowlist: {} for client: {}", redirectUri, clientId);
                return false;
            }
        }

        // TODO: In production, validate against client-specific registered redirect URIs
        log.debug("redirect_uri validated: {} for client: {}", redirectUri, clientId);
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
        return host != null && (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("::1"));
    }

    /**
     * Match redirect URI against allowed pattern
     * Supports:
     * - Exact match
     * - Prefix match (startsWith)
     *
     * @param redirectUri the redirect URI to check
     * @param allowedPattern the allowed pattern
     * @return true if the redirect URI matches the pattern
     */
    private boolean matchesPattern(String redirectUri, String allowedPattern) {
        // Exact match
        if (redirectUri.equals(allowedPattern)) {
            return true;
        }

        // Prefix match (for custom URI schemes like cursor://)
        if (redirectUri.startsWith(allowedPattern)) {
            return true;
        }
        return false;
    }
}
