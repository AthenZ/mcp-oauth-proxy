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
import java.util.regex.Pattern;
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
     * Match redirect URI against allowed pattern using regex
     * Supports:
     * - Exact match
     * - Prefix match for paths (scheme, host, port must match exactly)
     * - Custom URI schemes with proper boundary matching
     * Prevents subdomain attacks by using regex anchors and word boundaries
     *
     * <p><b>Security Issue - Security Task:</b> This method was refactored from using
     * {@code String.startsWith()} to regex-based validation to resolve a security vulnerability.
     * The previous implementation was vulnerable to subdomain attacks where an attacker could
     * bypass validation by using malicious URIs like {@code https://localhost.evil.com} which
     * would incorrectly match the allowed pattern {@code https://localhost} due to prefix matching.
     * The regex-based approach ensures exact host matching, preventing such subdomain attacks
     * while maintaining support for path prefix matching and custom URI schemes.
     *
     * @param redirectUri the redirect URI to check
     * @param allowedPattern the allowed pattern
     * @return true if the redirect URI matches the pattern
     */
    private boolean matchesPattern(String redirectUri, String allowedPattern) {
        // Exact match
        // Example: "https://app.example.com/callback" matches "https://app.example.com/callback"
        if (redirectUri.equals(allowedPattern)) {
            return true;
        }

        try {
            URI patternUri = URI.create(allowedPattern);
            String scheme = patternUri.getScheme();

            // For custom URI schemes (non-http/https), use careful prefix matching with regex
            // Example: scheme = "cursor" for "cursor://anysphere.cursor-"
            if (scheme != null && !"http".equals(scheme) && !"https".equals(scheme)) {
                // Escape special regex characters in the pattern
                // Example: "cursor://anysphere.cursor-" becomes literal match (dots escaped)
                String escapedPattern = Pattern.quote(allowedPattern);

                // If pattern ends with a delimiter (-, /, :), allow any continuation
                // Otherwise, require exact match or proper path continuation
                // Example: "cursor://anysphere.cursor-" ends with "-", so "cursor://anysphere.cursor-abc123" matches
                if (allowedPattern.endsWith("-") || allowedPattern.endsWith("/") || allowedPattern.endsWith(":")) {
                    // Pattern ends with delimiter, match prefix and allow any continuation
                    // Example: Pattern "cursor://anysphere.cursor-" matches "cursor://anysphere.cursor-abc123"
                    //          Pattern "cursor://anysphere.cursor-" matches "cursor://anysphere.cursor-callback/path"
                    Pattern regex = Pattern.compile("^" + escapedPattern + ".*$");
                    return regex.matcher(redirectUri).matches();
                } else {
                    // Pattern doesn't end with delimiter, require exact match or path continuation
                    // Example: Pattern "myapp://callback" matches "myapp://callback" (exact)
                    //          Pattern "myapp://callback" matches "myapp://callback/nested" (path continuation)
                    //          Pattern "myapp://callback" does NOT match "myapp://callbackevil" (no delimiter)
                    Pattern regex = Pattern.compile("^" + escapedPattern + "([/?].*)?$");
                    return regex.matcher(redirectUri).matches();
                }
            }

            // For http/https schemes, build a regex that matches exactly
            // Example: "https://app.example.com" -> host = "app.example.com"
            String host = patternUri.getHost();
            if (host == null) {
                return false;
            }

            // Escape special regex characters in scheme and host
            // Example: "https://app.example.com" -> escapedScheme = "https", escapedHost = "app\\.example\\.com"
            // This prevents dots in hostnames from being treated as regex wildcards
            String escapedScheme = Pattern.quote(scheme);
            String escapedHost = Pattern.quote(host);

            // Build regex pattern that prevents subdomain attacks
            StringBuilder regexBuilder = new StringBuilder();
            regexBuilder.append("^");  // Anchor to start of string
            regexBuilder.append(escapedScheme);  // Example: "https"
            regexBuilder.append("://");  // Literal "://"

            // Match host exactly to prevent subdomain attacks
            // Use word boundary or ensure host is followed by valid URI characters
            // This ensures "localhost" matches "localhost" but not "localhost.evil.com"
            // Example: Pattern "https://localhost" matches "https://localhost/callback"
            //          Pattern "https://localhost" does NOT match "https://localhost.evil.com/callback"
            regexBuilder.append(escapedHost);

            // Ensure host is not followed by a dot (which would indicate a subdomain)
            // The host must be immediately followed by : (port), / (path), ? (query), # (fragment), or end of string
            // Use negative lookahead to prevent dot after host
            // Example: "https://localhost" -> next char must be :, /, ?, #, or end (not .)
            //          "https://localhost/callback" -> next char is "/" ✓ (matches)
            //          "https://localhost.evil.com" -> next char is "." ✗ (doesn't match - prevents attack)
            //          "https://localhost:3000" -> next char is ":" ✓ (matches)
            regexBuilder.append("(?![.a-zA-Z0-9-])");

            // Handle port - if pattern has port, require exact match; otherwise allow any port
            // Example: Pattern "https://app.example.com:8443" requires port 8443 exactly
            //          Pattern "https://app.example.com" allows any port or no port
            int port = patternUri.getPort();
            if (port != -1) {
                // Pattern specifies port, require exact match
                // Example: Pattern "http://localhost:8080" matches "http://localhost:8080/callback"
                //          Pattern "http://localhost:8080" does NOT match "http://localhost:3000/callback"
                regexBuilder.append(":");
                regexBuilder.append(port);
            } else {
                // Allow optional port (must be followed by :port or /, ?, #, or end)
                // Example: Pattern "https://app.example.com" matches "https://app.example.com/callback" (no port)
                //          Pattern "https://app.example.com" matches "https://app.example.com:8443/callback" (any port)
                //          Pattern "https://app.example.com" matches "https://app.example.com:443/callback" (default port)
                regexBuilder.append("(?::\\d+)?");
            }

            // Handle path - if pattern has path, require prefix match; otherwise allow any path
            // Example: Pattern "https://app.example.com/callback" requires path starting with "/callback"
            String path = patternUri.getPath();
            if (path != null && !path.isEmpty()) {
                // Escape path and allow prefix matching
                // Example: Pattern "https://app.example.com/callback" -> escapedPath = "/callback"
                String escapedPath = Pattern.quote(path);
                // Allow path to continue (e.g., /callback matches /callback/nested)
                // Example: Pattern "/callback" matches "/callback/nested/path"
                regexBuilder.append(escapedPath);
                // If path ends with /, allow any continuation; otherwise require / after the path
                // Example: Pattern "/api/" matches "/api/v1/users" (ends with /, any continuation)
                //          Pattern "/callback" matches "/callback" (exact) or "/callback/nested" (with /)
                //          Pattern "/callback" does NOT match "/callbackevil" (no / separator)
                if (path.endsWith("/")) {
                    regexBuilder.append(".*");
                } else {
                    regexBuilder.append("(/.*)?");
                }
            } else {
                // No path restriction, allow any path or no path
                // Example: Pattern "https://app.example.com" matches "https://app.example.com" (no path)
                //          Pattern "https://app.example.com" matches "https://app.example.com/callback" (any path)
                //          Pattern "https://app.example.com" matches "https://app.example.com/any/path/here" (any path)
                regexBuilder.append("(/.*)?");
            }

            // Allow query and fragment
            // Example: Pattern "https://app.example.com/callback" matches "https://app.example.com/callback?code=123"
            //          Pattern "https://app.example.com/callback" matches "https://app.example.com/callback#section"
            //          Pattern "https://app.example.com/callback" matches "https://app.example.com/callback?code=123&state=xyz#section"
            regexBuilder.append("(\\?.*)?");
            regexBuilder.append("(#.*)?");
            regexBuilder.append("$");  // Anchor to end of string

            Pattern regex = Pattern.compile(regexBuilder.toString());
            return regex.matcher(redirectUri).matches();

        } catch (Exception e) {
            log.debug("Error creating regex pattern for matching: redirectUri={}, allowedPattern={}",
                    redirectUri, allowedPattern, e);
            return false;
        }
    }
}
