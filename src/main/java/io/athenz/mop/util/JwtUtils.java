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
package io.athenz.mop.util;

import com.nimbusds.jwt.SignedJWT;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JwtUtils {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    /**
     * Extracts a specific claim from a JWT token.
     * <p>
     * <b>Security Note:</b> This method is designed to parse tokens issued by trusted upstream
     * Identity Provider (IDP) authorization servers (e.g., Okta, Google, GitHub, Atlassian)
     * and is used from the Quarkus OIDC flow. The Quarkus OIDC extension performs ID Token
     * validation (signature verification using the provider JWK set, expiration, issuer,
     * audience, and nonce checks) before creating the SecurityIdentity. The application code
     * does not handle raw tokens and therefore does not perform additional validation.
     *
     * @param token The JWT token from a trusted IDP authorization server
     * @param claim The name of the claim to extract (e.g., "sub", "iss", "exp")
     * @return The claim value, or null if the token cannot be parsed or the claim does not exist
     */
    public static Object getClaimFromToken(String token, String claim) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getClaim(claim);
        } catch (ParseException e) {
            log.error("Failed to parse JWT token");
        }
        return null;
    }

    /**
     * Gets all claims from a JWT token.
     * <p>
     * <b>Security Note:</b> This method is designed to parse tokens issued by trusted upstream
     * Identity Provider (IDP) authorization servers (e.g., Okta, Google, GitHub, Atlassian)
     * and is used from the Quarkus OIDC flow. The Quarkus OIDC extension performs ID Token
     * validation (signature verification using the provider JWK set, expiration, issuer,
     * audience, and nonce checks) before creating the SecurityIdentity. The application code
     * does not handle raw tokens and therefore does not perform additional validation.
     *
     * @param token The JWT token from a trusted IDP authorization server
     * @return Map containing all claims from the token, or null if parsing fails
     */
    public static Map<String, Object> getAllClaimsFromToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getClaims();
        } catch (ParseException e) {
            log.error("Failed to parse JWT token", e);
            return null;
        }
    }

    /**
     * Creates a deterministic SHA-512 hash of the access token.
     * This hash is used as a lookup key in DynamoDB GSI to find tokens by access token.
     *
     * @param accessToken The access token to hash
     * @return Hex-encoded SHA-512 hash (128 characters)
     */
    public static String hashAccessToken(String accessToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            byte[] hashBytes = digest.digest(accessToken.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            log.error("SHA-512 algorithm not available", e);
            throw new RuntimeException("SHA-512 hashing not available", e);
        }
    }
}
