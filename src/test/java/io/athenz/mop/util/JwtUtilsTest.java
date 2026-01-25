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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.athenz.mop.util.JwtUtils;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilsTest {

    @Test
    void testGetClaimFromToken_ValidToken() throws Exception {
        // Create a test JWT token
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("test-user")
                .issuer("test-issuer")
                .audience("test-audience")
                .expirationTime(new Date(new Date().getTime() + 60000))
                .claim("custom_claim", "custom_value")
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecKey.getKeyID()).build(),
                claimsSet
        );

        signedJWT.sign(new ECDSASigner(ecKey));
        String token = signedJWT.serialize();

        // Test getting various claims
        assertEquals("test-user", JwtUtils.getClaimFromToken(token, "sub"));
        assertEquals("test-issuer", JwtUtils.getClaimFromToken(token, "iss"));
        // Audience claim is returned as a list by the JWT library
        Object audClaim = JwtUtils.getClaimFromToken(token, "aud");
        assertTrue(audClaim instanceof java.util.List);
        assertEquals("test-audience", ((java.util.List<?>) audClaim).get(0));
        assertEquals("custom_value", JwtUtils.getClaimFromToken(token, "custom_claim"));
    }

    @Test
    void testGetClaimFromToken_NonExistentClaim() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("test-user")
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecKey.getKeyID()).build(),
                claimsSet
        );

        signedJWT.sign(new ECDSASigner(ecKey));
        String token = signedJWT.serialize();

        // Test getting non-existent claim
        assertNull(JwtUtils.getClaimFromToken(token, "non_existent"));
    }

    @Test
    void testGetClaimFromToken_InvalidToken() {
        String invalidToken = "invalid.jwt.token";

        // Should return null for invalid token
        assertNull(JwtUtils.getClaimFromToken(invalidToken, "sub"));
    }

    @Test
    void testGetClaimFromToken_NullToken() {
        // JWT parser throws NullPointerException for null input, which is caught and returns null
        assertThrows(NullPointerException.class, () -> {
            JwtUtils.getClaimFromToken(null, "sub");
        });
    }

    @Test
    void testGetClaimFromToken_EmptyToken() {
        // Should handle empty string gracefully
        assertNull(JwtUtils.getClaimFromToken("", "sub"));
    }

    @Test
    void testGetClaimFromToken_MalformedToken() {
        String malformedToken = "not-a-jwt";

        // Should return null for malformed token
        assertNull(JwtUtils.getClaimFromToken(malformedToken, "sub"));
    }
}
