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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.service.AudienceConstants;
import io.athenz.mop.store.TokenStore;
import io.athenz.mop.store.impl.aws.UserInfoCrossRegionFallback;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for UserInfoResource, including cross-region fallback when token is not found locally.
 */
@ExtendWith(MockitoExtension.class)
class UserInfoResourceTest {

    private static final String ACCESS_TOKEN = "test_access_token";
    private static final String USER = "user.test";
    private static final String PROVIDER = AudienceConstants.PROVIDER_OKTA;

    @Mock
    private TokenStore tokenStore;

    @Mock
    private UserInfoCrossRegionFallback crossRegionFallback;

    @InjectMocks
    private UserInfoResource userInfoResource;

    private TokenWrapper tokenWrapper;
    private TokenWrapper oktaTokenWrapper;
    private String idToken;

    @BeforeEach
    void setUp() throws Exception {
        idToken = createIdToken(USER);
        long ttl = System.currentTimeMillis() / 1000 + 3600;
        tokenWrapper = new TokenWrapper(USER, PROVIDER, idToken, ACCESS_TOKEN, "refresh", ttl);
        oktaTokenWrapper = new TokenWrapper(USER, PROVIDER, idToken, null, null, ttl);
    }

    private static String createIdToken(String sub) throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(sub)
                .claim("name", "Test User")
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecKey.getKeyID()).build(),
                claims);
        jwt.sign(new ECDSASigner(ecKey));
        return jwt.serialize();
    }

    @Test
    void getUserInfo_missingAuthorization_returns401() {
        Response response = userInfoResource.getUserInfo(null);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertErrorBody(response, "invalid_token", "Missing or invalid Authorization header");
        verify(tokenStore, never()).getUserTokenByAccessTokenHash(ArgumentMatchers.any());
    }

    @Test
    void getUserInfo_invalidAuthorizationPrefix_returns401() {
        Response response = userInfoResource.getUserInfo("Basic xyz");

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertErrorBody(response, "invalid_token", "Missing or invalid Authorization header");
        verify(tokenStore, never()).getUserTokenByAccessTokenHash(ArgumentMatchers.any());
    }

    @Test
    void getUserInfo_tokenFoundInPrimary_returns200() {
        when(tokenStore.getUserTokenByAccessTokenHash(ArgumentMatchers.anyString())).thenReturn(tokenWrapper);
        when(tokenStore.getUserToken(USER, PROVIDER)).thenReturn(oktaTokenWrapper);

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(tokenStore, times(1)).getUserTokenByAccessTokenHash(ArgumentMatchers.anyString());
        verify(crossRegionFallback, never()).getUserTokenByAccessTokenHash(ArgumentMatchers.any());
    }

    @Test
    void getUserInfo_tokenFoundInFallback_returns200() {
        when(tokenStore.getUserTokenByAccessTokenHash(ArgumentMatchers.anyString())).thenReturn(null);
        when(crossRegionFallback.getUserTokenByAccessTokenHash(ArgumentMatchers.anyString())).thenReturn(tokenWrapper);
        when(crossRegionFallback.getUserToken(USER, PROVIDER)).thenReturn(oktaTokenWrapper);

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(tokenStore, times(1)).getUserTokenByAccessTokenHash(ArgumentMatchers.anyString());
        verify(crossRegionFallback, times(1)).getUserTokenByAccessTokenHash(ArgumentMatchers.anyString());
        verify(crossRegionFallback, times(1)).getUserToken(USER, PROVIDER);
    }

    @Test
    void getUserInfo_tokenNotFound_returns401() {
        when(tokenStore.getUserTokenByAccessTokenHash(ArgumentMatchers.anyString())).thenReturn(null);
        when(crossRegionFallback.getUserTokenByAccessTokenHash(ArgumentMatchers.anyString())).thenReturn(null);

        Response response = userInfoResource.getUserInfo("Bearer " + ACCESS_TOKEN);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertErrorBody(response, "invalid_token", "Token not found");
        verify(tokenStore, times(1)).getUserTokenByAccessTokenHash(ArgumentMatchers.anyString());
        verify(crossRegionFallback, times(1)).getUserTokenByAccessTokenHash(ArgumentMatchers.anyString());
    }

    @SuppressWarnings("unchecked")
    private static void assertErrorBody(Response response, String expectedError, String expectedDescription) {
        Object entity = response.getEntity();
        assertNotNull(entity);
        Map<String, Object> body = (Map<String, Object>) entity;
        assertEquals(expectedError, body.get("error"));
        assertEquals(expectedDescription, body.get("error_description"));
    }
}
