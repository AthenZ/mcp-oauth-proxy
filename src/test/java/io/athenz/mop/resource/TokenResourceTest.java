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

import io.athenz.mop.model.*;
import io.athenz.mop.service.AuthorizationCodeService;
import io.athenz.mop.service.AuthorizerService;
import io.athenz.mop.service.ConfigService;
import io.athenz.mop.service.RefreshTokenService;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for TokenResource, including refresh_token grant behavior when upstream fails.
 */
@ExtendWith(MockitoExtension.class)
class TokenResourceTest {

    private static final String TOKEN_FAMILY_ID = "family-1";
    private static final String USER_ID = "user-1";
    private static final String PROVIDER = "okta";
    private static final String CLIENT_ID = "client-1";
    private static final String RESOURCE = "https://resource.example.com";

    @Mock
    private AuthorizerService authorizerService;

    @Mock
    private AuthorizationCodeService authorizationCodeService;

    @Mock
    private ConfigService configService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private TokenResource tokenResource;

    @BeforeEach
    void setUp() {
        tokenResource.refreshExpirySeconds = 7776000L;
    }

    @Test
    void refreshTokenGrant_whenUpstreamReturnsNull_revokesFamilyAndReturnsInvalidGrant() {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        request.setGrantType("refresh_token");
        request.setRefreshToken("rt_validToken");
        request.setClientId(CLIENT_ID);
        request.setResource(RESOURCE);

        RefreshTokenRecord record = new RefreshTokenRecord(
                "refresh-id-1",
                "provider-user-1",
                USER_ID,
                CLIENT_ID,
                PROVIDER,
                "sub-1",
                "encrypted-upstream",
                "ACTIVE",
                TOKEN_FAMILY_ID,
                null,
                null,
                0L,
                System.currentTimeMillis() / 1000,
                System.currentTimeMillis() / 1000 + 7776000L,
                System.currentTimeMillis() / 1000 + 7776000L + 604800L
        );

        when(refreshTokenService.validate(eq("rt_validToken"), eq(CLIENT_ID)))
                .thenReturn(RefreshTokenValidationResult.active(record));
        when(refreshTokenService.rotate(eq("rt_validToken"), eq(CLIENT_ID)))
                .thenReturn(new RefreshTokenRotateResult("rt_newToken", "refresh-id-2", "provider-user-1"));
        when(authorizerService.refreshUpstreamAndGetToken(
                eq(USER_ID),
                eq(PROVIDER),
                eq(RESOURCE),
                eq("encrypted-upstream")))
                .thenReturn(null);

        Response response = tokenResource.generateTokenOAuth2(request);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        OAuth2ErrorResponse body = (OAuth2ErrorResponse) response.getEntity();
        assertNotNull(body);
        assertEquals(OAuth2ErrorResponse.ErrorCode.INVALID_GRANT, body.error());

        ArgumentCaptor<String> familyIdCaptor = ArgumentCaptor.forClass(String.class);
        verify(refreshTokenService).revokeFamily(familyIdCaptor.capture());
        assertEquals(TOKEN_FAMILY_ID, familyIdCaptor.getValue());
    }
}
