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

import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.model.UpstreamTokenRecord;
import io.athenz.mop.service.AudienceConstants;
import io.athenz.mop.service.AuthorizerService;
import io.athenz.mop.service.UpstreamRefreshService;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Unit tests for AuthorizeResource refresh token reuse: when the user already has an active
 * Okta refresh token (e.g. from a previous login for another resource), we reuse it instead of
 * overwriting with the new one from the current OIDC response.
 */
@ExtendWith(MockitoExtension.class)
class AuthorizeResourceRefreshTokenReuseTest {

    private static final String LOOKUP_KEY = "user-sub-1";
    private static final String PROVIDER = AudienceConstants.PROVIDER_OKTA;
    private static final String EXISTING_REFRESH = "existing-okta-refresh-token";
    private static final String NEW_FROM_OIDC = "new-okta-refresh-token";
    private static final String SUBJECT = "okta-subject-1";
    private static final String CENTRALIZED_RT = "centralized-rotated-rt";

    @Mock
    private AuthorizerService authorizerService;

    @Mock
    private UpstreamRefreshService upstreamRefreshService;

    private AuthorizeResource authorizeResource;

    @BeforeEach
    void setUp() {
        authorizeResource = new AuthorizeResource();
        authorizeResource.authorizerService = authorizerService;
        authorizeResource.upstreamRefreshService = upstreamRefreshService;
        authorizeResource.providerDefault = PROVIDER;
    }

    @Test
    void computeRefreshToStore_whenNoExistingToken_returnsOidcRefreshToken() {
        when(authorizerService.getUserToken(eq(LOOKUP_KEY), eq(PROVIDER))).thenReturn(null);

        String result = authorizeResource.computeRefreshToStore(LOOKUP_KEY, NEW_FROM_OIDC);

        assertEquals(NEW_FROM_OIDC, result);
    }

    @Test
    void computeRefreshToStore_whenNoExistingToken_andOidcRefreshNull_returnsNull() {
        when(authorizerService.getUserToken(eq(LOOKUP_KEY), eq(PROVIDER))).thenReturn(null);

        String result = authorizeResource.computeRefreshToStore(LOOKUP_KEY, null);

        assertNull(result);
    }

    @Test
    void computeRefreshToStore_whenExistingActiveToken_returnsExistingRefresh() {
        long ttlInFuture = System.currentTimeMillis() / 1000 + 3600;
        TokenWrapper existing = new TokenWrapper(
                LOOKUP_KEY,
                PROVIDER,
                "id-token",
                "access-token",
                EXISTING_REFRESH,
                ttlInFuture);
        when(authorizerService.getUserToken(eq(LOOKUP_KEY), eq(PROVIDER))).thenReturn(existing);

        String result = authorizeResource.computeRefreshToStore(LOOKUP_KEY, NEW_FROM_OIDC);

        assertEquals(EXISTING_REFRESH, result);
    }

    @Test
    void computeRefreshToStore_whenExistingTokenExpired_returnsOidcRefreshToken() {
        long ttlInPast = System.currentTimeMillis() / 1000 - 60;
        TokenWrapper existing = new TokenWrapper(
                LOOKUP_KEY,
                PROVIDER,
                "id-token",
                "access-token",
                EXISTING_REFRESH,
                ttlInPast);
        when(authorizerService.getUserToken(eq(LOOKUP_KEY), eq(PROVIDER))).thenReturn(existing);

        String result = authorizeResource.computeRefreshToStore(LOOKUP_KEY, NEW_FROM_OIDC);

        assertEquals(NEW_FROM_OIDC, result);
    }

    @Test
    void computeRefreshToStore_whenExistingTokenHasNullRefresh_returnsOidcRefreshToken() {
        long ttlInFuture = System.currentTimeMillis() / 1000 + 3600;
        TokenWrapper existing = new TokenWrapper(
                LOOKUP_KEY,
                PROVIDER,
                "id-token",
                "access-token",
                null,
                ttlInFuture);
        when(authorizerService.getUserToken(eq(LOOKUP_KEY), eq(PROVIDER))).thenReturn(existing);

        String result = authorizeResource.computeRefreshToStore(LOOKUP_KEY, NEW_FROM_OIDC);

        assertEquals(NEW_FROM_OIDC, result);
    }

    @Test
    void computeRefreshToStore_whenExistingTokenHasEmptyRefresh_returnsOidcRefreshToken() {
        long ttlInFuture = System.currentTimeMillis() / 1000 + 3600;
        TokenWrapper existing = new TokenWrapper(
                LOOKUP_KEY,
                PROVIDER,
                "id-token",
                "access-token",
                "",
                ttlInFuture);
        when(authorizerService.getUserToken(eq(LOOKUP_KEY), eq(PROVIDER))).thenReturn(existing);

        String result = authorizeResource.computeRefreshToStore(LOOKUP_KEY, NEW_FROM_OIDC);

        assertEquals(NEW_FROM_OIDC, result);
    }

    @Test
    void computeRefreshToStore_whenExistingTokenHasNullTtl_returnsOidcRefreshToken() {
        TokenWrapper existing = new TokenWrapper(
                LOOKUP_KEY,
                PROVIDER,
                "id-token",
                "access-token",
                EXISTING_REFRESH,
                null);
        when(authorizerService.getUserToken(eq(LOOKUP_KEY), eq(PROVIDER))).thenReturn(existing);

        String result = authorizeResource.computeRefreshToStore(LOOKUP_KEY, NEW_FROM_OIDC);

        assertEquals(NEW_FROM_OIDC, result);
    }

    @Test
    void preferCentralizedOktaUpstreamRefresh_whenNotOkta_returnsCandidate() {
        authorizeResource.providerDefault = "google-drive";
        assertEquals(NEW_FROM_OIDC, authorizeResource.preferCentralizedOktaUpstreamRefresh(SUBJECT, NEW_FROM_OIDC));
    }

    @Test
    void preferCentralizedOktaUpstreamRefresh_whenNoCentralRow_returnsCandidate() {
        when(upstreamRefreshService.getCurrentUpstream(eq(AudienceConstants.PROVIDER_OKTA + "#" + SUBJECT))).thenReturn(Optional.empty());
        assertEquals(NEW_FROM_OIDC, authorizeResource.preferCentralizedOktaUpstreamRefresh(SUBJECT, NEW_FROM_OIDC));
    }

    @Test
    void preferCentralizedOktaUpstreamRefresh_whenCentralRowHasRt_prefersCentral() {
        UpstreamTokenRecord rec = new UpstreamTokenRecord(
                AudienceConstants.PROVIDER_OKTA + "#" + SUBJECT, CENTRALIZED_RT, "", 2L, 0L, "", "");
        when(upstreamRefreshService.getCurrentUpstream(eq(AudienceConstants.PROVIDER_OKTA + "#" + SUBJECT))).thenReturn(Optional.of(rec));
        assertEquals(CENTRALIZED_RT, authorizeResource.preferCentralizedOktaUpstreamRefresh(SUBJECT, NEW_FROM_OIDC));
    }
}
