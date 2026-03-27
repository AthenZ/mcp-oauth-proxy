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

import io.athenz.mop.model.AuthorizationCode;
import io.athenz.mop.store.AuthCodeStore;
import io.athenz.mop.store.impl.aws.CrossRegionTokenStoreFallback;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class AuthCodeRegionResolverTest {

    @Mock
    AuthCodeStore authCodeStore;

    @Mock
    CrossRegionTokenStoreFallback crossRegionFallback;

    @InjectMocks
    AuthCodeRegionResolver resolver;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void resolve_ReturnsLocalWhenPresent() {
        AuthorizationCode code = new AuthorizationCode(
                "c1", "cid", "sub", "https://cb", "s", "r", "ch", "S256",
                Instant.now().plusSeconds(60), "st");
        when(authCodeStore.getAuthCode("c1", AudienceConstants.PROVIDER_OKTA)).thenReturn(code);

        AuthCodeResolution r = resolver.resolve("c1", AudienceConstants.PROVIDER_OKTA);

        assertSame(code, r.authorizationCode());
        assertFalse(r.resolvedFromFallback());
        verify(crossRegionFallback, never()).getAuthCode(anyString(), anyString());
    }

    @Test
    void resolve_UsesFallbackWhenLocalMissing() {
        AuthorizationCode code = new AuthorizationCode(
                "c1", "cid", "sub", "https://cb", "s", "r", "ch", "S256",
                Instant.now().plusSeconds(60), "st");
        when(authCodeStore.getAuthCode("c1", AudienceConstants.PROVIDER_OKTA)).thenReturn(null);
        when(crossRegionFallback.getAuthCode("c1", AudienceConstants.PROVIDER_OKTA)).thenReturn(code);

        AuthCodeResolution r = resolver.resolve("c1", AudienceConstants.PROVIDER_OKTA);

        assertSame(code, r.authorizationCode());
        assertTrue(r.resolvedFromFallback());
    }

    @Test
    void resolve_ReturnsNullWhenBothMissing() {
        when(authCodeStore.getAuthCode("c1", AudienceConstants.PROVIDER_OKTA)).thenReturn(null);
        when(crossRegionFallback.getAuthCode("c1", AudienceConstants.PROVIDER_OKTA)).thenReturn(null);

        AuthCodeResolution r = resolver.resolve("c1", AudienceConstants.PROVIDER_OKTA);

        assertNull(r.authorizationCode());
        assertFalse(r.resolvedFromFallback());
    }

    @Test
    void deleteAuthCode_RoutesToFallbackWhenResolvedFromPeer() {
        resolver.deleteAuthCode("c1", AudienceConstants.PROVIDER_OKTA, true);
        verify(crossRegionFallback).deleteAuthCode("c1", AudienceConstants.PROVIDER_OKTA);
        verify(authCodeStore, never()).deleteAuthCode(anyString(), anyString());
    }

    @Test
    void deleteAuthCode_RoutesToLocalWhenNotFromPeer() {
        resolver.deleteAuthCode("c1", AudienceConstants.PROVIDER_OKTA, false);
        verify(authCodeStore).deleteAuthCode("c1", AudienceConstants.PROVIDER_OKTA);
        verify(crossRegionFallback, never()).deleteAuthCode(anyString(), anyString());
    }
}
