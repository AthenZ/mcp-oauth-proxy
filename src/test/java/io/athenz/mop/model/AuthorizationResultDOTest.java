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
package io.athenz.mop.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class AuthorizationResultDOTest {

    @Test
    void unauthorized_helper_setsUnauthorizedAuthResultAndErrorMessage() {
        AuthorizationResultDO r = AuthorizationResultDO.unauthorized("Role=foo is not grantable");
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        assertNull(r.token());
        assertNull(r.oauthScope());
        assertEquals("Role=foo is not grantable", r.errorMessage());
    }

    @Test
    void unauthorized_helper_acceptsNullErrorMessage() {
        // Some legacy paths have nothing useful to say beyond the AuthResult; the helper
        // must still produce a valid record (no NPE) and AuthorizerService falls back to a
        // generic UpstreamExchangeException message.
        AuthorizationResultDO r = AuthorizationResultDO.unauthorized(null);
        assertEquals(AuthResult.UNAUTHORIZED, r.authResult());
        assertNull(r.errorMessage());
    }

    @Test
    void threeArgConstructor_isBackCompat_setsErrorMessageNull() {
        // Existing call sites (Atlassian, GitHub, ZTS AUTHORIZED success path, etc.) construct
        // with the legacy 3-arg ctor. Must stay valid and default errorMessage to null so
        // downstream null-checks behave predictably.
        TokenWrapper tw = new TokenWrapper(null, null, null, "tok", null, 600L);
        AuthorizationResultDO r = new AuthorizationResultDO(AuthResult.AUTHORIZED, tw, "scope-1");
        assertEquals(AuthResult.AUTHORIZED, r.authResult());
        assertEquals("tok", r.token().accessToken());
        assertEquals("scope-1", r.oauthScope());
        assertNull(r.errorMessage());
    }

    @Test
    void twoArgConstructor_isBackCompat_setsScopeAndErrorMessageNull() {
        // The simplest legacy ctor — preserve so passthrough providers (e.g. Atlassian) keep
        // compiling unchanged.
        TokenWrapper tw = new TokenWrapper(null, null, null, "tok", null, 600L);
        AuthorizationResultDO r = new AuthorizationResultDO(AuthResult.AUTHORIZED, tw);
        assertEquals(AuthResult.AUTHORIZED, r.authResult());
        assertNull(r.oauthScope());
        assertNull(r.errorMessage());
    }
}
