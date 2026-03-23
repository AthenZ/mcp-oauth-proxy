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

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class TokenExchangeDOTest {

    private static final TokenWrapper WRAPPER = new TokenWrapper("k", "p", "id", "access", "refresh", 3600L);

    @Test
    void testFiveArgConstructor_DefaultsRequestedZtsTokenTypeToNull() {
        TokenExchangeDO dto = new TokenExchangeDO(
                List.of("s1"),
                "res",
                "ns",
                "remote",
                WRAPPER
        );
        assertEquals(List.of("s1"), dto.scopes());
        assertEquals("res", dto.resource());
        assertEquals("ns", dto.namespace());
        assertEquals("remote", dto.remoteServer());
        assertSame(WRAPPER, dto.tokenWrapper());
        assertNull(dto.requestedZtsTokenType());
    }

    @Test
    void testSixArgConstructor_WithRequestedZtsTokenType() {
        TokenExchangeDO dto = new TokenExchangeDO(
                Collections.emptyList(),
                "r",
                "n",
                "srv",
                WRAPPER,
                RequestedZtsTokenType.ID_TOKEN
        );
        assertEquals(RequestedZtsTokenType.ID_TOKEN, dto.requestedZtsTokenType());
    }
}
