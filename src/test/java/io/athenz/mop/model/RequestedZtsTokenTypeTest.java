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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RequestedZtsTokenTypeTest {

    @Test
    void testValues() {
        RequestedZtsTokenType[] values = RequestedZtsTokenType.values();
        assertEquals(2, values.length);
        assertEquals(RequestedZtsTokenType.JAG, values[0]);
        assertEquals(RequestedZtsTokenType.ID_TOKEN, values[1]);
    }

    @Test
    void testValueOf() {
        assertEquals(RequestedZtsTokenType.JAG, RequestedZtsTokenType.valueOf("JAG"));
        assertEquals(RequestedZtsTokenType.ID_TOKEN, RequestedZtsTokenType.valueOf("ID_TOKEN"));
    }
}
