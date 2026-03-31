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

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JSON binding and accessors for ZMS {@code GET /zms/v1/resource} response POJOs.
 */
class ZmsResourceModelJsonTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void deserializeFullPayload() throws Exception {
        String json =
                """
                {
                  "resources": [
                    {
                      "principal": "user.yosrixp",
                      "assertions": [
                        {
                          "role": "calypso.nonprod:role.gcp.fed.power.user",
                          "resource": "projects/gcp-calypso-nonprod/roles/fed.power.user",
                          "action": "gcp.assume_role",
                          "effect": "ALLOW",
                          "id": 41455088,
                          "extraAssertionField": "ignored"
                        }
                      ],
                      "extraBlockField": 1
                    }
                  ]
                }
                """;

        ZmsResourceResponse root = mapper.readValue(json, ZmsResourceResponse.class);
        assertNotNull(root.getResources());
        assertEquals(1, root.getResources().size());

        ZmsResourcePrincipalEntry block = root.getResources().get(0);
        assertEquals("user.yosrixp", block.getPrincipal());
        assertNotNull(block.getAssertions());
        assertEquals(1, block.getAssertions().size());

        ZmsResourceAssertion a = block.getAssertions().get(0);
        assertEquals("calypso.nonprod:role.gcp.fed.power.user", a.getRole());
        assertEquals("projects/gcp-calypso-nonprod/roles/fed.power.user", a.getResource());
        assertEquals("gcp.assume_role", a.getAction());
        assertEquals("ALLOW", a.getEffect());
        assertEquals(41455088L, a.getId());
    }

    @Test
    void deserializeEmptyResourcesArray() throws Exception {
        ZmsResourceResponse root = mapper.readValue("{\"resources\":[]}", ZmsResourceResponse.class);
        assertNotNull(root.getResources());
        assertTrue(root.getResources().isEmpty());
    }

    @Test
    void deserializeMissingOptionalFields() throws Exception {
        String json = "{\"resources\":[{\"assertions\":[{\"role\":\"r:role.x\"}]}]}";
        ZmsResourceResponse root = mapper.readValue(json, ZmsResourceResponse.class);
        ZmsResourceAssertion a = root.getResources().get(0).getAssertions().get(0);
        assertEquals("r:role.x", a.getRole());
        assertNull(a.getResource());
        assertNull(a.getAction());
        assertNull(a.getEffect());
        assertNull(a.getId());
    }

    @Test
    void settersAndRoundTrip() throws Exception {
        ZmsResourceAssertion assertion = new ZmsResourceAssertion();
        assertion.setRole("dom:role.name");
        assertion.setResource("projects/p1/roles/r");
        assertion.setAction("gcp.assume_role");
        assertion.setEffect("ALLOW");
        assertion.setId(99L);

        ZmsResourcePrincipalEntry entry = new ZmsResourcePrincipalEntry();
        entry.setPrincipal("user.a");
        entry.setAssertions(List.of(assertion));

        ZmsResourceResponse response = new ZmsResourceResponse();
        response.setResources(List.of(entry));

        String out = mapper.writeValueAsString(response);
        ZmsResourceResponse back = mapper.readValue(out, ZmsResourceResponse.class);
        assertEquals("user.a", back.getResources().get(0).getPrincipal());
        assertEquals(99L, back.getResources().get(0).getAssertions().get(0).getId());
    }
}
