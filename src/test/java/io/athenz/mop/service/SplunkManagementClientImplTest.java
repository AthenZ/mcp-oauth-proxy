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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.athenz.mop.model.splunk.SplunkUsersFeedResponse;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SplunkManagementClientImplTest {

    private static final String BASE = "https://splunk-mgmt.test:8089";
    private static final String BEARER = "admin-token";

    @Test
    void splunkUsersFeedResponse_deserializesRolesArray() throws Exception {
        String json = "{\"entry\":[{\"content\":{\"roles\":[\"a\",\"b\"]}}]}";
        SplunkUsersFeedResponse f = new ObjectMapper().readValue(json, SplunkUsersFeedResponse.class);
        assertEquals(List.of("a", "b"), f.entry().get(0).content().roles());
    }

    @Test
    void normalizeBase_trimsTrailingSlashes() {
        assertEquals("https://h:8089", SplunkManagementClientImpl.normalizeBase("https://h:8089///"));
    }

    @Test
    void normalizeBase_blank_returnsNull() {
        assertNull(SplunkManagementClientImpl.normalizeBase("  "));
    }

    @Test
    void urlForm_null_encodesAsEmpty() {
        assertEquals("", SplunkManagementClientImpl.urlForm(null));
    }

    @Test
    void formEncodeRolesOnly_emptyRoles() {
        assertEquals("", SplunkManagementClientImpl.formEncodeRolesOnly(List.of()));
    }

    @Test
    void getUser_blankInputs_noHttpCall() throws Exception {
        SplunkHttpExecutor exec = mock(SplunkHttpExecutor.class);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertFalse(client.getUser(BASE, "", "alice").found());
        assertFalse(client.getUser(BASE, BEARER, "").found());
        assertFalse(client.getUser(null, BEARER, "alice").found());
        verify(exec, never()).send(any());
    }

    @Test
    void getUser_404() throws Exception {
        SplunkHttpExecutor exec = req -> mockResponse(404, "");
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        SplunkManagementClient.SplunkUserLookup u = client.getUser(BASE, BEARER, "alice");
        assertFalse(u.found());
        assertTrue(u.roles().isEmpty());
    }

    @Test
    void getUser_non200() throws Exception {
        SplunkHttpExecutor exec = req -> mockResponse(403, "");
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertFalse(client.getUser(BASE, BEARER, "alice").found());
    }

    @Test
    void getUser_200_emptyEntry() throws Exception {
        SplunkHttpExecutor exec = req -> mockResponse(200, "{\"entry\":[]}");
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertFalse(client.getUser(BASE, BEARER, "alice").found());
    }

    @Test
    void getUser_200_withRoles() throws Exception {
        String json =
                "{\"entry\":[{\"content\":{\"roles\":[\"yahoo_user\",\"user_yamas-026\"]}}]}";
        SplunkHttpExecutor exec = req -> mockResponse(200, json);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        SplunkManagementClient.SplunkUserLookup u = client.getUser(BASE, BEARER, "alice");
        assertTrue(u.found());
        assertEquals(List.of("yahoo_user", "user_yamas-026"), u.roles());
    }

    @Test
    void getUser_ioExceptionFromSend() throws Exception {
        SplunkHttpExecutor exec = req -> {
            throw new IOException("boom");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertFalse(client.getUser(BASE, BEARER, "alice").found());
    }

    @Test
    void getUser_interruptedException_restoresInterrupt() throws Exception {
        SplunkHttpExecutor exec = req -> {
            throw new InterruptedException("stop");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        Thread.interrupted(); // clear
        assertFalse(client.getUser(BASE, BEARER, "alice").found());
        assertTrue(Thread.interrupted());
    }

    @Test
    void getUser_invalidJsonBody() throws Exception {
        SplunkHttpExecutor exec = req -> mockResponse(200, "not-json");
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertFalse(client.getUser(BASE, BEARER, "alice").found());
    }

    @Test
    void mintToken_nullBase() throws Exception {
        SplunkHttpExecutor exec = mock(SplunkHttpExecutor.class);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertNull(client.mintToken("", BEARER, "u", "aud", "+1h"));
        verify(exec, never()).send(any());
    }

    @Test
    void mintToken_200_returnsToken() throws Exception {
        String json = "{\"entry\":[{\"content\":{\"token\":\"tok-abc\"}}]}";
        SplunkHttpExecutor exec = req -> mockResponse(200, json);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertEquals("tok-abc", client.mintToken(BASE, BEARER, "mirror", "aud", "+1h"));
    }

    @Test
    void mintToken_201_returnsToken() throws Exception {
        String json = "{\"entry\":[{\"content\":{\"token\":\"tok-201\"}}]}";
        SplunkHttpExecutor exec = req -> mockResponse(201, json);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertEquals("tok-201", client.mintToken(BASE, BEARER, "mirror", "aud", "+1h"));
    }

    @Test
    void mintToken_badStatus() throws Exception {
        SplunkHttpExecutor exec = req -> mockResponse(400, "{}");
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertNull(client.mintToken(BASE, BEARER, "mirror", "aud", "+1h"));
    }

    @Test
    void mintToken_emptyEntry() throws Exception {
        SplunkHttpExecutor exec = req -> mockResponse(200, "{\"entry\":[]}");
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertNull(client.mintToken(BASE, BEARER, "mirror", "aud", "+1h"));
    }

    @Test
    void mintToken_missingOrNonTextualToken() throws Exception {
        ObjectMapper om = new ObjectMapper();
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(om, req -> mockResponse(200, "{\"entry\":[{\"content\":{}}]}"));
        assertNull(client.mintToken(BASE, BEARER, "mirror", "aud", "+1h"));

        SplunkManagementClientImpl client2 = new SplunkManagementClientImpl(om, req -> mockResponse(200,
                "{\"entry\":[{\"content\":{\"token\":{}}}]}"));
        assertNull(client2.mintToken(BASE, BEARER, "mirror", "aud", "+1h"));
    }

    @Test
    void mintToken_ioException() throws Exception {
        SplunkHttpExecutor exec = req -> {
            throw new IOException("x");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertNull(client.mintToken(BASE, BEARER, "mirror", "aud", "+1h"));
    }

    @Test
    void mintToken_interruptedException_restoresInterrupt() throws Exception {
        SplunkHttpExecutor exec = req -> {
            throw new InterruptedException("x");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        Thread.interrupted();
        assertNull(client.mintToken(BASE, BEARER, "mirror", "aud", "+1h"));
        assertTrue(Thread.interrupted());
    }

    @Test
    void createUser_nullBase_doesNotSend() throws Exception {
        SplunkHttpExecutor exec = mock(SplunkHttpExecutor.class);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        client.createUser("", BEARER, "u", "pw", List.of("r"));
        verify(exec, never()).send(any());
    }

    @Test
    void createUser_postsForm() throws Exception {
        SplunkHttpExecutor exec = req -> {
            assertEquals("POST", req.method());
            assertTrue(req.uri().toString().contains("/services/authentication/users"));
            return mockResponse(201, "{}");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        client.createUser(BASE, BEARER, "mcp.alice", "secret", List.of("yahoo_user"));
    }

    @Test
    void updateUser_nullBase_doesNotSend() throws Exception {
        SplunkHttpExecutor exec = mock(SplunkHttpExecutor.class);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        client.updateUserRoles("", BEARER, "u", List.of("r"));
        verify(exec, never()).send(any());
    }

    @Test
    void updateUser_postsForm() throws Exception {
        SplunkHttpExecutor exec = req -> {
            assertEquals("POST", req.method());
            assertTrue(req.uri().toString().contains("/services/authentication/users/mcp.alice"));
            return mockResponse(200, "{}");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        client.updateUserRoles(BASE, BEARER, "mcp.alice", List.of("yahoo_user"));
    }

    @Test
    void postForm_non2xx_doesNotThrow() throws Exception {
        SplunkHttpExecutor exec = req -> mockResponse(500, "");
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        client.createUser(BASE, BEARER, "u", "p", List.of("r"));
    }

    @Test
    void postForm_interruptedException_restoresInterrupt() throws Exception {
        SplunkHttpExecutor exec = req -> {
            throw new InterruptedException("x");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        Thread.interrupted();
        client.createUser(BASE, BEARER, "u", "p", List.of("r"));
        assertTrue(Thread.interrupted());
    }

    @SuppressWarnings("unchecked")
    private static HttpResponse<String> mockResponse(int status, String body) {
        HttpResponse<String> r = mock(HttpResponse.class);
        when(r.statusCode()).thenReturn(status);
        lenient().when(r.body()).thenReturn(body);
        return r;
    }
}
