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
import static org.junit.jupiter.api.Assertions.assertThrows;
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
    void mintToken_nullBase_throws() throws Exception {
        SplunkHttpExecutor exec = mock(SplunkHttpExecutor.class);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        SplunkApiException ex = assertThrows(SplunkApiException.class,
                () -> client.mintToken("", BEARER, "u", "aud", "+1h"));
        assertEquals(0, ex.status());
        assertEquals("mintToken", ex.operation());
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
    void mintToken_badStatus_throwsWithParsedMessage() throws Exception {
        // Real Splunk 400 body shape from the schituprolu repro doc.
        String body = "{\"messages\":[{\"type\":\"ERROR\",\"text\":\"User \\\"mcp.foo\\\" does not exist.\"}]}";
        SplunkHttpExecutor exec = req -> mockResponse(400, body);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        SplunkApiException ex = assertThrows(SplunkApiException.class,
                () -> client.mintToken(BASE, BEARER, "mirror", "aud", "+1h"));
        assertEquals(400, ex.status());
        assertEquals("mintToken", ex.operation());
        assertEquals("User \"mcp.foo\" does not exist.", ex.upstreamMessage());
        assertTrue(ex.getMessage().contains("status=400"));
    }

    @Test
    void mintToken_emptyEntry_throws() throws Exception {
        SplunkHttpExecutor exec = req -> mockResponse(200, "{\"entry\":[]}");
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        SplunkApiException ex = assertThrows(SplunkApiException.class,
                () -> client.mintToken(BASE, BEARER, "mirror", "aud", "+1h"));
        assertTrue(ex.upstreamMessage().contains("no entry"));
    }

    @Test
    void mintToken_missingOrNonTextualToken_throws() throws Exception {
        ObjectMapper om = new ObjectMapper();
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(om,
                req -> mockResponse(200, "{\"entry\":[{\"content\":{}}]}"));
        SplunkApiException ex1 = assertThrows(SplunkApiException.class,
                () -> client.mintToken(BASE, BEARER, "mirror", "aud", "+1h"));
        assertTrue(ex1.upstreamMessage().contains("empty token"));

        SplunkManagementClientImpl client2 = new SplunkManagementClientImpl(om,
                req -> mockResponse(200, "{\"entry\":[{\"content\":{\"token\":{}}}]}"));
        assertThrows(SplunkApiException.class,
                () -> client2.mintToken(BASE, BEARER, "mirror", "aud", "+1h"));
    }

    @Test
    void mintToken_ioException_throws() throws Exception {
        SplunkHttpExecutor exec = req -> {
            throw new IOException("net-broken");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        SplunkApiException ex = assertThrows(SplunkApiException.class,
                () -> client.mintToken(BASE, BEARER, "mirror", "aud", "+1h"));
        assertEquals(0, ex.status());
        assertTrue(ex.upstreamMessage().startsWith("transport: "));
    }

    @Test
    void mintToken_interruptedException_restoresInterruptAndThrows() throws Exception {
        SplunkHttpExecutor exec = req -> {
            throw new InterruptedException("x");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        Thread.interrupted();
        SplunkApiException ex = assertThrows(SplunkApiException.class,
                () -> client.mintToken(BASE, BEARER, "mirror", "aud", "+1h"));
        assertTrue(ex.upstreamMessage().startsWith("interrupted: "));
        assertTrue(Thread.interrupted());
    }

    @Test
    void createUser_nullBase_throws() throws Exception {
        SplunkHttpExecutor exec = mock(SplunkHttpExecutor.class);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        SplunkApiException ex = assertThrows(SplunkApiException.class,
                () -> client.createUser("", BEARER, "u", "pw", List.of("r")));
        assertEquals("createUser", ex.operation());
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
    void createUser_403NotGrantable_throwsSplunkApiExceptionWithParsedMessage() throws Exception {
        // Real Splunk 403 body shape from the schituprolu repro doc.
        String body = "{\"messages\":[{\"type\":\"ERROR\",\"text\":\"Role=power_ads-pbp-008 is not grantable\"}]}";
        SplunkHttpExecutor exec = req -> mockResponse(403, body);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        SplunkApiException ex = assertThrows(SplunkApiException.class,
                () -> client.createUser(BASE, BEARER, "mcp.alice", "p", List.of("power_ads-pbp-008")));
        assertEquals(403, ex.status());
        assertEquals("createUser", ex.operation());
        assertEquals("Role=power_ads-pbp-008 is not grantable", ex.upstreamMessage());
    }

    @Test
    void updateUser_nullBase_throws() throws Exception {
        SplunkHttpExecutor exec = mock(SplunkHttpExecutor.class);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        SplunkApiException ex = assertThrows(SplunkApiException.class,
                () -> client.updateUserRoles("", BEARER, "u", List.of("r")));
        assertEquals("updateUserRoles", ex.operation());
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
    void postForm_non2xx_throwsWithRawBodyWhenNotJson() throws Exception {
        SplunkHttpExecutor exec = req -> mockResponse(500, "<html>bad gateway</html>");
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        SplunkApiException ex = assertThrows(SplunkApiException.class,
                () -> client.createUser(BASE, BEARER, "u", "p", List.of("r")));
        assertEquals(500, ex.status());
        // Non-JSON body forwarded verbatim — no parse, no truncation.
        assertEquals("<html>bad gateway</html>", ex.upstreamMessage());
    }

    @Test
    void postForm_non2xx_blankBody_returnsPlaceholder() throws Exception {
        SplunkHttpExecutor exec = req -> mockResponse(502, "");
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        SplunkApiException ex = assertThrows(SplunkApiException.class,
                () -> client.createUser(BASE, BEARER, "u", "p", List.of("r")));
        assertEquals(502, ex.status());
        assertEquals("<empty body>", ex.upstreamMessage());
    }

    @Test
    void postForm_interruptedException_restoresInterruptAndThrows() throws Exception {
        SplunkHttpExecutor exec = req -> {
            throw new InterruptedException("x");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        Thread.interrupted();
        SplunkApiException ex = assertThrows(SplunkApiException.class,
                () -> client.createUser(BASE, BEARER, "u", "p", List.of("r")));
        assertTrue(ex.upstreamMessage().startsWith("interrupted: "));
        assertTrue(Thread.interrupted());
    }

    @Test
    void parseSplunkMessage_blankFirstMessageText_skipsAndReturnsNextNonBlank() {
        // First entry's text is whitespace; second entry's text is the real error.
        // Asserts the helper iterates rather than indexing .get(0) blindly.
        SplunkManagementClientImpl client =
                new SplunkManagementClientImpl(new ObjectMapper(), req -> mockResponse(200, "{}"));
        String body = "{\"messages\":["
                + "{\"type\":\"INFO\",\"text\":\"   \"},"
                + "{\"type\":\"ERROR\",\"text\":\"Role=power_ads-pbp-008 is not grantable\"}"
                + "]}";
        assertEquals("Role=power_ads-pbp-008 is not grantable", client.parseSplunkMessage(body));
    }

    @Test
    void parseSplunkMessage_unparseableBody_returnsRawBodyVerbatim() {
        SplunkManagementClientImpl client =
                new SplunkManagementClientImpl(new ObjectMapper(), req -> mockResponse(200, "{}"));
        String body = "totally not json";
        // Verbatim — no truncation, no abbreviation.
        assertEquals(body, client.parseSplunkMessage(body));
    }

    @Test
    void parseSplunkMessage_blankBody_returnsPlaceholder() {
        SplunkManagementClientImpl client =
                new SplunkManagementClientImpl(new ObjectMapper(), req -> mockResponse(200, "{}"));
        assertEquals("<empty body>", client.parseSplunkMessage(""));
        assertEquals("<empty body>", client.parseSplunkMessage(null));
    }

    @Test
    void parseSplunkMessage_jsonWithNoUsableText_fallsBackToRawBody() {
        SplunkManagementClientImpl client =
                new SplunkManagementClientImpl(new ObjectMapper(), req -> mockResponse(200, "{}"));
        String body = "{\"messages\":[{\"type\":\"INFO\",\"text\":\"\"},{\"type\":\"INFO\"}]}";
        // No non-blank text -> raw body.
        assertEquals(body, client.parseSplunkMessage(body));
    }


    @Test
    void listExpiredMcpTokens_blankInputs_noHttpCall() throws Exception {
        SplunkHttpExecutor exec = mock(SplunkHttpExecutor.class);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertTrue(client.listExpiredMcpTokens("", BEARER, "mcp.", 100L).isEmpty());
        assertTrue(client.listExpiredMcpTokens(BASE, "", "mcp.", 100L).isEmpty());
        assertTrue(client.listExpiredMcpTokens(BASE, BEARER, "", 100L).isEmpty());
        verify(exec, never()).send(any());
    }

    @Test
    void listExpiredMcpTokens_hitsExpectedUrl() throws Exception {
        SplunkHttpExecutor exec = req -> {
            assertEquals("GET", req.method());
            assertTrue(req.uri().toString().endsWith(
                    "/services/authorization/tokens?output_mode=json&count=0"),
                    "actual=" + req.uri());
            return mockResponse(200, "{\"entry\":[]}");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertTrue(client.listExpiredMcpTokens(BASE, BEARER, "mcp.", 100L).isEmpty());
    }

    @Test
    void listExpiredMcpTokens_non2xx_returnsEmpty() throws Exception {
        SplunkHttpExecutor exec = req -> mockResponse(500, "");
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertTrue(client.listExpiredMcpTokens(BASE, BEARER, "mcp.", 100L).isEmpty());
    }

    @Test
    void listExpiredMcpTokens_filtersByPrefixAndExpiry() throws Exception {
        // now=1000. Want only tokens whose sub starts with "mcp." AND exp<1000.
        String json = "{\"entry\":["
                + "{\"name\":\"id-keep1\",\"content\":{\"claims\":{\"sub\":\"mcp.alice\",\"exp\":900}}},"
                + "{\"name\":\"id-livemcp\",\"content\":{\"claims\":{\"sub\":\"mcp.bob\",\"exp\":1500}}},"
                + "{\"name\":\"id-otheruser\",\"content\":{\"claims\":{\"sub\":\"admin\",\"exp\":1}}},"
                + "{\"name\":\"id-keep2\",\"content\":{\"claims\":{\"sub\":\"mcp.carol\",\"exp\":999}}},"
                + "{\"name\":\"id-equalsexp\",\"content\":{\"claims\":{\"sub\":\"mcp.dan\",\"exp\":1000}}},"
                + "{\"name\":\"id-noclaims\",\"content\":{}},"
                + "{\"name\":\"id-blanksub\",\"content\":{\"claims\":{\"exp\":1}}},"
                + "{\"name\":\"\",\"content\":{\"claims\":{\"sub\":\"mcp.x\",\"exp\":1}}}"
                + "]}";
        SplunkHttpExecutor exec = req -> mockResponse(200, json);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);

        List<SplunkManagementClient.SplunkExpiredToken> out =
                client.listExpiredMcpTokens(BASE, BEARER, "mcp.", 1000L);

        assertEquals(2, out.size());
        assertEquals("id-keep1", out.get(0).id());
        assertEquals("mcp.alice", out.get(0).sub());
        assertEquals(900L, out.get(0).exp());
        assertEquals("id-keep2", out.get(1).id());
        assertEquals("mcp.carol", out.get(1).sub());
    }

    @Test
    void listExpiredMcpTokens_invalidJson_returnsEmpty() throws Exception {
        SplunkHttpExecutor exec = req -> mockResponse(200, "not-json");
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertTrue(client.listExpiredMcpTokens(BASE, BEARER, "mcp.", 1000L).isEmpty());
    }

    @Test
    void listExpiredMcpTokens_ioException() throws Exception {
        SplunkHttpExecutor exec = req -> {
            throw new IOException("net");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertTrue(client.listExpiredMcpTokens(BASE, BEARER, "mcp.", 1000L).isEmpty());
    }

    @Test
    void listExpiredMcpTokens_interruptedException_restoresInterrupt() throws Exception {
        SplunkHttpExecutor exec = req -> {
            throw new InterruptedException("x");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        Thread.interrupted();
        assertTrue(client.listExpiredMcpTokens(BASE, BEARER, "mcp.", 1000L).isEmpty());
        assertTrue(Thread.interrupted());
    }

    // ---------- deleteToken ----------

    @Test
    void deleteToken_blankInputs_noHttpCall() throws Exception {
        SplunkHttpExecutor exec = mock(SplunkHttpExecutor.class);
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertFalse(client.deleteToken("", BEARER, "id"));
        assertFalse(client.deleteToken(BASE, "", "id"));
        assertFalse(client.deleteToken(BASE, BEARER, ""));
        verify(exec, never()).send(any());
    }

    @Test
    void deleteToken_2xx_success() throws Exception {
        SplunkHttpExecutor exec = req -> {
            assertEquals("DELETE", req.method());
            assertTrue(req.uri().toString().startsWith(
                    BASE + "/services/authorization/tokens/abc-123"),
                    "actual=" + req.uri());
            assertTrue(req.uri().toString().contains("output_mode=json"));
            return mockResponse(200, "");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertTrue(client.deleteToken(BASE, BEARER, "abc-123"));
    }

    @Test
    void deleteToken_404_returnsFalse() throws Exception {
        SplunkHttpExecutor exec = req -> mockResponse(404, "");
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertFalse(client.deleteToken(BASE, BEARER, "id"));
    }

    @Test
    void deleteToken_500_returnsFalse() throws Exception {
        SplunkHttpExecutor exec = req -> mockResponse(500, "");
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertFalse(client.deleteToken(BASE, BEARER, "id"));
    }

    @Test
    void deleteToken_ioException_returnsFalse() throws Exception {
        SplunkHttpExecutor exec = req -> {
            throw new IOException("net");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertFalse(client.deleteToken(BASE, BEARER, "id"));
    }

    @Test
    void deleteToken_interruptedException_restoresInterrupt() throws Exception {
        SplunkHttpExecutor exec = req -> {
            throw new InterruptedException("x");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        Thread.interrupted();
        assertFalse(client.deleteToken(BASE, BEARER, "id"));
        assertTrue(Thread.interrupted());
    }

    @Test
    void deleteToken_urlEncodesSpecialChars() throws Exception {
        SplunkHttpExecutor exec = req -> {
            // space + slash should be percent-encoded in the path segment
            String uri = req.uri().toString();
            assertTrue(uri.contains("/services/authorization/tokens/a%20b%2Fc?"), "actual=" + uri);
            return mockResponse(200, "");
        };
        SplunkManagementClientImpl client = new SplunkManagementClientImpl(new ObjectMapper(), exec);
        assertTrue(client.deleteToken(BASE, BEARER, "a b/c"));
    }

    @SuppressWarnings("unchecked")
    private static HttpResponse<String> mockResponse(int status, String body) {
        HttpResponse<String> r = mock(HttpResponse.class);
        when(r.statusCode()).thenReturn(status);
        lenient().when(r.body()).thenReturn(body);
        return r;
    }
}
