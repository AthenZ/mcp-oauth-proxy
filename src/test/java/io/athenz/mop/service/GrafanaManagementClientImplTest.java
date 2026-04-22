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
import io.athenz.mop.model.grafana.GrafanaTokenInfo;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class GrafanaManagementClientImplTest {

    private static final String BASE = "https://yahooinc.grafana.net";
    private static final String SA = "cfja56rp4ix34e";
    private static final String BEARER = "admin-token";

    @Test
    void normalizeBase_trimsTrailingSlashes() {
        assertEquals("https://h", GrafanaManagementClientImpl.normalizeBase("https://h///"));
    }

    @Test
    void normalizeBase_blank_returnsNull() {
        assertNull(GrafanaManagementClientImpl.normalizeBase("  "));
    }

    @Test
    void tokensUrl_composesExpectedPath() {
        assertEquals(
                "https://yahooinc.grafana.net/api/serviceaccounts/sa-id/tokens",
                GrafanaManagementClientImpl.tokensUrl("https://yahooinc.grafana.net", "sa-id"));
    }

    @Test
    void tokensUrl_blankSa_returnsNull() {
        assertNull(GrafanaManagementClientImpl.tokensUrl(BASE, ""));
    }

    @Test
    void mintToken_blankInputs_noHttpCall() throws Exception {
        GrafanaHttpExecutor exec = mock(GrafanaHttpExecutor.class);
        GrafanaManagementClientImpl client = new GrafanaManagementClientImpl(new ObjectMapper(), exec);

        assertNull(client.mintToken("", SA, BEARER, "mcp.x.1", 3600));
        assertNull(client.mintToken(BASE, "", BEARER, "mcp.x.1", 3600));
        assertNull(client.mintToken(BASE, SA, "", "mcp.x.1", 3600));
        assertNull(client.mintToken(BASE, SA, BEARER, "", 3600));
        verify(exec, never()).send(any());
    }

    @Test
    void mintToken_200_returnsKey() throws Exception {
        GrafanaHttpExecutor exec = req -> {
            assertEquals("POST", req.method());
            assertTrue(req.uri().toString().endsWith("/api/serviceaccounts/" + SA + "/tokens"));
            return mockResponse(200, "{\"id\":284,\"name\":\"mcp.yosrixp.1\",\"key\":\"glsa_abc\"}");
        };
        GrafanaManagementClientImpl client = new GrafanaManagementClientImpl(new ObjectMapper(), exec);
        assertEquals("glsa_abc", client.mintToken(BASE, SA, BEARER, "mcp.yosrixp.1", 3600));
    }

    @Test
    void mintToken_nonSuccessStatus_returnsNull() throws Exception {
        GrafanaHttpExecutor exec = req -> mockResponse(400,
                "{\"statusCode\":400,\"messageId\":\"serviceaccounts.ErrTokenAlreadyExists\"}");
        GrafanaManagementClientImpl client = new GrafanaManagementClientImpl(new ObjectMapper(), exec);
        assertNull(client.mintToken(BASE, SA, BEARER, "mcp.x.1", 3600));
    }

    @Test
    void mintToken_blankKeyInResponse_returnsNull() throws Exception {
        GrafanaHttpExecutor exec = req -> mockResponse(200, "{\"id\":1,\"name\":\"n\",\"key\":\"\"}");
        GrafanaManagementClientImpl client = new GrafanaManagementClientImpl(new ObjectMapper(), exec);
        assertNull(client.mintToken(BASE, SA, BEARER, "mcp.x.1", 3600));
    }

    @Test
    void mintToken_ioException_returnsNull() throws Exception {
        GrafanaHttpExecutor exec = req -> {
            throw new IOException("boom");
        };
        GrafanaManagementClientImpl client = new GrafanaManagementClientImpl(new ObjectMapper(), exec);
        assertNull(client.mintToken(BASE, SA, BEARER, "mcp.x.1", 3600));
    }

    @Test
    void mintToken_interrupted_restoresInterrupt() throws Exception {
        GrafanaHttpExecutor exec = req -> {
            throw new InterruptedException("x");
        };
        GrafanaManagementClientImpl client = new GrafanaManagementClientImpl(new ObjectMapper(), exec);
        Thread.interrupted();
        assertNull(client.mintToken(BASE, SA, BEARER, "mcp.x.1", 3600));
        assertTrue(Thread.interrupted());
    }

    @Test
    void listTokens_200_parsesHasExpiredAndIsRevoked() throws Exception {
        String body = "["
                + "{\"id\":1,\"name\":\"a\",\"expiration\":\"2026-01-01T00:00:00Z\",\"hasExpired\":true,\"isRevoked\":false},"
                + "{\"id\":2,\"name\":\"b\",\"expiration\":\"2027-01-01T00:00:00Z\",\"hasExpired\":false,\"isRevoked\":true},"
                + "{\"id\":3,\"name\":\"c\",\"expiration\":\"2027-01-01T00:00:00Z\",\"hasExpired\":false,\"isRevoked\":false}"
                + "]";
        GrafanaHttpExecutor exec = req -> {
            assertEquals("GET", req.method());
            return mockResponse(200, body);
        };
        GrafanaManagementClientImpl client = new GrafanaManagementClientImpl(new ObjectMapper(), exec);
        List<GrafanaTokenInfo> out = client.listTokens(BASE, SA, BEARER);
        assertEquals(3, out.size());
        assertTrue(out.get(0).hasExpired());
        assertTrue(out.get(1).isRevoked());
        assertFalse(out.get(2).hasExpired() || out.get(2).isRevoked());
    }

    @Test
    void listTokens_nonSuccess_returnsEmpty() throws Exception {
        GrafanaHttpExecutor exec = req -> mockResponse(500, "");
        GrafanaManagementClientImpl client = new GrafanaManagementClientImpl(new ObjectMapper(), exec);
        assertTrue(client.listTokens(BASE, SA, BEARER).isEmpty());
    }

    @Test
    void listTokens_blankInputs_returnsEmpty() throws Exception {
        GrafanaHttpExecutor exec = mock(GrafanaHttpExecutor.class);
        GrafanaManagementClientImpl client = new GrafanaManagementClientImpl(new ObjectMapper(), exec);
        assertTrue(client.listTokens("", SA, BEARER).isEmpty());
        assertTrue(client.listTokens(BASE, "", BEARER).isEmpty());
        assertTrue(client.listTokens(BASE, SA, "").isEmpty());
        verify(exec, never()).send(any());
    }

    @Test
    void listTokens_invalidJson_returnsEmpty() throws Exception {
        GrafanaHttpExecutor exec = req -> mockResponse(200, "not-json");
        GrafanaManagementClientImpl client = new GrafanaManagementClientImpl(new ObjectMapper(), exec);
        assertTrue(client.listTokens(BASE, SA, BEARER).isEmpty());
    }

    @Test
    void deleteToken_2xx_returnsTrue() throws Exception {
        GrafanaHttpExecutor exec = req -> {
            assertEquals("DELETE", req.method());
            assertTrue(req.uri().toString().endsWith("/tokens/284"));
            return mockResponse(200, "{}");
        };
        GrafanaManagementClientImpl client = new GrafanaManagementClientImpl(new ObjectMapper(), exec);
        assertTrue(client.deleteToken(BASE, SA, BEARER, 284L));
    }

    @Test
    void deleteToken_non2xx_returnsFalse() throws Exception {
        GrafanaHttpExecutor exec = req -> mockResponse(404, "");
        GrafanaManagementClientImpl client = new GrafanaManagementClientImpl(new ObjectMapper(), exec);
        assertFalse(client.deleteToken(BASE, SA, BEARER, 284L));
    }

    @Test
    void deleteToken_blankInputs_returnsFalseNoCall() throws Exception {
        GrafanaHttpExecutor exec = mock(GrafanaHttpExecutor.class);
        GrafanaManagementClientImpl client = new GrafanaManagementClientImpl(new ObjectMapper(), exec);
        assertFalse(client.deleteToken("", SA, BEARER, 1L));
        assertFalse(client.deleteToken(BASE, "", BEARER, 1L));
        assertFalse(client.deleteToken(BASE, SA, "", 1L));
        verify(exec, never()).send(any());
    }

    @Test
    void deleteToken_interrupted_restoresInterrupt() throws Exception {
        GrafanaHttpExecutor exec = req -> {
            throw new InterruptedException("x");
        };
        GrafanaManagementClientImpl client = new GrafanaManagementClientImpl(new ObjectMapper(), exec);
        Thread.interrupted();
        assertFalse(client.deleteToken(BASE, SA, BEARER, 1L));
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
