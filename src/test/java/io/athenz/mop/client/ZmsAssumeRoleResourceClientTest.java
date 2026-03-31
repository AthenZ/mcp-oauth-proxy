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
package io.athenz.mop.client;

import com.sun.net.httpserver.HttpServer;
import io.athenz.mop.tls.SslContextProducer;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ZmsAssumeRoleResourceClientTest {

    @Mock
    private SslContextProducer sslContextProducer;

    @Test
    void assumeRoleActionConstant() {
        assertEquals("gcp.assume_role", ZmsAssumeRoleResourceClient.ASSUME_ROLE_ACTION);
    }

    @Test
    void buildAssumeRoleResourceUrl_whenEndpointEndsWithZmsV1() {
        String url = ZmsAssumeRoleResourceClient.buildAssumeRoleResourceUrl(
                "https://zms.athenz.io:4443/zms/v1", "user.yosrixp");
        assertEquals(
                "https://zms.athenz.io:4443/zms/v1/resource?principal=user.yosrixp&action=gcp.assume_role", url);
    }

    @Test
    void buildAssumeRoleResourceUrl_whenEndpointEndsWithZmsV1TrailingSlash() {
        String url = ZmsAssumeRoleResourceClient.buildAssumeRoleResourceUrl(
                "https://zms.athenz.io:4443/zms/v1/", "user.yosrixp");
        assertEquals(
                "https://zms.athenz.io:4443/zms/v1/resource?principal=user.yosrixp&action=gcp.assume_role", url);
    }

    @Test
    void buildAssumeRoleResourceUrl_whenEndpointIsHostOnly() {
        String url = ZmsAssumeRoleResourceClient.buildAssumeRoleResourceUrl("https://zms.example.com:4443", "user.a");
        assertEquals(
                "https://zms.example.com:4443/zms/v1/resource?principal=user.a&action=gcp.assume_role", url);
    }

    @Test
    void buildAssumeRoleResourceUrl_encodesPrincipalQueryParameter() {
        String url = ZmsAssumeRoleResourceClient.buildAssumeRoleResourceUrl(
                "https://zms.example.com/zms/v1", "user name&x");
        assertTrue(url.contains("principal=user+name%26x"), url);
        assertTrue(url.endsWith("&action=gcp.assume_role"));
    }

    @Test
    void buildAssumeRoleResourceUrl_trimsMultipleTrailingSlashesBeforeZmsV1() {
        String url = ZmsAssumeRoleResourceClient.buildAssumeRoleResourceUrl(
                "https://zms.example.com/zms/v1///", "p");
        assertEquals("https://zms.example.com/zms/v1/resource?principal=p&action=gcp.assume_role", url);
    }

    @Test
    void getAssumeRoleResourceJson_nullPrincipal_returnsNull() {
        ZmsAssumeRoleResourceClient client = new ZmsAssumeRoleResourceClient();
        assertNull(client.getAssumeRoleResourceJson(null));
    }

    @Test
    void getAssumeRoleResourceJson_blankPrincipal_returnsNull() {
        ZmsAssumeRoleResourceClient client = new ZmsAssumeRoleResourceClient();
        assertNull(client.getAssumeRoleResourceJson("   "));
        assertNull(client.getAssumeRoleResourceJson("\t"));
    }

    @Test
    void getAssumeRoleResourceJson_sslContextThrows_returnsNull() throws Exception {
        when(sslContextProducer.get()).thenThrow(new RuntimeException("no keystore"));
        ZmsAssumeRoleResourceClient client = new ZmsAssumeRoleResourceClient();
        client.sslContextProducer = sslContextProducer;
        client.zmsEndpoint = "https://unreachable.example.test:4443/zms/v1";
        assertNull(client.getAssumeRoleResourceJson("user.x"));
    }

    @Test
    void getAssumeRoleResourceJson_returnsBodyOn200() throws Exception {
        when(sslContextProducer.get()).thenReturn(SSLContext.getDefault());
        byte[] body = "{\"resources\":[]}".getBytes(StandardCharsets.UTF_8);
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/zms/v1/resource", exchange -> {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();
        try {
            ZmsAssumeRoleResourceClient client = new ZmsAssumeRoleResourceClient();
            client.sslContextProducer = sslContextProducer;
            client.zmsEndpoint = "http://127.0.0.1:" + server.getAddress().getPort();
            assertEquals("{\"resources\":[]}", client.getAssumeRoleResourceJson("user.test"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void getAssumeRoleResourceJson_non200_returnsNull() throws Exception {
        when(sslContextProducer.get()).thenReturn(SSLContext.getDefault());
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/zms/v1/resource", exchange -> {
            exchange.sendResponseHeaders(503, 0);
            exchange.getResponseBody().close();
        });
        server.start();
        try {
            ZmsAssumeRoleResourceClient client = new ZmsAssumeRoleResourceClient();
            client.sslContextProducer = sslContextProducer;
            client.zmsEndpoint = "http://127.0.0.1:" + server.getAddress().getPort();
            assertNull(client.getAssumeRoleResourceJson("user.test"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void getAssumeRoleResourceJson_connectionFailure_returnsNull() throws Exception {
        when(sslContextProducer.get()).thenReturn(SSLContext.getDefault());
        ZmsAssumeRoleResourceClient client = new ZmsAssumeRoleResourceClient();
        client.sslContextProducer = sslContextProducer;
        client.zmsEndpoint = "http://127.0.0.1:65431/zms/v1";
        assertNull(client.getAssumeRoleResourceJson("user.x"));
    }
}
