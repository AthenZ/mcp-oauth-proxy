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

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DatabricksSqlTokenClientTest {

    @Test
    void postForm_returnsStatusBodyAndRequestIdHeader() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        try {
            server.createContext("/oidc/v1/token", exchange -> {
                try {
                    assertEquals("POST", exchange.getRequestMethod());
                    assertEquals("application/x-www-form-urlencoded",
                            exchange.getRequestHeaders().getFirst("Content-Type"));
                    assertEquals("application/json", exchange.getRequestHeaders().getFirst("Accept"));
                    byte[] in = exchange.getRequestBody().readAllBytes();
                    assertTrue(new String(in, StandardCharsets.UTF_8).contains("grant_type="));

                    exchange.getResponseHeaders().set("x-request-id", "rid-42");
                    byte[] resp = "{\"access_token\":\"t\"}".getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(200, resp.length);
                    exchange.getResponseBody().write(resp);
                } finally {
                    exchange.close();
                }
            });
            server.start();
            int port = server.getAddress().getPort();

            DatabricksSqlTokenClient client = new DatabricksSqlTokenClient();
            DatabricksSqlTokenClient.DatabricksTokenHttpResponse r = client.postForm(
                    URI.create("http://127.0.0.1:" + port + "/oidc/v1/token"),
                    "grant_type=x&a=b");

            assertEquals(200, r.statusCode());
            assertEquals("{\"access_token\":\"t\"}", r.body());
            assertEquals(Optional.of("rid-42"), r.requestId());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void postForm_missingRequestIdHeader_returnsEmptyOptional() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        try {
            server.createContext("/t", exchange -> {
                try {
                    byte[] resp = "ok".getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(201, resp.length);
                    exchange.getResponseBody().write(resp);
                } finally {
                    exchange.close();
                }
            });
            server.start();
            int port = server.getAddress().getPort();

            DatabricksSqlTokenClient client = new DatabricksSqlTokenClient();
            DatabricksSqlTokenClient.DatabricksTokenHttpResponse r =
                    client.postForm(URI.create("http://127.0.0.1:" + port + "/t"), "x=1");

            assertEquals(201, r.statusCode());
            assertEquals("ok", r.body());
            assertTrue(r.requestId().isEmpty());
        } finally {
            server.stop(0);
        }
    }
}
