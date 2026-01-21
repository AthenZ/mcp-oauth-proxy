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

import com.yahoo.athenz.zms.ZMSClient;
import io.athenz.mop.tls.SslContextProducer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.net.ssl.SSLContext;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ZMSClientProducerTest {

    @Mock
    private SslContextProducer sslContextProducer;

    @Mock
    private SSLContext sslContext;

    @InjectMocks
    private ZMSClientProducer zmsClientProducer;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        zmsClientProducer.zmsEndpoint = "https://zms.athenz.io:4443/zms/v1";
    }

    @Test
    void testGetZMSClient() {
        when(sslContextProducer.get()).thenReturn(sslContext);

        ZMSClient client = zmsClientProducer.getZMSClient();

        assertNotNull(client);
        verify(sslContextProducer, times(1)).get();
    }

    @Test
    void testGetZMSClient_WithDifferentEndpoint() {
        zmsClientProducer.zmsEndpoint = "https://different-zms.example.com/zms/v1";
        when(sslContextProducer.get()).thenReturn(sslContext);

        ZMSClient client = zmsClientProducer.getZMSClient();

        assertNotNull(client);
        verify(sslContextProducer, times(1)).get();
    }

    @Test
    void testGetZMSClient_MultipleCalls() {
        when(sslContextProducer.get()).thenReturn(sslContext);

        ZMSClient client1 = zmsClientProducer.getZMSClient();
        ZMSClient client2 = zmsClientProducer.getZMSClient();

        assertNotNull(client1);
        assertNotNull(client2);
        assertNotSame(client1, client2); // Each call creates a new instance
        verify(sslContextProducer, times(2)).get();
    }
}
