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

import com.yahoo.athenz.zts.ZTSClient;
import io.athenz.mop.tls.SslContextProducer;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped  
public class ZTSClientProducer {

  @Inject
  SslContextProducer sslContextHolder;

  @ConfigProperty(name = "server.athenz.zts.endpoint")
  String ztsEndpoint;

  @Produces
  public ZTSClient getZTSClient() {
    return new ZTSClient(ztsEndpoint, sslContextHolder.get());
  }
  
}
