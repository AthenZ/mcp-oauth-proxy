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
package io.athenz.mop.tls;

import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import java.lang.invoke.MethodHandles;
import javax.net.ssl.SSLContext;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class SslContextProducer {

  private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  @ConfigProperty(name = "server.athenz.cert-file")
  String certFile;

  @ConfigProperty(name = "server.athenz.key-file")
  String keyFile;

  @ConfigProperty(name = "server.athenz.truststore-file")
  String trustStoreFile;

  KeyRefresher keyRefresher;

  SSLContext sslContext;

  public static final char[] DEFAULT_JDK_TRUST_STORE_PWD = new char[] {'c', 'h', 'a', 'n', 'g', 'e', 'i', 't'};


    @PostConstruct
    void init() {
      log.info("Initializing SSL context {} {}", certFile, keyFile);
      try {
        char[] trustStorePassword = DEFAULT_JDK_TRUST_STORE_PWD.clone();
        keyRefresher = Utils.generateKeyRefresher(trustStoreFile, trustStorePassword, certFile, keyFile);
        // The Default refresh period is every hour.
        keyRefresher.startup();
        log.info("Creating SSL Context with certFile: {}, keyFile: {}, trustStoreFile: {}", certFile, keyFile, trustStoreFile);
        sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(), keyRefresher.getTrustManagerProxy());
      } catch (Exception e) {
        throw new RuntimeException("Failed to create SSL context", e);
      }
    }

    public SSLContext get() {
      return sslContext;
    }

    @PreDestroy
    public void shutdown() {
      if (keyRefresher != null) {
        keyRefresher.shutdown();
        log.info("KeyRefresher shut down successfully");
      }
    }
}