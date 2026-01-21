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

import io.quarkus.tls.runtime.KeyStoreAndKeyCertOptions;
import io.quarkus.tls.runtime.KeyStoreProvider;
import io.smallrye.common.annotation.Identifier;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.net.PemKeyCertOptions;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// This class provides a custom Keystores provider so that server can use the keystore from a secret store programmatically.
@ApplicationScoped
@Identifier("enterprise")
public class EnterpriseKeyStoreProvider implements KeyStoreProvider {

  private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  @Inject
  FileSystemSecretStore secretStore;

  @Override
  public KeyStoreAndKeyCertOptions getKeyStore(Vertx vertx) {
    try {
      log.info("Enterprise key store provider is being used");
      KeyStoreAndKeyCertOptions keyStoreAndKeyCertOptions;
      String certContent = secretStore.getCertificate();
      String keyContent = secretStore.getPrivateKey();
      var options = new PemKeyCertOptions()
              .addCertValue(Buffer.buffer(certContent))
              .addKeyValue(Buffer.buffer(keyContent));
      var keyStore = options.loadKeyStore(vertx);
      keyStoreAndKeyCertOptions = new KeyStoreAndKeyCertOptions(keyStore, options);

      return keyStoreAndKeyCertOptions;
    } catch (Exception e) {
      throw new RuntimeException("Failed to load key store from secret store", e);
    }
  }
}
