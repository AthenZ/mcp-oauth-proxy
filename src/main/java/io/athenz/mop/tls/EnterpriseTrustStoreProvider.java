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

import io.quarkus.tls.runtime.TrustStoreAndTrustOptions;
import io.quarkus.tls.runtime.TrustStoreProvider;
import io.smallrye.common.annotation.Identifier;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.net.PemTrustOptions;
import jakarta.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
@Identifier("enterprise")
public class EnterpriseTrustStoreProvider implements TrustStoreProvider {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @ConfigProperty(name = "server.tls.truststore.path")
    String trustStorePath;

    @Override
    public TrustStoreAndTrustOptions getTrustStore(Vertx vertx) {
        try {

            Path trustStoreFilePath = Paths.get(trustStorePath);
            if (!Files.exists(trustStoreFilePath)) {
                throw new IOException("trust store file not found: " + trustStoreFilePath);
            }

            var options = new PemTrustOptions()
                    .addCertValue(Buffer.buffer(Files.readString(trustStoreFilePath)));
            var trustStore = options.loadKeyStore(vertx);
            return new TrustStoreAndTrustOptions(trustStore, options);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
