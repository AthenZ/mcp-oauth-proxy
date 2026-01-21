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

import jakarta.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class FileSystemSecretStore {

    private static final Logger log = LoggerFactory.getLogger(FileSystemSecretStore.class);

    @ConfigProperty(name = "server.tls.certificate.path")
    String certificatePath;

    @ConfigProperty(name = "server.tls.private-key.path")
    String privateKeyPath;

    public String getCertificate() throws Exception {
        try {
            Path certPath = Paths.get(certificatePath);
            if (!Files.exists(certPath)) {
                throw new IOException("Certificate file not found: " + certificatePath);
            }

            String content = Files.readString(certPath);
            log.info("Successfully read certificate from: {}", certificatePath);
            return content;
        } catch (IOException e) {
            log.error("Failed to read certificate from: {}", certificatePath, e);
            throw new Exception("Failed to read certificate", e);
        }
    }

    public String getPrivateKey() throws Exception {
        try {
            Path keyPath = Paths.get(privateKeyPath);
            if (!Files.exists(keyPath)) {
                throw new IOException("Private key file not found: " + privateKeyPath);
            }

            String content = Files.readString(keyPath);
            log.info("Successfully read private key from: {}", privateKeyPath);
            return content;
        } catch (IOException e) {
            log.error("Failed to read private key from: {}", privateKeyPath, e);
            throw new Exception("Failed to read private key", e);
        }
    }

}
