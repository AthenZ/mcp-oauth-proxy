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

import io.quarkus.runtime.StartupEvent;
import io.quarkus.tls.CertificateUpdatedEvent;
import io.quarkus.tls.TlsConfiguration;
import io.quarkus.tls.TlsConfigurationRegistry;
import jakarta.enterprise.event.Event;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
// This class is responsible for periodically checking and reloading TLS certificates from a secret store.
// To work with the Quarkus server update mechanism, it fires an event notifying the server when a new certificate is available.
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertificateReloader {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    TlsConfigurationRegistry tlsRegistry;

    @Inject
    Event<CertificateUpdatedEvent> event;

    @ConfigProperty(name = "server.tls.refresh.interval", defaultValue = "3600")
    int refreshIntervalSeconds;

    @Inject
    FileSystemSecretStore secretStoreService;

    private volatile String currentCertContent;
    private volatile String currentKeyContent;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    void onStart(@Observes StartupEvent event) {
        startCertificateRefresh();
    }

    private void startCertificateRefresh() {
        scheduler.scheduleAtFixedRate(() -> {
            log.info("Refreshing TLS certificates from secret store");
            try {
                String certContent = secretStoreService.getCertificate();
                String keyContent = secretStoreService.getPrivateKey();
                if (!certContent.equals(currentCertContent) || !keyContent.equals(currentKeyContent)) {
                    log.info("New TLS certificates detected, updating configuration");
                    currentCertContent = certContent;
                    currentKeyContent = keyContent;
                    reloadTlsConfiguration();
                }
            } catch (Exception e) {
                log.error("Failed to refresh certificates: {}", e.getMessage());
            }
        }, refreshIntervalSeconds, refreshIntervalSeconds, TimeUnit.SECONDS);
    }

    void reloadTlsConfiguration() {
        try {
            log.info("firing CertificateUpdatedEvent for TLS configuration refresh");
            // Update TLS configuration
            TlsConfiguration tlsConfig = tlsRegistry.get("enterprise").orElseThrow();
            if (tlsConfig.reload()) {
                event.fire(new CertificateUpdatedEvent("enterprise", tlsConfig));
            }
            log.info("server certificate is reloaded successfully.");
        } catch (Exception e) {
            log.error("Failed to send certificate update event to the server: {}", e.getMessage());
        }
    }
}
