/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import io.athenz.mop.model.ResourceMeta;
import io.athenz.mop.service.ConfigService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class TelemetryProviderResolver {

    @Inject
    ConfigService configService;

    /**
     * Target audience / IdP label for metrics from a resource URI (RFC 8707).
     */
    public String fromResourceUri(String resourceUri) {
        if (resourceUri == null || resourceUri.isBlank()) {
            return "unknown";
        }
        ResourceMeta m = configService.getResourceMeta(resourceUri);
        if (m == null) {
            return "unknown";
        }
        if (m.audience() != null && !m.audience().isBlank()) {
            return OauthProviderLabel.normalize(m.audience());
        }
        return OauthProviderLabel.normalize(m.idpServer());
    }
}
