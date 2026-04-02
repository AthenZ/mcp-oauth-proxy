/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import jakarta.enterprise.context.RequestScoped;

@RequestScoped
public class TelemetryRequestContext {

    private String oauthProvider = "unknown";
    private String oauthClient = "unknown";
    private String normalizedRoute = "/";

    public String oauthProvider() {
        return oauthProvider;
    }

    public void setOauthProvider(String oauthProvider) {
        this.oauthProvider = oauthProvider != null && !oauthProvider.isEmpty() ? oauthProvider : "unknown";
    }

    public String oauthClient() {
        return oauthClient;
    }

    public void setOauthClient(String oauthClient) {
        this.oauthClient = oauthClient != null && !oauthClient.isEmpty() ? oauthClient : "unknown";
    }

    public String normalizedRoute() {
        return normalizedRoute;
    }

    public void setNormalizedRoute(String normalizedRoute) {
        this.normalizedRoute = normalizedRoute != null && !normalizedRoute.isEmpty() ? normalizedRoute : "/";
    }
}
