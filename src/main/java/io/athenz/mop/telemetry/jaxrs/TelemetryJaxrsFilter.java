/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry.jaxrs;

import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;

@Provider
@Priority(Priorities.USER)
public class TelemetryJaxrsFilter implements ContainerRequestFilter, ContainerResponseFilter {

    @Inject
    OauthProxyMetrics metrics;

    @Inject
    TelemetryRequestContext telemetryContext;

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String route = normalizeRoute(requestContext.getUriInfo().getPath());
        telemetryContext.setNormalizedRoute(route);
        metrics.incHttpInflight(route);
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        // Decrement using the same route as the request filter (request-scoped), not a second getPath()
        // normalization, which can differ across phases and skew the up/down counter negative.
        String route = telemetryContext.normalizedRoute();
        metrics.decHttpInflight(route);

        int status = responseContext.getStatus();
        if (status < 400) {
            return;
        }
        String method = requestContext.getMethod() != null ? requestContext.getMethod() : "UNKNOWN";
        String oauthProvider = telemetryContext.oauthProvider();
        String oauthClient = telemetryContext.oauthClient();
        String errorType = errorTypeForRouteAndStatus(route, status);
        if (status >= 400 && status < 500) {
            metrics.recordHttp4xx(method, route, status, errorType, oauthProvider, oauthClient);
        } else if (status >= 500) {
            metrics.recordHttp5xx(method, route, status, errorType, oauthProvider, oauthClient);
        }
        metrics.recordErrorsTotal(route, errorType, status, oauthProvider, oauthClient);
    }

    private static String normalizeRoute(String path) {
        if (path == null || path.isEmpty()) {
            return "/";
        }
        if (path.startsWith("/.well-known/")) {
            if (path.contains("openid-configuration")) {
                return "/.well-known/openid-configuration";
            }
            if (path.contains("oauth-authorization-server")) {
                return "/.well-known/oauth-authorization-server";
            }
            return "/.well-known";
        }
        return path;
    }

    private static String errorTypeForRouteAndStatus(String route, int status) {
        if (status >= 500) {
            return "internal";
        }
        if (route != null && route.startsWith("/userinfo") && status == 401) {
            return "invalid_token";
        }
        return "client_error";
    }
}
