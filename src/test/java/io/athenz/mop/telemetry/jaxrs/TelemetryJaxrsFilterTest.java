/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry.jaxrs;

import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TelemetryJaxrsFilterTest {

    @Mock
    private OauthProxyMetrics metrics;

    @Mock
    private TelemetryRequestContext telemetryContext;

    @Mock
    private ContainerRequestContext requestContext;

    @Mock
    private ContainerResponseContext responseContext;

    @Mock
    private UriInfo uriInfo;

    @InjectMocks
    private TelemetryJaxrsFilter filter;

    private void stubTokenPath() {
        when(requestContext.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/token");
        when(requestContext.getMethod()).thenReturn("POST");
        when(telemetryContext.normalizedRoute()).thenReturn("/token");
        when(telemetryContext.oauthProvider()).thenReturn("okta");
        when(telemetryContext.oauthClient()).thenReturn("c1");
    }

    @Test
    void requestFilter_incrementsInflight() {
        when(requestContext.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/token");
        filter.filter(requestContext);
        verify(metrics).incHttpInflight("/token");
    }

    @Test
    void responseFilter_status2xx_decrementsOnly() {
        stubTokenPath();
        when(responseContext.getStatus()).thenReturn(200);
        filter.filter(requestContext, responseContext);
        verify(metrics).decHttpInflight("/token");
        verify(metrics, never()).recordHttp4xx(anyString(), anyString(), anyInt(), anyString(), anyString(), anyString());
        verify(metrics, never()).recordHttp5xx(anyString(), anyString(), anyInt(), anyString(), anyString(), anyString());
        verify(metrics, never()).recordErrorsTotal(anyString(), anyString(), anyInt(), anyString(), anyString());
    }

    @Test
    void responseFilter_status404_records4xx() {
        stubTokenPath();
        when(responseContext.getStatus()).thenReturn(404);
        filter.filter(requestContext, responseContext);
        verify(metrics).recordHttp4xx(eq("POST"), eq("/token"), eq(404), eq("client_error"), eq("okta"), eq("c1"));
        verify(metrics).recordErrorsTotal(eq("/token"), eq("client_error"), eq(404), eq("okta"), eq("c1"));
    }

    @Test
    void responseFilter_status500_records5xx() {
        stubTokenPath();
        when(responseContext.getStatus()).thenReturn(500);
        filter.filter(requestContext, responseContext);
        verify(metrics).recordHttp5xx(eq("POST"), eq("/token"), eq(500), eq("internal"), eq("okta"), eq("c1"));
    }

    @Test
    void responseFilter_userinfo401_invalidTokenErrorType() {
        when(requestContext.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/userinfo");
        when(requestContext.getMethod()).thenReturn("POST");
        when(telemetryContext.normalizedRoute()).thenReturn("/userinfo");
        when(telemetryContext.oauthProvider()).thenReturn("okta");
        when(telemetryContext.oauthClient()).thenReturn("c1");
        when(responseContext.getStatus()).thenReturn(401);
        filter.filter(requestContext, responseContext);
        verify(metrics).recordHttp4xx(eq("POST"), eq("/userinfo"), eq(401), eq("invalid_token"), eq("okta"), eq("c1"));
    }
}
