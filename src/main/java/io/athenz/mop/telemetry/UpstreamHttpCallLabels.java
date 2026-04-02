/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

/**
 * Thread-local labels for {@link io.athenz.mop.service.DefaultExchangeTokenClient} so upstream
 * histograms get bounded {@code oauth_provider} and {@code upstream_endpoint} without changing
 * {@link io.athenz.mop.service.TokenClient} signatures.
 */
public final class UpstreamHttpCallLabels {

    /** {@code upstream_endpoint} label for OAuth token HTTP calls (RFC 6749 token endpoint). */
    public static final String ENDPOINT_OAUTH_TOKEN = "oauth_token";

    /** {@code upstream_endpoint} label for Google Security Token Service (workforce) token exchange. */
    public static final String ENDPOINT_GOOGLE_STS = "google_sts";

    private static final ThreadLocal<String> OAUTH_PROVIDER = new ThreadLocal<>();
    private static final ThreadLocal<String> UPSTREAM_ENDPOINT = new ThreadLocal<>();

    private UpstreamHttpCallLabels() {
    }

    public interface Scope extends AutoCloseable {
        @Override
        void close();
    }

    public static Scope withLabels(String oauthProvider, String upstreamEndpoint) {
        OAUTH_PROVIDER.set(oauthProvider);
        UPSTREAM_ENDPOINT.set(upstreamEndpoint);
        return () -> {
            OAUTH_PROVIDER.remove();
            UPSTREAM_ENDPOINT.remove();
        };
    }

    public static String oauthProvider() {
        return OAUTH_PROVIDER.get();
    }

    public static String upstreamEndpoint() {
        return UPSTREAM_ENDPOINT.get();
    }
}
