/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

/**
 * Normalizes {@code client_id} / DCR {@code client_name} for the {@code oauth_client} metric label:
 * any non-empty value after trim is kept; empty or missing becomes {@code unknown}.
 */
public final class OauthClientLabel {

    private OauthClientLabel() {
    }

    public static String normalize(String raw) {
        if (raw == null || raw.isBlank()) {
            return "unknown";
        }
        return raw.trim();
    }
}
