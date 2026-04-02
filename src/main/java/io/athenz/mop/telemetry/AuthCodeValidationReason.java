/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import java.util.List;

/**
 * {@code error_type} values for {@link io.athenz.mop.telemetry.OauthProxyMetrics#recordAuthCodeValidationFailure}.
 */
public final class AuthCodeValidationReason {

    private AuthCodeValidationReason() {
    }

    public static final String EMPTY_CODE = "empty_code";
    public static final String NOT_FOUND = "not_found";
    public static final String ALREADY_USED = "already_used";
    public static final String EXPIRED = "expired";
    public static final String CLIENT_ID_MISMATCH = "client_id_mismatch";
    public static final String REDIRECT_URI_MISMATCH = "redirect_uri_mismatch";
    public static final String PKCE_MISSING = "pkce_missing";
    public static final String PKCE_UNSUPPORTED_METHOD = "pkce_unsupported_method";
    public static final String PKCE_VERIFIER_MISMATCH = "pkce_verifier_mismatch";
    public static final String PKCE_INTERNAL_ERROR = "pkce_internal_error";

    /** All known failure reasons (for metric bootstrap / dashboards). */
    public static List<String> allFailureReasons() {
        return List.of(
                EMPTY_CODE,
                NOT_FOUND,
                ALREADY_USED,
                EXPIRED,
                CLIENT_ID_MISMATCH,
                REDIRECT_URI_MISMATCH,
                PKCE_MISSING,
                PKCE_UNSUPPORTED_METHOD,
                PKCE_VERIFIER_MISMATCH,
                PKCE_INTERNAL_ERROR);
    }
}
