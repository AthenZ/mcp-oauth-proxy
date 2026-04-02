/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthCodeValidationReasonTest {

    @Test
    void allFailureReasons_containsEveryConstantExactlyOnce() {
        var reasons = AuthCodeValidationReason.allFailureReasons();
        assertEquals(10, reasons.size());
        Set<String> unique = new HashSet<>(reasons);
        assertEquals(10, unique.size());
        assertTrue(unique.contains(AuthCodeValidationReason.EMPTY_CODE));
        assertTrue(unique.contains(AuthCodeValidationReason.NOT_FOUND));
        assertTrue(unique.contains(AuthCodeValidationReason.ALREADY_USED));
        assertTrue(unique.contains(AuthCodeValidationReason.EXPIRED));
        assertTrue(unique.contains(AuthCodeValidationReason.CLIENT_ID_MISMATCH));
        assertTrue(unique.contains(AuthCodeValidationReason.REDIRECT_URI_MISMATCH));
        assertTrue(unique.contains(AuthCodeValidationReason.PKCE_MISSING));
        assertTrue(unique.contains(AuthCodeValidationReason.PKCE_UNSUPPORTED_METHOD));
        assertTrue(unique.contains(AuthCodeValidationReason.PKCE_VERIFIER_MISMATCH));
        assertTrue(unique.contains(AuthCodeValidationReason.PKCE_INTERNAL_ERROR));
    }
}
