/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class OauthClientLabelTest {

    @Test
    void normalize_nullOrBlank_returnsUnknown() {
        assertEquals(OauthProviderLabel.UNKNOWN, OauthClientLabel.normalize(null));
        assertEquals(OauthProviderLabel.UNKNOWN, OauthClientLabel.normalize(""));
        assertEquals(OauthProviderLabel.UNKNOWN, OauthClientLabel.normalize("   "));
        assertEquals(OauthProviderLabel.UNKNOWN, OauthClientLabel.normalize("\t\n"));
    }

    @Test
    void normalize_nonBlank_returnsTrimmed() {
        assertEquals("my-client", OauthClientLabel.normalize("  my-client  "));
        assertEquals("a", OauthClientLabel.normalize("a"));
    }
}
