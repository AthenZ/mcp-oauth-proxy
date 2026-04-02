/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

import io.athenz.mop.model.ResourceMeta;
import io.athenz.mop.service.ConfigService;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TelemetryProviderResolverTest {

    @Mock
    private ConfigService configService;

    @InjectMocks
    private TelemetryProviderResolver resolver;

    @Test
    void fromResourceUri_nullOrBlank_returnsUnknown() {
        assertEquals(OauthProviderLabel.UNKNOWN, resolver.fromResourceUri(null));
        assertEquals(OauthProviderLabel.UNKNOWN, resolver.fromResourceUri(""));
        assertEquals(OauthProviderLabel.UNKNOWN, resolver.fromResourceUri("   "));
    }

    @Test
    void fromResourceUri_noMeta_returnsUnknown() {
        when(configService.getResourceMeta("https://r/x")).thenReturn(null);
        assertEquals(OauthProviderLabel.UNKNOWN, resolver.fromResourceUri("https://r/x"));
    }

    @Test
    void fromResourceUri_prefersAudienceWhenPresent() {
        ResourceMeta meta = new ResourceMeta(
                Collections.emptyList(), "d", "idp", "as", false, "j", "GLEAN");
        when(configService.getResourceMeta("https://r/x")).thenReturn(meta);
        assertEquals(OauthProviderLabel.GLEAN, resolver.fromResourceUri("https://r/x"));
    }

    @Test
    void fromResourceUri_usesIdpWhenAudienceBlank() {
        ResourceMeta meta = new ResourceMeta(
                Collections.emptyList(), "d", "OKTA", "as", false, "j", "");
        when(configService.getResourceMeta(anyString())).thenReturn(meta);
        assertEquals(OauthProviderLabel.OKTA, resolver.fromResourceUri("https://r/y"));
    }
}
