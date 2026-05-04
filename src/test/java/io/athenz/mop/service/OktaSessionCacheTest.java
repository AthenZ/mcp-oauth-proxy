/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.athenz.mop.config.OktaSessionCacheConfig;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OktaSessionCacheTest {

    @Mock
    OktaSessionCacheConfig config;

    @Mock
    OauthProxyMetrics metrics;

    @InjectMocks
    OktaSessionCache cache;

    @BeforeEach
    void setUp() {
        lenient().when(config.minRemainingSeconds()).thenReturn(120);
        lenient().when(config.l0MaxSize()).thenReturn(100);
        lenient().when(config.l0ExpireAfterWriteSeconds()).thenReturn(3600);
    }

    private static String jwtWithExp(long expEpochSeconds) throws Exception {
        byte[] secret = "01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .expirationTime(new Date(expEpochSeconds * 1000L))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).build(), claims);
        jwt.sign(new MACSigner(secret));
        return jwt.serialize();
    }

    @Test
    void put_thenGet_returnsSameEntry() throws Exception {
        when(config.enabled()).thenReturn(true);
        cache.init();
        long exp = Instant.now().getEpochSecond() + 3600;
        OktaSessionEntry entry = OktaSessionEntry.from(jwtWithExp(exp), jwtWithExp(exp), "rt");

        cache.put("okta#u1", entry);
        Optional<OktaSessionEntry> got = cache.get("okta#u1");

        assertTrue(got.isPresent());
        assertEquals(entry, got.get());
    }

    @Test
    void get_returnsEmpty_whenAbsent() {
        when(config.enabled()).thenReturn(true);
        cache.init();
        assertTrue(cache.get("okta#u1").isEmpty());
    }

    @Test
    void invalidate_removesEntry() throws Exception {
        when(config.enabled()).thenReturn(true);
        cache.init();
        long exp = Instant.now().getEpochSecond() + 3600;
        cache.put("okta#u1", OktaSessionEntry.from(jwtWithExp(exp), jwtWithExp(exp), "rt"));
        cache.invalidate("okta#u1");
        assertTrue(cache.get("okta#u1").isEmpty());
        verify(metrics).recordOktaSessionCacheEviction("explicit");
    }

    @Test
    void disabled_getAlwaysEmpty_putNoOp() throws Exception {
        when(config.enabled()).thenReturn(false);
        cache.init();
        long exp = Instant.now().getEpochSecond() + 3600;
        cache.put("okta#u1", OktaSessionEntry.from(jwtWithExp(exp), jwtWithExp(exp), "rt"));
        assertTrue(cache.get("okta#u1").isEmpty());
        verify(metrics, never()).registerOktaSessionCacheSizeGauge(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void unparseableTokens_yieldNegativeMinExp() {
        OktaSessionEntry e = OktaSessionEntry.from("not.a.jwt", "also-opaque", "rt");
        assertEquals(-1L, e.minExp());
    }

    @Test
    void minExp_picksEarlierOfIdAndAccessExp() throws Exception {
        long idExp = Instant.now().getEpochSecond() + 3600;
        long atExp = Instant.now().getEpochSecond() + 1800;
        OktaSessionEntry e = OktaSessionEntry.from(jwtWithExp(idExp), jwtWithExp(atExp), "rt");
        assertEquals(atExp, e.minExp());
    }

    @Test
    void minExp_fallsBackToIdToken_whenAccessOpaque() throws Exception {
        long idExp = Instant.now().getEpochSecond() + 3600;
        OktaSessionEntry e = OktaSessionEntry.from(jwtWithExp(idExp), "opaque-access", "rt");
        assertEquals(idExp, e.minExp());
    }

    @Test
    void invalidConfig_skewTooLow_throws() {
        // Validation runs before enabled() is consulted, so we don't stub it.
        when(config.minRemainingSeconds()).thenReturn(5);
        assertThrows(IllegalStateException.class, cache::init);
    }

    @Test
    void invalidConfig_l0MaxSizeOutOfRange_throws() {
        when(config.l0MaxSize()).thenReturn(50);
        assertThrows(IllegalStateException.class, cache::init);
    }

    @Test
    void invalidConfig_writeTtlOutOfRange_throws() {
        when(config.l0ExpireAfterWriteSeconds()).thenReturn(60);
        assertThrows(IllegalStateException.class, cache::init);
    }

    @Test
    void put_overwritesExistingEntry() throws Exception {
        when(config.enabled()).thenReturn(true);
        cache.init();
        long e1 = Instant.now().getEpochSecond() + 1800;
        long e2 = Instant.now().getEpochSecond() + 3600;
        cache.put("okta#u1", OktaSessionEntry.from(jwtWithExp(e1), jwtWithExp(e1), "rt-a"));
        cache.put("okta#u1", OktaSessionEntry.from(jwtWithExp(e2), jwtWithExp(e2), "rt-b"));
        assertEquals("rt-b", cache.get("okta#u1").orElseThrow().refreshToken());
    }

    @Test
    void get_nullKey_returnsEmpty() {
        when(config.enabled()).thenReturn(true);
        cache.init();
        assertTrue(cache.get(null).isEmpty());
    }

    @Test
    void put_nullKeyOrEntry_isNoOp() throws Exception {
        when(config.enabled()).thenReturn(true);
        cache.init();
        cache.put(null, null);
        cache.put("okta#u1", null);
        long exp = Instant.now().getEpochSecond() + 3600;
        cache.put("", OktaSessionEntry.from(jwtWithExp(exp), jwtWithExp(exp), "rt"));
        assertEquals(0L, cache.estimatedSize());
    }

    @Test
    void estimatedSize_isZero_whenDisabled() {
        when(config.enabled()).thenReturn(false);
        cache.init();
        assertEquals(0L, cache.estimatedSize());
        assertFalse(cache.get("okta#u1").isPresent());
    }
}
