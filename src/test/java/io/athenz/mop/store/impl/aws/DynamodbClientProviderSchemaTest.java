/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.athenz.mop.store.impl.aws;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction;

/**
 * Schema-coverage regression tests for {@link DynamodbClientProvider}'s AWS DBE attribute action
 * maps.
 *
 * <p>The AWS DynamoDB Encryption Client (DBE) refuses to write any attribute that is not declared
 * with a {@link CryptoAction} in {@code attributeActionsOnEncrypt}. Failure mode is a runtime
 * exception ("No Crypto Action configured for attribute &lt;name&gt;") that we have already hit
 * once in stage when adding the {@code audience} column to the refresh-tokens table — the column
 * was added to {@link RefreshTableAttribute} and to all reads/writes, but the action map was not
 * updated, and 1292 in-memory unit tests passed cleanly while production silently dropped the
 * refresh_token from /token responses.
 *
 * <p>These tests fail the build at the moment a new attribute is added to one of the
 * {@code *TableAttribute} enums without a corresponding action registration. The intent is to
 * front-load the failure into CI rather than discover it in stage.
 */
class DynamodbClientProviderSchemaTest {

    @Test
    void tokensTable_actionMapCoversEveryAttribute() {
        Map<String, CryptoAction> actions = DynamodbClientProvider.buildTokensAttributeActions();
        Set<String> declared = Arrays.stream(TokenTableAttribute.values())
                .map(TokenTableAttribute::attr)
                .collect(Collectors.toSet());

        assertCoverage("mcp-oauth-proxy-tokens", declared, actions);
    }

    @Test
    void refreshTokensTable_actionMapCoversEveryAttribute() {
        Map<String, CryptoAction> actions = DynamodbClientProvider.buildRefreshTokensAttributeActions();
        Set<String> declared = Arrays.stream(RefreshTableAttribute.values())
                .map(RefreshTableAttribute::attr)
                // Skip the GSI-only synthetic attribute that is written by DDB itself, not by app code.
                // Currently none, but if a future column is GSI-projection-only and not written from
                // the app, exclude it here with a documented reason.
                .collect(Collectors.toSet());

        assertCoverage("mcp-oauth-proxy-refresh-tokens", declared, actions);
    }

    @Test
    void upstreamTokensTable_actionMapCoversEveryAttribute() {
        Map<String, CryptoAction> actions = DynamodbClientProvider.buildUpstreamTokensAttributeActions();
        Set<String> declared = Arrays.stream(UpstreamTableAttribute.values())
                .map(UpstreamTableAttribute::attr)
                .collect(Collectors.toSet());

        assertCoverage("mcp-oauth-proxy-upstream-tokens", declared, actions);
    }

    /**
     * Asserts the action map exactly covers the declared attribute set: no missing entries (the
     * "audience" bug class) and no orphan entries (a stale action for an attribute that has been
     * removed). A close diff is included in the failure message so the missing/orphan attribute
     * names appear directly in CI output.
     */
    private static void assertCoverage(String tableName, Set<String> declared, Map<String, CryptoAction> actions) {
        Set<String> registered = actions.keySet();

        Set<String> missingActions = declared.stream()
                .filter(attr -> !registered.contains(attr))
                .collect(Collectors.toCollection(java.util.TreeSet::new));
        Set<String> orphanActions = registered.stream()
                .filter(attr -> !declared.contains(attr))
                .collect(Collectors.toCollection(java.util.TreeSet::new));

        assertAll("DBE schema coverage for " + tableName,
                () -> assertTrue(missingActions.isEmpty(),
                        "Attributes declared in enum but missing from DBE action map for "
                                + tableName + ": " + missingActions
                                + " — DBE will refuse to PutItem with these attributes. "
                                + "Add a CryptoAction (SIGN_ONLY for plaintext-but-tamper-evident, "
                                + "ENCRYPT_AND_SIGN for sensitive payload, DO_NOTHING for the TTL only)."),
                () -> assertTrue(orphanActions.isEmpty(),
                        "DBE action map for " + tableName + " has actions for attributes that "
                                + "are not declared in the enum: " + orphanActions
                                + " — likely a stale entry from a removed column. Remove or rename it."),
                () -> assertEquals(declared.size(), registered.size(),
                        "Action map size must equal enum size for " + tableName)
        );
    }

    @Test
    void refreshTokens_audienceIsSignOnly() {
        // Pinning the new audience column specifically: it must be SIGN_ONLY (low-cardinality
        // diagnostic label, not a secret) — never DO_NOTHING (would skip tamper evidence) and
        // never ENCRYPT_AND_SIGN (would prevent operators querying audience in DDB).
        Map<String, CryptoAction> actions = DynamodbClientProvider.buildRefreshTokensAttributeActions();
        CryptoAction action = actions.get(RefreshTableAttribute.AUDIENCE.attr());
        assertNotNull(action, "audience column must be in the refresh-tokens action map");
        assertEquals(CryptoAction.SIGN_ONLY, action,
                "audience must be SIGN_ONLY: it is not a secret (operators should be able to "
                        + "query DDB by audience for diagnostics) but it must be tamper-evident.");
    }

    @Test
    void allActionMapsHaveTtlAsDoNothing() {
        // TTL is rewritten by DDB itself when items are evicted, so it must be DO_NOTHING — any
        // signed action would invalidate the row's signature on the next eviction sweep.
        assertEquals(CryptoAction.DO_NOTHING,
                DynamodbClientProvider.buildTokensAttributeActions()
                        .get(TokenTableAttribute.TTL.attr()));
        assertEquals(CryptoAction.DO_NOTHING,
                DynamodbClientProvider.buildRefreshTokensAttributeActions()
                        .get(RefreshTableAttribute.TTL.attr()));
        assertEquals(CryptoAction.DO_NOTHING,
                DynamodbClientProvider.buildUpstreamTokensAttributeActions()
                        .get(UpstreamTableAttribute.TTL.attr()));
    }

    @Test
    void encryptAndSignActionsAreLimitedToSensitivePayloads() {
        // Defense-in-depth: keep ENCRYPT_AND_SIGN to actual token payloads. New columns should
        // default to SIGN_ONLY unless they carry secret material. This locks the current intent
        // so a future "let's encrypt this string field too" change shows up in code review.
        assertEquals(Set.of(
                        TokenTableAttribute.ID_TOKEN.attr(),
                        TokenTableAttribute.ACCESS_TOKEN.attr(),
                        TokenTableAttribute.REFRESH_TOKEN.attr(),
                        TokenTableAttribute.AUTH_CODE_JSON.attr(),
                        TokenTableAttribute.AUTH_TOKENS_JSON.attr()),
                DynamodbClientProvider.buildTokensAttributeActions().entrySet().stream()
                        .filter(e -> e.getValue() == CryptoAction.ENCRYPT_AND_SIGN)
                        .map(Map.Entry::getKey)
                        .collect(Collectors.toSet()),
                "ENCRYPT_AND_SIGN set on tokens table changed. Confirm new entry actually carries "
                        + "secret material (not just a string).");

        assertEquals(Set.of(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr()),
                DynamodbClientProvider.buildRefreshTokensAttributeActions().entrySet().stream()
                        .filter(e -> e.getValue() == CryptoAction.ENCRYPT_AND_SIGN)
                        .map(Map.Entry::getKey)
                        .collect(Collectors.toSet()),
                "ENCRYPT_AND_SIGN set on refresh-tokens table changed. Confirm new entry carries "
                        + "secret material.");

        assertEquals(Set.of(
                        UpstreamTableAttribute.ENCRYPTED_OKTA_REFRESH_TOKEN.attr(),
                        UpstreamTableAttribute.LAST_MINTED_ACCESS_TOKEN.attr()),
                DynamodbClientProvider.buildUpstreamTokensAttributeActions().entrySet().stream()
                        .filter(e -> e.getValue() == CryptoAction.ENCRYPT_AND_SIGN)
                        .map(Map.Entry::getKey)
                        .collect(Collectors.toSet()),
                "ENCRYPT_AND_SIGN set on upstream-tokens table changed. Confirm new entry carries "
                        + "secret material. The L2 staged-AT (last_minted_access_token) is a "
                        + "credential and must be encrypted; the timestamp/version siblings are SIGN_ONLY.");
    }

    @Test
    void actionMapsAreNotEmpty() {
        // Belt-and-braces: catches the "I refactored and accidentally returned an empty map"
        // failure mode that {@link #assertCoverage} would also catch — but with a friendlier
        // message that doesn't try to diff against the entire enum.
        assertFalse(DynamodbClientProvider.buildTokensAttributeActions().isEmpty());
        assertFalse(DynamodbClientProvider.buildRefreshTokensAttributeActions().isEmpty());
        assertFalse(DynamodbClientProvider.buildUpstreamTokensAttributeActions().isEmpty());
    }
}
