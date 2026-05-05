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

import io.athenz.mop.model.RefreshTokenRecord;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;

/**
 * Read-only helpers for the {@code mcp-oauth-proxy-refresh-tokens} table. The primary store and the
 * cross-region fallback share these so schema/marshalling stays in one place.
 *
 * <p>This class is intentionally read-only: nothing here issues a {@code PutItem},
 * {@code DeleteItem} or {@code TransactWriteItems}. The cross-region fallback bean is allowed to
 * invoke any of these methods; rotation/revoke writes stay inside {@code RefreshTokenServiceImpl}
 * and only run against the primary client.
 */
public final class RefreshTokenStoreDynamodbHelpers {

    private RefreshTokenStoreDynamodbHelpers() {
    }

    /**
     * Look up a refresh-token row by hash via {@link RefreshTableConstants#GSI_REFRESH_TOKEN_HASH}.
     * Returns {@code null} when no row is found.
     */
    public static RefreshTokenRecord lookupByHash(DynamoDbClient client, String table, String hash) {
        QueryResponse response = client.query(QueryRequest.builder()
                .tableName(table)
                .indexName(RefreshTableConstants.GSI_REFRESH_TOKEN_HASH)
                .keyConditionExpression(RefreshTableAttribute.REFRESH_TOKEN_HASH.attr() + " = :h")
                .expressionAttributeValues(Map.of(":h", AttributeValue.builder().s(hash).build()))
                .build());
        if (response.items() == null || response.items().isEmpty()) {
            return null;
        }
        return itemToRecord(response.items().get(0));
    }

    /**
     * Fetch a refresh-token row by primary key (refresh_token_id, provider_user_id).
     * Returns the underlying {@code Map<String, AttributeValue>} so callers can mutate it for
     * conditional writes; returns {@code null} when no row is found.
     */
    public static Map<String, AttributeValue> getItemByPrimaryKey(DynamoDbClient client, String table,
                                                                   String refreshTokenId, String providerUserId) {
        Map<String, AttributeValue> key = Map.of(
                RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s(refreshTokenId).build(),
                RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(providerUserId).build()
        );
        var resp = client.getItem(GetItemRequest.builder().tableName(table).key(key).build());
        if (resp.item() == null || resp.item().isEmpty()) {
            return null;
        }
        return resp.item();
    }

    /**
     * Query {@link RefreshTableConstants#GSI_USER_PROVIDER} for a (userId, provider) pair and
     * return the best non-revoked, unexpired record (highest issued_at) <em>that actually carries
     * an upstream refresh token</em>.
     *
     * <p>The {@code encrypted_upstream_refresh_token} attribute is configured for client-side
     * encryption (see {@code DynamodbClientProvider#buildRefreshTokensTableEncryptionConfig}).
     * The AWS DynamoDB Encryption Client only decrypts attributes returned via {@code GetItem},
     * {@code PutItem} and similar base-table operations; results returned from a GSI {@code Query}
     * carry the raw ciphertext as a Binary attribute, which our String-typed marshalling
     * ({@link #getS}) reads back as {@code null}. We therefore use the GSI to identify the
     * winning row by (status, expiry, has-legacy-RT, issued_at) and then re-fetch that row by
     * primary key on the base table so the encryption interceptor can decrypt the upstream
     * refresh token.
     *
     * <p>Why the "has-legacy-RT" filter matters: post-L2-promotion (okta + the 12 google-workspace
     * providers), every newly-issued MoP refresh-token row for a promoted provider is written
     * with {@code encrypted_upstream_refresh_token} explicitly NULL — the canonical upstream RT
     * lives in the {@code mcp-oauth-proxy-upstream-tokens} (L2) table. Without this filter the
     * rank-by-{@code issued_at} loop would pick a brand-new L2-only row whose legacy column is
     * null, return it to the caller, and the caller would interpret that as "no usable upstream
     * RT" — even when older sibling rows still carry valid pre-rollout legacy ciphertext that
     * could rescue the request. The filter makes this method's contract "give me the newest row
     * I can <em>actually</em> seed an upstream-RT lookup from", which is what every call site
     * wants. Inspection of the raw {@code B} attribute is required because GSI projections do not
     * trigger DBE decryption, so {@code record.encryptedUpstreamRefreshToken()} (a String view of
     * a Binary attribute) is null on every GSI item regardless of whether the underlying row
     * actually carries a token.
     *
     * <p>Returns {@code null} when no row qualifies.
     */
    public static RefreshTokenRecord queryBestUpstreamRefresh(DynamoDbClient client, String table,
                                                              String userId, String provider) {
        QueryResponse response = client.query(QueryRequest.builder()
                .tableName(table)
                .indexName(RefreshTableConstants.GSI_USER_PROVIDER)
                .keyConditionExpression(
                        RefreshTableAttribute.USER_ID.attr() + " = :uid AND "
                                + RefreshTableAttribute.PROVIDER.attr() + " = :prov")
                .expressionAttributeValues(Map.of(
                        ":uid", AttributeValue.builder().s(userId).build(),
                        ":prov", AttributeValue.builder().s(provider).build()))
                .build());
        if (response.items() == null || response.items().isEmpty()) {
            return null;
        }
        long now = System.currentTimeMillis() / 1000;
        RefreshTokenRecord best = null;
        for (Map<String, AttributeValue> item : response.items()) {
            RefreshTokenRecord record = itemToRecord(item);
            if (record.expiresAt() > 0 && now > record.expiresAt()) {
                continue;
            }
            if (RefreshTableConstants.STATUS_REVOKED.equals(record.status())) {
                continue;
            }
            // Skip rows that don't carry an upstream RT in the legacy column. Inspect the raw
            // Binary/String attribute on the GSI item directly: itemToRecord() reads via getS()
            // which returns null for a Binary attribute, so we cannot rely on the decoded String
            // view here. Test-only writers may use the String form; production writers always
            // use Binary via DBE, so we accept either.
            if (!hasLegacyUpstreamRt(item)) {
                continue;
            }
            if (best == null || record.issuedAt() > best.issuedAt()) {
                best = record;
            }
        }
        if (best == null) {
            return null;
        }
        // The GSI projection holds the raw ciphertext for encrypted_upstream_refresh_token.
        // Re-fetch the winning row by primary key so the encryption interceptor decrypts it.
        if ((best.encryptedUpstreamRefreshToken() == null || best.encryptedUpstreamRefreshToken().isEmpty())
                && best.refreshTokenId() != null && best.providerUserId() != null) {
            Map<String, AttributeValue> baseItem =
                    getItemByPrimaryKey(client, table, best.refreshTokenId(), best.providerUserId());
            if (baseItem != null) {
                return itemToRecord(baseItem);
            }
        }
        return best;
    }

    private static boolean hasLegacyUpstreamRt(Map<String, AttributeValue> item) {
        AttributeValue v = item.get(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr());
        if (v == null) {
            return false;
        }
        if (v.b() != null && v.b().asByteArray().length > 0) {
            return true;
        }
        if (v.s() != null && !v.s().isEmpty()) {
            return true;
        }
        return false;
    }

    /**
     * Query {@link RefreshTableConstants#GSI_TOKEN_FAMILY} for a token family and return the row
     * with the highest {@code issued_at} that is still {@code ACTIVE} and unexpired. Used by the
     * rotated-grace path in {@code RefreshTokenServiceImpl} to find the live successor of a
     * recently-rotated row without re-following the {@code replaced_by} pointer chain (which can
     * miss when rotations are cross-region).
     *
     * <p>Unlike {@link #queryBestUpstreamRefresh}, this does <em>not</em> re-fetch the winning row
     * by primary key. The grace-path caller in {@code RefreshTokenServiceImpl#rotateGraceSuccessor}
     * always re-reads the row by PK before rotating against it (both to defend against TOCTOU and
     * to obtain the decrypted upstream RT for non-OKTA providers), so adding a redundant GetItem
     * here would only inflate the per-grace DDB cost. Returns {@code null} when no live ACTIVE
     * row exists in the family.</p>
     */
    public static RefreshTokenRecord queryLatestActiveInFamily(DynamoDbClient client, String table,
                                                               String tokenFamilyId) {
        if (tokenFamilyId == null || tokenFamilyId.isEmpty()) {
            return null;
        }
        QueryResponse response = client.query(QueryRequest.builder()
                .tableName(table)
                .indexName(RefreshTableConstants.GSI_TOKEN_FAMILY)
                .keyConditionExpression(RefreshTableAttribute.TOKEN_FAMILY_ID.attr() + " = :fid")
                .expressionAttributeValues(Map.of(":fid", AttributeValue.builder().s(tokenFamilyId).build()))
                .build());
        if (response.items() == null || response.items().isEmpty()) {
            return null;
        }
        long now = System.currentTimeMillis() / 1000;
        RefreshTokenRecord best = null;
        for (Map<String, AttributeValue> item : response.items()) {
            RefreshTokenRecord record = itemToRecord(item);
            if (!RefreshTableConstants.STATUS_ACTIVE.equals(record.status())) {
                continue;
            }
            if (record.expiresAt() > 0 && now > record.expiresAt()) {
                continue;
            }
            if (best == null || record.issuedAt() > best.issuedAt()) {
                best = record;
            }
        }
        return best;
    }

    public static RefreshTokenRecord itemToRecord(Map<String, AttributeValue> item) {
        return new RefreshTokenRecord(
                getS(item, RefreshTableAttribute.REFRESH_TOKEN_ID.attr()),
                getS(item, RefreshTableAttribute.PROVIDER_USER_ID.attr()),
                getS(item, RefreshTableAttribute.USER_ID.attr()),
                getS(item, RefreshTableAttribute.CLIENT_ID.attr()),
                getS(item, RefreshTableAttribute.PROVIDER.attr()),
                getS(item, RefreshTableAttribute.AUDIENCE.attr()),
                getS(item, RefreshTableAttribute.PROVIDER_SUBJECT.attr()),
                getS(item, RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr()),
                getS(item, RefreshTableAttribute.STATUS.attr()),
                getS(item, RefreshTableAttribute.TOKEN_FAMILY_ID.attr()),
                getS(item, RefreshTableAttribute.ROTATED_FROM.attr()),
                getS(item, RefreshTableAttribute.REPLACED_BY.attr()),
                getN(item, RefreshTableAttribute.ROTATED_AT.attr(), 0L),
                getN(item, RefreshTableAttribute.ISSUED_AT.attr(), 0L),
                getN(item, RefreshTableAttribute.EXPIRES_AT.attr(), 0L),
                getN(item, RefreshTableAttribute.TTL.attr(), 0L)
        );
    }

    private static String getS(Map<String, AttributeValue> item, String key) {
        if (!item.containsKey(key)) return null;
        AttributeValue v = item.get(key);
        return v == null || v.s() == null ? null : v.s();
    }

    private static long getN(Map<String, AttributeValue> item, String key, long def) {
        if (!item.containsKey(key)) return def;
        AttributeValue v = item.get(key);
        if (v == null || v.n() == null) return def;
        try {
            return Long.parseLong(v.n());
        } catch (NumberFormatException e) {
            return def;
        }
    }
}
