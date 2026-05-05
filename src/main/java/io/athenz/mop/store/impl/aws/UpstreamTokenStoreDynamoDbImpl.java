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

import io.athenz.mop.config.UpstreamTokenConfig;
import io.athenz.mop.model.UpstreamTokenRecord;
import io.athenz.mop.store.UpstreamTokenStore;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

@ApplicationScoped
public class UpstreamTokenStoreDynamoDbImpl implements UpstreamTokenStore {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    DynamoDbClient dynamoDbClient;

    @Inject
    UpstreamTokenConfig upstreamTokenConfig;

    @Override
    public void save(UpstreamTokenRecord record) {
        if (record == null || record.providerUserId() == null || record.providerUserId().isEmpty()) {
            throw new IllegalArgumentException("upstream save: providerUserId required");
        }
        long version = record.version() > 0 ? record.version() : 1L;
        Map<String, AttributeValue> item = toItem(record, version);
        dynamoDbClient.putItem(PutItemRequest.builder().tableName(upstreamTokenConfig.tableName()).item(item).build());
        log.info(
                "event=upstream_token_created provider_user_id={} version={} status={} ttl={}",
                record.providerUserId(), version, record.status(), record.ttl());
    }

    @Override
    public Optional<UpstreamTokenRecord> get(String providerUserId) {
        return getWithClient(dynamoDbClient, upstreamTokenConfig.tableName(), providerUserId);
    }

    /**
     * Strongly-consistent read of an upstream-token row using the supplied client and table.
     * Used by the primary store and by {@code CrossRegionTokenStoreFallback} to consult the peer
     * region's table with the same marshalling.
     */
    public static Optional<UpstreamTokenRecord> getWithClient(DynamoDbClient client, String table, String providerUserId) {
        if (providerUserId == null || providerUserId.isEmpty()) {
            return Optional.empty();
        }
        Map<String, AttributeValue> key = new HashMap<>();
        key.put(UpstreamTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(providerUserId).build());
        var resp = client.getItem(
                GetItemRequest.builder()
                        .tableName(table)
                        .key(key)
                        .consistentRead(true)
                        .build());
        if (resp.item() == null || resp.item().isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(fromItem(resp.item()));
    }

    @Override
    public boolean updateWithVersionCheck(String providerUserId, String newPlainUpstreamRefreshToken, long expectedVersion) {
        return updateWithVersionCheckInternal(providerUserId, newPlainUpstreamRefreshToken,
                /* stagedAccessToken */ null, /* stagedAtExpiresAt */ 0L, expectedVersion);
    }

    @Override
    public boolean updateWithVersionCheckAndStagedAt(String providerUserId, String newPlainUpstreamRefreshToken,
                                                     String newAccessToken, long newAccessTokenExpiresAt,
                                                     long expectedVersion) {
        return updateWithVersionCheckInternal(providerUserId, newPlainUpstreamRefreshToken,
                newAccessToken, newAccessTokenExpiresAt, expectedVersion);
    }

    private boolean updateWithVersionCheckInternal(String providerUserId, String newPlainUpstreamRefreshToken,
                                                   String stagedAccessToken, long stagedAtExpiresAt,
                                                   long expectedVersion) {
        if (providerUserId == null || providerUserId.isEmpty() || newPlainUpstreamRefreshToken == null) {
            return false;
        }
        Optional<UpstreamTokenRecord> currentOpt = get(providerUserId);
        if (currentOpt.isEmpty()) {
            return false;
        }
        UpstreamTokenRecord current = currentOpt.get();
        if (current.version() != expectedVersion) {
            return false;
        }
        if (!current.isActive()) {
            log.info(
                    "event=upstream_okta_rotate_skipped_revoked provider_user_id={} version={} status={}",
                    providerUserId, current.version(), current.status());
            return false;
        }
        String now = Instant.now().toString();
        long newVersion = expectedVersion + 1;
        long newRotationCount = current.rotationCount() + 1L;
        long ttl = computeActiveTtlEpochSeconds();

        Map<String, AttributeValue> item = new HashMap<>();
        item.put(UpstreamTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(providerUserId).build());
        item.put(UpstreamTableAttribute.ENCRYPTED_OKTA_REFRESH_TOKEN.attr(), AttributeValue.builder().s(newPlainUpstreamRefreshToken).build());
        item.put(UpstreamTableAttribute.LAST_ROTATED_AT.attr(), AttributeValue.builder().s(now).build());
        item.put(UpstreamTableAttribute.VERSION.attr(), AttributeValue.builder().n(String.valueOf(newVersion)).build());
        item.put(UpstreamTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(ttl)).build());
        item.put(UpstreamTableAttribute.CREATED_AT.attr(), AttributeValue.builder().s(current.createdAt() != null ? current.createdAt() : now).build());
        item.put(UpstreamTableAttribute.UPDATED_AT.attr(), AttributeValue.builder().s(now).build());
        item.put(UpstreamTableAttribute.STATUS.attr(),
                AttributeValue.builder().s(UpstreamTokenRecord.STATUS_ACTIVE).build());
        item.put(UpstreamTableAttribute.ROTATION_COUNT.attr(),
                AttributeValue.builder().n(String.valueOf(newRotationCount)).build());
        // Staged-AT trio. ALWAYS written so the row carries a consistent shape for the DBE
        // signature; an absent AT is encoded as empty string and an absent expiry as 0. The
        // rotation_version pin tells the second client which RT version produced the staged AT.
        String stagedAtValue = stagedAccessToken != null ? stagedAccessToken : "";
        long stagedExpiresAtValue = stagedAccessToken != null && stagedAtExpiresAt > 0L ? stagedAtExpiresAt : 0L;
        long stagedRotationVersionValue = stagedAccessToken != null ? newVersion : 0L;
        item.put(UpstreamTableAttribute.LAST_MINTED_ACCESS_TOKEN.attr(),
                AttributeValue.builder().s(stagedAtValue).build());
        item.put(UpstreamTableAttribute.LAST_MINTED_AT_EXPIRES_AT.attr(),
                AttributeValue.builder().n(String.valueOf(stagedExpiresAtValue)).build());
        item.put(UpstreamTableAttribute.LAST_MINTED_AT_ROTATION_VERSION.attr(),
                AttributeValue.builder().n(String.valueOf(stagedRotationVersionValue)).build());

        Map<String, String> exprNames = new HashMap<>();
        exprNames.put("#ver", UpstreamTableAttribute.VERSION.attr());
        Map<String, AttributeValue> exprValues = new HashMap<>();
        exprValues.put(":expected", AttributeValue.builder().n(String.valueOf(expectedVersion)).build());

        try {
            dynamoDbClient.putItem(
                    PutItemRequest.builder()
                            .tableName(upstreamTokenConfig.tableName())
                            .item(item)
                            .conditionExpression("#ver = :expected")
                            .expressionAttributeNames(exprNames)
                            .expressionAttributeValues(exprValues)
                            .build());
            log.info(
                    "event=upstream_token_rotated provider_user_id={} prior_version={} new_version={} rotation_count={} staged_at={}",
                    providerUserId, expectedVersion, newVersion, newRotationCount, stagedAccessToken != null);
            return true;
        } catch (ConditionalCheckFailedException e) {
            log.debug("upstream version check failed for provider_user_id={}", providerUserId);
            return false;
        }
    }

    @Override
    public boolean markRevoked(String providerUserId, long expectedVersion, String reason) {
        if (providerUserId == null || providerUserId.isEmpty()) {
            return false;
        }
        Optional<UpstreamTokenRecord> currentOpt = get(providerUserId);
        if (currentOpt.isEmpty()) {
            log.info(
                    "event=upstream_okta_revoke_noop_missing provider_user_id={} expected_version={}",
                    providerUserId, expectedVersion);
            return false;
        }
        UpstreamTokenRecord current = currentOpt.get();
        if (current.version() != expectedVersion) {
            log.info(
                    "event=upstream_okta_revoke_noop_rotated provider_user_id={} expected_version={} actual_version={}",
                    providerUserId, expectedVersion, current.version());
            return false;
        }
        if (!current.isActive()) {
            log.info(
                    "event=upstream_okta_revoke_noop_already_revoked provider_user_id={} version={} status={}",
                    providerUserId, current.version(), current.status());
            return false;
        }

        String now = Instant.now().toString();
        long ttl = computeRevokedTtlEpochSeconds();
        String reasonValue = reason != null ? reason : "";

        Map<String, AttributeValue> item = new HashMap<>();
        item.put(UpstreamTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(providerUserId).build());
        // Clear the secret material — the row stays for audit, but the encrypted RT is no
        // longer needed and we don't want to keep ciphertext around any longer than necessary.
        item.put(UpstreamTableAttribute.ENCRYPTED_OKTA_REFRESH_TOKEN.attr(), AttributeValue.builder().s("").build());
        item.put(UpstreamTableAttribute.LAST_ROTATED_AT.attr(),
                AttributeValue.builder().s(current.lastRotatedAt() != null ? current.lastRotatedAt() : "").build());
        item.put(UpstreamTableAttribute.VERSION.attr(), AttributeValue.builder().n(String.valueOf(current.version())).build());
        item.put(UpstreamTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(ttl)).build());
        item.put(UpstreamTableAttribute.CREATED_AT.attr(),
                AttributeValue.builder().s(current.createdAt() != null ? current.createdAt() : now).build());
        item.put(UpstreamTableAttribute.UPDATED_AT.attr(), AttributeValue.builder().s(now).build());
        item.put(UpstreamTableAttribute.STATUS.attr(),
                AttributeValue.builder().s(UpstreamTokenRecord.STATUS_REVOKED_INVALID_GRANT).build());
        item.put(UpstreamTableAttribute.REVOKED_AT.attr(), AttributeValue.builder().s(now).build());
        item.put(UpstreamTableAttribute.REVOKED_REASON.attr(), AttributeValue.builder().s(reasonValue).build());
        item.put(UpstreamTableAttribute.ROTATION_COUNT.attr(),
                AttributeValue.builder().n(String.valueOf(current.rotationCount())).build());
        // Clear the staged AT alongside the canonical RT — once revoked, no client should be
        // able to bypass the upstream call by reading a stale staged AT off this row.
        item.put(UpstreamTableAttribute.LAST_MINTED_ACCESS_TOKEN.attr(), AttributeValue.builder().s("").build());
        item.put(UpstreamTableAttribute.LAST_MINTED_AT_EXPIRES_AT.attr(),
                AttributeValue.builder().n("0").build());
        item.put(UpstreamTableAttribute.LAST_MINTED_AT_ROTATION_VERSION.attr(),
                AttributeValue.builder().n("0").build());

        Map<String, String> exprNames = new HashMap<>();
        exprNames.put("#ver", UpstreamTableAttribute.VERSION.attr());
        Map<String, AttributeValue> exprValues = new HashMap<>();
        exprValues.put(":expected", AttributeValue.builder().n(String.valueOf(expectedVersion)).build());

        try {
            dynamoDbClient.putItem(
                    PutItemRequest.builder()
                            .tableName(upstreamTokenConfig.tableName())
                            .item(item)
                            .conditionExpression("#ver = :expected")
                            .expressionAttributeNames(exprNames)
                            .expressionAttributeValues(exprValues)
                            .build());
            log.warn(
                    "event=upstream_token_revoked provider_user_id={} version={} rotation_count={} ttl={} reason=\"{}\"",
                    providerUserId, current.version(), current.rotationCount(), ttl, reasonValue);
            return true;
        } catch (ConditionalCheckFailedException e) {
            log.info(
                    "event=upstream_token_revoke_cas_failed provider_user_id={} expected_version={}",
                    providerUserId, expectedVersion);
            return false;
        }
    }

    @Override
    public void delete(String providerUserId) {
        if (providerUserId == null || providerUserId.isEmpty()) {
            return;
        }
        Map<String, AttributeValue> key = new HashMap<>();
        key.put(UpstreamTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(providerUserId).build());
        dynamoDbClient.deleteItem(
                DeleteItemRequest.builder().tableName(upstreamTokenConfig.tableName()).key(key).build());
    }

    private Map<String, AttributeValue> toItem(UpstreamTokenRecord record, long version) {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put(UpstreamTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(record.providerUserId()).build());
        item.put(UpstreamTableAttribute.ENCRYPTED_OKTA_REFRESH_TOKEN.attr(),
                AttributeValue.builder().s(record.encryptedOktaRefreshToken() != null ? record.encryptedOktaRefreshToken() : "").build());
        item.put(UpstreamTableAttribute.LAST_ROTATED_AT.attr(),
                AttributeValue.builder().s(record.lastRotatedAt() != null ? record.lastRotatedAt() : "").build());
        item.put(UpstreamTableAttribute.VERSION.attr(), AttributeValue.builder().n(String.valueOf(version)).build());
        item.put(UpstreamTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(record.ttl())).build());
        item.put(UpstreamTableAttribute.CREATED_AT.attr(),
                AttributeValue.builder().s(record.createdAt() != null ? record.createdAt() : "").build());
        item.put(UpstreamTableAttribute.UPDATED_AT.attr(),
                AttributeValue.builder().s(record.updatedAt() != null ? record.updatedAt() : "").build());
        String status = record.status() != null && !record.status().isEmpty()
                ? record.status() : UpstreamTokenRecord.STATUS_ACTIVE;
        item.put(UpstreamTableAttribute.STATUS.attr(), AttributeValue.builder().s(status).build());
        item.put(UpstreamTableAttribute.REVOKED_AT.attr(),
                AttributeValue.builder().s(record.revokedAt() != null ? record.revokedAt() : "").build());
        item.put(UpstreamTableAttribute.REVOKED_REASON.attr(),
                AttributeValue.builder().s(record.revokedReason() != null ? record.revokedReason() : "").build());
        item.put(UpstreamTableAttribute.ROTATION_COUNT.attr(),
                AttributeValue.builder().n(String.valueOf(Math.max(0L, record.rotationCount()))).build());
        // Always write the staged-AT trio so the row's DBE signature is stable; an absent
        // staged AT is encoded as empty string + 0 + 0.
        item.put(UpstreamTableAttribute.LAST_MINTED_ACCESS_TOKEN.attr(),
                AttributeValue.builder().s(record.lastMintedAccessToken() != null ? record.lastMintedAccessToken() : "").build());
        item.put(UpstreamTableAttribute.LAST_MINTED_AT_EXPIRES_AT.attr(),
                AttributeValue.builder().n(String.valueOf(Math.max(0L, record.lastMintedAtExpiresAt()))).build());
        item.put(UpstreamTableAttribute.LAST_MINTED_AT_ROTATION_VERSION.attr(),
                AttributeValue.builder().n(String.valueOf(Math.max(0L, record.lastMintedAtRotationVersion()))).build());
        return item;
    }

    private static UpstreamTokenRecord fromItem(Map<String, AttributeValue> item) {
        String providerUserId = s(item, UpstreamTableAttribute.PROVIDER_USER_ID.attr());
        String token = s(item, UpstreamTableAttribute.ENCRYPTED_OKTA_REFRESH_TOKEN.attr());
        String lastRotated = s(item, UpstreamTableAttribute.LAST_ROTATED_AT.attr());
        long version = n(item, UpstreamTableAttribute.VERSION.attr());
        long ttl = n(item, UpstreamTableAttribute.TTL.attr());
        String created = s(item, UpstreamTableAttribute.CREATED_AT.attr());
        String updated = s(item, UpstreamTableAttribute.UPDATED_AT.attr());
        // Backward compat: rows written before the soft-delete fields were introduced have no
        // status attribute. Treat those as ACTIVE so they continue to participate in refresh.
        String status = s(item, UpstreamTableAttribute.STATUS.attr());
        if (status == null || status.isEmpty()) {
            status = UpstreamTokenRecord.STATUS_ACTIVE;
        }
        String revokedAt = s(item, UpstreamTableAttribute.REVOKED_AT.attr());
        String revokedReason = s(item, UpstreamTableAttribute.REVOKED_REASON.attr());
        long rotationCount = n(item, UpstreamTableAttribute.ROTATION_COUNT.attr());
        // Backward compat: rows written before the staged-AT change have no last_minted_*
        // attributes. The DBE schema does include them now, so reads of those older rows will
        // still succeed (the missing attributes simply don't appear in the AttributeValue map);
        // {@code n}/{@code s} return 0/"" defaults and the record's stagedAtIsFresh() returns
        // false. The first successful refresh for that row populates them.
        String lastMintedAt = s(item, UpstreamTableAttribute.LAST_MINTED_ACCESS_TOKEN.attr());
        long lastMintedAtExpires = n(item, UpstreamTableAttribute.LAST_MINTED_AT_EXPIRES_AT.attr());
        long lastMintedAtRotationVersion = n(item, UpstreamTableAttribute.LAST_MINTED_AT_ROTATION_VERSION.attr());
        return new UpstreamTokenRecord(providerUserId, token, lastRotated, version, ttl, created, updated,
                status, revokedAt, revokedReason, rotationCount,
                lastMintedAt, lastMintedAtExpires, lastMintedAtRotationVersion);
    }

    private static String s(Map<String, AttributeValue> item, String attr) {
        AttributeValue v = item.get(attr);
        return v != null && v.s() != null ? v.s() : "";
    }

    private static long n(Map<String, AttributeValue> item, String attr) {
        AttributeValue v = item.get(attr);
        if (v == null || v.n() == null || v.n().isEmpty()) {
            return 0L;
        }
        try {
            return Long.parseLong(v.n());
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    private long computeActiveTtlEpochSeconds() {
        long expirySeconds = upstreamTokenConfig.expirySeconds();
        int bufferDays = upstreamTokenConfig.ttlBufferDays();
        return Instant.now().plus(expirySeconds, ChronoUnit.SECONDS).plus(bufferDays, ChronoUnit.DAYS).getEpochSecond();
    }

    private long computeRevokedTtlEpochSeconds() {
        int retentionDays = upstreamTokenConfig.revokedRetentionDays();
        return Instant.now().plus(retentionDays, ChronoUnit.DAYS).getEpochSecond();
    }
}
