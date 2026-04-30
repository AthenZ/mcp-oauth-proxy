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
package io.athenz.mop.service;

import io.athenz.mop.model.RefreshTokenLockKey;
import io.athenz.mop.model.RefreshTokenRecord;
import io.athenz.mop.model.RefreshTokenRotateResult;
import io.athenz.mop.model.RefreshTokenValidationResult;
import io.athenz.mop.store.impl.aws.RefreshTableAttribute;
import io.athenz.mop.store.impl.aws.RefreshTableConstants;
import io.athenz.mop.store.impl.aws.RefreshTokenStoreDynamodbHelpers;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.Put;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;

@ApplicationScoped
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final int TOKEN_BYTES = 32;
    private static final String TOKEN_PREFIX = "rt_";
    private static final String SHA_256 = "SHA-256";

    private final SecureRandom secureRandom = new SecureRandom();

    @Inject
    DynamoDbClient dynamoDbClient;

    /**
     * Optional cross-region resolver. When the bean is present (always in production), reads on
     * {@code refresh_token_hash} (validate / replay / lock-key lookup), {@code refresh_token_id}
     * primary-key fetch (rotate), and the user-provider GSI (getUpstreamRefreshToken) consult the
     * peer region's table after a local miss. Writes (rotate / store / revokeFamily) stay local.
     */
    @Inject
    RefreshTokenRegionResolver refreshTokenRegionResolver;

    @ConfigProperty(name = "server.refresh-token.table-name")
    String tableName;

    @ConfigProperty(name = "server.refresh-token.expiry-seconds", defaultValue = "7776000")
    long expirySeconds;

    @ConfigProperty(name = "server.refresh-token.ttl-buffer-days", defaultValue = "7")
    int ttlBufferDays;

    @Override
    public String generateSecureToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return TOKEN_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Override
    public String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256);
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 unavailable", e);
        }
    }

    /** Constant-time comparison for sensitive values. Uses MessageDigest.isEqual to avoid timing leaks. */
    static boolean secureEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        byte[] aa = a.getBytes(StandardCharsets.UTF_8);
        byte[] bb = b.getBytes(StandardCharsets.UTF_8);
        if (aa.length != bb.length) {
            return false;
        }
        return java.security.MessageDigest.isEqual(aa, bb);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Override
    public String store(String userId, String clientId, String provider, String providerSubject,
                       String upstreamRefreshToken) {
        String refreshTokenId = UUID.randomUUID().toString();
        String rawToken = generateSecureToken();
        String tokenHash = hashToken(rawToken);
        String providerUserId = provider + "#" + userId;
        long now = System.currentTimeMillis() / 1000;
        long expiresAt = now + expirySeconds;
        long ttl = expiresAt + (ttlBufferDays * 86400L);

        Map<String, AttributeValue> item = new HashMap<>();
        item.put(RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s(refreshTokenId).build());
        item.put(RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(providerUserId).build());
        item.put(RefreshTableAttribute.REFRESH_TOKEN_HASH.attr(), AttributeValue.builder().s(tokenHash).build());
        item.put(RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s(userId).build());
        item.put(RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s(clientId).build());
        item.put(RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(provider).build());
        item.put(RefreshTableAttribute.PROVIDER_SUBJECT.attr(), AttributeValue.builder().s(providerSubject != null ? providerSubject : "").build());
        if (upstreamRefreshToken != null && !upstreamRefreshToken.isEmpty()) {
            item.put(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), AttributeValue.builder().s(upstreamRefreshToken).build());
        }
        item.put(RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build());
        item.put(RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), AttributeValue.builder().s(refreshTokenId).build());
        item.put(RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n(String.valueOf(now)).build());
        item.put(RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(expiresAt)).build());
        item.put(RefreshTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(ttl)).build());

        dynamoDbClient.putItem(PutItemRequest.builder().tableName(tableName).item(item).build());
        log.info("store: saved refresh token refresh_token_id={} userId={} provider={} client_id={} expires_at={}",
                refreshTokenId, userId, provider, clientId, expiresAt);
        return rawToken;
    }

    @Override
    public Optional<RefreshTokenLockKey> lookupUserIdAndProviderForLock(String refreshToken, String clientId) {
        if (refreshToken == null || refreshToken.isEmpty() || clientId == null || clientId.isEmpty()) {
            return Optional.empty();
        }
        String hash = hashToken(refreshToken);
        RefreshTokenRecord record = lookupByHash(hash);
        if (record == null || !clientId.equals(record.clientId())) {
            return Optional.empty();
        }
        return Optional.of(new RefreshTokenLockKey(record.userId(), record.provider()));
    }

    @Override
    public RefreshTokenValidationResult validate(String refreshToken, String clientId) {
        if (refreshToken == null || refreshToken.isEmpty() || clientId == null || clientId.isEmpty()) {
            log.info("validate: invalid grant - missing refresh_token or client_id");
            return RefreshTokenValidationResult.invalid();
        }
        String hash = hashToken(refreshToken);
        log.debug("validate: refresh_token lookup by hash client_id={} (hash redacted)", clientId);
        RefreshTokenRecord record = lookupByHash(hash);
        if (record == null) {
            log.info("validate: invalid grant - no record found for refresh token (client_id={})", clientId);
            return RefreshTokenValidationResult.invalid();
        }
        long now = System.currentTimeMillis() / 1000;
        log.info("validate: found record refresh_token_id={} status={} expires_at={} now={} userId={}",
                record.refreshTokenId(), record.status(), record.expiresAt(), now, record.userId());
        if (now > record.expiresAt()) {
            log.info("validate: invalid grant - refresh token expired; userId={} provider={} expires_at={} now={}",
                    record.userId(), record.provider(), record.expiresAt(), now);
            return RefreshTokenValidationResult.invalid();
        }
        if (!clientId.equals(record.clientId())) {
            log.info("validate: invalid grant - client_id mismatch; stored={} request={}", record.clientId(), clientId);
            return RefreshTokenValidationResult.invalid();
        }
        switch (record.status()) {
            case RefreshTableConstants.STATUS_REVOKED:
                return RefreshTokenValidationResult.revoked(record);
            case RefreshTableConstants.STATUS_ROTATED:
                return RefreshTokenValidationResult.rotatedReplay(record);
            case RefreshTableConstants.STATUS_ACTIVE:
                return RefreshTokenValidationResult.active(record);
            default:
                log.info("validate: invalid grant - unknown status={}; userId={}", record.status(), record.userId());
                return RefreshTokenValidationResult.invalid();
        }
    }

    @Override
    public RefreshTokenRotateResult rotate(String refreshToken, String clientId) {
        RefreshTokenValidationResult result = validate(refreshToken, clientId);
        if (result.status() != RefreshTokenValidationResult.Status.ACTIVE || result.record() == null) {
            return null;
        }
        RefreshTokenRecord current = result.record();
        long now = System.currentTimeMillis() / 1000;
        String newTokenId = UUID.randomUUID().toString();
        String newRawToken = generateSecureToken();
        String newHash = hashToken(newRawToken);
        String providerUserId = current.provider() + "#" + current.userId();

        Map<String, AttributeValue> currentItem = getItemByPrimaryKey(current.refreshTokenId(), current.providerUserId());
        if (currentItem == null) {
            log.warn("rotate: current row not found by primary key");
            return null;
        }
        Map<String, AttributeValue> currentItemAsRotated = new HashMap<>(currentItem);
        currentItemAsRotated.put(RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ROTATED).build());
        currentItemAsRotated.put(RefreshTableAttribute.REPLACED_BY.attr(), AttributeValue.builder().s(newTokenId).build());
        currentItemAsRotated.put(RefreshTableAttribute.ROTATED_AT.attr(), AttributeValue.builder().n(String.valueOf(now)).build());
        TransactWriteItem putCurrent = TransactWriteItem.builder()
            .put(Put.builder()
                .tableName(tableName)
                .item(currentItemAsRotated)
                .conditionExpression("#s = :active")
                .expressionAttributeNames(Map.of("#s", RefreshTableAttribute.STATUS.attr()))
                .expressionAttributeValues(Map.of(":active", AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build()))
                .build())
            .build();

        Map<String, AttributeValue> newItem = new HashMap<>();
        newItem.put(RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s(newTokenId).build());
        newItem.put(RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(providerUserId).build());
        newItem.put(RefreshTableAttribute.REFRESH_TOKEN_HASH.attr(), AttributeValue.builder().s(newHash).build());
        newItem.put(RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s(current.userId()).build());
        newItem.put(RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s(current.clientId()).build());
        newItem.put(RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(current.provider()).build());
        newItem.put(RefreshTableAttribute.PROVIDER_SUBJECT.attr(), AttributeValue.builder().s(current.providerSubject() != null ? current.providerSubject() : "").build());
        if (!AudienceConstants.PROVIDER_OKTA.equals(current.provider())
                && current.encryptedUpstreamRefreshToken() != null && !current.encryptedUpstreamRefreshToken().isEmpty()) {
            newItem.put(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), AttributeValue.builder().s(current.encryptedUpstreamRefreshToken()).build());
        }
        newItem.put(RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build());
        newItem.put(RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), AttributeValue.builder().s(current.tokenFamilyId()).build());
        newItem.put(RefreshTableAttribute.ROTATED_FROM.attr(), AttributeValue.builder().s(current.refreshTokenId()).build());
        newItem.put(RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n(String.valueOf(now)).build());
        newItem.put(RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(current.expiresAt())).build());
        newItem.put(RefreshTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(current.ttl())).build());

        TransactWriteItem putNew = TransactWriteItem.builder()
            .put(Put.builder()
                .tableName(tableName)
                .item(newItem)
                .build())
            .build();

        try {
            dynamoDbClient.transactWriteItems(TransactWriteItemsRequest.builder()
                .transactItems(List.of(putCurrent, putNew))
                .build());
        } catch (ConditionalCheckFailedException e) {
            log.debug("Rotation conditional check failed (concurrent rotation); treating as replay");
            handleReplay(refreshToken);
            return null;
        } catch (Exception e) {
            log.warn("rotate: TransactWriteItems failed; userId={} provider={} error={}", current.userId(), current.provider(), e.getMessage());
            return null;
        }

        return new RefreshTokenRotateResult(newRawToken, newTokenId, providerUserId);
    }

    @Override
    public void revokeFamily(String tokenFamilyId) {
        if (tokenFamilyId == null || tokenFamilyId.isEmpty()) return;
        QueryResponse response = dynamoDbClient.query(QueryRequest.builder()
            .tableName(tableName)
            .indexName(RefreshTableConstants.GSI_TOKEN_FAMILY)
            .keyConditionExpression(RefreshTableAttribute.TOKEN_FAMILY_ID.attr() + " = :fid")
            .expressionAttributeValues(Map.of(":fid", AttributeValue.builder().s(tokenFamilyId).build()))
            .build());
        List<Map<String, AttributeValue>> items = response.items();
        if (items == null || items.isEmpty()) return;
        for (Map<String, AttributeValue> item : items) {
            Map<String, AttributeValue> itemWithRevoked = new HashMap<>(item);
            itemWithRevoked.put(RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_REVOKED).build());
            dynamoDbClient.putItem(PutItemRequest.builder().tableName(tableName).item(itemWithRevoked).build());
        }
    }

    @Override
    public void handleReplay(String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) return;
        String hash = hashToken(refreshToken);
        RefreshTokenRecord record = lookupByHash(hash);
        if (record != null) {
            log.warn("Refresh token replay detected; revoking family tokenFamilyId={} userId={}", record.tokenFamilyId(), record.userId());
            revokeFamily(record.tokenFamilyId());
        }
    }

    @Override
    public String getUpstreamRefreshToken(String userId, String provider) {
        if (userId == null || userId.isEmpty() || provider == null || provider.isEmpty()) {
            return null;
        }
        RefreshTokenRecord best = refreshTokenRegionResolver != null
                ? refreshTokenRegionResolver.resolveBestUpstream(userId, provider).record()
                : RefreshTokenStoreDynamodbHelpers.queryBestUpstreamRefresh(dynamoDbClient, tableName, userId, provider);
        if (best == null || best.encryptedUpstreamRefreshToken() == null || best.encryptedUpstreamRefreshToken().isEmpty()) {
            return null;
        }
        return best.encryptedUpstreamRefreshToken();
    }

    private RefreshTokenRecord lookupByHash(String hash) {
        if (refreshTokenRegionResolver != null) {
            RefreshTokenResolution resolution = refreshTokenRegionResolver.resolveByHash(hash);
            log.debug("lookupByHash: resolver returned record={} fromFallback={} (hash redacted)",
                    resolution.record() != null, resolution.resolvedFromFallback());
            return resolution.record();
        }
        RefreshTokenRecord record = RefreshTokenStoreDynamodbHelpers.lookupByHash(dynamoDbClient, tableName, hash);
        log.debug("lookupByHash: returned record={} (hash redacted)", record != null);
        return record;
    }

    @Override
    public void updateUpstreamRefreshForToken(String mopRefreshToken, String newUpstreamRefresh) {
        if (mopRefreshToken == null || mopRefreshToken.isEmpty()
                || newUpstreamRefresh == null || newUpstreamRefresh.isEmpty()) {
            return;
        }
        String hash = hashToken(mopRefreshToken);
        RefreshTokenRecord record = lookupByHash(hash);
        if (record == null) {
            log.warn("updateUpstreamRefreshForToken: no row found for MOP token hash");
            return;
        }
        Map<String, AttributeValue> currentItem = getItemByPrimaryKey(record.refreshTokenId(), record.providerUserId());
        if (currentItem == null) {
            log.warn("updateUpstreamRefreshForToken: row not found by primary key");
            return;
        }
        Map<String, AttributeValue> updatedItem = new HashMap<>(currentItem);
        updatedItem.put(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), AttributeValue.builder().s(newUpstreamRefresh).build());
        dynamoDbClient.putItem(PutItemRequest.builder().tableName(tableName).item(updatedItem).build());
    }

    @Override
    public void updateUpstreamRefreshForToken(String refreshTokenId, String providerUserId, String newUpstreamRefresh) {
        if (refreshTokenId == null || refreshTokenId.isEmpty() || providerUserId == null || providerUserId.isEmpty()
                || newUpstreamRefresh == null || newUpstreamRefresh.isEmpty()) {
            return;
        }
        Map<String, AttributeValue> currentItem = getItemByPrimaryKey(refreshTokenId, providerUserId);
        if (currentItem == null) {
            log.warn("updateUpstreamRefreshForToken: row not found by primary key refreshTokenId={} providerUserId={}", refreshTokenId, providerUserId);
            return;
        }
        Map<String, AttributeValue> updatedItem = new HashMap<>(currentItem);
        updatedItem.put(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), AttributeValue.builder().s(newUpstreamRefresh).build());
        dynamoDbClient.putItem(PutItemRequest.builder().tableName(tableName).item(updatedItem).build());
        log.debug("updateUpstreamRefreshForToken: updated upstream token for refreshTokenId={}", refreshTokenId);
    }

    @Override
    public void updateUpstreamRefreshForAllRowsWithUserAndProvider(String userId, String provider, String newUpstreamRefresh) {
        if (userId == null || userId.isEmpty() || provider == null || provider.isEmpty()
                || newUpstreamRefresh == null || newUpstreamRefresh.isEmpty()) {
            return;
        }
        Map<String, AttributeValue> exprValues = new HashMap<>(Map.of(
                ":uid", AttributeValue.builder().s(userId).build(),
                ":prov", AttributeValue.builder().s(provider).build(),
                ":active", AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build()));
        QueryResponse response = dynamoDbClient.query(QueryRequest.builder()
            .tableName(tableName)
            .indexName(RefreshTableConstants.GSI_USER_PROVIDER)
            .keyConditionExpression(
                RefreshTableAttribute.USER_ID.attr() + " = :uid AND " + RefreshTableAttribute.PROVIDER.attr() + " = :prov")
            .filterExpression("#s = :active")
            .expressionAttributeNames(Map.of("#s", RefreshTableAttribute.STATUS.attr()))
            .expressionAttributeValues(exprValues)
            .build());
        List<Map<String, AttributeValue>> items = response.items();
        if (items == null || items.isEmpty()) {
            log.debug("updateUpstreamRefreshForAllRowsWithUserAndProvider: no rows for userId={} provider={}", userId, provider);
            return;
        }
        for (Map<String, AttributeValue> item : items) {
            Map<String, AttributeValue> updatedItem = new HashMap<>(item);
            updatedItem.put(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), AttributeValue.builder().s(newUpstreamRefresh).build());
            dynamoDbClient.putItem(PutItemRequest.builder().tableName(tableName).item(updatedItem).build());
        }
        log.info("updateUpstreamRefreshForAllRowsWithUserAndProvider: updated {} row(s) for userId={} provider={}",
                items.size(), userId, provider);
    }

    public RefreshTokenRecord getByPrimaryKey(String refreshTokenId, String providerUserId) {
        Map<String, AttributeValue> item = getItemByPrimaryKey(refreshTokenId, providerUserId);
        return item == null ? null : RefreshTokenStoreDynamodbHelpers.itemToRecord(item);
    }

    /**
     * Local-then-peer PK lookup. Used by {@code rotate} so a row that was just rotated/written in
     * the peer region is still found here even if the global-table replication has not landed
     * locally yet. Returns {@code null} when both regions miss.
     */
    private Map<String, AttributeValue> getItemByPrimaryKey(String refreshTokenId, String providerUserId) {
        Map<String, AttributeValue> local = RefreshTokenStoreDynamodbHelpers.getItemByPrimaryKey(
                dynamoDbClient, tableName, refreshTokenId, providerUserId);
        if (local != null) {
            return local;
        }
        if (refreshTokenRegionResolver != null) {
            return refreshTokenRegionResolver.resolveItemByPrimaryKey(refreshTokenId, providerUserId);
        }
        return null;
    }
}
