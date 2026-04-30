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
        log.debug("upstream save: provider_user_id={} version={}", record.providerUserId(), version);
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
    public boolean updateWithVersionCheck(String providerUserId, String newPlainOktaRefreshToken, long expectedVersion) {
        if (providerUserId == null || providerUserId.isEmpty() || newPlainOktaRefreshToken == null) {
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
        String now = Instant.now().toString();
        long newVersion = expectedVersion + 1;
        long ttl = computeTtlEpochSeconds();

        Map<String, AttributeValue> item = new HashMap<>();
        item.put(UpstreamTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(providerUserId).build());
        item.put(UpstreamTableAttribute.ENCRYPTED_OKTA_REFRESH_TOKEN.attr(), AttributeValue.builder().s(newPlainOktaRefreshToken).build());
        item.put(UpstreamTableAttribute.LAST_ROTATED_AT.attr(), AttributeValue.builder().s(now).build());
        item.put(UpstreamTableAttribute.VERSION.attr(), AttributeValue.builder().n(String.valueOf(newVersion)).build());
        item.put(UpstreamTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(ttl)).build());
        item.put(UpstreamTableAttribute.CREATED_AT.attr(), AttributeValue.builder().s(current.createdAt() != null ? current.createdAt() : now).build());
        item.put(UpstreamTableAttribute.UPDATED_AT.attr(), AttributeValue.builder().s(now).build());

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
            return true;
        } catch (ConditionalCheckFailedException e) {
            log.debug("upstream version check failed for provider_user_id={}", providerUserId);
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
        return new UpstreamTokenRecord(providerUserId, token, lastRotated, version, ttl, created, updated);
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

    private long computeTtlEpochSeconds() {
        long expirySeconds = upstreamTokenConfig.expirySeconds();
        int bufferDays = upstreamTokenConfig.ttlBufferDays();
        return Instant.now().plus(expirySeconds, ChronoUnit.SECONDS).plus(bufferDays, ChronoUnit.DAYS).getEpochSecond();
    }
}
