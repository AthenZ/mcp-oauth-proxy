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

import io.athenz.mop.service.RefreshLockStore;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

/**
 * DynamoDB-backed distributed lock for refresh coordination.
 * Lock table: PK lock_key (S), attributes lock_owner (S), lock_expires_at (N), ttl (N).
 * No encryption; lock table is not in the encryption config.
 */
@ApplicationScoped
public class RefreshLockStoreDynamodbImpl implements RefreshLockStore {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String LOCK_KEY = "lock_key";
    private static final String LOCK_OWNER = "lock_owner";
    private static final String LOCK_EXPIRES_AT = "lock_expires_at";
    private static final String TTL = "ttl";

    @Inject
    DynamoDbClient dynamoDbClient;

    @ConfigProperty(name = "server.refresh-lock.table-name", defaultValue = "mcp-oauth-proxy-refresh-locks")
    String tableName;

    @Override
    public boolean tryAcquire(String lockKey, String owner, long expiresAt) {
        if (lockKey == null || lockKey.isEmpty() || owner == null || owner.isEmpty()) {
            return false;
        }
        long now = System.currentTimeMillis() / 1000;
        long ttlValue = expiresAt + 86400; // TTL = expires_at + 1 day for DynamoDB cleanup

        Map<String, AttributeValue> item = new HashMap<>();
        item.put(LOCK_KEY, AttributeValue.builder().s(lockKey).build());
        item.put(LOCK_OWNER, AttributeValue.builder().s(owner).build());
        item.put(LOCK_EXPIRES_AT, AttributeValue.builder().n(String.valueOf(expiresAt)).build());
        item.put(TTL, AttributeValue.builder().n(String.valueOf(ttlValue)).build());

        String condition = "attribute_not_exists(#owner) OR #exp < :now";
        Map<String, String> names = new HashMap<>();
        names.put("#owner", LOCK_OWNER);
        names.put("#exp", LOCK_EXPIRES_AT);
        Map<String, AttributeValue> values = new HashMap<>();
        values.put(":now", AttributeValue.builder().n(String.valueOf(now)).build());

        try {
            dynamoDbClient.putItem(PutItemRequest.builder()
                    .tableName(tableName)
                    .item(item)
                    .conditionExpression(condition)
                    .expressionAttributeNames(names)
                    .expressionAttributeValues(values)
                    .build());
            log.debug("Refresh lock acquired lockKey={} owner={}", lockKey, owner);
            return true;
        } catch (ConditionalCheckFailedException e) {
            log.debug("Refresh lock not acquired (held by another) lockKey={}", lockKey);
            return false;
        }
    }

    @Override
    public void release(String lockKey, String owner) {
        if (lockKey == null || lockKey.isEmpty()) {
            return;
        }
        Map<String, AttributeValue> key = new HashMap<>();
        key.put(LOCK_KEY, AttributeValue.builder().s(lockKey).build());
        String condition = "#owner = :owner";
        Map<String, String> names = new HashMap<>();
        names.put("#owner", LOCK_OWNER);
        Map<String, AttributeValue> values = new HashMap<>();
        values.put(":owner", AttributeValue.builder().s(owner != null ? owner : "").build());

        try {
            dynamoDbClient.deleteItem(DeleteItemRequest.builder()
                    .tableName(tableName)
                    .key(key)
                    .conditionExpression(condition)
                    .expressionAttributeNames(names)
                    .expressionAttributeValues(values)
                    .build());
            log.debug("Refresh lock released lockKey={} owner={}", lockKey, owner);
        } catch (ConditionalCheckFailedException e) {
            log.debug("Refresh lock release skipped (not owner or already gone) lockKey={}", lockKey);
        }
    }
}
