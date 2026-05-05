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

import io.athenz.mop.model.BearerIndexRecord;
import io.athenz.mop.store.BearerIndexStore;
import io.athenz.mop.store.EnterpriseStoreQualifier;
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
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemResponse;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemResponse;

/**
 * DynamoDB implementation of {@link BearerIndexStore} backed by the
 * {@code mcp-oauth-proxy-bearer-index} table. The row carries no token material — it is purely a
 * pointer keyed by {@code H(bearer)}, so we reuse the existing application DynamoDB client (no
 * encryption interceptor entries required for this table).
 */
@ApplicationScoped
@EnterpriseStoreQualifier
public class BearerIndexStoreDynamodbImpl implements BearerIndexStore {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    DynamoDbClient dynamoDbClient;

    @ConfigProperty(name = "server.bearer-index.table-name")
    String tableName;

    @Override
    public void putBearer(String accessTokenHash, String userId, String clientId, String provider,
                          long exp, long ttl) {
        putBearer(dynamoDbClient, tableName, accessTokenHash, userId, clientId, provider, exp, ttl);
    }

    /**
     * Static helper used both by the primary store and by tests / cross-region paths so the
     * hash-keyed item layout lives in exactly one place.
     */
    public static void putBearer(DynamoDbClient client, String table, String accessTokenHash,
                                 String userId, String clientId, String provider,
                                 long exp, long ttl) {
        if (accessTokenHash == null || accessTokenHash.isEmpty()) {
            log.warn("bearer-index put skipped: empty accessTokenHash");
            return;
        }
        Map<String, AttributeValue> item = new HashMap<>();
        item.put(BearerIndexTableAttribute.ACCESS_TOKEN_HASH.attr(),
                AttributeValue.builder().s(accessTokenHash).build());
        if (userId != null && !userId.isEmpty()) {
            item.put(BearerIndexTableAttribute.USER_ID.attr(),
                    AttributeValue.builder().s(userId).build());
        }
        if (clientId != null && !clientId.isEmpty()) {
            item.put(BearerIndexTableAttribute.CLIENT_ID.attr(),
                    AttributeValue.builder().s(clientId).build());
        }
        if (provider != null && !provider.isEmpty()) {
            item.put(BearerIndexTableAttribute.PROVIDER.attr(),
                    AttributeValue.builder().s(provider).build());
        }
        item.put(BearerIndexTableAttribute.EXP.attr(),
                AttributeValue.builder().n(Long.toString(exp)).build());
        item.put(BearerIndexTableAttribute.TTL.attr(),
                AttributeValue.builder().n(Long.toString(ttl)).build());

        PutItemRequest req = PutItemRequest.builder().tableName(table).item(item).build();
        PutItemResponse res = client.putItem(req);
        log.debug("bearer-index put: userId={} clientId={} provider={} exp={} ttl={} status={}",
                userId, clientId, provider, exp, ttl, res.sdkHttpResponse().statusCode());
    }

    @Override
    public BearerIndexRecord getBearer(String accessTokenHash) {
        return getBearer(dynamoDbClient, tableName, accessTokenHash);
    }

    /**
     * Static fetch used both by the primary store and by the cross-region fallback path
     * ({@link CrossRegionTokenStoreFallback#getBearerIndex(String)}).
     */
    public static BearerIndexRecord getBearer(DynamoDbClient client, String table, String accessTokenHash) {
        if (accessTokenHash == null || accessTokenHash.isEmpty()) {
            return null;
        }
        Map<String, AttributeValue> key = new HashMap<>();
        key.put(BearerIndexTableAttribute.ACCESS_TOKEN_HASH.attr(),
                AttributeValue.builder().s(accessTokenHash).build());
        GetItemResponse res = client.getItem(GetItemRequest.builder().tableName(table).key(key).build());
        Map<String, AttributeValue> item = res.item();
        if (item == null || item.isEmpty()) {
            return null;
        }
        String userId = stringOrEmpty(item, BearerIndexTableAttribute.USER_ID);
        String clientId = stringOrEmpty(item, BearerIndexTableAttribute.CLIENT_ID);
        String provider = stringOrEmpty(item, BearerIndexTableAttribute.PROVIDER);
        long exp = numberOrZero(item, BearerIndexTableAttribute.EXP);
        long ttl = numberOrZero(item, BearerIndexTableAttribute.TTL);
        return new BearerIndexRecord(accessTokenHash, userId, clientId, provider, exp, ttl);
    }

    @Override
    public void deleteBearer(String accessTokenHash) {
        deleteBearer(dynamoDbClient, tableName, accessTokenHash);
    }

    /**
     * Static delete used both by the primary store and by tests / cross-region paths. Failures
     * are swallowed at the caller boundary; this method itself simply propagates.
     */
    public static void deleteBearer(DynamoDbClient client, String table, String accessTokenHash) {
        if (accessTokenHash == null || accessTokenHash.isEmpty()) {
            return;
        }
        Map<String, AttributeValue> key = new HashMap<>();
        key.put(BearerIndexTableAttribute.ACCESS_TOKEN_HASH.attr(),
                AttributeValue.builder().s(accessTokenHash).build());
        DeleteItemResponse res = client.deleteItem(DeleteItemRequest.builder().tableName(table).key(key).build());
        log.debug("bearer-index delete: status={}", res.sdkHttpResponse().statusCode());
    }

    private static String stringOrEmpty(Map<String, AttributeValue> item, BearerIndexTableAttribute attr) {
        AttributeValue v = item.get(attr.attr());
        return (v == null || v.s() == null) ? "" : v.s();
    }

    private static long numberOrZero(Map<String, AttributeValue> item, BearerIndexTableAttribute attr) {
        AttributeValue v = item.get(attr.attr());
        if (v == null || v.n() == null) {
            return 0L;
        }
        try {
            return Long.parseLong(v.n());
        } catch (NumberFormatException e) {
            return 0L;
        }
    }
}
