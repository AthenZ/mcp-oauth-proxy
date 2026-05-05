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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.athenz.mop.model.AuthorizationCode;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.store.AuthCodeStore;
import io.athenz.mop.store.EnterpriseStoreQualifier;
import io.athenz.mop.store.TokenStore;
import io.athenz.mop.util.JwtUtils;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

@ApplicationScoped
@EnterpriseStoreQualifier
public class TokenStoreDynamodbImpl implements TokenStore, AuthCodeStore {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    DynamoDbClient dynamoDbClient;

    @ConfigProperty(name = "server.token-store.aws.dynamodb.table-name")
    String tableName;

    @ConfigProperty(name = "server.athenz.user-prefix")
    String userPrefix;

    ObjectMapper objectMapper = new ObjectMapper();

    @PostConstruct
    void init() {
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    @Override
    public void storeUserToken(String user, String provider, String clientId, TokenWrapper token) {
        // The per-client (clientId#userId, provider) row in mcp-oauth-proxy-tokens is no longer
        // written. Every minted bearer is now indexed in the dedicated mcp-oauth-proxy-bearer-index
        // table (BearerIndexStore), keyed by H(bearer), so /userinfo resolves siblings without
        // GSI clobbering. This overload remains on the interface so legacy callers stay
        // source-compatible during rollout, but it is intentionally a no-op.
        log.debug("storeUserToken(clientId): no-op for user={} provider={} clientId={} (bearer-index handles per-client lookup)",
                user, provider, clientId);
    }

    @Override
    public void storeUserToken(String user, String provider, TokenWrapper token) {
        log.info("Storing token for user {}, provider {} (no clientId; bare row for upstream session marker / Okta SSO)", user, provider);
        putUserTokenItem(user, provider, token);
    }

    /**
     * Compose the DynamoDB partition-key value for a per-MCP-client bearer row. Falls back
     * to the bare userId when {@code clientId} is null or blank so unauthenticated edge
     * paths degrade to today's behavior instead of stuffing a placeholder into the table.
     * Sanitizes any '#' inside {@code clientId} (defense-in-depth; DCR registration also
     * rejects '#').
     */
    static String compositeUserKey(String clientId, String user) {
        if (clientId == null || clientId.isEmpty()) {
            return user;
        }
        String safeClientId = clientId.indexOf('#') >= 0 ? clientId.replace("#", "_") : clientId;
        return safeClientId + "#" + user;
    }

    private void putUserTokenItem(String partitionKey, String provider, TokenWrapper token) {
        final HashMap<String, AttributeValue> item = new HashMap<>();
        item.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(partitionKey).build());
        item.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(provider).build());

        if (token.idToken() != null) {
            item.put(TokenTableAttribute.ID_TOKEN.attr(), AttributeValue.builder().s(token.idToken()).build());
        }

        item.put(TokenTableAttribute.ACCESS_TOKEN.attr(), AttributeValue.builder().s(token.accessToken()).build());
        String accessTokenHash = JwtUtils.hashAccessToken(token.accessToken());
        item.put(TokenTableAttribute.ACCESS_TOKEN_HASH.attr(), AttributeValue.builder().s(accessTokenHash).build());

        if (token.refreshToken() != null) {
            item.put(TokenTableAttribute.REFRESH_TOKEN.attr(), AttributeValue.builder().s(token.refreshToken()).build());
        }

        item.put(TokenTableAttribute.TTL.attr(), AttributeValue.builder().n(token.ttl().toString()).build());

        final PutItemRequest putRequest = PutItemRequest
                .builder()
                .tableName(tableName)
                .item(item)
                .build();

        final PutItemResponse putResponse = dynamoDbClient.putItem(putRequest);
        log.info("storeUserToken: partitionKey={}, provider={} HTTPStatusCode={}", partitionKey, provider, putResponse.sdkHttpResponse().statusCode());
    }

    @Override
    public void deleteUserToken(String user, String provider) {
        deleteUserToken(dynamoDbClient, tableName, user, provider);
    }

    public void deleteUserToken(DynamoDbClient client, String table, String user, String provider) {
        final HashMap<String, AttributeValue> key = new HashMap<>();
        key.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(user).build());
        key.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(provider).build());
        DeleteItemResponse response = client.deleteItem(DeleteItemRequest.builder().key(key).tableName(table).build());
        log.info("deleteUserToken: key={}, provider={} HTTPStatusCode={}", user, provider, response.sdkHttpResponse().statusCode());
    }

    @Override
    public TokenWrapper getUserToken(String user, String provider) {
        return getUserToken(dynamoDbClient, tableName, user, provider);
    }

    /**
     * Look up user token by partition and sort key using the given client and table.
     * Used by the primary store and by cross-region fallback with an alternate client/table.
     */
    public TokenWrapper getUserToken(DynamoDbClient client, String table, String user, String provider) {
        final GetItemResponse getResponse = queryTable(client, table, user, provider);
        log.info("getUserToken: key={}, provider={} HTTPStatusCode={}", user, provider, getResponse.sdkHttpResponse().statusCode());
        TokenWrapper token = mapItemToTokenWrapper(getResponse.item(), user, provider);
        if (token != null && token.isExpired()) {
            log.info("Token expired for key={}, provider={}, ttl={} — deleting stale row", user, provider, token.ttl());
            deleteUserToken(client, table, user, provider);
            return null;
        }
        if (token != null) {
            log.info("fetched token for lookupKey: {} user: {}, provider: {} with ttl: {}", user, user, provider, token.ttl());
        }
        return token;
    }

    @Override
    public void storeAuthCode(String code, String provider, AuthorizationCode codeObj) {
        String codePrefixForLog = code.substring(0, Math.min(8, code.length()));
        log.info("Storing authorization code {}, provider {}", codePrefixForLog, provider);
        String authCodeJson;
        try {
            authCodeJson = objectMapper.writeValueAsString(codeObj);
        } catch (JsonProcessingException e) {
            log.error("unable to marshal auth code: {}", e.getMessage());
            throw new RuntimeException(e);
        }
        final HashMap<String, AttributeValue> item = new HashMap<>();
        item.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(code).build());
        item.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(provider).build());
        item.put(TokenTableAttribute.AUTH_CODE_JSON.attr(), AttributeValue.builder().s(authCodeJson).build());
        item.put(TokenTableAttribute.TTL.attr(), AttributeValue.builder().n(Long.valueOf(codeObj.getExpiresAt().getEpochSecond()).toString()).build());

        final PutItemRequest putRequest = PutItemRequest
                .builder()
                .tableName(tableName)
                .item(item)
                .build();

        final PutItemResponse putResponse = dynamoDbClient.putItem(putRequest);
        log.info("storeAuthCode: code={} provider={} HTTPStatusCode={}", codePrefixForLog, provider, putResponse.sdkHttpResponse().statusCode());
    }

    @Override
    public AuthorizationCode getAuthCode(String code, String provider) {
        return getAuthCode(dynamoDbClient, tableName, code, provider);
    }

    /**
     * Look up authorization code using the given client and table (primary store or cross-region fallback).
     */
    public AuthorizationCode getAuthCode(DynamoDbClient client, String table, String code, String provider) {
        String codePrefixForLog = code.substring(0, Math.min(8, code.length()));
        final GetItemResponse getResponse = queryTable(client, table, code, provider);
        log.info("getAuthCode: code={}, provider={} HTTPStatusCode={}", codePrefixForLog, provider, getResponse.sdkHttpResponse().statusCode());

        final Map<String, AttributeValue> returnedItem = getResponse.item();
        AuthorizationCode authCode = null;
        if (returnedItem != null && !returnedItem.isEmpty()) {
            String authCodeJson = returnedItem.get(TokenTableAttribute.AUTH_CODE_JSON.attr()).s();
            try {
                authCode = objectMapper.readValue(authCodeJson, AuthorizationCode.class);
            } catch (JsonProcessingException e) {
                log.error("unable to unmarshal auth code: {}", e.getMessage());
                throw new RuntimeException(e);
            }
            log.info("fetched auth code for lookupKey={} provider={}", codePrefixForLog, provider);
        }
        return authCode;
    }

    @Override
    public void deleteAuthCode(String code, String provider) {
        deleteAuthCode(dynamoDbClient, tableName, code, provider);
    }

    /**
     * Delete authorization code using the given client and table (primary store or cross-region fallback).
     */
    public void deleteAuthCode(DynamoDbClient client, String table, String code, String provider) {
        String codePrefixForLog = code.substring(0, Math.min(8, code.length()));
        final HashMap<String, AttributeValue> codeKey = new HashMap<>();
        codeKey.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(code).build());
        codeKey.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(provider).build());
        final DeleteItemRequest deleteRequest = DeleteItemRequest
                .builder()
                .key(codeKey)
                .tableName(table)
                .build();
        final DeleteItemResponse deleteResponse = client.deleteItem(deleteRequest);
        log.info("deleteAuthCode: code={} resource={} HTTPStatusCode={}", codePrefixForLog, provider, deleteResponse.sdkHttpResponse().statusCode());
    }

    private GetItemResponse queryTable(DynamoDbClient client, String table, String partitionKey, String sortKey) {
        final HashMap<String, AttributeValue> key = new HashMap<>();
        key.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(partitionKey).build());
        key.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(sortKey).build());
        return client.getItem(GetItemRequest.builder().key(key).tableName(table).build());
    }

    @Override
    public TokenWrapper getUserTokenByAccessTokenHash(String accessTokenHash) {
        return getUserTokenByAccessTokenHash(dynamoDbClient, tableName, accessTokenHash);
    }

    /**
     * Look up token by access token hash (GSI) using the given client and table.
     * Used by the primary store and by cross-region fallback with an alternate client/table.
     */
    public TokenWrapper getUserTokenByAccessTokenHash(DynamoDbClient client, String table, String accessTokenHash) {
        log.info("Looking up user token by bearer credential (hash not logged)");
        QueryRequest queryRequest = QueryRequest.builder()
                .tableName(table)
                .indexName("access-token-hash-index")
                .keyConditionExpression("access_token_hash = :hash")
                .expressionAttributeValues(Map.of(
                        ":hash", AttributeValue.builder().s(accessTokenHash).build()
                ))
                .build();

        QueryResponse queryResponse = client.query(queryRequest);
        log.debug("getUserTokenByAccessTokenHash: HTTPStatusCode={} (access_token_hash redacted)",
                queryResponse.sdkHttpResponse().statusCode());
        if (queryResponse.items() != null && !queryResponse.items().isEmpty()) {
            Map<String, AttributeValue> item = queryResponse.items().get(0);
            String user = item.get(TokenTableAttribute.USER.attr()).s();
            String provider = item.get(TokenTableAttribute.PROVIDER.attr()).s();
            TokenWrapper token = mapItemToTokenWrapper(item, user, provider);
            if (token != null && token.isExpired()) {
                log.info("Token expired for user={}, provider={}, ttl={} — deleting stale row", user, provider, token.ttl());
                deleteUserToken(client, table, user, provider);
                return null;
            }
            if (token != null) {
                log.info("Found token for user: {}, provider: {} with ttl: {}", user, provider, token.ttl());
            }
            return token;
        }
        log.info("No token found for bearer credential lookup");
        return null;
    }

    private static TokenWrapper mapItemToTokenWrapper(Map<String, AttributeValue> item, String user, String provider) {
        if (item == null || item.isEmpty()) {
            return null;
        }
        String idToken = item.containsKey(TokenTableAttribute.ID_TOKEN.attr())
                ? item.get(TokenTableAttribute.ID_TOKEN.attr()).s()
                : null;
        String refreshToken = item.containsKey(TokenTableAttribute.REFRESH_TOKEN.attr())
                ? item.get(TokenTableAttribute.REFRESH_TOKEN.attr()).s()
                : null;
        // The row's persisted partition key (USER attribute) is authoritative when present:
        // GSI lookups (access-token-hash-index) project the partition key into the row, so
        // even when callers pass us a different "user" value (e.g. the bare userId for a
        // /userinfo lookup that resolved through the hash GSI), we recover the original
        // composite key here. For per-MCP-client rows the partition key is "<clientId>#<userId>"
        // (see compositeUserKey); we split it so /userinfo can surface mcp_client_id while
        // downstream Okta/upstream-IDP lookups by (userId, provider) keep using the bare userId.
        String storedUser = item.containsKey(TokenTableAttribute.USER.attr())
                ? item.get(TokenTableAttribute.USER.attr()).s()
                : user;
        String bareUserId = storedUser;
        String extractedClientId = null;
        if (storedUser != null) {
            int hashIdx = storedUser.indexOf('#');
            if (hashIdx >= 0) {
                extractedClientId = storedUser.substring(0, hashIdx);
                bareUserId = storedUser.substring(hashIdx + 1);
            }
        }
        return new TokenWrapper(bareUserId, provider,
                idToken,
                item.get(TokenTableAttribute.ACCESS_TOKEN.attr()).s(),
                refreshToken,
                Long.parseLong(item.get(TokenTableAttribute.TTL.attr()).n()),
                extractedClientId);
    }
}
