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
    public void storeUserToken(String user, String provider, TokenWrapper token) {
        log.info("Storing token for user {}, provider {}", user, provider);

        final HashMap<String, AttributeValue> item = new HashMap<>();
        item.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(user).build());
        item.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(provider).build());
        item.put(TokenTableAttribute.ID_TOKEN.attr(), AttributeValue.builder().s(token.idToken()).build());
        item.put(TokenTableAttribute.ACCESS_TOKEN.attr(), AttributeValue.builder().s(token.accessToken()).build());
        item.put(TokenTableAttribute.REFRESH_TOKEN.attr(), AttributeValue.builder().s(token.refreshToken()).build());
        item.put(TokenTableAttribute.TTL.attr(), AttributeValue.builder().n(token.ttl().toString()).build());

        final PutItemRequest putRequest = PutItemRequest
                .builder()
                .tableName(tableName)
                .item(item)
                .build();

        final PutItemResponse putResponse = dynamoDbClient.putItem(putRequest);
        log.info("storeUserToken: key={}, provider={} HTTPStatusCode={}", user, provider, putResponse.sdkHttpResponse().statusCode());
    }

    @Override
    public TokenWrapper getUserToken(String user, String provider) {

        final GetItemResponse getResponse = queryTable(user, provider);
        log.info("getUserToken: key={}, provider={} HTTPStatusCode={}", user, provider, getResponse.sdkHttpResponse().statusCode());

        final Map<String, AttributeValue> returnedItem = getResponse.item();
        TokenWrapper token = null;
        if (returnedItem != null && !returnedItem.isEmpty()) {
            token = new TokenWrapper(user, provider,
                    returnedItem.get(TokenTableAttribute.ID_TOKEN.attr()).s(), returnedItem.get(TokenTableAttribute.ACCESS_TOKEN.attr()).s(), 
                    returnedItem.get(TokenTableAttribute.REFRESH_TOKEN.attr()).s(), Long.parseLong(returnedItem.get(TokenTableAttribute.TTL.attr()).n()));
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
        String codePrefixForLog = code.substring(0, Math.min(8, code.length()));
        final GetItemResponse getResponse = queryTable(code, provider);
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
        String codePrefixForLog = code.substring(0, Math.min(8, code.length()));
        final HashMap<String, AttributeValue> codeKey = new HashMap<>();
        codeKey.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(code).build());
        codeKey.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(provider).build());
        final DeleteItemRequest deleteRequest = DeleteItemRequest
                .builder()
                .key(codeKey)
                .tableName(tableName)
                .build();
        final DeleteItemResponse deleteResponse = dynamoDbClient.deleteItem(deleteRequest);
        log.info("deleteAuthCode: code={} resource={} HTTPStatusCode={}", codePrefixForLog, provider, deleteResponse.sdkHttpResponse().statusCode());
    }

    private GetItemResponse queryTable(String code, String provider) {
        final HashMap<String, AttributeValue> codeKey = new HashMap<>();
        codeKey.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(code).build());
        codeKey.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(provider).build());

        final GetItemRequest getRequest = GetItemRequest
                .builder()
                .key(codeKey)
                .tableName(tableName)
                .build();

        return dynamoDbClient.getItem(getRequest);
    }
}
