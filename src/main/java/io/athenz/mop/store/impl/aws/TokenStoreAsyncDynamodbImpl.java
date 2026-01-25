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
import io.athenz.mop.model.AuthorizationCodeTokensDO;
import io.athenz.mop.store.EnterpriseStoreQualifier;
import io.athenz.mop.store.TokenStoreAsync;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.infrastructure.Infrastructure;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

@ApplicationScoped
@EnterpriseStoreQualifier
public class TokenStoreAsyncDynamodbImpl implements TokenStoreAsync {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    DynamoDbClient dynamoDbClient;

    @ConfigProperty(name = "server.token-store.aws.dynamodb.table-name")
    String tableName;

    ObjectMapper objectMapper = new ObjectMapper();

    @PostConstruct
    void init() {
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    @Override
    public Uni<String> storeTokenAsync(String id, String provider, AuthorizationCodeTokensDO token) {
        log.info("Storing auth code tokens on the server for id {}, resource {}", id, provider);

        String authTokensJson;
        try {
            authTokensJson = objectMapper.writeValueAsString(token);
        } catch (JsonProcessingException e) {
            log.error("unable to marshal auth tokens: {}", e.getMessage());
            throw new RuntimeException(e);
        }

        long ttl = Instant.now().getEpochSecond() + token.getAccessTokenExpiresIn();
        final HashMap<String, AttributeValue> item = new HashMap<>();
        item.put(TokenTableAttribute.USER.attr(), AttributeValue.builder().s(id).build());
        item.put(TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(provider).build());
        item.put(TokenTableAttribute.AUTH_TOKENS_JSON.attr(), AttributeValue.builder().s(authTokensJson).build());
        item.put(TokenTableAttribute.TTL.attr(), AttributeValue.builder().n(Long.toString(ttl)).build());

        final PutItemRequest putRequest = PutItemRequest
                .builder()
                .tableName(tableName)
                .item(item)
                .build();
        return Uni.createFrom().item(() -> dynamoDbClient.putItem(putRequest))
                .runSubscriptionOn(Infrastructure.getDefaultExecutor())
                .map(resp -> id);
    }

    @Override
    public Uni<AuthorizationCodeTokensDO> getTokenAsync(String id, String provider) {
        Map<String, AttributeValue> key = Map.of(
                TokenTableAttribute.USER.attr(), AttributeValue.builder().s(id).build(),
                TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(provider).build()
        );
        GetItemRequest req = GetItemRequest.builder()
                .tableName(tableName)
                .key(key)
                .consistentRead(true)
                .build();
        return Uni.createFrom().item(() -> dynamoDbClient.getItem(req)).flatMap(resp -> {
            Map<String, AttributeValue> item = resp.item();
            if (item == null || item.isEmpty()) {
                log.error("No auth code tokens found for id {}, resource {}", id, provider);
                return Uni.createFrom().failure(new RuntimeException("No auth code tokens found for id " + id));
            }
            String authTokensJson = item.get(TokenTableAttribute.AUTH_TOKENS_JSON.attr()).s();
            try {
                return Uni.createFrom().item(objectMapper.readValue(authTokensJson, AuthorizationCodeTokensDO.class));
            } catch (JsonProcessingException e) {
                log.error("unable to unmarshal auth code tokens: {}", e.getMessage());
                return Uni.createFrom().failure(e);
            }
        });
    }

    @Override
    public Uni<Boolean> deleteTokenAsync(String id, String provider) {
        Map<String, AttributeValue> key = Map.of(
                TokenTableAttribute.USER.attr(), AttributeValue.builder().s(id).build(),
                TokenTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(provider).build()
        );
        DeleteItemRequest req = DeleteItemRequest.builder()
                .tableName(tableName)
                .key(key)
                .build();
        return Uni.createFrom().item(() -> dynamoDbClient.deleteItem(req)).map(resp -> true);
    }
}
