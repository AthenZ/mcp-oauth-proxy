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

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.DynamoDbTablesEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMrkMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.DBEAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

@ApplicationScoped
public class DynamodbClientProvider {

    @ConfigProperty(name = "server.token-store.aws.kms.key-id")
    String kmsKeyId;

    @ConfigProperty(name = "server.token-store.aws.dynamodb.table-name")
    String tableName;

    private DynamoDbEncryptionInterceptor getDynamoDbEncryptionInterceptor() {
        final MaterialProviders matProv = MaterialProviders
                .builder()
                .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
                .build();
        final CreateAwsKmsMrkMultiKeyringInput keyringInput = CreateAwsKmsMrkMultiKeyringInput
                .builder()
                .generator(kmsKeyId)
                .build();
        final IKeyring kmsKeyring = matProv.CreateAwsKmsMrkMultiKeyring(keyringInput);

        final Map<String, CryptoAction> attributeActionsOnEncrypt = new HashMap<>();
        attributeActionsOnEncrypt.put(TokenTableAttribute.USER.attr(), CryptoAction.SIGN_ONLY); // Our partition attribute must be SIGN_ONLY
        attributeActionsOnEncrypt.put(TokenTableAttribute.PROVIDER.attr(), CryptoAction.SIGN_ONLY); // Our sort attribute must be SIGN_ONLY
        attributeActionsOnEncrypt.put(TokenTableAttribute.ID_TOKEN.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        attributeActionsOnEncrypt.put(TokenTableAttribute.ACCESS_TOKEN.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        attributeActionsOnEncrypt.put(TokenTableAttribute.REFRESH_TOKEN.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        attributeActionsOnEncrypt.put(TokenTableAttribute.AUTH_CODE_JSON.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        attributeActionsOnEncrypt.put(TokenTableAttribute.AUTH_TOKENS_JSON.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        attributeActionsOnEncrypt.put(TokenTableAttribute.TTL.attr(), CryptoAction.DO_NOTHING);

        final Map<String, DynamoDbTableEncryptionConfig> tableConfigs = new HashMap<>();
        tableConfigs.put(
                tableName,
                DynamoDbTableEncryptionConfig
                        .builder()
                        .logicalTableName(tableName)
                        .partitionKeyName(TokenTableAttribute.USER.attr())
                        .sortKeyName(TokenTableAttribute.PROVIDER.attr())
                        .attributeActionsOnEncrypt(attributeActionsOnEncrypt)
                        .allowedUnsignedAttributes(List.of(TokenTableAttribute.TTL.attr()))
                        .keyring(kmsKeyring)
                        .algorithmSuiteId(DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384)
                        .build()
        );

        return DynamoDbEncryptionInterceptor
                        .builder()
                        .config(
                                DynamoDbTablesEncryptionConfig
                                        .builder()
                                        .tableEncryptionConfigs(tableConfigs)
                                        .build()
                        )
                        .build();

    }

    @Produces
    public DynamoDbClient getDynamodbClient() {
        final DynamoDbEncryptionInterceptor encryptionInterceptor = getDynamoDbEncryptionInterceptor();

        return DynamoDbClient
                .builder()
                .overrideConfiguration(
                        ClientOverrideConfiguration
                                .builder()
                                .addExecutionInterceptor(encryptionInterceptor)
                                .build()
                )
                .build();
    }

    @Produces
    public DynamoDbAsyncClient getDynamodbAsyncClient() {
        final DynamoDbEncryptionInterceptor encryptionInterceptor = getDynamoDbEncryptionInterceptor();

        return DynamoDbAsyncClient.builder()
                .overrideConfiguration(
                        ClientOverrideConfiguration
                                .builder()
                                .addExecutionInterceptor(encryptionInterceptor)
                                .build()
                )
                .build();
    }
}

