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
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
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

    @ConfigProperty(name = "server.refresh-token.table-name", defaultValue = "")
    String refreshTokenTableName;

    @ConfigProperty(name = "server.token-store.aws.sts.role-arn")
    String stsRoleArn;

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
        attributeActionsOnEncrypt.put(TokenTableAttribute.ACCESS_TOKEN_HASH.attr(), CryptoAction.SIGN_ONLY); // GSI partition key must be SIGN_ONLY
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

        if (refreshTokenTableName != null && !refreshTokenTableName.isBlank()) {
            final Map<String, CryptoAction> refreshAttributeActions = new HashMap<>();
            refreshAttributeActions.put(RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), CryptoAction.SIGN_ONLY);
            refreshAttributeActions.put(RefreshTableAttribute.PROVIDER_USER_ID.attr(), CryptoAction.SIGN_ONLY);
            refreshAttributeActions.put(RefreshTableAttribute.REFRESH_TOKEN_HASH.attr(), CryptoAction.SIGN_ONLY);
            refreshAttributeActions.put(RefreshTableAttribute.USER_ID.attr(), CryptoAction.SIGN_ONLY);
            refreshAttributeActions.put(RefreshTableAttribute.PROVIDER.attr(), CryptoAction.SIGN_ONLY);
            refreshAttributeActions.put(RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), CryptoAction.SIGN_ONLY);
            refreshAttributeActions.put(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), CryptoAction.ENCRYPT_AND_SIGN);
            refreshAttributeActions.put(RefreshTableAttribute.STATUS.attr(), CryptoAction.SIGN_ONLY);
            refreshAttributeActions.put(RefreshTableAttribute.CLIENT_ID.attr(), CryptoAction.SIGN_ONLY);
            refreshAttributeActions.put(RefreshTableAttribute.PROVIDER_SUBJECT.attr(), CryptoAction.SIGN_ONLY);
            refreshAttributeActions.put(RefreshTableAttribute.ROTATED_FROM.attr(), CryptoAction.SIGN_ONLY);
            refreshAttributeActions.put(RefreshTableAttribute.REPLACED_BY.attr(), CryptoAction.SIGN_ONLY);
            refreshAttributeActions.put(RefreshTableAttribute.ROTATED_AT.attr(), CryptoAction.SIGN_ONLY);
            refreshAttributeActions.put(RefreshTableAttribute.ISSUED_AT.attr(), CryptoAction.SIGN_ONLY);
            refreshAttributeActions.put(RefreshTableAttribute.EXPIRES_AT.attr(), CryptoAction.SIGN_ONLY);
            refreshAttributeActions.put(RefreshTableAttribute.TTL.attr(), CryptoAction.DO_NOTHING);

            tableConfigs.put(
                    refreshTokenTableName,
                    DynamoDbTableEncryptionConfig
                            .builder()
                            .logicalTableName(refreshTokenTableName)
                            .partitionKeyName(RefreshTableAttribute.REFRESH_TOKEN_ID.attr())
                            .sortKeyName(RefreshTableAttribute.PROVIDER_USER_ID.attr())
                            .attributeActionsOnEncrypt(refreshAttributeActions)
                            .allowedUnsignedAttributes(List.of(RefreshTableAttribute.TTL.attr()))
                            .keyring(kmsKeyring)
                            .algorithmSuiteId(DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384)
                            .build()
            );
        }

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
        final StsAssumeRoleCredentialsProvider credentialsProvider = StsAssumeRoleCredentialsProvider
                .builder()
                .stsClient(StsClient.create())
                .refreshRequest(AssumeRoleRequest.builder()
                        .roleArn(stsRoleArn)
                        .roleSessionName("mcp-oauth-proxy-session")
                        .build())
                .build();

        return DynamoDbClient
                .builder()
                .credentialsProvider(credentialsProvider)
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
        final StsAssumeRoleCredentialsProvider credentialsProvider = StsAssumeRoleCredentialsProvider
                .builder()
                .stsClient(StsClient.create())
                .refreshRequest(AssumeRoleRequest.builder()
                        .roleArn(stsRoleArn)
                        .roleSessionName("mcp-oauth-proxy-session")
                        .build())
                .build();

        return DynamoDbAsyncClient.builder()
                .credentialsProvider(credentialsProvider)
                .overrideConfiguration(
                        ClientOverrideConfiguration
                                .builder()
                                .addExecutionInterceptor(encryptionInterceptor)
                                .build()
                )
                .build();
    }
}

