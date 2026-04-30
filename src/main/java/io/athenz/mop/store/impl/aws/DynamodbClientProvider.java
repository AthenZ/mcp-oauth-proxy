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

    @ConfigProperty(name = "server.upstream-token.table-name", defaultValue = "")
    String upstreamTokenTableName;

    @ConfigProperty(name = "server.token-store.aws.sts.role-arn")
    String stsRoleArn;

    /**
     * Creates an encryption interceptor for a single tokens table (e.g. for cross-region fallback client).
     * Uses the same encryption config as the main tokens table.
     */
    public DynamoDbEncryptionInterceptor createEncryptionInterceptorForTokensTable(String tokensTableName, String tokensKmsKeyId) {
        final Map<String, DynamoDbTableEncryptionConfig> tableConfigs = new HashMap<>();
        tableConfigs.put(tokensTableName, buildTokensTableEncryptionConfig(tokensTableName, tokensKmsKeyId));
        return wrapInInterceptor(tableConfigs);
    }

    /**
     * Creates an encryption interceptor that covers the user-tokens table plus, when a non-blank
     * name is supplied, the refresh-tokens and/or upstream-tokens tables. Used by the cross-region
     * fallback client to read from the peer region's copy of any of the three tables under the
     * shared MRK keyring.
     */
    public DynamoDbEncryptionInterceptor createEncryptionInterceptorForFallbackTables(
            String tokensTableName,
            String tokensKmsKeyId,
            String refreshTokensTableName,
            String upstreamTokensTableName) {
        final Map<String, DynamoDbTableEncryptionConfig> tableConfigs = new HashMap<>();
        if (tokensTableName != null && !tokensTableName.isBlank()) {
            tableConfigs.put(tokensTableName, buildTokensTableEncryptionConfig(tokensTableName, tokensKmsKeyId));
        }
        if (refreshTokensTableName != null && !refreshTokensTableName.isBlank()) {
            tableConfigs.put(refreshTokensTableName, buildRefreshTokensTableEncryptionConfig(refreshTokensTableName, tokensKmsKeyId));
        }
        if (upstreamTokensTableName != null && !upstreamTokensTableName.isBlank()) {
            tableConfigs.put(upstreamTokensTableName, buildUpstreamTokensTableEncryptionConfig(upstreamTokensTableName, tokensKmsKeyId));
        }
        return wrapInInterceptor(tableConfigs);
    }

    private static DynamoDbEncryptionInterceptor wrapInInterceptor(Map<String, DynamoDbTableEncryptionConfig> tableConfigs) {
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

    private DynamoDbTableEncryptionConfig buildTokensTableEncryptionConfig(String tokenTableName, String tokenKmsKeyId) {
        final MaterialProviders matProv = MaterialProviders
                .builder()
                .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
                .build();
        final CreateAwsKmsMrkMultiKeyringInput keyringInput = CreateAwsKmsMrkMultiKeyringInput
                .builder()
                .generator(tokenKmsKeyId)
                .build();
        final IKeyring kmsKeyring = matProv.CreateAwsKmsMrkMultiKeyring(keyringInput);

        final Map<String, CryptoAction> attributeActionsOnEncrypt = new HashMap<>();
        attributeActionsOnEncrypt.put(TokenTableAttribute.USER.attr(), CryptoAction.SIGN_ONLY);
        attributeActionsOnEncrypt.put(TokenTableAttribute.PROVIDER.attr(), CryptoAction.SIGN_ONLY);
        attributeActionsOnEncrypt.put(TokenTableAttribute.ACCESS_TOKEN_HASH.attr(), CryptoAction.SIGN_ONLY);
        attributeActionsOnEncrypt.put(TokenTableAttribute.ID_TOKEN.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        attributeActionsOnEncrypt.put(TokenTableAttribute.ACCESS_TOKEN.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        attributeActionsOnEncrypt.put(TokenTableAttribute.REFRESH_TOKEN.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        attributeActionsOnEncrypt.put(TokenTableAttribute.AUTH_CODE_JSON.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        attributeActionsOnEncrypt.put(TokenTableAttribute.AUTH_TOKENS_JSON.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        attributeActionsOnEncrypt.put(TokenTableAttribute.TTL.attr(), CryptoAction.DO_NOTHING);

        return DynamoDbTableEncryptionConfig
                .builder()
                .logicalTableName(tokenTableName)
                .partitionKeyName(TokenTableAttribute.USER.attr())
                .sortKeyName(TokenTableAttribute.PROVIDER.attr())
                .attributeActionsOnEncrypt(attributeActionsOnEncrypt)
                .allowedUnsignedAttributes(List.of(TokenTableAttribute.TTL.attr()))
                .keyring(kmsKeyring)
                .algorithmSuiteId(DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384)
                .build();
    }

    private DynamoDbTableEncryptionConfig buildRefreshTokensTableEncryptionConfig(String refreshTokensTableName, String refreshKmsKeyId) {
        final MaterialProviders matProv = MaterialProviders
                .builder()
                .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
                .build();
        final CreateAwsKmsMrkMultiKeyringInput keyringInput = CreateAwsKmsMrkMultiKeyringInput
                .builder()
                .generator(refreshKmsKeyId)
                .build();
        final IKeyring kmsKeyring = matProv.CreateAwsKmsMrkMultiKeyring(keyringInput);

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

        return DynamoDbTableEncryptionConfig
                .builder()
                .logicalTableName(refreshTokensTableName)
                .partitionKeyName(RefreshTableAttribute.REFRESH_TOKEN_ID.attr())
                .sortKeyName(RefreshTableAttribute.PROVIDER_USER_ID.attr())
                .attributeActionsOnEncrypt(refreshAttributeActions)
                .allowedUnsignedAttributes(List.of(RefreshTableAttribute.TTL.attr()))
                .keyring(kmsKeyring)
                .algorithmSuiteId(DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384)
                .build();
    }

    private DynamoDbTableEncryptionConfig buildUpstreamTokensTableEncryptionConfig(String upstreamTokensTableName, String upstreamKmsKeyId) {
        final MaterialProviders matProv = MaterialProviders
                .builder()
                .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
                .build();
        final CreateAwsKmsMrkMultiKeyringInput keyringInput = CreateAwsKmsMrkMultiKeyringInput
                .builder()
                .generator(upstreamKmsKeyId)
                .build();
        final IKeyring kmsKeyring = matProv.CreateAwsKmsMrkMultiKeyring(keyringInput);

        final Map<String, CryptoAction> upstreamAttributeActions = new HashMap<>();
        upstreamAttributeActions.put(UpstreamTableAttribute.PROVIDER_USER_ID.attr(), CryptoAction.SIGN_ONLY);
        upstreamAttributeActions.put(UpstreamTableAttribute.ENCRYPTED_OKTA_REFRESH_TOKEN.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        upstreamAttributeActions.put(UpstreamTableAttribute.LAST_ROTATED_AT.attr(), CryptoAction.SIGN_ONLY);
        upstreamAttributeActions.put(UpstreamTableAttribute.VERSION.attr(), CryptoAction.SIGN_ONLY);
        upstreamAttributeActions.put(UpstreamTableAttribute.CREATED_AT.attr(), CryptoAction.SIGN_ONLY);
        upstreamAttributeActions.put(UpstreamTableAttribute.UPDATED_AT.attr(), CryptoAction.SIGN_ONLY);
        upstreamAttributeActions.put(UpstreamTableAttribute.TTL.attr(), CryptoAction.DO_NOTHING);

        return DynamoDbTableEncryptionConfig
                .builder()
                .logicalTableName(upstreamTokensTableName)
                .partitionKeyName(UpstreamTableAttribute.PROVIDER_USER_ID.attr())
                .attributeActionsOnEncrypt(upstreamAttributeActions)
                .allowedUnsignedAttributes(List.of(UpstreamTableAttribute.TTL.attr()))
                .keyring(kmsKeyring)
                .algorithmSuiteId(DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384)
                .build();
    }

    private DynamoDbEncryptionInterceptor getDynamoDbEncryptionInterceptor() {
        final Map<String, DynamoDbTableEncryptionConfig> tableConfigs = new HashMap<>();
        tableConfigs.put(tableName, buildTokensTableEncryptionConfig(tableName, kmsKeyId));

        if (refreshTokenTableName != null && !refreshTokenTableName.isBlank()) {
            tableConfigs.put(refreshTokenTableName,
                    buildRefreshTokensTableEncryptionConfig(refreshTokenTableName, kmsKeyId));
        }

        if (upstreamTokenTableName != null && !upstreamTokenTableName.isBlank()) {
            tableConfigs.put(upstreamTokenTableName,
                    buildUpstreamTokensTableEncryptionConfig(upstreamTokenTableName, kmsKeyId));
        }

        return wrapInInterceptor(tableConfigs);
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

