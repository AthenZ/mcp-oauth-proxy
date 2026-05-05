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

        return DynamoDbTableEncryptionConfig
                .builder()
                .logicalTableName(tokenTableName)
                .partitionKeyName(TokenTableAttribute.USER.attr())
                .sortKeyName(TokenTableAttribute.PROVIDER.attr())
                .attributeActionsOnEncrypt(buildTokensAttributeActions())
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

        return DynamoDbTableEncryptionConfig
                .builder()
                .logicalTableName(refreshTokensTableName)
                .partitionKeyName(RefreshTableAttribute.REFRESH_TOKEN_ID.attr())
                .sortKeyName(RefreshTableAttribute.PROVIDER_USER_ID.attr())
                .attributeActionsOnEncrypt(buildRefreshTokensAttributeActions())
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

        return DynamoDbTableEncryptionConfig
                .builder()
                .logicalTableName(upstreamTokensTableName)
                .partitionKeyName(UpstreamTableAttribute.PROVIDER_USER_ID.attr())
                .attributeActionsOnEncrypt(buildUpstreamTokensAttributeActions())
                .allowedUnsignedAttributes(List.of(UpstreamTableAttribute.TTL.attr()))
                .keyring(kmsKeyring)
                .algorithmSuiteId(DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384)
                .build();
    }

    /*
     * Action-map builders for the AWS DynamoDB Encryption Client (DBE).
     *
     * DBE operates on a closed-world principle: every attribute written to a DBE-wrapped table
     * must have an explicit {@link CryptoAction} declared in {@code attributeActionsOnEncrypt},
     * otherwise PutItem fails at runtime with "No Crypto Action configured for attribute X".
     * The interceptor cannot infer intent — defaulting to plaintext could leak secrets, defaulting
     * to encrypted could break query paths — so column additions are an explicit security decision.
     *
     * These builders are pulled out of the encryption-config builders above so a unit test can
     * assert coverage against the corresponding attribute enum without needing real KMS or STS.
     * If you add a new attribute to one of the {@code *TableAttribute} enums, you must register
     * an action here too. {@code DynamodbClientProviderSchemaTest} fails the build if you forget.
     */
    static Map<String, CryptoAction> buildTokensAttributeActions() {
        final Map<String, CryptoAction> actions = new HashMap<>();
        actions.put(TokenTableAttribute.USER.attr(), CryptoAction.SIGN_ONLY);
        actions.put(TokenTableAttribute.PROVIDER.attr(), CryptoAction.SIGN_ONLY);
        actions.put(TokenTableAttribute.ACCESS_TOKEN_HASH.attr(), CryptoAction.SIGN_ONLY);
        actions.put(TokenTableAttribute.ID_TOKEN.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(TokenTableAttribute.ACCESS_TOKEN.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(TokenTableAttribute.REFRESH_TOKEN.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(TokenTableAttribute.AUTH_CODE_JSON.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(TokenTableAttribute.AUTH_TOKENS_JSON.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(TokenTableAttribute.TTL.attr(), CryptoAction.DO_NOTHING);
        return actions;
    }

    static Map<String, CryptoAction> buildRefreshTokensAttributeActions() {
        final Map<String, CryptoAction> actions = new HashMap<>();
        actions.put(RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.PROVIDER_USER_ID.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.REFRESH_TOKEN_HASH.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.USER_ID.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.PROVIDER.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.AUDIENCE.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(RefreshTableAttribute.STATUS.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.CLIENT_ID.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.PROVIDER_SUBJECT.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.ROTATED_FROM.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.REPLACED_BY.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.ROTATED_AT.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.ISSUED_AT.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.EXPIRES_AT.attr(), CryptoAction.SIGN_ONLY);
        actions.put(RefreshTableAttribute.TTL.attr(), CryptoAction.DO_NOTHING);
        return actions;
    }

    static Map<String, CryptoAction> buildUpstreamTokensAttributeActions() {
        final Map<String, CryptoAction> actions = new HashMap<>();
        actions.put(UpstreamTableAttribute.PROVIDER_USER_ID.attr(), CryptoAction.SIGN_ONLY);
        actions.put(UpstreamTableAttribute.ENCRYPTED_OKTA_REFRESH_TOKEN.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(UpstreamTableAttribute.LAST_ROTATED_AT.attr(), CryptoAction.SIGN_ONLY);
        actions.put(UpstreamTableAttribute.VERSION.attr(), CryptoAction.SIGN_ONLY);
        actions.put(UpstreamTableAttribute.CREATED_AT.attr(), CryptoAction.SIGN_ONLY);
        actions.put(UpstreamTableAttribute.UPDATED_AT.attr(), CryptoAction.SIGN_ONLY);
        actions.put(UpstreamTableAttribute.TTL.attr(), CryptoAction.DO_NOTHING);
        actions.put(UpstreamTableAttribute.STATUS.attr(), CryptoAction.SIGN_ONLY);
        actions.put(UpstreamTableAttribute.REVOKED_AT.attr(), CryptoAction.SIGN_ONLY);
        actions.put(UpstreamTableAttribute.REVOKED_REASON.attr(), CryptoAction.SIGN_ONLY);
        actions.put(UpstreamTableAttribute.ROTATION_COUNT.attr(), CryptoAction.SIGN_ONLY);
        // Staged-AT columns: written atomically with the rotated RT in updateWithVersionCheck so
        // a second client arriving at the L2 lock within a 30-second grace can copy the AT into
        // its own per-client cells without issuing a fresh upstream refresh. The AT itself is a
        // credential and therefore ENCRYPT_AND_SIGN; the timestamp/version metadata is signed so
        // the grace window cannot be extended by tampering with the stored row.
        actions.put(UpstreamTableAttribute.LAST_MINTED_ACCESS_TOKEN.attr(), CryptoAction.ENCRYPT_AND_SIGN);
        actions.put(UpstreamTableAttribute.LAST_MINTED_AT_EXPIRES_AT.attr(), CryptoAction.SIGN_ONLY);
        actions.put(UpstreamTableAttribute.LAST_MINTED_AT_ROTATION_VERSION.attr(), CryptoAction.SIGN_ONLY);
        return actions;
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

