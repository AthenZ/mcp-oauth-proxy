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

import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.store.EnterpriseStoreQualifier;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

/**
 * When enabled (e.g. in us-east-1 and us-west-2 production), allows /userinfo to look up
 * the token in the other region's DynamoDB table if not found in the local region.
 * Delegates actual lookup to {@link TokenStoreDynamodbImpl} with the fallback client/table.
 */
@ApplicationScoped
public class UserInfoCrossRegionFallback {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @ConfigProperty(name = "server.userinfo.cross-region-fallback.enabled", defaultValue = "false")
    boolean enabled;

    @ConfigProperty(name = "server.userinfo.cross-region-fallback.region")
    Optional<String> fallbackRegion;

    @ConfigProperty(name = "server.userinfo.cross-region-fallback.table-name")
    Optional<String> fallbackTableName;

    @ConfigProperty(name = "server.userinfo.cross-region-fallback.kms.key-id")
    Optional<String> fallbackKmsKeyId;

    @ConfigProperty(name = "server.userinfo.cross-region-fallback.sts.role-arn")
    Optional<String> fallbackStsRoleArn;

    @Inject
    DynamodbClientProvider dynamodbClientProvider;

    @Inject
    @EnterpriseStoreQualifier
    TokenStoreDynamodbImpl tokenStoreDynamodb;

    private DynamoDbClient fallbackClient;
    private String fallbackTableNameResolved;

    @PostConstruct
    void init() {
        String region = fallbackRegion.map(String::trim).filter(s -> !s.isEmpty()).orElse(null);
        String tableName = fallbackTableName.map(String::trim).filter(s -> !s.isEmpty()).orElse(null);
        String kmsKeyId = fallbackKmsKeyId.map(String::trim).filter(s -> !s.isEmpty()).orElse(null);
        String stsRoleArn = fallbackStsRoleArn.map(String::trim).filter(s -> !s.isEmpty()).orElse(null);
        if (!enabled || region == null || tableName == null || kmsKeyId == null || stsRoleArn == null) {
            log.info("Userinfo cross-region fallback disabled or incomplete config");
            return;
        }
        try {
            DynamoDbEncryptionInterceptor encryptionInterceptor = dynamodbClientProvider
                    .createEncryptionInterceptorForTokensTable(tableName, kmsKeyId);
            StsAssumeRoleCredentialsProvider credentialsProvider = StsAssumeRoleCredentialsProvider
                    .builder()
                    .stsClient(StsClient.builder().region(Region.of(region)).build())
                    .refreshRequest(AssumeRoleRequest.builder()
                            .roleArn(stsRoleArn)
                            .roleSessionName("mcp-oauth-proxy-userinfo-fallback")
                            .build())
                    .build();

            fallbackClient = DynamoDbClient
                    .builder()
                    .region(Region.of(region))
                    .credentialsProvider(credentialsProvider)
                    .overrideConfiguration(
                            ClientOverrideConfiguration
                                    .builder()
                                    .addExecutionInterceptor(encryptionInterceptor)
                                    .build()
                    )
                    .build();
            fallbackTableNameResolved = tableName;
            log.info("Userinfo cross-region fallback enabled for region={} table={}", region, tableName);
        } catch (Exception e) {
            log.warn("Failed to build userinfo cross-region fallback client: {}", e.getMessage());
        }
    }

    /**
     * Look up token by access token hash in the fallback region's DynamoDB. Returns null if fallback
     * is disabled, client failed to build, or token not found.
     */
    public TokenWrapper getUserTokenByAccessTokenHash(String accessTokenHash) {
        if (fallbackClient == null) {
            return null;
        }
        try {
            TokenWrapper token = tokenStoreDynamodb.getUserTokenByAccessTokenHash(fallbackClient, fallbackTableNameResolved, accessTokenHash);
            if (token != null) {
                String regionLabel = fallbackRegion != null ? fallbackRegion.orElse("") : "";
                log.info("Found token in fallback region {} for user: {}, provider: {}", regionLabel, token.key(), token.provider());
            }
            return token;
        } catch (Exception e) {
            log.warn("Fallback region bearer credential lookup failed: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Look up user token (e.g. okta) by user and provider in the fallback region. Returns null if
     * fallback is disabled, client failed to build, or token not found.
     */
    public TokenWrapper getUserToken(String user, String provider) {
        if (fallbackClient == null) {
            return null;
        }
        try {
            return tokenStoreDynamodb.getUserToken(fallbackClient, fallbackTableNameResolved, user, provider);
        } catch (Exception e) {
            log.warn("Fallback region getUserToken failed for user={} provider={}: {}", user, provider, e.getMessage());
            return null;
        }
    }
}
