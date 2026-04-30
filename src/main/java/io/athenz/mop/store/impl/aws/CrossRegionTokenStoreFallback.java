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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.athenz.mop.model.AuthorizationCode;
import io.athenz.mop.model.AuthorizationCodeTokensDO;
import io.athenz.mop.model.RefreshTokenRecord;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.model.UpstreamTokenRecord;
import io.athenz.mop.store.EnterpriseStoreQualifier;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.util.Map;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

/**
 * When enabled (e.g. in us-east-1 and us-west-2 production), allows reading from the peer region's
 * DynamoDB tokens table if not found locally — used for /userinfo, MoP authorization code resolution
 * (POST /token, IdP callbacks), etc. Delegates to {@link TokenStoreDynamodbImpl} with the fallback client/table.
 */
@ApplicationScoped
public class CrossRegionTokenStoreFallback {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @ConfigProperty(name = "server.cross-region-fallback.enabled", defaultValue = "false")
    boolean enabled;

    @ConfigProperty(name = "server.cross-region-fallback.region")
    Optional<String> fallbackRegion;

    @ConfigProperty(name = "server.cross-region-fallback.table-name")
    Optional<String> fallbackTableName;

    @ConfigProperty(name = "server.cross-region-fallback.kms.key-id")
    Optional<String> fallbackKmsKeyId;

    @ConfigProperty(name = "server.cross-region-fallback.sts.role-arn")
    Optional<String> fallbackStsRoleArn;

    @ConfigProperty(name = "server.cross-region-fallback.refresh-token.table-name")
    Optional<String> fallbackRefreshTokenTableName;

    @ConfigProperty(name = "server.cross-region-fallback.upstream-token.table-name")
    Optional<String> fallbackUpstreamTokenTableName;

    @Inject
    DynamodbClientProvider dynamodbClientProvider;

    @Inject
    @EnterpriseStoreQualifier
    TokenStoreDynamodbImpl tokenStoreDynamodb;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    private DynamoDbClient fallbackClient;
    private String fallbackTableNameResolved;
    private String fallbackRefreshTokenTableNameResolved;
    private String fallbackUpstreamTokenTableNameResolved;
    private final ObjectMapper objectMapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    /**
     * True when {@code server.cross-region-fallback.enabled} is set (e.g. prod). Used to gate cross-region-only
     * metrics so stage/single-region deployments do not increment them on ordinary “not found” paths.
     */
    public boolean isActive() {
        return enabled;
    }

    @PostConstruct
    void init() {
        String region = fallbackRegion.map(String::trim).filter(s -> !s.isEmpty()).orElse(null);
        String tableName = fallbackTableName.map(String::trim).filter(s -> !s.isEmpty()).orElse(null);
        String kmsKeyId = fallbackKmsKeyId.map(String::trim).filter(s -> !s.isEmpty()).orElse(null);
        String stsRoleArn = fallbackStsRoleArn.map(String::trim).filter(s -> !s.isEmpty()).orElse(null);
        if (!enabled || region == null || tableName == null || kmsKeyId == null || stsRoleArn == null) {
            log.info("Cross-region DynamoDB fallback disabled or incomplete config");
            return;
        }
        String refreshTokenTable = fallbackRefreshTokenTableName.map(String::trim).filter(s -> !s.isEmpty()).orElse(null);
        String upstreamTokenTable = fallbackUpstreamTokenTableName.map(String::trim).filter(s -> !s.isEmpty()).orElse(null);
        try {
            DynamoDbEncryptionInterceptor encryptionInterceptor = dynamodbClientProvider
                    .createEncryptionInterceptorForFallbackTables(tableName, kmsKeyId, refreshTokenTable, upstreamTokenTable);
            StsAssumeRoleCredentialsProvider credentialsProvider = StsAssumeRoleCredentialsProvider
                    .builder()
                    .stsClient(StsClient.builder().region(Region.of(region)).build())
                    .refreshRequest(AssumeRoleRequest.builder()
                            .roleArn(stsRoleArn)
                            .roleSessionName("mcp-oauth-proxy-cross-region-fallback")
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
            fallbackRefreshTokenTableNameResolved = refreshTokenTable;
            fallbackUpstreamTokenTableNameResolved = upstreamTokenTable;
            log.info("Cross-region DynamoDB fallback enabled for region={} userTokensTable={} refreshTokensTable={} upstreamTokensTable={}",
                    region, tableName, refreshTokenTable, upstreamTokenTable);
        } catch (Exception e) {
            log.warn("Failed to build cross-region DynamoDB fallback client: {}", e.getMessage());
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
            oauthProxyMetrics.recordCrossRegionDynamoFailure(
                    "getUserTokenByAccessTokenHash", e.getClass().getSimpleName(), "unknown");
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
            oauthProxyMetrics.recordCrossRegionDynamoFailure(
                    "getUserToken", e.getClass().getSimpleName(), provider != null ? provider : "unknown");
            return null;
        }
    }

    /**
     * Look up MoP authorization code in the fallback region's tokens table.
     */
    public AuthorizationCode getAuthCode(String code, String provider) {
        if (fallbackClient == null) {
            return null;
        }
        try {
            AuthorizationCode authCode = tokenStoreDynamodb.getAuthCode(fallbackClient, fallbackTableNameResolved, code, provider);
            if (authCode != null) {
                String regionLabel = fallbackRegion != null ? fallbackRegion.map(String::trim).orElse("") : "";
                log.info("Found authorization code in fallback region {}", regionLabel);
            }
            return authCode;
        } catch (Exception e) {
            log.warn("Fallback region getAuthCode failed: {}", e.getMessage());
            oauthProxyMetrics.recordCrossRegionDynamoFailure(
                    "getAuthCode", e.getClass().getSimpleName(), provider != null ? provider : "unknown");
            return null;
        }
    }

    /**
     * Delete MoP authorization code from the fallback region's table (after successful consume in /token).
     */
    public void deleteAuthCode(String code, String provider) {
        if (fallbackClient == null) {
            return;
        }
        try {
            tokenStoreDynamodb.deleteAuthCode(fallbackClient, fallbackTableNameResolved, code, provider);
        } catch (Exception e) {
            log.warn("Fallback region deleteAuthCode failed: {}", e.getMessage());
            oauthProxyMetrics.recordCrossRegionDynamoFailure(
                    "deleteAuthCode", e.getClass().getSimpleName(), provider != null ? provider : "unknown");
        }
    }

    /**
     * Look up the auth-code-tokens row ({@code auth_tokens_json}) in the fallback region's
     * user-tokens table. Returns {@code null} when the fallback is disabled, the client failed to
     * build, or the row was not found.
     */
    public AuthorizationCodeTokensDO getTokenAsync(String id, String provider) {
        if (fallbackClient == null) {
            return null;
        }
        try {
            AuthorizationCodeTokensDO token = TokenStoreAsyncDynamodbImpl.getTokenSync(
                    fallbackClient, fallbackTableNameResolved, id, provider, objectMapper);
            if (token != null) {
                String regionLabel = fallbackRegion.map(String::trim).orElse("");
                log.info("Found auth code tokens in fallback region {} for id={} provider={}",
                        regionLabel, id, provider);
            }
            return token;
        } catch (Exception e) {
            log.warn("Fallback region getTokenAsync failed for id={} provider={}: {}", id, provider, e.getMessage());
            oauthProxyMetrics.recordCrossRegionDynamoFailure(
                    "getTokenAsync", e.getClass().getSimpleName(), provider != null ? provider : "unknown");
            return null;
        }
    }

    /**
     * Look up a refresh-token row in the fallback region by hash (GSI). Returns {@code null} when
     * the fallback is disabled, the refresh-token table is not configured for fallback, the client
     * failed to build, or the row was not found.
     */
    public RefreshTokenRecord lookupRefreshTokenByHash(String hash) {
        if (fallbackClient == null || fallbackRefreshTokenTableNameResolved == null) {
            return null;
        }
        try {
            RefreshTokenRecord record = RefreshTokenStoreDynamodbHelpers.lookupByHash(
                    fallbackClient, fallbackRefreshTokenTableNameResolved, hash);
            if (record != null) {
                String regionLabel = fallbackRegion.map(String::trim).orElse("");
                log.info("Found refresh token in fallback region {} for refresh_token_id={} userId={} provider={}",
                        regionLabel, record.refreshTokenId(), record.userId(), record.provider());
            }
            return record;
        } catch (Exception e) {
            log.warn("Fallback region lookupRefreshTokenByHash failed: {}", e.getMessage());
            oauthProxyMetrics.recordCrossRegionDynamoFailure(
                    "lookupRefreshTokenByHash", e.getClass().getSimpleName(), "unknown");
            return null;
        }
    }

    /**
     * Fetch a refresh-token row in the fallback region by primary key. Returns {@code null} on
     * miss, fallback disabled, refresh-token table not configured for fallback, or any failure.
     */
    public Map<String, AttributeValue> getRefreshTokenItemByPrimaryKey(String refreshTokenId, String providerUserId) {
        if (fallbackClient == null || fallbackRefreshTokenTableNameResolved == null) {
            return null;
        }
        try {
            Map<String, AttributeValue> item = RefreshTokenStoreDynamodbHelpers.getItemByPrimaryKey(
                    fallbackClient, fallbackRefreshTokenTableNameResolved, refreshTokenId, providerUserId);
            if (item != null) {
                String regionLabel = fallbackRegion.map(String::trim).orElse("");
                log.info("Found refresh token row by primary key in fallback region {} for refresh_token_id={} provider_user_id={}",
                        regionLabel, refreshTokenId, providerUserId);
            }
            return item;
        } catch (Exception e) {
            log.warn("Fallback region getRefreshTokenItemByPrimaryKey failed: {}", e.getMessage());
            oauthProxyMetrics.recordCrossRegionDynamoFailure(
                    "getRefreshTokenItemByPrimaryKey", e.getClass().getSimpleName(), "unknown");
            return null;
        }
    }

    /**
     * Query the user-provider GSI on the fallback region's refresh-tokens table and return the best
     * non-revoked, unexpired record. Returns {@code null} on miss / failure / fallback disabled.
     */
    public RefreshTokenRecord queryBestUpstreamRefresh(String userId, String provider) {
        if (fallbackClient == null || fallbackRefreshTokenTableNameResolved == null) {
            return null;
        }
        try {
            RefreshTokenRecord record = RefreshTokenStoreDynamodbHelpers.queryBestUpstreamRefresh(
                    fallbackClient, fallbackRefreshTokenTableNameResolved, userId, provider);
            if (record != null) {
                String regionLabel = fallbackRegion.map(String::trim).orElse("");
                log.info("Found best upstream refresh in fallback region {} for userId={} provider={} refresh_token_id={}",
                        regionLabel, userId, provider, record.refreshTokenId());
            }
            return record;
        } catch (Exception e) {
            log.warn("Fallback region queryBestUpstreamRefresh failed for userId={} provider={}: {}",
                    userId, provider, e.getMessage());
            oauthProxyMetrics.recordCrossRegionDynamoFailure(
                    "queryBestUpstreamRefresh", e.getClass().getSimpleName(), provider != null ? provider : "unknown");
            return null;
        }
    }

    /**
     * Strongly-consistent read of an upstream-token row in the fallback region. Returns
     * {@code Optional.empty()} on miss, fallback disabled, upstream-token table not configured for
     * fallback, or any failure.
     */
    public Optional<UpstreamTokenRecord> getUpstreamToken(String providerUserId) {
        if (fallbackClient == null || fallbackUpstreamTokenTableNameResolved == null) {
            return Optional.empty();
        }
        try {
            Optional<UpstreamTokenRecord> opt = UpstreamTokenStoreDynamoDbImpl.getWithClient(
                    fallbackClient, fallbackUpstreamTokenTableNameResolved, providerUserId);
            if (opt.isPresent()) {
                String regionLabel = fallbackRegion.map(String::trim).orElse("");
                log.info("Found upstream token row in fallback region {} for provider_user_id={} version={}",
                        regionLabel, providerUserId, opt.get().version());
            }
            return opt;
        } catch (Exception e) {
            log.warn("Fallback region getUpstreamToken failed for provider_user_id={}: {}",
                    providerUserId, e.getMessage());
            oauthProxyMetrics.recordCrossRegionDynamoFailure(
                    "getUpstreamToken", e.getClass().getSimpleName(), "unknown");
            return Optional.empty();
        }
    }
}
