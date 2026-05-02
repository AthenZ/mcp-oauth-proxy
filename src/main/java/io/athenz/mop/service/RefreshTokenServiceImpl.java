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
package io.athenz.mop.service;

import io.athenz.mop.model.RefreshTokenLockKey;
import io.athenz.mop.model.RefreshTokenRecord;
import io.athenz.mop.model.RefreshTokenRotateResult;
import io.athenz.mop.model.RefreshTokenValidationResult;
import io.athenz.mop.store.impl.aws.RefreshTableAttribute;
import io.athenz.mop.store.impl.aws.RefreshTableConstants;
import io.athenz.mop.store.impl.aws.RefreshTokenStoreDynamodbHelpers;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.Put;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;

@ApplicationScoped
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final int TOKEN_BYTES = 32;
    private static final String TOKEN_PREFIX = "rt_";
    private static final String SHA_256 = "SHA-256";

    private final SecureRandom secureRandom = new SecureRandom();

    @Inject
    DynamoDbClient dynamoDbClient;

    /**
     * Optional cross-region resolver. When the bean is present (always in production), reads on
     * {@code refresh_token_hash} (validate / replay / lock-key lookup), {@code refresh_token_id}
     * primary-key fetch (rotate), and the user-provider GSI (getUpstreamRefreshToken) consult the
     * peer region's table after a local miss. Writes (rotate / store / revokeFamily) stay local.
     */
    @Inject
    RefreshTokenRegionResolver refreshTokenRegionResolver;

    @ConfigProperty(name = "server.refresh-token.table-name")
    String tableName;

    @ConfigProperty(name = "server.refresh-token.expiry-seconds", defaultValue = "7776000")
    long expirySeconds;

    @ConfigProperty(name = "server.refresh-token.ttl-buffer-days", defaultValue = "7")
    int ttlBufferDays;

    /**
     * Token-age grace window (seconds): how recently the presented refresh token must have been
     * rotated to be eligible for the grace path instead of the stolen-RT replay path. Defaults to
     * 7200s (2h) — covers the bulk of multi-window Cursor / Claude Desktop self-collisions where
     * one window's RT is up to a couple of hours stale relative to its sibling's. Combined with
     * {@link #familyIdleGraceSeconds} for defense-in-depth at long windows; see {@code resolveRotated}.
     */
    @ConfigProperty(name = "server.refresh-token.rotated-grace-seconds", defaultValue = "7200")
    long rotatedGraceSeconds;

    /**
     * Family-idle grace gate (seconds). When set to a value &gt; 0, the grace path additionally
     * requires that the token family has had a successful rotation within this many seconds —
     * i.e. <em>somebody</em> in the family is still actively refreshing. This bounds the window
     * during which a stolen RT can be quietly accepted: an attacker arriving long after the
     * legitimate user abandoned the session will see family-idle exceeded and fall through to
     * the revoke path. Set to 0 to disable the gate (token-age check alone governs grace).
     *
     * <p><strong>Default 0 (disabled).</strong> The gate is the second predicate in the sliding-
     * grace plan; it adds one extra GSI query per grace-eligible call. Enable it together with a
     * widened {@link #rotatedGraceSeconds} once Paranoids signs off on the long-window design
     * (typical post-review setting: both at 172800s = 48h).</p>
     */
    @ConfigProperty(name = "server.refresh-token.family-idle-grace-seconds", defaultValue = "0")
    long familyIdleGraceSeconds;

    /** Per-pod in-flight result cache TTL (seconds) for the per-RT singleflight. */
    @ConfigProperty(name = "server.refresh-token.inflight-cache-seconds", defaultValue = "30")
    long inflightCacheSeconds;

    /** TTL (seconds) of the per-RT distributed lock written into the refresh-locks table. */
    @ConfigProperty(name = "server.refresh-token.inflight-lock-ttl-seconds", defaultValue = "30")
    long inflightLockTtlSeconds;

    /**
     * Max retries to take the per-RT lock before giving up. With initial-backoff-ms=50 and
     * exponential doubling capped at 2000ms, 7 retries = ~3.5s total wait — comfortably above the
     * observed p99 rotate latency.
     */
    @ConfigProperty(name = "server.refresh-token.inflight-lock-max-retries", defaultValue = "12")
    int inflightLockMaxRetries;

    @ConfigProperty(name = "server.refresh-token.inflight-lock-initial-backoff-ms", defaultValue = "100")
    long inflightLockInitialBackoffMs;

    @Inject
    RefreshLockStore refreshLockStore;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    /**
     * Per-pod in-flight rotate-result cache. Keyed on the SHA-256 hash of the presented refresh
     * token so concurrent callers landing on this pod receive the same rotation outcome
     * (singleflight). Entries are evicted opportunistically on read once
     * {@code inflightCacheSeconds} elapses; a real attacker holding a stolen RT cannot extract
     * value because (a) the entry only contains the freshly-minted successor RT (which the
     * legitimate client also has), and (b) the entry only lives for a few seconds.
     */
    private final ConcurrentHashMap<String, InFlightRotateResult> inFlight = new ConcurrentHashMap<>();

    /** Unique per-process owner id for the per-RT distributed lock. */
    private String lockOwnerId;

    @PostConstruct
    void init() {
        // Hostname under K8s + a UUID suffix so multiple JVM restarts on the same pod don't reuse
        // the same owner id (which would let a stale lock from a previous boot be released by us).
        String host = System.getenv("HOSTNAME");
        if (host == null || host.isEmpty()) {
            host = "mop";
        }
        this.lockOwnerId = host + "#" + UUID.randomUUID();
    }

    /**
     * In-flight rotation result kept in the per-pod cache. Carries the freshly minted raw RT so a
     * duplicate caller presenting the same parent RT can be served from cache without re-rotating
     * (and without ever reaching the genuine-replay revoke path).
     */
    private record InFlightRotateResult(RefreshTokenRotateResult result, long completedAtMillis) {
        boolean isFresh(long ttlMillis) {
            return System.currentTimeMillis() - completedAtMillis < ttlMillis;
        }
    }

    @Override
    public String generateSecureToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return TOKEN_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Override
    public String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256);
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 unavailable", e);
        }
    }

    /** Constant-time comparison for sensitive values. Uses MessageDigest.isEqual to avoid timing leaks. */
    static boolean secureEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        byte[] aa = a.getBytes(StandardCharsets.UTF_8);
        byte[] bb = b.getBytes(StandardCharsets.UTF_8);
        if (aa.length != bb.length) {
            return false;
        }
        return java.security.MessageDigest.isEqual(aa, bb);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Override
    public String store(String userId, String clientId, String provider, String providerSubject,
                       String upstreamRefreshToken) {
        String refreshTokenId = UUID.randomUUID().toString();
        String rawToken = generateSecureToken();
        String tokenHash = hashToken(rawToken);
        String providerUserId = provider + "#" + userId;
        long now = System.currentTimeMillis() / 1000;
        long expiresAt = now + expirySeconds;
        long ttl = expiresAt + (ttlBufferDays * 86400L);

        Map<String, AttributeValue> item = new HashMap<>();
        item.put(RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s(refreshTokenId).build());
        item.put(RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(providerUserId).build());
        item.put(RefreshTableAttribute.REFRESH_TOKEN_HASH.attr(), AttributeValue.builder().s(tokenHash).build());
        item.put(RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s(userId).build());
        item.put(RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s(clientId).build());
        item.put(RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(provider).build());
        item.put(RefreshTableAttribute.PROVIDER_SUBJECT.attr(), AttributeValue.builder().s(providerSubject != null ? providerSubject : "").build());
        if (upstreamRefreshToken != null && !upstreamRefreshToken.isEmpty()) {
            item.put(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), AttributeValue.builder().s(upstreamRefreshToken).build());
        }
        item.put(RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build());
        item.put(RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), AttributeValue.builder().s(refreshTokenId).build());
        item.put(RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n(String.valueOf(now)).build());
        item.put(RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(expiresAt)).build());
        item.put(RefreshTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(ttl)).build());

        dynamoDbClient.putItem(PutItemRequest.builder().tableName(tableName).item(item).build());
        log.info("store: saved refresh token refresh_token_id={} userId={} provider={} client_id={} expires_at={}",
                refreshTokenId, userId, provider, clientId, expiresAt);
        return rawToken;
    }

    @Override
    public Optional<RefreshTokenLockKey> lookupUserIdAndProviderForLock(String refreshToken, String clientId) {
        if (refreshToken == null || refreshToken.isEmpty() || clientId == null || clientId.isEmpty()) {
            return Optional.empty();
        }
        String hash = hashToken(refreshToken);
        RefreshTokenRecord record = lookupByHash(hash);
        if (record == null || !clientId.equals(record.clientId())) {
            return Optional.empty();
        }
        return Optional.of(new RefreshTokenLockKey(record.userId(), record.provider()));
    }

    @Override
    public RefreshTokenValidationResult validate(String refreshToken, String clientId) {
        if (refreshToken == null || refreshToken.isEmpty() || clientId == null || clientId.isEmpty()) {
            log.info("validate: invalid grant - missing refresh_token or client_id");
            return RefreshTokenValidationResult.invalid();
        }
        String hash = hashToken(refreshToken);
        log.debug("validate: refresh_token lookup by hash client_id={} (hash redacted)", clientId);
        RefreshTokenRecord record = lookupByHash(hash);
        if (record == null) {
            log.info("validate: invalid grant - no record found for refresh token (client_id={})", clientId);
            return RefreshTokenValidationResult.invalid();
        }
        long now = System.currentTimeMillis() / 1000;
        log.info("validate: found record refresh_token_id={} status={} expires_at={} now={} userId={}",
                record.refreshTokenId(), record.status(), record.expiresAt(), now, record.userId());
        if (now > record.expiresAt()) {
            log.info("validate: invalid grant - refresh token expired; userId={} provider={} expires_at={} now={}",
                    record.userId(), record.provider(), record.expiresAt(), now);
            return RefreshTokenValidationResult.invalid();
        }
        if (!clientId.equals(record.clientId())) {
            log.info("validate: invalid grant - client_id mismatch; stored={} request={}", record.clientId(), clientId);
            return RefreshTokenValidationResult.invalid();
        }
        switch (record.status()) {
            case RefreshTableConstants.STATUS_REVOKED:
                return RefreshTokenValidationResult.revoked(record);
            case RefreshTableConstants.STATUS_ROTATED:
                return resolveRotated(record, now);
            case RefreshTableConstants.STATUS_ACTIVE:
                return RefreshTokenValidationResult.active(record);
            default:
                log.info("validate: invalid grant - unknown status={}; userId={}", record.status(), record.userId());
                return RefreshTokenValidationResult.invalid();
        }
    }

    /**
     * Layer 2 (rotated-grace window): when a refresh-token row is found in {@code ROTATED} status,
     * decide between {@code ROTATED_GRACE_SUCCESSOR} (recent rotation, treat as benign client
     * retry) and {@code ROTATED_REPLAY} (old rotation, real stolen-RT defense).
     *
     * <p>The grace path opens when:
     * <ol>
     *   <li><strong>Token-age predicate:</strong> the presented row's {@code rotated_at} is
     *       within {@link #rotatedGraceSeconds} of now (i.e. the stale credential isn't ancient).</li>
     *   <li><strong>Family-idle predicate (defense-in-depth, opt-in):</strong> when
     *       {@link #familyIdleGraceSeconds} &gt; 0, the family must also have had a successful
     *       rotation within that many seconds. The latest ACTIVE leaf's {@code issued_at} is the
     *       proxy for "family last active". This bounds the window during which a stolen RT can
     *       quietly succeed against an abandoned session: even if the token-age check passes, an
     *       attacker arriving after the legitimate user has stopped refreshing will see family-
     *       idle exceeded and fall through to revoke. Disabled by default
     *       ({@code familyIdleGraceSeconds=0}) to avoid the extra GSI cost while the token-age
     *       window is short (default 2h); enable when widening the token-age window per the
     *       sliding-grace design.</li>
     * </ol>
     *
     * <p>When both predicates pass and a live ACTIVE successor exists in the family, returns
     * {@code ROTATED_GRACE_SUCCESSOR} carrying that successor (caller will rotate from it via
     * {@link #rotateGraceSuccessor}). When either predicate fails, or no live successor exists,
     * returns {@code ROTATED_REPLAY} so the original family-revoke defense fires.</p>
     */
    private RefreshTokenValidationResult resolveRotated(RefreshTokenRecord record, long now) {
        long rotatedAt = record.rotatedAt();
        long ageSeconds = rotatedAt > 0 ? (now - rotatedAt) : Long.MAX_VALUE;
        if (rotatedAt <= 0 || ageSeconds > rotatedGraceSeconds) {
            return RefreshTokenValidationResult.rotatedReplay(record);
        }
        RefreshTokenRecord successor = RefreshTokenStoreDynamodbHelpers.queryLatestActiveInFamily(
                dynamoDbClient, tableName, record.tokenFamilyId());
        if (successor == null) {
            log.warn("validate: ROTATED row within token-age grace but no live ACTIVE successor in familyId={}; falling back to replay",
                    record.tokenFamilyId());
            if (oauthProxyMetrics != null) {
                oauthProxyMetrics.recordRefreshTokenGraceServed("successor_unavailable");
            }
            return RefreshTokenValidationResult.rotatedReplay(record);
        }
        // Defense-in-depth: when configured, require recent family activity. The successor's
        // issued_at is "family last active" since queryLatestActiveInFamily picks the highest
        // issued_at ACTIVE leaf. A 0 value (the default) skips this check entirely.
        String gracePath = "token_age_only";
        if (familyIdleGraceSeconds > 0) {
            long familyIdleSeconds = successor.issuedAt() > 0
                    ? (now - successor.issuedAt())
                    : Long.MAX_VALUE;
            if (familyIdleSeconds > familyIdleGraceSeconds) {
                log.info("validate: ROTATED row in token-age grace but family-idle exceeded familyId={} ageSec={} familyIdleSec={}; falling back to replay",
                        record.tokenFamilyId(), ageSeconds, familyIdleSeconds);
                if (oauthProxyMetrics != null) {
                    oauthProxyMetrics.recordRefreshTokenGraceServed("family_idle_exceeded");
                }
                return RefreshTokenValidationResult.rotatedReplay(record);
            }
            gracePath = "family_idle_validated";
        }
        log.info("validate: ROTATED row within grace window ({}); serving from successor familyId={} ageSec={}",
                gracePath, record.tokenFamilyId(), ageSeconds);
        if (oauthProxyMetrics != null) {
            oauthProxyMetrics.recordRefreshTokenGraceServed(gracePath);
        }
        return RefreshTokenValidationResult.rotatedGraceSuccessor(record, successor);
    }

    @Override
    public RefreshTokenRotateResult rotate(String refreshToken, String clientId) {
        if (refreshToken == null || refreshToken.isEmpty() || clientId == null || clientId.isEmpty()) {
            return null;
        }
        String hash = hashToken(refreshToken);
        String lockKey = "rt-rotate:" + hash;
        long ttlMillis = inflightCacheSeconds * 1000L;

        // Layer 1a (singleflight - same pod): if another caller on this pod already rotated this
        // exact RT in the recent past, hand back the same result without touching DDB or the lock.
        InFlightRotateResult cached = inFlight.get(hash);
        if (cached != null && cached.isFresh(ttlMillis)) {
            log.info("rotate: served from in-flight cache (singleflight hit)");
            if (oauthProxyMetrics != null) {
                oauthProxyMetrics.recordRefreshTokenInflightCacheServed();
            }
            return cached.result();
        } else if (cached != null) {
            inFlight.remove(hash, cached);
        }

        // Layer 1b (cross-pod coalescing): take the per-RT distributed lock so concurrent callers
        // on different pods serialize. Lock TTL is short (seconds) and only guards the rotate path
        // — the upstream Okta refresh stays under its own existing lock in UpstreamRefreshService.
        long lockAttemptStartNanos = System.nanoTime();
        boolean acquired = tryAcquirePerRtLock(lockKey);
        if (!acquired) {
            // Couldn't take the lock after retries. The other holder is presumably about to write
            // the result; check the cache one last time so we don't waste a rotate attempt.
            cached = inFlight.get(hash);
            if (cached != null && cached.isFresh(ttlMillis)) {
                log.info("rotate: served from in-flight cache after lock contention clientId={} lockKey={}",
                        clientId, lockKey);
                if (oauthProxyMetrics != null) {
                    oauthProxyMetrics.recordRefreshTokenInflightLock("wait_succeeded");
                    oauthProxyMetrics.recordRefreshTokenInflightCacheServed();
                }
                return cached.result();
            }
            double waitSec = (System.nanoTime() - lockAttemptStartNanos) / 1_000_000_000.0;
            log.warn("rotate: per-RT lock timeout, returning transient null clientId={} lockKey={} attempts={} waitSec={}",
                    clientId, lockKey, inflightLockMaxRetries, String.format("%.3f", waitSec));
            if (oauthProxyMetrics != null) {
                oauthProxyMetrics.recordRefreshTokenInflightLock("timeout");
            }
            // Returning null lets TokenResource emit invalid_grant. The Layer 2 grace window
            // (validate -> ROTATED_GRACE_SUCCESSOR) will normally catch the next attempt from the
            // same client because the lock holder will have rotated by then.
            return null;
        }
        if (oauthProxyMetrics != null) {
            oauthProxyMetrics.recordRefreshTokenInflightLock("acquired");
        }
        long holdStartNanos = System.nanoTime();
        String holdOutcome = "null_result";
        try {
            // Re-check the cache: the lock holder may have just finished while we were taking it
            // (TTL on the cache entry is longer than the lock, by design).
            cached = inFlight.get(hash);
            if (cached != null && cached.isFresh(ttlMillis)) {
                log.info("rotate: served from in-flight cache after acquiring lock");
                if (oauthProxyMetrics != null) {
                    oauthProxyMetrics.recordRefreshTokenInflightCacheServed();
                }
                holdOutcome = "cache_hit_after_lock";
                return cached.result();
            }
            RefreshTokenRotateResult result = rotateInternal(refreshToken, clientId);
            if (result != null) {
                inFlight.put(hash, new InFlightRotateResult(result, System.currentTimeMillis()));
                pruneInFlight(ttlMillis);
                holdOutcome = "rotated_internal";
            }
            return result;
        } finally {
            try {
                refreshLockStore.release(lockKey, lockOwnerId);
            } catch (Exception releaseEx) {
                // Lock release is best-effort; the TTL guarantees the lock will free itself
                // within inflight-lock-ttl-seconds even if this throws (DDB throttle, network blip,
                // pod going down). We log so we know to look if it spikes.
                log.warn("rotate: per-RT lock release threw lockKey={} clientId={} error={}",
                        lockKey, clientId, releaseEx.getMessage());
            }
            if (oauthProxyMetrics != null) {
                oauthProxyMetrics.recordRefreshTokenRotateHold(holdOutcome,
                        (System.nanoTime() - holdStartNanos) / 1_000_000_000.0);
            }
        }
    }

    @Override
    public RefreshTokenRotateResult rotateGraceSuccessor(RefreshTokenRecord successor) {
        if (successor == null || successor.refreshTokenId() == null || successor.providerUserId() == null) {
            return null;
        }
        // Re-fetch the successor row by primary key to make sure it's still ACTIVE; a real
        // attacker racing the legitimate client could otherwise convince us to mint off a row that
        // has just been rotated/revoked.
        Map<String, AttributeValue> currentItem =
                getItemByPrimaryKey(successor.refreshTokenId(), successor.providerUserId());
        if (currentItem == null) {
            log.warn("rotateGraceSuccessor: successor row not found by primary key");
            return null;
        }
        RefreshTokenRecord current = RefreshTokenStoreDynamodbHelpers.itemToRecord(currentItem);
        if (!RefreshTableConstants.STATUS_ACTIVE.equals(current.status())) {
            log.info("rotateGraceSuccessor: successor no longer ACTIVE (status={}); aborting", current.status());
            return null;
        }
        long now = System.currentTimeMillis() / 1000;
        if (current.expiresAt() > 0 && now > current.expiresAt()) {
            log.info("rotateGraceSuccessor: successor expired; aborting");
            return null;
        }
        return rotateRecord(current, now);
    }

    /**
     * Today's strict rotate body: validate (must be ACTIVE) then atomically mark current as
     * ROTATED and insert a new ACTIVE child. Replay path triggers {@link #handleReplay} as before.
     * Always called under the per-RT lock from {@link #rotate}; never call directly.
     */
    private RefreshTokenRotateResult rotateInternal(String refreshToken, String clientId) {
        RefreshTokenValidationResult result = validate(refreshToken, clientId);
        if (result.status() != RefreshTokenValidationResult.Status.ACTIVE || result.record() == null) {
            return null;
        }
        RefreshTokenRecord current = result.record();
        long now = System.currentTimeMillis() / 1000;
        return rotateRecord(current, now);
    }

    /**
     * Common rotate body shared by {@link #rotateInternal} and {@link #rotateGraceSuccessor}.
     * Atomic via {@code TransactWriteItems} with condition {@code status = ACTIVE}.
     */
    private RefreshTokenRotateResult rotateRecord(RefreshTokenRecord current, long now) {
        String newTokenId = UUID.randomUUID().toString();
        String newRawToken = generateSecureToken();
        String newHash = hashToken(newRawToken);
        String providerUserId = current.provider() + "#" + current.userId();

        Map<String, AttributeValue> currentItem = getItemByPrimaryKey(current.refreshTokenId(), current.providerUserId());
        if (currentItem == null) {
            log.warn("rotate: current row not found by primary key");
            return null;
        }
        Map<String, AttributeValue> currentItemAsRotated = new HashMap<>(currentItem);
        currentItemAsRotated.put(RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ROTATED).build());
        currentItemAsRotated.put(RefreshTableAttribute.REPLACED_BY.attr(), AttributeValue.builder().s(newTokenId).build());
        currentItemAsRotated.put(RefreshTableAttribute.ROTATED_AT.attr(), AttributeValue.builder().n(String.valueOf(now)).build());
        TransactWriteItem putCurrent = TransactWriteItem.builder()
            .put(Put.builder()
                .tableName(tableName)
                .item(currentItemAsRotated)
                .conditionExpression("#s = :active")
                .expressionAttributeNames(Map.of("#s", RefreshTableAttribute.STATUS.attr()))
                .expressionAttributeValues(Map.of(":active", AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build()))
                .build())
            .build();

        Map<String, AttributeValue> newItem = new HashMap<>();
        newItem.put(RefreshTableAttribute.REFRESH_TOKEN_ID.attr(), AttributeValue.builder().s(newTokenId).build());
        newItem.put(RefreshTableAttribute.PROVIDER_USER_ID.attr(), AttributeValue.builder().s(providerUserId).build());
        newItem.put(RefreshTableAttribute.REFRESH_TOKEN_HASH.attr(), AttributeValue.builder().s(newHash).build());
        newItem.put(RefreshTableAttribute.USER_ID.attr(), AttributeValue.builder().s(current.userId()).build());
        newItem.put(RefreshTableAttribute.CLIENT_ID.attr(), AttributeValue.builder().s(current.clientId()).build());
        newItem.put(RefreshTableAttribute.PROVIDER.attr(), AttributeValue.builder().s(current.provider()).build());
        newItem.put(RefreshTableAttribute.PROVIDER_SUBJECT.attr(), AttributeValue.builder().s(current.providerSubject() != null ? current.providerSubject() : "").build());
        if (!AudienceConstants.PROVIDER_OKTA.equals(current.provider())
                && current.encryptedUpstreamRefreshToken() != null && !current.encryptedUpstreamRefreshToken().isEmpty()) {
            newItem.put(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), AttributeValue.builder().s(current.encryptedUpstreamRefreshToken()).build());
        }
        newItem.put(RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build());
        newItem.put(RefreshTableAttribute.TOKEN_FAMILY_ID.attr(), AttributeValue.builder().s(current.tokenFamilyId()).build());
        newItem.put(RefreshTableAttribute.ROTATED_FROM.attr(), AttributeValue.builder().s(current.refreshTokenId()).build());
        newItem.put(RefreshTableAttribute.ISSUED_AT.attr(), AttributeValue.builder().n(String.valueOf(now)).build());
        newItem.put(RefreshTableAttribute.EXPIRES_AT.attr(), AttributeValue.builder().n(String.valueOf(current.expiresAt())).build());
        newItem.put(RefreshTableAttribute.TTL.attr(), AttributeValue.builder().n(String.valueOf(current.ttl())).build());

        TransactWriteItem putNew = TransactWriteItem.builder()
            .put(Put.builder()
                .tableName(tableName)
                .item(newItem)
                .build())
            .build();

        try {
            dynamoDbClient.transactWriteItems(TransactWriteItemsRequest.builder()
                .transactItems(List.of(putCurrent, putNew))
                .build());
        } catch (ConditionalCheckFailedException e) {
            // Under the per-RT lock, this means the row was rotated by another path between our
            // status read and the TransactWrite (e.g. a cross-region replica that won the race or
            // a manual operator action). We do NOT call handleReplay() here: the lock guarantees no
            // concurrent same-pod / same-region duplicate rotation of this RT, so this is not a
            // genuine stolen-RT replay signal. Returning null lets the caller's next attempt hit
            // the grace path in validate() and recover from the now-rotated successor.
            log.info("rotateRecord: conditional check failed under lock; row already rotated, falling back to grace path");
            return null;
        } catch (Exception e) {
            log.warn("rotateRecord: TransactWriteItems failed; userId={} provider={} error={}", current.userId(), current.provider(), e.getMessage());
            return null;
        }

        return new RefreshTokenRotateResult(newRawToken, newTokenId, providerUserId);
    }

    /**
     * Try to acquire the per-RT distributed lock with bounded exponential backoff. The lock is
     * intentionally short-lived (a few seconds) — the only thing it guards is the
     * {@code TransactWriteItems} that flips the row to ROTATED and inserts the child. Any caller
     * that times out falls through to the grace path on its next attempt.
     */
    private boolean tryAcquirePerRtLock(String lockKey) {
        long backoffMs = inflightLockInitialBackoffMs;
        long expiresAt = System.currentTimeMillis() / 1000 + inflightLockTtlSeconds;
        long startNanos = System.nanoTime();
        for (int attempt = 0; attempt < inflightLockMaxRetries; attempt++) {
            if (refreshLockStore.tryAcquire(lockKey, lockOwnerId, expiresAt)) {
                if (oauthProxyMetrics != null) {
                    oauthProxyMetrics.recordRefreshTokenInflightLockWait("acquired",
                            (System.nanoTime() - startNanos) / 1_000_000_000.0);
                }
                return true;
            }
            try {
                Thread.sleep(backoffMs);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                if (oauthProxyMetrics != null) {
                    oauthProxyMetrics.recordRefreshTokenInflightLock("interrupted");
                    oauthProxyMetrics.recordRefreshTokenInflightLockWait("interrupted",
                            (System.nanoTime() - startNanos) / 1_000_000_000.0);
                }
                return false;
            }
            backoffMs = Math.min(backoffMs * 2, 2000);
        }
        if (oauthProxyMetrics != null) {
            oauthProxyMetrics.recordRefreshTokenInflightLockWait("timeout",
                    (System.nanoTime() - startNanos) / 1_000_000_000.0);
        }
        return false;
    }

    /**
     * Best-effort eviction of in-flight cache entries older than the cache TTL. Called on every
     * successful rotate; the map is small (bounded by current concurrent refreshes) so a linear
     * sweep is fine. We deliberately avoid a scheduled background task to keep the bean
     * stateless across restarts.
     */
    private void pruneInFlight(long ttlMillis) {
        if (inFlight.size() < 64) {
            return;
        }
        inFlight.entrySet().removeIf(e -> !e.getValue().isFresh(ttlMillis));
    }

    @Override
    public void revokeFamily(String tokenFamilyId) {
        if (tokenFamilyId == null || tokenFamilyId.isEmpty()) return;
        QueryResponse response = dynamoDbClient.query(QueryRequest.builder()
            .tableName(tableName)
            .indexName(RefreshTableConstants.GSI_TOKEN_FAMILY)
            .keyConditionExpression(RefreshTableAttribute.TOKEN_FAMILY_ID.attr() + " = :fid")
            .expressionAttributeValues(Map.of(":fid", AttributeValue.builder().s(tokenFamilyId).build()))
            .build());
        List<Map<String, AttributeValue>> items = response.items();
        if (items == null || items.isEmpty()) return;
        for (Map<String, AttributeValue> item : items) {
            Map<String, AttributeValue> itemWithRevoked = new HashMap<>(item);
            itemWithRevoked.put(RefreshTableAttribute.STATUS.attr(), AttributeValue.builder().s(RefreshTableConstants.STATUS_REVOKED).build());
            dynamoDbClient.putItem(PutItemRequest.builder().tableName(tableName).item(itemWithRevoked).build());
        }
    }

    @Override
    public void handleReplay(String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) return;
        String hash = hashToken(refreshToken);
        RefreshTokenRecord record = lookupByHash(hash);
        if (record != null) {
            log.warn("Refresh token replay detected; revoking family tokenFamilyId={} userId={}", record.tokenFamilyId(), record.userId());
            if (oauthProxyMetrics != null) {
                oauthProxyMetrics.recordRefreshTokenReplayRevoked();
            }
            revokeFamily(record.tokenFamilyId());
        }
    }

    @Override
    public String getUpstreamRefreshToken(String userId, String provider) {
        if (userId == null || userId.isEmpty() || provider == null || provider.isEmpty()) {
            return null;
        }
        RefreshTokenRecord best = refreshTokenRegionResolver != null
                ? refreshTokenRegionResolver.resolveBestUpstream(userId, provider).record()
                : RefreshTokenStoreDynamodbHelpers.queryBestUpstreamRefresh(dynamoDbClient, tableName, userId, provider);
        if (best == null || best.encryptedUpstreamRefreshToken() == null || best.encryptedUpstreamRefreshToken().isEmpty()) {
            return null;
        }
        return best.encryptedUpstreamRefreshToken();
    }

    private RefreshTokenRecord lookupByHash(String hash) {
        if (refreshTokenRegionResolver != null) {
            RefreshTokenResolution resolution = refreshTokenRegionResolver.resolveByHash(hash);
            log.debug("lookupByHash: resolver returned record={} fromFallback={} (hash redacted)",
                    resolution.record() != null, resolution.resolvedFromFallback());
            return resolution.record();
        }
        RefreshTokenRecord record = RefreshTokenStoreDynamodbHelpers.lookupByHash(dynamoDbClient, tableName, hash);
        log.debug("lookupByHash: returned record={} (hash redacted)", record != null);
        return record;
    }

    @Override
    public void updateUpstreamRefreshForToken(String mopRefreshToken, String newUpstreamRefresh) {
        if (mopRefreshToken == null || mopRefreshToken.isEmpty()
                || newUpstreamRefresh == null || newUpstreamRefresh.isEmpty()) {
            return;
        }
        String hash = hashToken(mopRefreshToken);
        RefreshTokenRecord record = lookupByHash(hash);
        if (record == null) {
            log.warn("updateUpstreamRefreshForToken: no row found for MOP token hash");
            return;
        }
        Map<String, AttributeValue> currentItem = getItemByPrimaryKey(record.refreshTokenId(), record.providerUserId());
        if (currentItem == null) {
            log.warn("updateUpstreamRefreshForToken: row not found by primary key");
            return;
        }
        Map<String, AttributeValue> updatedItem = new HashMap<>(currentItem);
        updatedItem.put(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), AttributeValue.builder().s(newUpstreamRefresh).build());
        dynamoDbClient.putItem(PutItemRequest.builder().tableName(tableName).item(updatedItem).build());
    }

    @Override
    public void updateUpstreamRefreshForToken(String refreshTokenId, String providerUserId, String newUpstreamRefresh) {
        if (refreshTokenId == null || refreshTokenId.isEmpty() || providerUserId == null || providerUserId.isEmpty()
                || newUpstreamRefresh == null || newUpstreamRefresh.isEmpty()) {
            return;
        }
        Map<String, AttributeValue> currentItem = getItemByPrimaryKey(refreshTokenId, providerUserId);
        if (currentItem == null) {
            log.warn("updateUpstreamRefreshForToken: row not found by primary key refreshTokenId={} providerUserId={}", refreshTokenId, providerUserId);
            return;
        }
        Map<String, AttributeValue> updatedItem = new HashMap<>(currentItem);
        updatedItem.put(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), AttributeValue.builder().s(newUpstreamRefresh).build());
        dynamoDbClient.putItem(PutItemRequest.builder().tableName(tableName).item(updatedItem).build());
        log.debug("updateUpstreamRefreshForToken: updated upstream token for refreshTokenId={}", refreshTokenId);
    }

    @Override
    public void updateUpstreamRefreshForAllRowsWithUserAndProvider(String userId, String provider, String newUpstreamRefresh) {
        if (userId == null || userId.isEmpty() || provider == null || provider.isEmpty()
                || newUpstreamRefresh == null || newUpstreamRefresh.isEmpty()) {
            return;
        }
        Map<String, AttributeValue> exprValues = new HashMap<>(Map.of(
                ":uid", AttributeValue.builder().s(userId).build(),
                ":prov", AttributeValue.builder().s(provider).build(),
                ":active", AttributeValue.builder().s(RefreshTableConstants.STATUS_ACTIVE).build()));
        QueryResponse response = dynamoDbClient.query(QueryRequest.builder()
            .tableName(tableName)
            .indexName(RefreshTableConstants.GSI_USER_PROVIDER)
            .keyConditionExpression(
                RefreshTableAttribute.USER_ID.attr() + " = :uid AND " + RefreshTableAttribute.PROVIDER.attr() + " = :prov")
            .filterExpression("#s = :active")
            .expressionAttributeNames(Map.of("#s", RefreshTableAttribute.STATUS.attr()))
            .expressionAttributeValues(exprValues)
            .build());
        List<Map<String, AttributeValue>> items = response.items();
        if (items == null || items.isEmpty()) {
            log.debug("updateUpstreamRefreshForAllRowsWithUserAndProvider: no rows for userId={} provider={}", userId, provider);
            return;
        }
        for (Map<String, AttributeValue> item : items) {
            Map<String, AttributeValue> updatedItem = new HashMap<>(item);
            updatedItem.put(RefreshTableAttribute.ENCRYPTED_UPSTREAM_REFRESH_TOKEN.attr(), AttributeValue.builder().s(newUpstreamRefresh).build());
            dynamoDbClient.putItem(PutItemRequest.builder().tableName(tableName).item(updatedItem).build());
        }
        log.info("updateUpstreamRefreshForAllRowsWithUserAndProvider: updated {} row(s) for userId={} provider={}",
                items.size(), userId, provider);
    }

    public RefreshTokenRecord getByPrimaryKey(String refreshTokenId, String providerUserId) {
        Map<String, AttributeValue> item = getItemByPrimaryKey(refreshTokenId, providerUserId);
        return item == null ? null : RefreshTokenStoreDynamodbHelpers.itemToRecord(item);
    }

    /**
     * Local-then-peer PK lookup. Used by {@code rotate} so a row that was just rotated/written in
     * the peer region is still found here even if the global-table replication has not landed
     * locally yet. Returns {@code null} when both regions miss.
     */
    private Map<String, AttributeValue> getItemByPrimaryKey(String refreshTokenId, String providerUserId) {
        Map<String, AttributeValue> local = RefreshTokenStoreDynamodbHelpers.getItemByPrimaryKey(
                dynamoDbClient, tableName, refreshTokenId, providerUserId);
        if (local != null) {
            return local;
        }
        if (refreshTokenRegionResolver != null) {
            return refreshTokenRegionResolver.resolveItemByPrimaryKey(refreshTokenId, providerUserId);
        }
        return null;
    }
}
