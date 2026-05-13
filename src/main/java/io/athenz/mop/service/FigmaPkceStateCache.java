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

import jakarta.enterprise.context.ApplicationScoped;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.util.Iterator;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Per-pod single-use state cache for the custom Figma OAuth code flow.
 *
 * <p>Why this exists: the {@code figma} provider does NOT use Quarkus OIDC. Quarkus's
 * {@code CodeAuthenticationMechanism} HS256-signs the synthetic internal ID token using the
 * tenant's {@code client_secret} verbatim, and Figma's currently-issued client secret is 30
 * ASCII characters (240 bits) — below jose4j's 256-bit floor for HS256. So the {@link
 * io.athenz.mop.resource.FigmaResource} performs the upstream OAuth code flow itself; this
 * cache stores the per-flow PKCE {@code code_verifier} along with the originating MoP
 * authorization code (received as the {@code state} query-string param of {@code /figma/authorize})
 * keyed by a fresh upstream {@code state} value sent to Figma. The Figma redirect back to
 * {@code /figma/authorize/callback} carries that upstream state, which we use to look up and
 * atomically remove the entry (single-use; replay attempts after consumption fail closed).
 *
 * <p>Entries are evicted automatically on read after 10 minutes of age — well above any
 * reasonable browser-mediated round-trip but short enough to limit blast radius if a
 * code_verifier ever leaked. A periodic sweep (every 100 reads) garbage-collects expired
 * entries from the underlying map so abandoned/expired flows do not accumulate.
 *
 * <p>Per-pod (not cross-pod) is fine: the browser stays bound to the same pod for the duration
 * of the redirect via the standard sticky-session behavior of the load balancer, and the OAuth
 * round-trip is short. If MoP grows pod-affinity-less browser flows in the future this cache
 * would need to move to DynamoDB; for now ConcurrentHashMap is a deliberate simplicity choice.
 */
@ApplicationScoped
public class FigmaPkceStateCache {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    /** Max age (seconds) for an entry; Figma redirects round-trip in seconds, so 10 min is generous. */
    static final long TTL_SECONDS = 600L;
    /** Cleanup-sweep cadence in number of {@link #pop} calls between full map walks. */
    private static final int SWEEP_EVERY_N_POPS = 100;

    private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();
    private final java.util.concurrent.atomic.AtomicLong popCount = new java.util.concurrent.atomic.AtomicLong();

    /**
     * Stores the PKCE state for a fresh outbound redirect to Figma.
     *
     * @param upstreamState the random {@code state} value MoP will pass to Figma's authorize URL
     *                      (Figma echoes it back on the callback). MUST be unguessable.
     * @param codeVerifier  the PKCE {@code code_verifier} for this flow (43-128 chars, RFC 7636).
     * @param mopAuthCode   the MoP authorization code received as the {@code state} param on
     *                      {@code GET /figma/authorize}; we will resolve this on the callback to
     *                      look up the originating MCP-client redirect URI / scope / etc.
     */
    public void put(String upstreamState, String codeVerifier, String mopAuthCode) {
        if (upstreamState == null || upstreamState.isEmpty()
                || codeVerifier == null || codeVerifier.isEmpty()
                || mopAuthCode == null || mopAuthCode.isEmpty()) {
            throw new IllegalArgumentException("upstreamState, codeVerifier, and mopAuthCode are all required");
        }
        entries.put(upstreamState, new Entry(codeVerifier, mopAuthCode, Instant.now().getEpochSecond()));
    }

    /**
     * Atomically removes and returns the entry for {@code upstreamState}, or empty if no such
     * entry exists or the entry is older than {@link #TTL_SECONDS}. Single-use — a successful
     * pop guarantees no other caller will see this entry.
     */
    public Optional<Entry> pop(String upstreamState) {
        if (upstreamState == null || upstreamState.isEmpty()) {
            return Optional.empty();
        }
        Entry e = entries.remove(upstreamState);
        long now = Instant.now().getEpochSecond();
        if ((popCount.incrementAndGet() % SWEEP_EVERY_N_POPS) == 0L) {
            sweepExpired(now);
        }
        if (e == null) {
            return Optional.empty();
        }
        if (now - e.createdAtEpochSeconds > TTL_SECONDS) {
            log.warn("FigmaPkceStateCache: dropping expired entry (age={}s)", now - e.createdAtEpochSeconds);
            return Optional.empty();
        }
        return Optional.of(e);
    }

    /** Test seam: how many entries are currently held (post-sweep). */
    int sizeForTests() {
        return entries.size();
    }

    private void sweepExpired(long now) {
        Iterator<java.util.Map.Entry<String, Entry>> it = entries.entrySet().iterator();
        int removed = 0;
        while (it.hasNext()) {
            java.util.Map.Entry<String, Entry> mapEntry = it.next();
            if (now - mapEntry.getValue().createdAtEpochSeconds > TTL_SECONDS) {
                it.remove();
                removed++;
            }
        }
        if (removed > 0) {
            log.info("FigmaPkceStateCache: swept {} expired entries", removed);
        }
    }

    /**
     * Cache entry. {@link #createdAtEpochSeconds} is captured on {@link #put} so {@link #pop}
     * can refuse stale entries without relying on the underlying map's eviction.
     */
    public record Entry(String codeVerifier, String mopAuthCode, long createdAtEpochSeconds) {
    }
}
