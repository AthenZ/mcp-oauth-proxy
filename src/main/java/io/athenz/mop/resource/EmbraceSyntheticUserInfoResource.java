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
package io.athenz.mop.resource;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Optional;
import java.util.Set;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * OIDC UserInfo-compatible endpoint for the Embrace tenant. Embrace does not return an {@code id_token}
 * and has no UserInfo URL; Quarkus OIDC still requires UserInfo when {@code id-token-required} is false.
 * This resource verifies the Bearer access token as a JWT against Embrace JWKS and returns its claims.
 * Expected access-token {@code iss} is taken from {@code quarkus.oidc.embrace.auth-server-url} so the tenant can set
 * {@code quarkus.oidc.embrace.token.issuer=any} (Quarkus-documented) to skip {@code iss} checks on the self-signed
 * internal ID token, which never includes a top-level {@code iss} when UserInfo is cached into it.
 * Embrace uses {@code typ: at+jwt} (RFC 9068) for access tokens; Nimbus must allow that in addition to {@code JWT}.
 * <p>Embrace's token endpoint returns {@code access_token} and {@code refresh_token} only (no {@code id_token}), matching
 * a direct {@code authorization_code} exchange to {@code https://dash-api.embrace.io/oauth/token}.
 */
@ApplicationScoped
@Path("/internal/embrace/oauth-userinfo")
public class EmbraceSyntheticUserInfoResource {

    /** Embrace-issued JWTs include {@code nbf}; allow skew vs MoP clock and issuer token endpoints. */
    private static final int MAX_CLOCK_SKEW_SECONDS = 300;

    @Inject
    OauthProxyMetrics oauthProxyMetrics;

    @Inject
    TelemetryRequestContext telemetryRequestContext;

    @ConfigProperty(name = "quarkus.oidc.embrace.auth-server-url")
    Optional<String> authServerUrl;

    @ConfigProperty(name = "quarkus.oidc.embrace.jwks-path")
    Optional<String> jwksPath;

    private volatile JWSKeySelector<SecurityContext> jwsKeySelector;

    @PostConstruct
    void init() {
        try {
            URL url = resolveJwksUrl(
                    authServerUrl.orElse("https://dash-api.embrace.io"),
                    jwksPath.orElse("/.well-known/jwks.json"));
            JWKSource<SecurityContext> jwkSource = JWKSourceBuilder.create(url).build();
            jwsKeySelector = JWSAlgorithmFamilyJWSKeySelector.fromJWKSource(jwkSource);
        } catch (MalformedURLException | KeySourceException e) {
            throw new IllegalStateException("Invalid Embrace JWKS URL for synthetic UserInfo", e);
        }
    }

    static URL resolveJwksUrl(String authServer, String jwksPathStr) throws MalformedURLException {
        String path = jwksPathStr != null ? jwksPathStr.trim() : "/.well-known/jwks.json";
        if (path.startsWith("http://") || path.startsWith("https://")) {
            return URI.create(path).toURL();
        }
        String base = authServer.endsWith("/") ? authServer.substring(0, authServer.length() - 1) : authServer;
        String rel = path.startsWith("/") ? path : "/" + path;
        return URI.create(base + rel).toURL();
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response get(@HeaderParam(HttpHeaders.AUTHORIZATION) String authorization) {
        long startNanos = System.nanoTime();
        telemetryRequestContext.setOauthProvider(OauthProviderLabel.EMBRACE);
        if (authorization == null) {
            return finishSyntheticUserinfo(startNanos, false, 401, "invalid_token", "missing_bearer",
                    Response.status(Response.Status.UNAUTHORIZED).build());
        }
        authorization = authorization.trim();
        if (!authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return finishSyntheticUserinfo(startNanos, false, 401, "invalid_token", "not_bearer",
                    Response.status(Response.Status.UNAUTHORIZED).build());
        }
        String token = authorization.substring(7).trim();
        if (token.isEmpty()) {
            return finishSyntheticUserinfo(startNanos, false, 401, "invalid_token", "empty_token",
                    Response.status(Response.Status.UNAUTHORIZED).build());
        }
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            if (signedJWT.getHeader().getAlgorithm() == null) {
                return finishSyntheticUserinfo(startNanos, false, 401, "invalid_token", "no_algorithm",
                        Response.status(Response.Status.UNAUTHORIZED).build());
            }
            ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(
                    JOSEObjectType.JWT, new JOSEObjectType("at+jwt")));
            processor.setJWSKeySelector(jwsKeySelector);
            // Do not put iss in exact-match claims: Nimbus is strict; verify iss after signature/JWKS check.
            DefaultJWTClaimsVerifier<SecurityContext> verifier =
                    new DefaultJWTClaimsVerifier<>(new JWTClaimsSet.Builder().build(), Set.of("sub", "exp"));
            verifier.setMaxClockSkew(MAX_CLOCK_SKEW_SECONDS);
            processor.setJWTClaimsSetVerifier(verifier);
            JWTClaimsSet claims = processor.process(signedJWT, null);
            Optional<String> wantIss = authServerUrl.filter(s -> !s.isBlank());
            if (wantIss.isPresent()) {
                String tokIss = claims.getIssuer();
                if (tokIss == null || !tokIss.equals(wantIss.get())) {
                    return finishSyntheticUserinfo(startNanos, false, 401, "invalid_token", "issuer_mismatch",
                            Response.status(Response.Status.UNAUTHORIZED).build());
                }
            }
            LinkedHashMap<String, Object> body = new LinkedHashMap<>(claims.getClaims());
            wantIss.ifPresent(iss -> body.putIfAbsent("iss", iss));
            return finishSyntheticUserinfo(startNanos, true, 200, null, null, Response.ok(body).build());
        } catch (Exception e) {
            return finishSyntheticUserinfo(startNanos, false, 401, "invalid_token", "verification_failed",
                    Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }

    private Response finishSyntheticUserinfo(long startNanos, boolean success, int httpStatus,
            String errorType, String userinfoFailureReason, Response response) {
        double seconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        oauthProxyMetrics.recordUserinfoDuration(OauthProviderLabel.EMBRACE, success, userinfoFailureReason, seconds);
        oauthProxyMetrics.recordUserinfoRequest(OauthProviderLabel.EMBRACE, success, httpStatus, errorType,
                userinfoFailureReason);
        return response;
    }
}
