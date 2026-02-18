package io.athenz.mop.resource;

import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.store.TokenStore;
import io.athenz.mop.util.JwtUtils;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("/userinfo")
public class UserInfoResource {
    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Inject
    TokenStore tokenStore;

    @GET
    @Path("/")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUserInfo(@HeaderParam("Authorization") String authorization) {
        // Validate Authorization header
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            log.warn("Missing or invalid Authorization header");
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of(
                            "error", "invalid_token",
                            "error_description", "Missing or invalid Authorization header"
                    ))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        String accessToken = authorization.substring("Bearer ".length());
        log.info("Processing userinfo request for access token");

        String accessTokenHash = JwtUtils.hashAccessToken(accessToken);
        TokenWrapper tokenByHash = tokenStore.getUserTokenByAccessTokenHash(accessTokenHash);

        if (tokenByHash == null) {
            log.warn("Token not found for access token hash");
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of(
                            "error", "invalid_token",
                            "error_description", "Token not found"
                    ))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        long currentTime = Instant.now().getEpochSecond();
        if (currentTime >= tokenByHash.ttl()) {
            log.warn("Token expired. Current time: {}, Token TTL: {}", currentTime, tokenByHash.ttl());
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of(
                            "error", "invalid_token",
                            "error_description", "Token has expired"
                    ))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        String user = tokenByHash.key();
        log.info("Found token by hash for user: {}, provider: {}", user, tokenByHash.provider());

        TokenWrapper oktaToken = tokenStore.getUserToken(user, "okta");

        if (oktaToken == null) {
            log.error("Okta token not found for user: {}", user);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of(
                            "error", "server_error",
                            "error_description", "Okta token record not found"
                    ))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        String idToken = oktaToken.idToken();
        if (idToken == null || idToken.isEmpty()) {
            log.error("id_token is missing in Okta record for user: {}", user);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of(
                            "error", "server_error",
                            "error_description", "id_token not available"
                    ))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        Map<String, Object> userInfo = buildUserInfo(idToken, tokenByHash.provider());
        log.info("Successfully returned userinfo for user: {}", user);
        return Response.ok(userInfo).type(MediaType.APPLICATION_JSON).build();
    }

    /**
     * Builds a userinfo response with all claims from the id_token.
     *
     * @param idToken The id_token JWT
     * @return Map containing all claims from the id_token
     */
    private Map<String, Object> buildUserInfo(String idToken, String provider) {
        Map<String, Object> allClaims = JwtUtils.getAllClaimsFromToken(idToken);
        if (allClaims == null) {
            log.warn("Failed to extract claims from id_token");
            return new HashMap<>();
        }

        Map<String, Object> userInfo = new HashMap<>();
        for (Map.Entry<String, Object> entry : allClaims.entrySet()) {
            String claimName = entry.getKey();
            // Exclude JWT metadata claims and specific internal claims that shouldn't be in userinfo response
            // Standard OIDC userinfo should include: sub, name, given_name, family_name,
            // middle_name, nickname, preferred_username, profile, picture, website,
            // email, email_verified, gender, birthdate, zoneinfo, locale, phone_number,
            // phone_number_verified, address, updated_at, and any custom claims
            if (!claimName.equals("iat") && !claimName.equals("exp") &&
                !claimName.equals("nbf") && !claimName.equals("jti") &&
                !claimName.equals("iss") && !claimName.equals("aud") &&
                !claimName.equals("azp") && !claimName.equals("nonce") &&
                !claimName.equals("auth_time") && !claimName.equals("at_hash") &&
                !claimName.equals("c_hash") && !claimName.equals("ver") &&
                !claimName.equals("personId") && !claimName.equals("countryCode") &&
                !claimName.equals("user_contingent_type") && !claimName.equals("amr")) {
                userInfo.put(claimName, entry.getValue());
            }
        }
        if (!userInfo.isEmpty()) {
            userInfo.put("mcp_resource_idp", provider);
        }
        return userInfo;
    }
}
