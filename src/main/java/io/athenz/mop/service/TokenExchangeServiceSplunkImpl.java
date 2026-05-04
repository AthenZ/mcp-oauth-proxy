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

import io.athenz.mop.config.SplunkTokenExchangeConfig;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.secret.K8SSecretsProvider;
import io.athenz.mop.util.JwtUtils;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class TokenExchangeServiceSplunkImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final long DEFAULT_SPLUNK_TOKEN_TTL_SECONDS = 3600L;
    private static final String PASSWORD_ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_=+";

    /** Used only when {@code allowed-roles} is missing or all entries are blank after trim. */
    static final String ALLOWED_ROLES_FALLBACK = "yahoo_user";

    @Inject
    SplunkTokenExchangeConfig splunkConfig;

    @Inject
    SplunkManagementClient splunkManagementClient;

    @Inject
    K8SSecretsProvider k8SSecretsProvider;

    @Inject
    ConfigService configService;

    @Override
    public AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO) {
        throw new UnsupportedOperationException("Splunk exchange uses getAccessTokenFromResourceAuthorizationServer");
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO) {
        TokenWrapper oktaWrap = tokenExchangeDO != null ? tokenExchangeDO.tokenWrapper() : null;
        if (oktaWrap == null || StringUtils.isBlank(oktaWrap.idToken())) {
            log.warn("Splunk exchange: missing Okta id_token");
            return AuthorizationResultDO.unauthorized("Splunk exchange: missing Okta id_token");
        }
        String mgmtBase = tokenExchangeDO.remoteServer();
        if (StringUtils.isBlank(mgmtBase)) {
            log.warn("Splunk exchange: missing remote server (mgmt base URL)");
            return AuthorizationResultDO.unauthorized("Splunk exchange: missing remote server (mgmt base URL)");
        }

        String usernameClaim =
                StringUtils.defaultIfBlank(configService.getRemoteServerUsernameClaim("splunk"), "short_id");
        Object claimVal = JwtUtils.getClaimFromToken(oktaWrap.idToken(), usernameClaim);
        String humanUser = StringUtils.trimToNull(claimVal != null ? claimVal.toString() : null);
        if (StringUtils.isBlank(humanUser)) {
            log.warn("Splunk exchange: missing claim {} in id_token", usernameClaim);
            return AuthorizationResultDO.unauthorized("Splunk exchange: missing claim " + usernameClaim + " in id_token");
        }

        Map<String, String> creds = k8SSecretsProvider.getCredentials(null);
        String adminBearer = creds.get(splunkConfig.adminTokenSecretKey());
        if (StringUtils.isBlank(adminBearer)) {
            log.error("Splunk exchange: splunk admin token not configured in credentials map");
            return AuthorizationResultDO.unauthorized("Splunk exchange: admin token not configured");
        }

        String prefix = StringUtils.defaultIfBlank(splunkConfig.mirrorUserPrefix(), "mcp.");
        String mirrorUser = prefix + humanUser;

        Set<String> baselineRoles = toAllowedRoleSet(splunkConfig.allowedRoles());

        SplunkManagementClient.SplunkUserLookup real = splunkManagementClient.getUser(mgmtBase, adminBearer, humanUser);
        SplunkManagementClient.SplunkUserLookup mirror = splunkManagementClient.getUser(mgmtBase, adminBearer, mirrorUser);

        List<String> desiredRoles = buildDesiredMirrorRoles(
                real.found(),
                real.found() ? real.roles() : List.of(),
                baselineRoles);
        Set<String> desiredSet = new TreeSet<>(desiredRoles);

        log.info(
                "Splunk exchange: humanUser={} mirrorUser={} realUserFound={} desiredRoleCount={}",
                humanUser,
                mirrorUser,
                real.found(),
                desiredSet.size());

        boolean mirrorExisted = mirror.found();
        Set<String> currentMirrorRoles = new TreeSet<>(mirrorExisted ? mirror.roles() : List.of());
        boolean rolesMatch = mirrorExisted && currentMirrorRoles.equals(desiredSet);

        if (!mirrorExisted) {
            // Capture rather than rethrow so we can post-verify and surface the more useful
            // "user truly does not exist after createUser" error when both signals coincide.
            String upstreamFailure = null;
            String password = generateMirrorPassword();
            try {
                splunkManagementClient.createUser(mgmtBase, adminBearer, mirrorUser, password, desiredRoles);
            } catch (SplunkApiException e) {
                upstreamFailure = e.getMessage();
                log.error("Splunk exchange: createUser failed for mirrorUser={} desiredRoles={}: {}",
                        mirrorUser, desiredRoles, e.getMessage());
            }
            SplunkManagementClient.SplunkUserLookup verify =
                    splunkManagementClient.getUser(mgmtBase, adminBearer, mirrorUser);
            if (!verify.found()) {
                String msg = upstreamFailure != null
                        ? upstreamFailure
                        : "Splunk mirror user " + mirrorUser + " not present after createUser (no upstream error captured)";
                log.error("Splunk exchange: mirror user {} not present after createUser ({}); aborting mint",
                        mirrorUser, msg);
                return AuthorizationResultDO.unauthorized(msg);
            }
            log.info("Splunk exchange: created mirror user {}", mirrorUser);
        } else if (!rolesMatch) {
            try {
                splunkManagementClient.updateUserRoles(mgmtBase, adminBearer, mirrorUser, desiredRoles);
            } catch (SplunkApiException e) {
                log.error("Splunk exchange: updateUserRoles failed for mirrorUser={}: {}", mirrorUser, e.getMessage());
                return AuthorizationResultDO.unauthorized(e.getMessage());
            }
            log.info("Splunk exchange: updated mirror user roles {}", mirrorUser);
        } else {
            log.info("Splunk exchange: mirror user roles unchanged {}", mirrorUser);
        }

        String splunkAudience = splunkConfig.splunkTokenAudience();
        String expiresOn = splunkConfig.tokenExpiresOn();
        String token;
        try {
            token = splunkManagementClient.mintToken(mgmtBase, adminBearer, mirrorUser, splunkAudience, expiresOn);
        } catch (SplunkApiException e) {
            log.error("Splunk exchange: mintToken failed for mirrorUser={}: {}", mirrorUser, e.getMessage());
            return AuthorizationResultDO.unauthorized(e.getMessage());
        }

        log.info("Splunk exchange: token mint ok mirrorUser={} mirrorExisted={} rolesChanged={}",
                mirrorUser, mirrorExisted, mirrorExisted && !rolesMatch);

        TokenWrapper out = new TokenWrapper(
                null,
                null,
                null,
                token,
                null,
                DEFAULT_SPLUNK_TOKEN_TTL_SECONDS);
        return new AuthorizationResultDO(AuthResult.AUTHORIZED, out);
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(TokenExchangeDO tokenExchangeDO) {
        throw new UnsupportedOperationException("Splunk exchange does not support client credentials");
    }

    @Override
    public TokenWrapper refreshWithUpstreamToken(String upstreamRefreshToken) {
        return null;
    }

    /**
     * Trims configured role names; if nothing valid remains (misconfiguration), uses {@link #ALLOWED_ROLES_FALLBACK}.
     */
    static Set<String> toAllowedRoleSet(List<String> configured) {
        Set<String> out = new TreeSet<>();
        if (configured != null) {
            for (String part : configured) {
                String t = StringUtils.trimToNull(part);
                if (t != null) {
                    out.add(t);
                }
            }
        }
        if (out.isEmpty()) {
            out.add(ALLOWED_ROLES_FALLBACK);
        }
        return out;
    }

    /**
     * Mirror roles = {@code baselineRoles} ∪ (all non-blank roles from the real Splunk user when found). Real user is
     * looked up by the same id as {@code humanUser} (e.g. {@code short_id}); roles are not filtered against the baseline
     * list.
     */
    static List<String> buildDesiredMirrorRoles(
            boolean realFound, List<String> realRoles, Set<String> baselineRoles) {
        Set<String> desired = new TreeSet<>(baselineRoles);
        if (realFound && realRoles != null) {
            for (String r : realRoles) {
                if (StringUtils.isNotBlank(r)) {
                    desired.add(r.trim());
                }
            }
        }
        return new ArrayList<>(desired);
    }

    static String generateMirrorPassword() {
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(32);
        for (int i = 0; i < 32; i++) {
            sb.append(PASSWORD_ALPHABET.charAt(rnd.nextInt(PASSWORD_ALPHABET.length())));
        }
        return sb.toString();
    }
}
