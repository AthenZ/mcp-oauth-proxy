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

import io.athenz.mop.config.AthenzTokenExchangeConfig;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.RequestedZtsTokenType;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.util.JwtUtils;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.invoke.MethodHandles;
import java.util.Arrays;
import java.util.List;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Token exchange for GCP Monitoring and GCP Logging MCP: Okta id_token → ZMS scope →
 * Athenz id_token → Google STS access token. Same flow for both; Google scope is selected by audience.
 */
@ApplicationScoped
public class TokenExchangeServiceGcpWorkforceImpl implements TokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final long DEFAULT_STS_TTL_SECONDS = 3600L;

    @Inject
    ZMSServiceImpl zmsServiceImpl;

    @Inject
    TokenExchangeServiceProducer tokenExchangeServiceProducer;

    @Inject
    AthenzTokenExchangeConfig athenzTokenExchangeConfig;

    @Inject
    GoogleWorkforceTokenExchange googleWorkforceTokenExchange;

    @Inject
    ConfigService configService;

    @ConfigProperty(name = "server.token-exchange.gcp-role-name", defaultValue = "gcp.fed.mcp.user")
    String gcpRoleName;

    @Override
    public AuthorizationResultDO getJWTAuthorizationGrantFromIdentityProvider(TokenExchangeDO tokenExchangeDO) {
        throw new UnsupportedOperationException("Google GCP exchange uses getAccessTokenFromResourceAuthorizationServer");
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServer(TokenExchangeDO tokenExchangeDO) {
        TokenWrapper oktaToken = tokenExchangeDO != null ? tokenExchangeDO.tokenWrapper() : null;
        if (oktaToken == null) {
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }
        String oktaIdToken = oktaToken.idToken();
        if (oktaIdToken == null || oktaIdToken.isBlank()) {
            log.warn("Google GCP exchange: missing Okta id_token");
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }
        String resource = tokenExchangeDO.resource();
        io.athenz.mop.model.ResourceMeta resourceMeta = configService.getResourceMeta(resource);
        if (resourceMeta == null || resourceMeta.audience() == null) {
            log.warn("Google GCP exchange: no resource meta or audience for resource: {}", resource);
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }
        String audience = resourceMeta.audience();
        if (!AudienceConstants.PROVIDER_GOOGLE_MONITORING.equals(audience) && !AudienceConstants.PROVIDER_GOOGLE_LOGGING.equals(audience)) {
            log.warn("Google GCP exchange: unsupported audience: {}", audience);
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }

        Object shortIdObj = JwtUtils.getClaimFromToken(oktaIdToken, "short_id");
        String shortId = shortIdObj != null ? shortIdObj.toString().trim() : null;
        if (shortId == null || shortId.isBlank()) {
            log.warn("Google GCP exchange: missing short_id claim in Okta id_token");
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }
        String roleMember = "user." + shortId;;
        String scopeStr = zmsServiceImpl.getScopeForPrincipal(roleMember, gcpRoleName);
        List<String> scopeList = (scopeStr != null && !scopeStr.isBlank())
                ? Arrays.asList(scopeStr.split("\\s+"))
                : List.of();
        TokenExchangeDO athenzRequest = new TokenExchangeDO(
                scopeList,
                resource,
                "",
                athenzTokenExchangeConfig.audience(),
                oktaToken,
                RequestedZtsTokenType.ID_TOKEN);
        TokenExchangeService athenzExchange = tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("athenz");
        AuthorizationResultDO athenzResult = athenzExchange.getAccessTokenFromResourceAuthorizationServer(athenzRequest);
        if (athenzResult == null || athenzResult.token() == null || athenzResult.authResult() != AuthResult.AUTHORIZED) {
            log.warn("Google GCP exchange: Athenz ID token exchange failed");
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }
        String athenzIdToken = athenzResult.token().idToken();
        if (athenzIdToken == null || athenzIdToken.isBlank()) {
            log.warn("Google GCP exchange: Athenz ID token exchange returned no id_token");
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }

        String stsAccessToken = googleWorkforceTokenExchange.exchange(athenzIdToken, audience);
        if (stsAccessToken == null || stsAccessToken.isBlank()) {
            log.warn("Google GCP exchange: Google STS exchange failed");
            return new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null);
        }

        TokenWrapper result = new TokenWrapper(
                null,
                null,
                null,
                stsAccessToken,
                null,
                DEFAULT_STS_TTL_SECONDS
        );
        return new AuthorizationResultDO(AuthResult.AUTHORIZED, result);
    }

    @Override
    public AuthorizationResultDO getAccessTokenFromResourceAuthorizationServerWithClientCredentials(TokenExchangeDO tokenExchangeDO) {
        throw new UnsupportedOperationException("Google GCP exchange does not support client credentials");
    }

    @Override
    public TokenWrapper refreshWithUpstreamToken(String upstreamRefreshToken) {
        // Upstream for GCP Monitoring/Logging is Okta; refresh is performed by Okta exchange service.
        return null;
    }
}
