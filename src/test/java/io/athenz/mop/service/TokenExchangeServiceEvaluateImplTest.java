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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.athenz.mop.config.EvaluateTokenExchangeConfig;
import io.athenz.mop.model.AuthResult;
import io.athenz.mop.model.AuthorizationResultDO;
import io.athenz.mop.model.RequestedZtsTokenType;
import io.athenz.mop.model.TokenExchangeDO;
import io.athenz.mop.model.TokenWrapper;
import io.athenz.mop.telemetry.ExchangeStep;
import io.athenz.mop.telemetry.MetricsRegionProvider;
import io.athenz.mop.telemetry.OauthProviderLabel;
import io.athenz.mop.telemetry.OauthProxyMetrics;
import io.athenz.mop.telemetry.TelemetryRequestContext;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class TokenExchangeServiceEvaluateImplTest {

    private static final String EVAL_AUDIENCE = "evaluateplus.k8s.evaluate-elide-production";
    private static final String EVAL_SCOPE = "evaluateplus.k8s:role.evaluate-mcp-user";
    private static final String RESOURCE = "https://mcp-gateway.ouryahoo.com/v1/evaluate/mcp";
    private static final String REMOTE_SERVER = "https://yahooinc.grafana.net";

    @Mock
    private TokenExchangeServiceProducer tokenExchangeServiceProducer;

    @Mock
    private EvaluateTokenExchangeConfig evaluateTokenExchangeConfig;

    @Mock
    private OauthProxyMetrics oauthProxyMetrics;

    @Mock
    private TelemetryRequestContext telemetryRequestContext;

    @Mock
    private MetricsRegionProvider metricsRegionProvider;

    @Mock
    private TokenExchangeService athenzExchange;

    @InjectMocks
    private TokenExchangeServiceEvaluateImpl service;

    private TokenWrapper oktaToken;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(evaluateTokenExchangeConfig.audience()).thenReturn(EVAL_AUDIENCE);
        when(evaluateTokenExchangeConfig.scopes()).thenReturn(List.of(EVAL_SCOPE));
        when(tokenExchangeServiceProducer.getTokenExchangeServiceImplementation("athenz"))
                .thenReturn(athenzExchange);
        when(telemetryRequestContext.oauthClient()).thenReturn("mcp-client");
        when(metricsRegionProvider.primaryRegion()).thenReturn("us-east-1");

        oktaToken = new TokenWrapper(
                "user-key",
                "okta",
                "okta-id-token",
                null,
                "okta-refresh",
                3600L);
    }

    private TokenExchangeDO newRequest(TokenWrapper wrapper) {
        return new TokenExchangeDO(
                Collections.emptyList(),
                RESOURCE,
                "ignored-namespace",
                REMOTE_SERVER,
                wrapper,
                null);
    }

    // --- Success ---

    @Test
    void getAccessToken_success_returnsAthenzIdTokenInAccessTokenField() {
        TokenWrapper athenzOut = new TokenWrapper(
                "user-key", REMOTE_SERVER, "athenz-id-token", null, null, 4200L);
        when(athenzExchange.getAccessTokenFromResourceAuthorizationServer(any()))
                .thenReturn(new AuthorizationResultDO(AuthResult.AUTHORIZED, athenzOut));

        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(oktaToken));

        assertNotNull(result);
        assertEquals(AuthResult.AUTHORIZED, result.authResult());
        assertNotNull(result.token());
        assertEquals("user-key", result.token().key());
        assertEquals(REMOTE_SERVER, result.token().provider());
        assertNull(result.token().idToken());
        assertEquals("athenz-id-token", result.token().accessToken());
        assertNull(result.token().refreshToken());
        assertEquals(4200L, result.token().ttl());

        ArgumentCaptor<TokenExchangeDO> captor = ArgumentCaptor.forClass(TokenExchangeDO.class);
        verify(athenzExchange, times(1)).getAccessTokenFromResourceAuthorizationServer(captor.capture());
        TokenExchangeDO sent = captor.getValue();
        assertEquals(EVAL_AUDIENCE, sent.namespace());
        assertEquals(List.of(EVAL_SCOPE), sent.scopes());
        assertEquals(RESOURCE, sent.resource());
        assertEquals(REMOTE_SERVER, sent.remoteServer());
        assertSame(oktaToken, sent.tokenWrapper());
        assertEquals(RequestedZtsTokenType.ID_TOKEN, sent.requestedZtsTokenType());

        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.EVALUATE_ATHENZ_ID_TOKEN),
                eq(OauthProviderLabel.EVALUATE),
                eq(true),
                eq(null),
                eq("mcp-client"),
                eq("us-east-1"),
                anyDouble());
    }

    // --- Validation failures (no metrics, no downstream call) ---

    @Test
    void getAccessToken_nullRequest_returnsUnauthorized() {
        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(null);
        assertNotNull(result);
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        assertNull(result.token());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
        verify(oauthProxyMetrics, never()).recordExchangeStep(
                any(), anyString(), anyBoolean(), any(), anyString(), anyString(), anyDouble());
    }

    @Test
    void getAccessToken_nullTokenWrapper_returnsUnauthorized() {
        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(null));
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        assertNull(result.token());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
    }

    @Test
    void getAccessToken_blankIdToken_returnsUnauthorized() {
        TokenWrapper blank = new TokenWrapper("k", "okta", "", null, null, 3600L);
        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(blank));
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        assertNull(result.token());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
    }

    @Test
    void getAccessToken_nullIdToken_returnsUnauthorized() {
        TokenWrapper blank = new TokenWrapper("k", "okta", null, null, null, 3600L);
        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(blank));
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
    }

    // --- Config validation ---

    @Test
    void getAccessToken_blankAudience_returnsUnauthorized() {
        when(evaluateTokenExchangeConfig.audience()).thenReturn("  ");
        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(oktaToken));
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
    }

    @Test
    void getAccessToken_nullScopes_returnsUnauthorized() {
        when(evaluateTokenExchangeConfig.scopes()).thenReturn(null);
        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(oktaToken));
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
    }

    @Test
    void getAccessToken_emptyScopes_returnsUnauthorized() {
        when(evaluateTokenExchangeConfig.scopes()).thenReturn(List.of());
        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(oktaToken));
        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        verify(athenzExchange, never()).getAccessTokenFromResourceAuthorizationServer(any());
    }

    // --- Downstream ZTS failure modes ---

    @Test
    void getAccessToken_athenzReturnsNull_returnsUnauthorizedAndRecordsFailure() {
        when(athenzExchange.getAccessTokenFromResourceAuthorizationServer(any())).thenReturn(null);

        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(oktaToken));

        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        assertNull(result.token());
        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.EVALUATE_ATHENZ_ID_TOKEN),
                eq(OauthProviderLabel.EVALUATE),
                eq(false),
                eq("unauthorized"),
                eq("mcp-client"),
                eq("us-east-1"),
                anyDouble());
    }

    @Test
    void getAccessToken_athenzUnauthorized_returnsUnauthorizedAndRecordsFailure() {
        when(athenzExchange.getAccessTokenFromResourceAuthorizationServer(any()))
                .thenReturn(new AuthorizationResultDO(AuthResult.UNAUTHORIZED, null));

        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(oktaToken));

        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.EVALUATE_ATHENZ_ID_TOKEN),
                eq(OauthProviderLabel.EVALUATE),
                eq(false),
                eq("unauthorized"),
                eq("mcp-client"),
                eq("us-east-1"),
                anyDouble());
    }

    @Test
    void getAccessToken_athenzAuthorizedWithNullToken_returnsUnauthorizedAndRecordsFailure() {
        when(athenzExchange.getAccessTokenFromResourceAuthorizationServer(any()))
                .thenReturn(new AuthorizationResultDO(AuthResult.AUTHORIZED, null));

        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(oktaToken));

        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.EVALUATE_ATHENZ_ID_TOKEN),
                eq(OauthProviderLabel.EVALUATE),
                eq(false),
                eq("unauthorized"),
                eq("mcp-client"),
                eq("us-east-1"),
                anyDouble());
    }

    @Test
    void getAccessToken_athenzReturnsBlankIdToken_returnsUnauthorizedAndRecordsFailure() {
        TokenWrapper athenzOut = new TokenWrapper(
                "user-key", REMOTE_SERVER, "   ", null, null, 3600L);
        when(athenzExchange.getAccessTokenFromResourceAuthorizationServer(any()))
                .thenReturn(new AuthorizationResultDO(AuthResult.AUTHORIZED, athenzOut));

        AuthorizationResultDO result = service.getAccessTokenFromResourceAuthorizationServer(newRequest(oktaToken));

        assertEquals(AuthResult.UNAUTHORIZED, result.authResult());
        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.EVALUATE_ATHENZ_ID_TOKEN),
                eq(OauthProviderLabel.EVALUATE),
                eq(false),
                eq("unauthorized"),
                eq("mcp-client"),
                eq("us-east-1"),
                anyDouble());
    }

    @Test
    void getAccessToken_athenzThrows_propagatesAndRecordsFailure() {
        RuntimeException boom = new RuntimeException("zts down");
        when(athenzExchange.getAccessTokenFromResourceAuthorizationServer(any())).thenThrow(boom);

        RuntimeException caught = assertThrows(RuntimeException.class,
                () -> service.getAccessTokenFromResourceAuthorizationServer(newRequest(oktaToken)));
        assertSame(boom, caught);

        verify(oauthProxyMetrics, times(1)).recordExchangeStep(
                eq(ExchangeStep.EVALUATE_ATHENZ_ID_TOKEN),
                eq(OauthProviderLabel.EVALUATE),
                eq(false),
                eq("unauthorized"),
                eq("mcp-client"),
                eq("us-east-1"),
                anyDouble());
    }

    // --- Unsupported operations ---

    @Test
    void getJWTAuthorizationGrant_throws() {
        assertThrows(UnsupportedOperationException.class,
                () -> service.getJWTAuthorizationGrantFromIdentityProvider(newRequest(oktaToken)));
    }

    @Test
    void getAccessTokenWithClientCredentials_throws() {
        assertThrows(UnsupportedOperationException.class,
                () -> service.getAccessTokenFromResourceAuthorizationServerWithClientCredentials(newRequest(oktaToken)));
    }

    @Test
    void refreshWithUpstreamToken_returnsNull() {
        assertNull(service.refreshWithUpstreamToken("any"));
    }
}
