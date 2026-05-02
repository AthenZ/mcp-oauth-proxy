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

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import io.athenz.mop.config.OktaTokenExchangeConfig;
import io.athenz.mop.secret.K8SSecretsProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OktaTokenClientTest {

    @Mock
    OktaTokenExchangeConfig oktaTokenExchangeConfig;

    @Mock
    K8SSecretsProvider k8SSecretsProvider;

    @Mock
    TokenClient tokenClient;

    @InjectMocks
    OktaTokenClient oktaTokenClient;

    @BeforeEach
    void setUp() throws Exception {
        var f1 = OktaTokenClient.class.getDeclaredField("oidcClientId");
        f1.setAccessible(true);
        f1.set(oktaTokenClient, "cid");
        var f2 = OktaTokenClient.class.getDeclaredField("oidcClientSecretKey");
        f2.setAccessible(true);
        f2.set(oktaTokenClient, "sec-key");
    }

    @Test
    void refreshToken_success_returnsOktaTokens() throws Exception {
        when(oktaTokenExchangeConfig.authServerUrl()).thenReturn("https://okta.example.com/oauth2/default");
        Map<String, String> creds = new HashMap<>();
        creds.put("sec-key", "secret");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(creds);

        String json = "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":7200,\"refresh_token\":\"rt\"}";
        HTTPResponse http = new HTTPResponse(200);
        http.setContentType("application/json");
        http.setBody(json);
        TokenResponse tr = TokenResponse.parse(http);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(tr);

        OktaTokens t = oktaTokenClient.refreshToken("upstream-rt");
        assertEquals("at", t.accessToken());
        assertEquals("rt", t.refreshToken());
        assertEquals(7200, t.expiresIn());
    }

    @Test
    void refreshToken_invalidGrant_throwsRevoked() throws Exception {
        when(oktaTokenExchangeConfig.authServerUrl()).thenReturn("https://okta.example.com/oauth2/default");
        Map<String, String> creds = new HashMap<>();
        creds.put("sec-key", "secret");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(creds);

        String json = "{\"error\":\"invalid_grant\",\"error_description\":\"expired\"}";
        HTTPResponse http = new HTTPResponse(400);
        http.setContentType("application/json");
        http.setBody(json);
        TokenResponse tr = TokenResponse.parse(http);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(tr);

        assertThrows(OktaTokenRevokedException.class, () -> oktaTokenClient.refreshToken("bad-rt"));
    }

    @Test
    void refreshToken_sendsExplicitOidcScope() throws Exception {
        when(oktaTokenExchangeConfig.authServerUrl()).thenReturn("https://okta.example.com/oauth2/default");
        Map<String, String> creds = new HashMap<>();
        creds.put("sec-key", "secret");
        when(k8SSecretsProvider.getCredentials(null)).thenReturn(creds);

        String json = "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"rt\"}";
        HTTPResponse http = new HTTPResponse(200);
        http.setContentType("application/json");
        http.setBody(json);
        TokenResponse tr = TokenResponse.parse(http);
        when(tokenClient.execute(any(TokenRequest.class))).thenReturn(tr);

        oktaTokenClient.refreshToken("upstream-rt");

        ArgumentCaptor<TokenRequest> reqCap = ArgumentCaptor.forClass(TokenRequest.class);
        verify(tokenClient).execute(reqCap.capture());
        Scope sentScope = reqCap.getValue().getScope();
        assertNotNull(sentScope, "expected explicit scope on refresh request");
        Set<String> values = sentScope.toStringList().stream().collect(Collectors.toSet());
        assertEquals(Set.of("openid", "profile", "email", "offline_access"), values,
                "expected openid+profile+email+offline_access on Okta refresh");
    }
}
