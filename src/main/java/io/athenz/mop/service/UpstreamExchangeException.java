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

/**
 * Thrown by {@link AuthorizerService#getTokenFromAuthorizationServer} when the upstream
 * resource authorization server (Splunk, Databricks, GCP Workforce, Grafana, Evaluate,
 * Okta-exchange, ZTS, ...) fails to issue a token.
 *
 * <p>Carries the upstream-reported failure message verbatim so {@link
 * io.athenz.mop.resource.TokenResource} can surface it as the {@code error_description} of a
 * 401 {@code invalid_token} response, instead of the previous behavior which dereferenced a
 * null {@code TokenWrapper} and returned a 500 with an NPE stacktrace.</p>
 */
public class UpstreamExchangeException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public UpstreamExchangeException(String message) {
        super(message);
    }
}
