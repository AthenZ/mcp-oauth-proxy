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
package io.athenz.mop.model;

/**
 * Requested token type when calling ZTS getAccessTokenFromResourceAuthorizationServer.
 * JAG = access token via getJAGExchangeToken; ID_TOKEN = id_token via getIDToken (token exchange).
 */
public enum RequestedZtsTokenType {
    /** JAG path: getJAGExchangeToken, returns access_token. */
    JAG,
    /** Token exchange path: getIDToken, returns Athenz id_token (e.g. for Google Monitoring). */
    ID_TOKEN
}
