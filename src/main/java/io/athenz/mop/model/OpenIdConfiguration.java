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

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record OpenIdConfiguration(
    @JsonProperty("issuer") String issuer,
    @JsonProperty("authorization_endpoint") String authorizationEndpoint,
    @JsonProperty("token_endpoint") String tokenEndpoint,
    @JsonProperty("registration_endpoint") String registrationEndpoint,
    @JsonProperty("userinfo_endpoint") String userinfoEndpoint,
    @JsonProperty("response_types_supported") List<String> responseTypesSupported,
    @JsonProperty("subject_types_supported") List<String> subjectTypesSupported,
    @JsonProperty("id_token_signing_alg_values_supported") List<String> idTokenSigningAlgValuesSupported,
    @JsonProperty("scopes_supported") List<String> scopesSupported,
    @JsonProperty("token_endpoint_auth_methods_supported") List<String> tokenEndpointAuthMethodsSupported,
    @JsonProperty("claims_supported") List<String> claimsSupported,
    @JsonProperty("grant_types_supported") List<String> grantTypesSupported,
    @JsonProperty("code_challenge_methods_supported") List<String> codeChallengeMethodsSupported
) {}
