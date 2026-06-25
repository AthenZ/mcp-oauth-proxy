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

import jakarta.enterprise.context.Dependent;

/**
 * Token exchange implementation for the Gemini Enterprise (GE Stream Assist) provider.
 *
 * <p>Gemini Enterprise authenticates via direct Google OAuth/OIDC exactly like the Google
 * Workspace providers (consent pass-through, no synthetic exchange), so it shares the resource-side
 * pass-through logic in {@link TokenExchangeServiceGoogleWorkspaceBase}. It differs only in using a
 * dedicated Google OAuth client; that distinction lives in
 * {@link GeminiEnterpriseUpstreamRefreshClient}, not here.
 */
@Dependent
public class TokenExchangeServiceGeminiEnterpriseImpl extends TokenExchangeServiceGoogleWorkspaceBase {
}
