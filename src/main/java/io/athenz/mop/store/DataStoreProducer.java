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
package io.athenz.mop.store;

import io.quarkus.runtime.Startup;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.inject.Produces;
import jakarta.enterprise.util.AnnotationLiteral;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
@Startup
public class DataStoreProducer {
    @Inject
    @Any
    Instance<TokenStore> tokenStores;

    @Inject
    @Any
    Instance<AuthCodeStore> authCodeStores;

    @Inject
    @Any
    Instance<TokenStoreAsync> tokenStoresAsync;

    @ConfigProperty(name = "server.token-store.implementation", defaultValue = "enterprise")
    String storeImplementation;

    @Produces
    public TokenStore selectTokenStore() {

        switch (storeImplementation) {
            case "memory":
                return tokenStores.select(new AnnotationLiteral<MemoryStoreQualifier>() {}).get();
            case "enterprise":
                return tokenStores.select(new AnnotationLiteral<EnterpriseStoreQualifier>() {}).get();
            default:
                throw new RuntimeException("Unknown token store implementation: " + storeImplementation);
        }
    }

    @Produces
    public AuthCodeStore selectAuthStore() {

        switch (storeImplementation) {
            case "memory":
                return authCodeStores.select(new AnnotationLiteral<MemoryStoreQualifier>() {}).get();
            case "enterprise":
                return authCodeStores.select(new AnnotationLiteral<EnterpriseStoreQualifier>() {}).get();
            default:
                throw new RuntimeException("Unknown auth code store implementation: " + storeImplementation);
        }
    }

    @Produces
    public TokenStoreAsync selectTokenStoreAsync() {
        switch (storeImplementation) {
            case "memory":
                return tokenStoresAsync.select(new AnnotationLiteral<MemoryStoreQualifier>() {}).get();
            case "enterprise":
                return tokenStoresAsync.select(new AnnotationLiteral<EnterpriseStoreQualifier>() {}).get();
            default:
                throw new RuntimeException("Unknown async token store implementation: " + storeImplementation);
        }
    }
}
