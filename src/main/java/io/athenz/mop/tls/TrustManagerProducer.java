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
package io.athenz.mop.tls;

import static io.athenz.mop.tls.SslContextProducer.DEFAULT_JDK_TRUST_STORE_PWD;

import com.oath.auth.KeyRefresherException;
import com.oath.auth.Utils;
import jakarta.enterprise.inject.Produces;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TrustManagerProducer {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @ConfigProperty(name = "server.athenz.truststore-file")
    String trustStoreFile;

    @Produces
    public X509TrustManager getTrustManager() {

        TrustManagerFactory trustManagerFactory;
        KeyStore mTLSTruststore;
        try {
            mTLSTruststore = Utils.getKeyStore(trustStoreFile, DEFAULT_JDK_TRUST_STORE_PWD);
            trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(mTLSTruststore);
        } catch (NoSuchAlgorithmException | IOException | KeyRefresherException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
        X509TrustManager trustManager = null;
        TrustManager[] tms = trustManagerFactory.getTrustManagers();
        for (TrustManager tm : tms) {
            if (tm instanceof X509TrustManager) {
                trustManager = (X509TrustManager) tm;
                break;
            }
        }
        if (trustManager == null) {
            log.error("No X509TrustManager found");
            throw new RuntimeException("No X509TrustManager found in TrustManagerFactory");
        }
        return trustManager;
    }
}
