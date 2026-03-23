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
 * One centralized Okta upstream refresh token per {@code provider_user_id} (e.g. {@code okta#subject}).
 * The Okta refresh value is encrypted at rest by the DynamoDB encryption client; at the application
 * layer this record carries plaintext for that field after decrypt on read.
 */
public record UpstreamTokenRecord(
        String providerUserId,
        String encryptedOktaRefreshToken,
        String lastRotatedAt,
        long version,
        long ttl,
        String createdAt,
        String updatedAt
) {
    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String providerUserId;
        private String encryptedOktaRefreshToken;
        private String lastRotatedAt;
        private long version = 1L;
        private long ttl;
        private String createdAt;
        private String updatedAt;

        public Builder providerUserId(String v) {
            this.providerUserId = v;
            return this;
        }

        public Builder encryptedOktaRefreshToken(String v) {
            this.encryptedOktaRefreshToken = v;
            return this;
        }

        public Builder lastRotatedAt(String v) {
            this.lastRotatedAt = v;
            return this;
        }

        public Builder version(long v) {
            this.version = v;
            return this;
        }

        public Builder ttl(long v) {
            this.ttl = v;
            return this;
        }

        public Builder createdAt(String v) {
            this.createdAt = v;
            return this;
        }

        public Builder updatedAt(String v) {
            this.updatedAt = v;
            return this;
        }

        public UpstreamTokenRecord build() {
            return new UpstreamTokenRecord(
                    providerUserId,
                    encryptedOktaRefreshToken,
                    lastRotatedAt,
                    version,
                    ttl,
                    createdAt,
                    updatedAt
            );
        }
    }
}
