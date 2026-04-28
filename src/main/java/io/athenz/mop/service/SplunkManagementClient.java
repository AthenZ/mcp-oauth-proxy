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

import java.util.List;

/**
 * Splunk REST management API (authentication users + authorization tokens).
 */
public interface SplunkManagementClient {

    record SplunkUserLookup(boolean found, List<String> roles) {}

    /**
     * Snapshot of a single Splunk authorization token entry kept by the cleanup CronJob. {@code id}
     * is the {@code entry.name} returned by Splunk and is what gets passed in the DELETE URL path.
     */
    record SplunkExpiredToken(String id, String sub, long exp) {}

    SplunkUserLookup getUser(String mgmtBaseUrl, String adminBearer, String username);

    void createUser(String mgmtBaseUrl, String adminBearer, String username, String password, List<String> roles);

    void updateUserRoles(String mgmtBaseUrl, String adminBearer, String username, List<String> roles);

    /**
     * @return minted Splunk bearer token, or null on failure
     */
    String mintToken(String mgmtBaseUrl, String adminBearer, String username, String audience, String expiresOn);

    /**
     * Lists tokens whose {@code claims.sub} starts with {@code subjectPrefix} and whose
     * {@code claims.exp} is strictly less than {@code nowEpochSeconds}. On any non-2xx response or
     * I/O failure an empty list is returned (errors are logged by the implementation).
     */
    List<SplunkExpiredToken> listExpiredMcpTokens(
            String mgmtBaseUrl, String adminBearer, String subjectPrefix, long nowEpochSeconds);

    /**
     * Deletes one token by id (the entry name from the list feed). Returns true only on a 2xx
     * status; non-2xx and exceptions return false (and are logged so the cleanup CronJob can
     * surface which token ids could not be removed).
     */
    boolean deleteToken(String mgmtBaseUrl, String adminBearer, String tokenId);
}
