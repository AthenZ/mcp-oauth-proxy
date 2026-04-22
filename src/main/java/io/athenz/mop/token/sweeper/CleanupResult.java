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
package io.athenz.mop.token.sweeper;

/**
 * Aggregate outcome of one {@link TokenCleaner#cleanupOnce()} invocation.
 *
 * @param deleted number of tokens the cleaner successfully deleted
 * @param failed  number of tokens the cleaner tried to delete but couldn't (HTTP error, I/O, etc.)
 */
public record CleanupResult(int deleted, int failed) {

    public static final CleanupResult EMPTY = new CleanupResult(0, 0);

    /** {@code true} iff no per-token failures occurred (regardless of whether anything was deleted). */
    public boolean isSuccess() {
        return failed == 0;
    }
}
