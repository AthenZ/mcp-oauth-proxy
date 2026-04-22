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
package io.athenz.mop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class MopMainTest {

    @Test
    void isCronJobMode_falseForNullOrBlank() {
        assertFalse(MopMain.isCronJobMode(null));
        assertFalse(MopMain.isCronJobMode(""));
        assertFalse(MopMain.isCronJobMode("   "));
    }

    @Test
    void isCronJobMode_falseForZero() {
        assertFalse(MopMain.isCronJobMode("0"));
        assertFalse(MopMain.isCronJobMode("  0  "));
    }

    @Test
    void isCronJobMode_trueForOne() {
        assertTrue(MopMain.isCronJobMode("1"));
        assertTrue(MopMain.isCronJobMode(" 1 "));
    }

    @Test
    void isCronJobMode_trueForTrueAnyCase() {
        assertTrue(MopMain.isCronJobMode("true"));
        assertTrue(MopMain.isCronJobMode("TRUE"));
        assertTrue(MopMain.isCronJobMode("True"));
        assertTrue(MopMain.isCronJobMode(" true "));
    }

    @Test
    void isCronJobMode_falseForFalseAnyCase() {
        assertFalse(MopMain.isCronJobMode("false"));
        assertFalse(MopMain.isCronJobMode("FALSE"));
        assertFalse(MopMain.isCronJobMode("False"));
    }

    @Test
    void isCronJobMode_falseForGarbageValues() {
        assertFalse(MopMain.isCronJobMode("bogus"));
        assertFalse(MopMain.isCronJobMode("2"));
        assertFalse(MopMain.isCronJobMode("yes"));
        assertFalse(MopMain.isCronJobMode("on"));
    }

    @Test
    void envConstants_matchExpectedNames() {
        assertEquals("CRON_JOB_MODE", MopMain.ENV_CRON_JOB_MODE);
        assertEquals("CRON_JOB_PROVIDER", MopMain.ENV_CRON_JOB_PROVIDER);
    }
}
