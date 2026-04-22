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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.enterprise.inject.Instance;
import java.util.Iterator;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TokenCleanupRunnerTest {

    private TokenCleanupRunner runner;
    private TokenCleaner grafana;
    private TokenCleaner splunk;

    @BeforeEach
    void setUp() {
        runner = new TokenCleanupRunner();
        grafana = mock(TokenCleaner.class);
        splunk = mock(TokenCleaner.class);
        when(grafana.providerId()).thenReturn("grafana");
        when(splunk.providerId()).thenReturn("splunk");
        runner.cleaners = instanceOf(List.of(grafana, splunk));
    }

    @Test
    void runOnce_missingProvider_returnsExit3() {
        assertEquals(TokenCleanupRunner.EXIT_MISSING_PROVIDER, runner.runOnce(null));
        assertEquals(TokenCleanupRunner.EXIT_MISSING_PROVIDER, runner.runOnce(""));
        assertEquals(TokenCleanupRunner.EXIT_MISSING_PROVIDER, runner.runOnce("   "));
        verify(grafana, never()).cleanupOnce();
        verify(splunk, never()).cleanupOnce();
    }

    @Test
    void runOnce_unknownProvider_returnsExit2() {
        assertEquals(TokenCleanupRunner.EXIT_UNKNOWN_PROVIDER, runner.runOnce("okta"));
        verify(grafana, never()).cleanupOnce();
        verify(splunk, never()).cleanupOnce();
    }

    @Test
    void runOnce_successfulDispatch_returnsExit0() {
        when(grafana.cleanupOnce()).thenReturn(new CleanupResult(5, 0));

        assertEquals(TokenCleanupRunner.EXIT_OK, runner.runOnce("grafana"));
        verify(grafana).cleanupOnce();
        verify(splunk, never()).cleanupOnce();
    }

    @Test
    void runOnce_partialFailures_returnsExit1() {
        when(grafana.cleanupOnce()).thenReturn(new CleanupResult(2, 1));

        assertEquals(TokenCleanupRunner.EXIT_PARTIAL_FAILURE, runner.runOnce("grafana"));
    }

    @Test
    void runOnce_cleanerThrows_returnsExit1() {
        when(grafana.cleanupOnce()).thenThrow(new RuntimeException("boom"));

        assertEquals(TokenCleanupRunner.EXIT_PARTIAL_FAILURE, runner.runOnce("grafana"));
    }

    @Test
    void runOnce_cleanerReturnsNull_returnsExit1() {
        when(grafana.cleanupOnce()).thenReturn(null);

        assertEquals(TokenCleanupRunner.EXIT_PARTIAL_FAILURE, runner.runOnce("grafana"));
    }

    @Test
    void runOnce_providerIdTrimmed() {
        when(splunk.cleanupOnce()).thenReturn(new CleanupResult(0, 0));

        assertEquals(TokenCleanupRunner.EXIT_OK, runner.runOnce("  splunk  "));
        verify(splunk).cleanupOnce();
    }

    @SuppressWarnings("unchecked")
    private static <T> Instance<T> instanceOf(List<T> items) {
        Instance<T> inst = mock(Instance.class);
        when(inst.iterator()).thenAnswer(inv -> copyIterator(items));
        when(inst.stream()).thenAnswer(inv -> items.stream());
        return inst;
    }

    private static <T> Iterator<T> copyIterator(List<T> items) {
        return List.copyOf(items).iterator();
    }
}
