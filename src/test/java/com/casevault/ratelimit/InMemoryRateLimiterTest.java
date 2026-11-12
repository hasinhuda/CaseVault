package com.casevault.ratelimit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unit tests of the limiter core: window logic, key independence, memory bound and thread safety. No sleeping. */
class InMemoryRateLimiterTest {

    /** A clock that only moves when the test says so. */
    static final class MutableClock extends Clock {
        private final AtomicLong millis = new AtomicLong(1_700_000_000_000L);

        void advanceSeconds(long seconds) {
            millis.addAndGet(seconds * 1000L);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(millis.get());
        }

        @Override
        public long millis() {
            return millis.get();
        }
    }

    private static RateLimitProperties settings(int loginLimit, int windowSeconds, int maxKeys) {
        RateLimitProperties p = new RateLimitProperties();
        p.setLoginLimit(loginLimit);
        p.setLoginWindowSeconds(windowSeconds);
        p.setSearchLimit(loginLimit);
        p.setSearchWindowSeconds(windowSeconds);
        p.setMaxTrackedKeys(maxKeys);
        return p;
    }

    @Test
    @DisplayName("SEC-RATE-01: the limit+1th attempt in a window is denied with a Retry-After of 1..window seconds; the window reset allows it again (no sleeping)")
    void windowLogic() {
        MutableClock clock = new MutableClock();
        InMemoryRateLimiter limiter = new InMemoryRateLimiter(settings(3, 60, 100), clock);
        for (int i = 0; i < 3; i++) {
            assertTrue(limiter.tryAcquire(LimiterName.LOGIN, "a").allowed());
        }
        RateLimiter.Decision denied = limiter.tryAcquire(LimiterName.LOGIN, "a");
        assertFalse(denied.allowed());
        assertEquals(60, denied.retryAfterSeconds());
        clock.advanceSeconds(45);
        RateLimiter.Decision later = limiter.tryAcquire(LimiterName.LOGIN, "a");
        assertFalse(later.allowed());
        assertEquals(15, later.retryAfterSeconds());
        clock.advanceSeconds(15);
        assertTrue(limiter.tryAcquire(LimiterName.LOGIN, "a").allowed(), "a new window starts after 60 seconds");
        assertEquals(0, limiter.tryAcquire(LimiterName.LOGIN, "a").retryAfterSeconds());
    }

    @Test
    @DisplayName("SEC-RATE-02: keys and limiter names are independent; denied attempts do not extend the window")
    void keysAreIndependent() {
        MutableClock clock = new MutableClock();
        InMemoryRateLimiter limiter = new InMemoryRateLimiter(settings(2, 60, 100), clock);
        assertTrue(limiter.tryAcquire(LimiterName.LOGIN, "a").allowed());
        assertTrue(limiter.tryAcquire(LimiterName.LOGIN, "a").allowed());
        assertFalse(limiter.tryAcquire(LimiterName.LOGIN, "a").allowed());
        assertTrue(limiter.tryAcquire(LimiterName.LOGIN, "b").allowed(), "another key is unaffected");
        assertTrue(limiter.tryAcquire(LimiterName.SEARCH, "a").allowed(), "another limiter is unaffected");
        for (int i = 0; i < 100; i++) {
            limiter.tryAcquire(LimiterName.LOGIN, "a");
        }
        clock.advanceSeconds(60);
        assertTrue(limiter.tryAcquire(LimiterName.LOGIN, "a").allowed(), "hammering a closed window does not postpone it");
    }

    @Test
    @DisplayName("SEC-RATE-03: memory bound: rotating far more keys than the cap never grows the map beyond the cap; expired windows are purged first")
    void memoryIsBounded() {
        MutableClock clock = new MutableClock();
        int cap = 100;
        InMemoryRateLimiter limiter = new InMemoryRateLimiter(settings(5, 60, cap), clock);
        for (int i = 0; i < cap * 20; i++) {
            limiter.tryAcquire(LimiterName.LOGIN, "10.0." + (i / 250) + "." + (i % 250));
            assertTrue(limiter.trackedKeys() <= cap, "map size " + limiter.trackedKeys() + " after key " + i);
        }
        assertEquals(cap, limiter.trackedKeys(), "the map stays full, not larger");
        clock.advanceSeconds(61);
        limiter.tryAcquire(LimiterName.LOGIN, "fresh");
        assertEquals(1, limiter.trackedKeys(), "all expired windows were purged to make room");
    }

    @Test
    @DisplayName("SEC-RATE-04: memory bound under parallel new keys: the cap is exact")
    void memoryIsBoundedUnderConcurrency() throws Exception {
        MutableClock clock = new MutableClock();
        int cap = 50;
        InMemoryRateLimiter limiter = new InMemoryRateLimiter(settings(5, 60, cap), clock);
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            CountDownLatch go = new CountDownLatch(1);
            AtomicInteger counter = new AtomicInteger();
            Future<?>[] futures = new Future<?>[8];
            for (int t = 0; t < 8; t++) {
                futures[t] = executor.submit(() -> {
                    go.await();
                    for (int i = 0; i < 500; i++) {
                        limiter.tryAcquire(LimiterName.LOGIN, "k" + counter.incrementAndGet());
                    }
                    return null;
                });
            }
            go.countDown();
            for (Future<?> f : futures) {
                f.get(60, TimeUnit.SECONDS);
            }
        } finally {
            executor.shutdownNow();
        }
        assertTrue(limiter.trackedKeys() <= cap, "size " + limiter.trackedKeys());
    }

    @Test
    @DisplayName("SEC-RATE-05: 50 parallel attempts with a limit of 10 let exactly 10 through")
    void exactlyLimitUnderConcurrency() throws Exception {
        for (int round = 0; round < 20; round++) {
            InMemoryRateLimiter limiter = new InMemoryRateLimiter(settings(10, 60, 100), new MutableClock());
            ExecutorService executor = Executors.newFixedThreadPool(50);
            try {
                CountDownLatch go = new CountDownLatch(1);
                Future<Boolean>[] futures = new Future[50];
                for (int i = 0; i < 50; i++) {
                    futures[i] = executor.submit(() -> {
                        go.await();
                        return limiter.tryAcquire(LimiterName.LOGIN, "same").allowed();
                    });
                }
                go.countDown();
                int allowed = 0;
                for (Future<Boolean> f : futures) {
                    if (f.get(30, TimeUnit.SECONDS)) {
                        allowed++;
                    }
                }
                assertEquals(10, allowed, "round " + round);
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    @DisplayName("SEC-RATE-06: a configuration below 1 is raised to 1 instead of disabling or blocking everything unpredictably")
    void degenerateConfiguration() {
        InMemoryRateLimiter limiter = new InMemoryRateLimiter(settings(0, 0, 0), new MutableClock());
        assertTrue(limiter.tryAcquire(LimiterName.LOGIN, "a").allowed());
        assertFalse(limiter.tryAcquire(LimiterName.LOGIN, "a").allowed());
        assertTrue(limiter.trackedKeys() <= 1);
    }
}
