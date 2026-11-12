package com.casevault.ratelimit;

import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Fixed-window counter per (limiter, key). Self written, no dependency, injectable {@link Clock}.
 *
 * <ul>
 *   <li><b>Thread safe:</b> every counter update is one atomic {@code ConcurrentHashMap.compute}, so N parallel
 *       requests can never admit more than the limit within a window.</li>
 *   <li><b>Memory bounded:</b> at most {@code maxTrackedKeys} windows are kept. A new key first removes expired
 *       windows and, if the map is still full, the oldest ones. New keys are inserted under one lock so the cap is
 *       exact. Residual risk: an attacker who rotates many distinct keys can push out (reset) the counters of
 *       others; that costs the attacker at least one request per evicted key.</li>
 *   <li><b>Honest limits:</b> in-process and per node, lost on restart. A fixed window allows up to twice the
 *       limit around a window boundary.</li>
 * </ul>
 */
@Component
public class InMemoryRateLimiter implements RateLimiter {

    /** One window: when it started, how long it lasts, and how many attempts were counted. */
    private record Window(long startMillis, long lengthMillis, int count) {
        boolean expiredAt(long now) {
            return now - startMillis >= lengthMillis;
        }
    }

    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final Object insertLock = new Object();
    private final RateLimitSettings settings;
    private final LongSupplier nowMillis;

    public InMemoryRateLimiter(RateLimitSettings settings, Clock clock) {
        this.settings = settings;
        this.nowMillis = clock::millis;
    }

    @Override
    public Decision tryAcquire(LimiterName name, String key) {
        RateRule rule = settings.rule(name);
        long now = nowMillis.getAsLong();
        String mapKey = name.name() + "|" + key;
        if (windows.containsKey(mapKey)) {
            return count(mapKey, rule, now);
        }
        synchronized (insertLock) {
            if (!windows.containsKey(mapKey)) {
                makeRoom(now);
            }
            return count(mapKey, rule, now);
        }
    }

    /** Number of tracked windows (for tests and diagnostics). */
    public int trackedKeys() {
        return windows.size();
    }

    private Decision count(String mapKey, RateRule rule, long now) {
        long length = rule.windowSeconds() * 1000L;
        Decision[] result = new Decision[1];
        windows.compute(mapKey, (k, current) -> {
            if (current == null || current.expiredAt(now)) {
                result[0] = new Decision(true, 0);
                return new Window(now, length, 1);
            }
            if (current.count() < rule.limit()) {
                result[0] = new Decision(true, 0);
                return new Window(current.startMillis(), current.lengthMillis(), current.count() + 1);
            }
            long remainingMillis = current.startMillis() + current.lengthMillis() - now;
            result[0] = new Decision(false, Math.max(1L, (remainingMillis + 999L) / 1000L));
            return current;
        });
        return result[0];
    }

    /** Called under {@code insertLock} before a new key is added. */
    private void makeRoom(long now) {
        int cap = settings.maxTrackedKeys();
        if (windows.size() < cap) {
            return;
        }
        windows.entrySet().removeIf(entry -> entry.getValue().expiredAt(now));
        int excess = windows.size() - cap + 1;
        if (excess <= 0) {
            return;
        }
        int toRemove = excess + cap / 100;
        List<Map.Entry<String, Window>> oldestFirst = new ArrayList<>(windows.entrySet());
        oldestFirst.sort(Comparator.comparingLong(entry -> entry.getValue().startMillis()));
        for (int i = 0; i < toRemove && i < oldestFirst.size(); i++) {
            windows.remove(oldestFirst.get(i).getKey());
        }
    }
}
