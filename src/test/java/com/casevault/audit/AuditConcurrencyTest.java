package com.casevault.audit;

import com.casevault.service.AuditEventType;
import com.casevault.service.AuditLogService;
import com.casevault.service.ChainVerificationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.LongStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class AuditConcurrencyTest {

    private static final int THREADS = 8;
    private static final int APPENDS_PER_THREAD = 25;

    @TempDir
    static Path sharedTempDir;

    @DynamicPropertySource
    static void configureAudit(DynamicPropertyRegistry registry) {
        registry.add("casevault.audit.key-path", () -> sharedTempDir.resolve("keys").resolve("audit.key").toString());
        registry.add("casevault.storage.evidence-dir", () -> sharedTempDir.resolve("evidence").toString());
        registry.add("casevault.storage.keyset-path", () -> sharedTempDir.resolve("keyset.json").toString());
    }

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    void cleanChain() {
        jdbc.update("DELETE FROM audit_events");
    }

    @RepeatedTest(10)
    @DisplayName("SEC-AUDIT-15: 8 threads x 25 appends give sequence 1..200 without gap or duplicate and a valid chain")
    void concurrentAppends() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int t = 0; t < THREADS; t++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    UUID user = UUID.randomUUID();
                    for (int i = 0; i < APPENDS_PER_THREAD; i++) {
                        auditLogService.append(AuditEventType.CASE_UPDATED, user, null, "UPDATED");
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> future : futures) {
                try {
                    future.get(120, TimeUnit.SECONDS);
                } catch (ExecutionException e) {
                    throw new AssertionError("append failed in a worker thread: " + e.getCause(), e.getCause());
                }
            }
        } finally {
            pool.shutdownNow();
        }

        int total = THREADS * APPENDS_PER_THREAD;
        List<Long> sequences = jdbc.queryForList("SELECT sequence_no FROM audit_events ORDER BY sequence_no", Long.class);
        assertEquals(LongStream.rangeClosed(1, total).boxed().collect(Collectors.toList()), sequences);

        ChainVerificationResult result = auditLogService.verifyChain();
        assertTrue(result.valid(), "chain must verify, first break: " + result.firstBrokenSequenceNo());
        assertEquals(total, result.eventsVerified());
        assertTrue(auditLogService.verifyChain(7).valid());
    }
}
