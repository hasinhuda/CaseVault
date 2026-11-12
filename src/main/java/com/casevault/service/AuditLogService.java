package com.casevault.service;

import com.casevault.model.AuditEvent;
import com.casevault.repository.AuditEventRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Append-only, HMAC-SHA256 chained audit log (FR-13, SR-13, SR-14). The only class that touches the audit
 * repository. See docs/adr/0005-audit-chain.md for the canonical format and the lock design.
 */
@Service
public class AuditLogService implements AuditAppender, AuditLogReader {

    /** Fixed, documented prev_hash of the first event: 64 hexadecimal zeros. */
    public static final String GENESIS_PREV_HASH = "0".repeat(64);

    static final int DEFAULT_PAGE_SIZE = 500;
    private static final String FORMAT_TAG = "CVAUDIT1";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final AuditEventRepository repository;
    private final AuditKeyProvider keyProvider;
    private final TransactionTemplate transactionTemplate;
    private final ReentrantLock appendLock = new ReentrantLock(true);

    public AuditLogService(AuditEventRepository repository,
                           PlatformTransactionManager transactionManager,
                           AuditKeyProvider keyProvider) {
        this.repository = repository;
        this.keyProvider = keyProvider;
        // REQUIRES_NEW: the event commits inside this method, so the lock is released only after the commit,
        // even when the caller already runs inside a transaction.
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        this.transactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /**
     * Appends one event to the chain. The reason code is mapped through {@link AuditReasonCode}; anything not on
     * the whitelist is stored as UNSPECIFIED. Nothing else (no names, files, hashes of files, secrets) is stored.
     */
    @Override
    public AuditEvent recordEvent(AuditEventType eventType, UUID userId, UUID caseId, String reasonCode) {
        return append(eventType, userId, caseId, reasonCode);
    }

    public AuditEvent append(AuditEventType eventType, UUID userId, UUID caseId, String reasonCode) {
        if (eventType == null) {
            throw new IllegalArgumentException("eventType is required");
        }
        String reason = AuditReasonCode.fromString(reasonCode).name();
        SecretKey key = keyProvider.key();
        appendLock.lock();
        try {
            return transactionTemplate.execute(status -> {
                Optional<AuditEvent> last = repository.findFirstByOrderBySequenceNoDesc();
                long sequenceNo = last.map(e -> e.getSequenceNo() + 1).orElse(1L);
                String prevHash = last.map(AuditEvent::getHmac).orElse(GENESIS_PREV_HASH);
                Instant occurredAt = Instant.now().truncatedTo(ChronoUnit.MILLIS);
                String hmac = computeHmac(key, sequenceNo, eventType.name(), userId, caseId, reason,
                        occurredAt, prevHash);
                return repository.save(new AuditEvent(UUID.randomUUID(), sequenceNo, eventType.name(),
                        userId, caseId, reason, occurredAt, prevHash, hmac));
            });
        } finally {
            appendLock.unlock();
        }
    }

    /** Verifies the whole chain in pages of {@value #DEFAULT_PAGE_SIZE} events. */
    @Override
    public ChainVerificationResult verifyChain() {
        return verifyChain(DEFAULT_PAGE_SIZE);
    }

    /**
     * Recomputes every HMAC and every link in sequence order and reports the first break. Detects modification of
     * any stored field, deleted or inserted rows inside the chain and re-ordering. Cannot detect removal of the
     * newest rows (tail truncation) unless the caller compares {@link #currentHead()} with an externally kept copy.
     */
    public ChainVerificationResult verifyChain(int pageSize) {
        if (pageSize < 1) {
            throw new IllegalArgumentException("pageSize must be positive");
        }
        SecretKey key = keyProvider.key();
        long expectedSequence = 1L;
        String expectedPrevHash = GENESIS_PREV_HASH;
        long verified = 0L;
        long cursor = 0L;
        while (true) {
            List<AuditEvent> page = repository.findBySequenceNoGreaterThanOrderBySequenceNoAsc(
                    cursor, PageRequest.of(0, pageSize));
            if (page.isEmpty()) {
                return ChainVerificationResult.ok(verified);
            }
            for (AuditEvent event : page) {
                if (event.getSequenceNo() != expectedSequence) {
                    return ChainVerificationResult.broken(expectedSequence,
                            ChainVerificationResult.BreakKind.SEQUENCE_GAP, verified);
                }
                if (!constantTimeEquals(event.getPrevHash(), expectedPrevHash)) {
                    return ChainVerificationResult.broken(event.getSequenceNo(),
                            ChainVerificationResult.BreakKind.LINK_MISMATCH, verified);
                }
                String recomputed = computeHmac(key, event.getSequenceNo(), event.getEventType(),
                        event.getUserId(), event.getCaseId(), event.getReasonCode(),
                        event.getOccurredAt(), event.getPrevHash());
                if (!constantTimeEquals(event.getHmac(), recomputed)) {
                    return ChainVerificationResult.broken(event.getSequenceNo(),
                            ChainVerificationResult.BreakKind.HMAC_MISMATCH, verified);
                }
                expectedPrevHash = event.getHmac();
                expectedSequence++;
                verified++;
            }
            cursor = page.get(page.size() - 1).getSequenceNo();
        }
    }

    /** Newest sequence number and its HMAC, for anchoring outside the database (tail-truncation detection). */
    @Override
    public Optional<ChainHead> currentHead() {
        return repository.findFirstByOrderBySequenceNoDesc()
                .map(e -> new ChainHead(e.getSequenceNo(), e.getHmac()));
    }

    /** Hard upper bound of a read page for the auditor view. */
    public static final int MAX_READ_PAGE_SIZE = 50;

    private static final UUID NO_USER = new UUID(0L, 0L);
    private static final Instant MIN_TIME = Instant.EPOCH;
    private static final Instant MAX_TIME = Instant.parse("9999-01-01T00:00:00Z");

    /**
     * Newest-first filtered read (fixed sort, size capped at {@value #MAX_READ_PAGE_SIZE}). A null filter means
     * "any". {@code toExclusive} is an exclusive upper bound.
     */
    @Override
    public Page<AuditEvent> searchEvents(AuditEventType eventType, UUID userId, Instant fromInclusive,
                                         Instant toExclusive, int page, int size) {
        int safeSize = Math.max(1, Math.min(size, MAX_READ_PAGE_SIZE));
        int safePage = Math.max(0, page);
        return repository.findFiltered(eventType == null, eventType == null ? "" : eventType.name(),
                userId == null, userId == null ? NO_USER : userId,
                fromInclusive == null ? MIN_TIME : fromInclusive,
                toExclusive == null ? MAX_TIME : toExclusive,
                PageRequest.of(safePage, safeSize));
    }

    /** Head of the chain; an external copy of this value is what detects deletion of the newest rows. */
    public record ChainHead(long sequenceNo, String hmac) {
    }

    /**
     * Canonical input, fixed order, every field unambiguous:
     * str(s) = int32 big-endian UTF-8 byte length + bytes; opt(s) = byte 0, or byte 1 followed by str(s);
     * fields: str("CVAUDIT1"), int64 sequence_no, str(event_type), opt(user_id), opt(case_id),
     * str(reason_code), int64 occurred_at epoch milliseconds, str(prev_hash).
     */
    static byte[] canonicalBytes(long sequenceNo, String eventType, UUID userId, UUID caseId, String reasonCode,
                                 Instant occurredAt, String prevHash) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(buffer);
            writeString(out, FORMAT_TAG);
            out.writeLong(sequenceNo);
            writeString(out, eventType);
            writeOptional(out, userId == null ? null : userId.toString());
            writeOptional(out, caseId == null ? null : caseId.toString());
            writeString(out, reasonCode);
            out.writeLong(occurredAt.toEpochMilli());
            writeString(out, prevHash);
            out.flush();
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException("Canonical serialisation failed", e);
        }
    }

    private static void writeString(DataOutputStream out, String value) throws IOException {
        byte[] bytes = Objects.requireNonNull(value, "audit field").getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static void writeOptional(DataOutputStream out, String value) throws IOException {
        if (value == null) {
            out.writeByte(0);
        } else {
            out.writeByte(1);
            writeString(out, value);
        }
    }

    private static String computeHmac(SecretKey key, long sequenceNo, String eventType, UUID userId, UUID caseId,
                                      String reasonCode, Instant occurredAt, String prevHash) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(key);
            byte[] tag = mac.doFinal(canonicalBytes(sequenceNo, eventType, userId, caseId, reasonCode,
                    occurredAt, prevHash));
            return HexFormat.of().formatHex(tag);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC computation failed", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
