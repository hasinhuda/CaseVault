package com.casevault.service;

import com.casevault.exception.ResourceNotFoundException;
import com.casevault.model.AuditEvent;
import com.casevault.model.Role;
import com.casevault.security.CaseVaultUserPrincipal;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

/**
 * Read side of the audit log for the AUDITOR_ADMIN view (Phase 6C). Depends on {@link AuditLogService} only; it
 * never exposes usernames, case content, file names or hashes of events, just ids and codes. The last chain
 * verification result is kept in memory (lost on restart, per node): the chain is NOT verified on page views.
 */
@Service
public class AuditQueryService {

    public static final int DEFAULT_PAGE_SIZE = 25;
    public static final int MAX_PAGE_SIZE = AuditLogService.MAX_READ_PAGE_SIZE;
    static final int MAX_PAGE_INDEX = 100_000;
    private static final int MAX_INPUT_LENGTH = 64;
    private static final Pattern UUID_SHAPE = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    private final AuditLogReader auditLogService;
    private final AuditEventRecorder recorder;
    private final ReentrantLock verifyLock = new ReentrantLock();
    private volatile VerificationStatus lastVerification;

    public AuditQueryService(AuditLogReader auditLogService, AuditEventRecorder recorder) {
        this.auditLogService = auditLogService;
        this.recorder = recorder;
    }

    /** One displayed row: ids and codes only. */
    public record AuditRow(long sequenceNo, Instant occurredAt, String eventType, String userId, String caseId,
                           String reasonCode) {
    }

    /** Last verification outcome kept in memory. */
    public record VerificationStatus(Instant checkedAt, boolean valid, Long firstBrokenSequenceNo,
                                     String breakKind, long eventsVerified) {
    }

    /** Head of the chain with a shortened HMAC for the on-screen comparison. */
    public record HeadView(long sequenceNo, String hmacPrefix) {
    }

    /** Everything the page needs. Filter fields hold validated, normalised values only (never raw input). */
    public record AuditPageView(List<AuditRow> rows, int page, int size, int totalPages, long totalElements,
                                boolean hasPrevious, boolean hasNext, List<String> errors,
                                String eventType, String userId, String from, String to,
                                VerificationStatus verification, HeadView head, List<String> eventTypes) {
        public AuditPageView {
            rows = List.copyOf(rows);
            errors = List.copyOf(errors);
            eventTypes = List.copyOf(eventTypes);
        }

        @Override
        public List<AuditRow> rows() {
            return List.copyOf(rows);
        }

        @Override
        public List<String> errors() {
            return List.copyOf(errors);
        }

        @Override
        public List<String> eventTypes() {
            return List.copyOf(eventTypes);
        }
    }

    /** Outcome of a verification request. */
    public enum VerifyOutcome { COMPLETED_VALID, COMPLETED_INVALID, ALREADY_RUNNING }

    public AuditPageView view(CaseVaultUserPrincipal principal, String eventTypeRaw, String userIdRaw,
                              String fromRaw, String toRaw, String pageRaw, String sizeRaw) {
        requireAuditor(principal);
        List<String> errors = new ArrayList<>();

        AuditEventType eventType = null;
        if (isPresent(eventTypeRaw)) {
            eventType = parseEventType(eventTypeRaw);
            if (eventType == null) {
                errors.add("Unknown event type. Choose one of the listed event types.");
            }
        }
        UUID userId = null;
        if (isPresent(userIdRaw)) {
            userId = parseUuid(userIdRaw);
            if (userId == null) {
                errors.add("User id must be a UUID such as 123e4567-e89b-12d3-a456-426614174000.");
            }
        }
        LocalDate from = null;
        if (isPresent(fromRaw)) {
            from = parseDate(fromRaw);
            if (from == null) {
                errors.add("The \"from\" date must be a valid date in the form yyyy-MM-dd.");
            }
        }
        LocalDate to = null;
        if (isPresent(toRaw)) {
            to = parseDate(toRaw);
            if (to == null) {
                errors.add("The \"to\" date must be a valid date in the form yyyy-MM-dd.");
            }
        }
        if (from != null && to != null && from.isAfter(to)) {
            errors.add("The \"from\" date must not be after the \"to\" date.");
        }

        int size = clampSize(sizeRaw);
        int page = clampPage(pageRaw);
        List<AuditRow> rows = List.of();
        int totalPages = 0;
        long total = 0;
        boolean hasPrev = false;
        boolean hasNext = false;
        if (errors.isEmpty()) {
            Instant fromInstant = from == null ? null : from.atStartOfDay().toInstant(ZoneOffset.UTC);
            Instant toExclusive = to == null ? null : to.plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC);
            Page<AuditEvent> result = auditLogService.searchEvents(eventType, userId, fromInstant, toExclusive,
                    page, size);
            rows = result.getContent().stream().map(AuditQueryService::toRow).toList();
            totalPages = result.getTotalPages();
            total = result.getTotalElements();
            hasPrev = result.hasPrevious();
            hasNext = result.hasNext();
        }
        HeadView head = auditLogService.currentHead()
                .map(h -> new HeadView(h.sequenceNo(), h.hmac().substring(0, Math.min(12, h.hmac().length()))))
                .orElse(null);
        return new AuditPageView(rows, page, size, totalPages, total, hasPrev, hasNext, List.copyOf(errors),
                eventType == null ? "" : eventType.name(), userId == null ? "" : userId.toString(),
                from == null || errors.stream().anyMatch(e -> e.startsWith("The \"from\"")) ? "" : from.toString(),
                to == null || errors.stream().anyMatch(e -> e.startsWith("The \"to\"")) ? "" : to.toString(),
                lastVerification, head,
                Arrays.stream(AuditEventType.values()).map(Enum::name).toList());
    }

    /**
     * Verifies the whole chain (one run at a time), keeps the result in memory and then appends one
     * AUDIT_CHAIN_VERIFIED event for the auditor, after the verification has finished.
     */
    public VerifyOutcome verifyChain(CaseVaultUserPrincipal principal) {
        requireAuditor(principal);
        if (!verifyLock.tryLock()) {
            return VerifyOutcome.ALREADY_RUNNING;
        }
        ChainVerificationResult result;
        try {
            result = auditLogService.verifyChain();
            lastVerification = new VerificationStatus(Instant.now(), result.valid(),
                    result.firstBrokenSequenceNo(), result.breakKind() == null ? null : result.breakKind().name(),
                    result.eventsVerified());
        } finally {
            verifyLock.unlock();
        }
        // Outcome event, appended after the verification finished (6B ordering rules, fail-closed).
        recorder.record(AuditEventType.AUDIT_CHAIN_VERIFIED, principal.getUserId(), null,
                result.valid() ? AuditReasonCode.CHAIN_VALID.name() : AuditReasonCode.CHAIN_INVALID.name());
        return result.valid() ? VerifyOutcome.COMPLETED_VALID : VerifyOutcome.COMPLETED_INVALID;
    }

    private void requireAuditor(CaseVaultUserPrincipal principal) {
        if (principal == null || principal.getRole() != Role.AUDITOR_ADMIN) {
            if (principal != null) {
                recorder.record(AuditEventType.ACCESS_DENIED, principal.getUserId(), null,
                        AuditReasonCode.NOT_VISIBLE.name());
            }
            throw new ResourceNotFoundException("Not found");
        }
    }

    private static AuditRow toRow(AuditEvent e) {
        return new AuditRow(e.getSequenceNo(), e.getOccurredAt(), e.getEventType(),
                e.getUserId() == null ? "" : e.getUserId().toString(),
                e.getCaseId() == null ? "" : e.getCaseId().toString(), e.getReasonCode());
    }

    private static boolean isPresent(String raw) {
        return raw != null && !raw.isBlank();
    }

    private static AuditEventType parseEventType(String raw) {
        String value = raw.trim();
        for (AuditEventType type : AuditEventType.values()) {
            if (type.name().equals(value)) {
                return type;
            }
        }
        return null;
    }

    private static UUID parseUuid(String raw) {
        String value = raw.trim();
        if (value.length() > MAX_INPUT_LENGTH || !UUID_SHAPE.matcher(value).matches()) {
            return null;
        }
        return UUID.fromString(value);
    }

    private static LocalDate parseDate(String raw) {
        String value = raw.trim();
        if (value.length() > MAX_INPUT_LENGTH) {
            return null;
        }
        try {
            return LocalDate.parse(value);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static int clampSize(String raw) {
        Optional<Integer> parsed = parseInt(raw);
        if (parsed.isEmpty() || parsed.get() < 1) {
            return DEFAULT_PAGE_SIZE;
        }
        return Math.min(parsed.get(), MAX_PAGE_SIZE);
    }

    private static int clampPage(String raw) {
        Optional<Integer> parsed = parseInt(raw);
        if (parsed.isEmpty()) {
            return 0;
        }
        return Math.max(0, Math.min(parsed.get(), MAX_PAGE_INDEX));
    }

    /** Overflowing or non-numeric text is "absent"; huge but valid numbers are clamped by the callers. */
    private static Optional<Integer> parseInt(String raw) {
        if (raw == null || raw.isBlank() || raw.length() > 12) {
            return Optional.empty();
        }
        try {
            long value = Long.parseLong(raw.trim());
            return Optional.of((int) Math.max(Integer.MIN_VALUE, Math.min(Integer.MAX_VALUE, value)));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }
}
