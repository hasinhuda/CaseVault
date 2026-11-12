package com.casevault.service;

import com.casevault.dto.ReportRequestDto;
import com.casevault.dto.ReportResponseDto;
import com.casevault.exception.BadRequestException;
import com.casevault.exception.ResourceNotFoundException;
import com.casevault.model.Case;
import com.casevault.model.Report;
import com.casevault.model.ReportStatus;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.ReportRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.AccessPolicy;
import com.casevault.security.CaseVaultUserPrincipal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Default {@link ReportService}. Visibility of a report derives from case visibility ({@link AccessPolicy}); on
 * top of that CLIENT sees APPROVED reports only. Assumption: creating, editing and submitting reports on a CLOSED
 * case is rejected (400); approving an already submitted report is still allowed so a manager can release it.
 * REPORT_TRANSITION events are recorded through {@link AuditEventRecorder}, which appends them after commit.
 */
@Service
@Transactional(readOnly = true)
public class DefaultReportService implements ReportService {

    private static final String CLOSED = "CLOSED";

    private final ReportRepository reportRepository;
    private final CaseRepository caseRepository;
    private final UserRepository userRepository;
    private final AccessPolicy accessPolicy;
    private final AuditEventRecorder auditEventRecorder;

    public DefaultReportService(ReportRepository reportRepository, CaseRepository caseRepository,
                                UserRepository userRepository, AccessPolicy accessPolicy,
                                AuditEventRecorder auditEventRecorder) {
        this.reportRepository = reportRepository;
        this.caseRepository = caseRepository;
        this.userRepository = userRepository;
        this.accessPolicy = accessPolicy;
        this.auditEventRecorder = auditEventRecorder;
    }

    @Override
    @Transactional
    @PreAuthorize("isAuthenticated()")
    public ReportResponseDto createDraft(String caseId, ReportRequestDto request, CaseVaultUserPrincipal principal) {
        Case aCase = visibleCase(caseId, principal);
        if (principal.getRole() != Role.ANALYST) {
            throw masked(principal, caseId);
        }
        requireOpen(aCase);
        String body = validateBody(request);
        User author = userRepository.findById(principal.getUserId())
                .orElseThrow(() -> new ResourceNotFoundException("Report not found"));
        Report saved = reportRepository.save(new Report(UUID.randomUUID().toString(), aCase, author, body, now()));
        auditEventRecorder.record(AuditEventType.REPORT_TRANSITION, principal.getUserId(), caseId, "REPORT_CREATED");
        return ReportResponseDto.fromEntity(saved);
    }

    @Override
    @Transactional
    @PreAuthorize("isAuthenticated()")
    public ReportResponseDto updateDraft(String caseId, String reportId, ReportRequestDto request,
                                         CaseVaultUserPrincipal principal) {
        Case aCase = visibleCase(caseId, principal);
        Report report = reportOfCase(reportId, caseId, principal);
        requireAuthor(report, principal);
        requireOpen(aCase);
        if (report.getStatus() != ReportStatus.DRAFT) {
            throw new BadRequestException("Only a DRAFT report can be edited");
        }
        report.replaceBody(validateBody(request), now());
        return ReportResponseDto.fromEntity(reportRepository.save(report));
    }

    @Override
    @Transactional
    @PreAuthorize("isAuthenticated()")
    public ReportResponseDto submit(String caseId, String reportId, CaseVaultUserPrincipal principal) {
        Case aCase = visibleCase(caseId, principal);
        Report report = reportOfCase(reportId, caseId, principal);
        requireAuthor(report, principal);
        requireOpen(aCase);
        if (report.getStatus() != ReportStatus.DRAFT) {
            throw new BadRequestException("Only a DRAFT report can be submitted");
        }
        report.markSubmitted(now());
        Report saved = reportRepository.save(report);
        auditEventRecorder.record(AuditEventType.REPORT_TRANSITION, principal.getUserId(), caseId, "REPORT_SUBMITTED");
        return ReportResponseDto.fromEntity(saved);
    }

    @Override
    @Transactional
    @PreAuthorize("isAuthenticated()")
    public ReportResponseDto approve(String caseId, String reportId, CaseVaultUserPrincipal principal) {
        visibleCase(caseId, principal);
        Report report = reportOfCase(reportId, caseId, principal);
        if (principal.getRole() != Role.MANAGER) {
            throw masked(principal, caseId);
        }
        // Four-eyes (FR-12, SR-06): enforced here regardless of roles, so a role overlap can never self-approve.
        if (Objects.equals(report.getAuthorId(), principal.getUserId())) {
            auditEventRecorder.record(AuditEventType.ACCESS_DENIED, principal.getUserId(), caseId, "NOT_PERMITTED");
            throw new BadRequestException("The author of a report cannot approve it");
        }
        if (report.getStatus() != ReportStatus.SUBMITTED) {
            throw new BadRequestException("Only a SUBMITTED report can be approved");
        }
        User approver = userRepository.findById(principal.getUserId())
                .orElseThrow(() -> new ResourceNotFoundException("Report not found"));
        report.markApproved(approver, now());
        Report saved = reportRepository.save(report);
        auditEventRecorder.record(AuditEventType.REPORT_TRANSITION, principal.getUserId(), caseId, "REPORT_APPROVED");
        return ReportResponseDto.fromEntity(saved);
    }

    @Override
    @PreAuthorize("isAuthenticated()")
    public List<ReportResponseDto> list(String caseId, CaseVaultUserPrincipal principal) {
        visibleCase(caseId, principal);
        List<Report> reports = principal.getRole() == Role.CLIENT
                ? reportRepository.findByCaseEntityIdAndStatusOrderByCreatedAtAsc(caseId, ReportStatus.APPROVED)
                : reportRepository.findByCaseEntityIdOrderByCreatedAtAsc(caseId);
        return reports.stream().map(ReportResponseDto::fromEntity).toList();
    }

    @Override
    @PreAuthorize("isAuthenticated()")
    public ReportResponseDto get(String caseId, String reportId, CaseVaultUserPrincipal principal) {
        visibleCase(caseId, principal);
        return ReportResponseDto.fromEntity(reportOfCase(reportId, caseId, principal));
    }

    // ---- helpers ----

    /** The case if the caller may read it; otherwise 404 (masked and audited when it exists). */
    private Case visibleCase(String caseId, CaseVaultUserPrincipal principal) {
        if (principal == null || principal.getRole() == Role.AUDITOR_ADMIN) {
            throw masked(principal, caseId);
        }
        Case aCase = caseRepository.findById(caseId == null ? "" : caseId)
                .orElseThrow(() -> new ResourceNotFoundException("Case not found"));
        if (!accessPolicy.canReadCase(principal, aCase)) {
            throw masked(principal, caseId);
        }
        return aCase;
    }

    /** The report must belong to the case of the path; a CLIENT only ever reaches APPROVED reports. */
    private Report reportOfCase(String reportId, String caseId, CaseVaultUserPrincipal principal) {
        Report report = reportRepository.findByIdAndCaseEntityId(reportId == null ? "" : reportId, caseId)
                .orElseThrow(() -> new ResourceNotFoundException("Report not found"));
        if (principal.getRole() == Role.CLIENT && report.getStatus() != ReportStatus.APPROVED) {
            throw masked(principal, caseId);
        }
        return report;
    }

    private void requireAuthor(Report report, CaseVaultUserPrincipal principal) {
        if (!Objects.equals(report.getAuthorId(), principal.getUserId())
                || principal.getRole() != Role.ANALYST) {
            throw masked(principal, report.getCaseId());
        }
    }

    private static void requireOpen(Case aCase) {
        if (CLOSED.equals(aCase.getStatus())) {
            throw new BadRequestException("Reports cannot be created or changed on a closed case");
        }
    }

    private ResourceNotFoundException masked(CaseVaultUserPrincipal principal, String caseId) {
        auditEventRecorder.record(AuditEventType.ACCESS_DENIED,
                principal == null ? null : principal.getUserId(), caseId, "NOT_VISIBLE");
        return new ResourceNotFoundException("Report not found");
    }

    /**
     * Plain text only. CRLF is normalised to LF (browsers submit CRLF), then empty, over-length and control
     * characters other than newline and tab are rejected. HTML-looking text is kept as is: it is escaped on output.
     */
    static String validateBody(ReportRequestDto request) {
        String raw = request == null ? null : request.getBody();
        if (raw == null) {
            throw new BadRequestException("Report body is required");
        }
        String body = raw.replace("\r\n", "\n");
        if (body.isBlank()) {
            throw new BadRequestException("Report body is required");
        }
        if (body.length() > Report.MAX_BODY_LENGTH) {
            throw new BadRequestException("Report body must not exceed " + Report.MAX_BODY_LENGTH + " characters");
        }
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (Character.isISOControl(c) && c != '\n' && c != '\t') {
                throw new BadRequestException("Report body contains a control character that is not allowed");
            }
        }
        return body;
    }

    private static Instant now() {
        return Instant.now().truncatedTo(ChronoUnit.MILLIS);
    }
}
