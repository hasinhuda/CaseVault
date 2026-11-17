package com.casevault.service;

import com.casevault.dto.CreateUserRequestDto;
import com.casevault.exception.AdminActionRefusedException;
import com.casevault.exception.ResourceNotFoundException;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseNoteRepository;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.EvidenceRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.RemediationActionRepository;
import com.casevault.repository.ReportRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.security.PasswordPolicyValidator;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

/**
 * Default {@link AdminUserService}.
 *
 * <p>Concurrency: disable and enable run one at a time inside this JVM ({@code adminLock}, held until the
 * transaction committed) and additionally row-lock the active admins in the database, so two admins disabling each
 * other at the same moment cannot leave zero active admins. Sessions are ended through Spring Security's
 * in-memory {@link SessionRegistry} (per node, lost on restart). Audit events are recorded through
 * {@link AuditEventRecorder} (appended after commit); the actor is the only user id stored.
 */
@Service
public class DefaultAdminUserService implements AdminUserService {

    static final int DEFAULT_PAGE_SIZE = 25;
    static final int MAX_PAGE_SIZE = 50;
    private static final int MAX_PAGE_INDEX = 100_000;
    private static final Pattern UUID_SHAPE = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    private final UserRepository userRepository;
    private final OrganisationRepository organisationRepository;
    private final CaseRepository caseRepository;
    private final EvidenceRepository evidenceRepository;
    private final CaseNoteRepository caseNoteRepository;
    private final RemediationActionRepository remediationActionRepository;
    private final ReportRepository reportRepository;
    private final PasswordEncoder passwordEncoder;
    private final java.util.function.Consumer<String> sessionExpirer;
    private final AuditEventRecorder recorder;
    private final EvidenceStore evidenceStore;
    private final AuditStatusProvider auditStatus;
    private final TransactionTemplate transactionTemplate;
    private final ReentrantLock adminLock = new ReentrantLock(true);

    public DefaultAdminUserService(UserRepository userRepository,
                                   OrganisationRepository organisationRepository,
                                   CaseRepository caseRepository,
                                   EvidenceRepository evidenceRepository,
                                   CaseNoteRepository caseNoteRepository,
                                   RemediationActionRepository remediationActionRepository,
                                   ReportRepository reportRepository,
                                   PasswordEncoder passwordEncoder,
                                   SessionRegistry sessionRegistry,
                                   AuditEventRecorder recorder, EvidenceStore evidenceStore,
                                   AuditStatusProvider auditStatus,
                                   PlatformTransactionManager transactionManager) {
        this.userRepository = userRepository;
        this.organisationRepository = organisationRepository;
        this.caseRepository = caseRepository;
        this.evidenceRepository = evidenceRepository;
        this.caseNoteRepository = caseNoteRepository;
        this.remediationActionRepository = remediationActionRepository;
        this.reportRepository = reportRepository;
        this.passwordEncoder = passwordEncoder;
        // Only the expiring action is kept, not the registry object itself.
        this.sessionExpirer = userId -> expireSessions(sessionRegistry, userId);
        this.recorder = recorder;
        this.evidenceStore = evidenceStore;
        this.auditStatus = auditStatus;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @Override
    public UserPage listUsers(CaseVaultUserPrincipal admin, String pageRaw, String sizeRaw) {
        requireAdmin(admin);
        int size = clamp(sizeRaw, DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE, DEFAULT_PAGE_SIZE);
        int page = clamp(pageRaw, 0, 0, MAX_PAGE_INDEX, 0);
        Instant now = Instant.now();
        Page<User> result = userRepository.findAll(PageRequest.of(page, size, Sort.by("username").ascending()));
        List<UserRow> rows = result.getContent().stream().map(u -> toRow(u, now)).toList();
        return new UserPage(rows, page, size, result.getTotalPages(), result.getTotalElements(),
                result.hasPrevious(), result.hasNext());
    }

    @Override
    public UserRow getUser(CaseVaultUserPrincipal admin, String userId) {
        requireAdmin(admin);
        return toRow(find(userId), Instant.now());
    }

    @Override
    public ActionResult disable(CaseVaultUserPrincipal admin, String userId) {
        requireAdmin(admin);
        String targetId = requireShape(userId);
        ActionResult result = locked(admin, () -> transactionTemplate.execute(status -> {
            requireActiveActor(admin);
            User target = userRepository.findById(targetId)
                    .orElseThrow(() -> new ResourceNotFoundException("Not found"));
            if (Objects.equals(target.getId(), admin.getUserId())) {
                throw new AdminActionRefusedException("You cannot disable your own account.");
            }
            if (!target.isEnabled()) {
                return ActionResult.NO_CHANGE;
            }
            if (target.getRole() == Role.AUDITOR_ADMIN) {
                // Row locks + count in the same transaction: the last active admin cannot be disabled.
                long activeAdmins = userRepository.lockActiveByRole(Role.AUDITOR_ADMIN).size();
                if (activeAdmins <= 1) {
                    throw new AdminActionRefusedException("The last active administrator cannot be disabled.");
                }
            }
            target.setEnabled(false);
            target.recordStatusChange(admin.getUserId(), now());
            userRepository.save(target);
            recorder.record(AuditEventType.ADMIN_ACCOUNT_DISABLED, admin.getUserId(), null,
                    AuditReasonCode.DISABLED_BY_ADMIN.name());
            return ActionResult.DONE;
        }));
        if (result == ActionResult.DONE) {
            sessionExpirer.accept(targetId);
        }
        return result;
    }

    @Override
    public ActionResult enable(CaseVaultUserPrincipal admin, String userId) {
        requireAdmin(admin);
        String targetId = requireShape(userId);
        return locked(admin, () -> transactionTemplate.execute(status -> {
            requireActiveActor(admin);
            User target = userRepository.findById(targetId)
                    .orElseThrow(() -> new ResourceNotFoundException("Not found"));
            if (target.isEnabled()) {
                return ActionResult.NO_CHANGE;
            }
            target.setEnabled(true);
            target.recordStatusChange(admin.getUserId(), now());
            userRepository.save(target);
            recorder.record(AuditEventType.ADMIN_ACCOUNT_ENABLED, admin.getUserId(), null,
                    AuditReasonCode.ENABLED_BY_ADMIN.name());
            return ActionResult.DONE;
        }));
    }

    @Override
    public void revokeSessions(CaseVaultUserPrincipal admin, String userId) {
        requireAdmin(admin);
        String targetId = requireShape(userId);
        locked(admin, () -> transactionTemplate.execute(status -> {
            requireActiveActor(admin);
            if (userRepository.findById(targetId).isEmpty()) {
                throw new ResourceNotFoundException("Not found");
            }
            if (Objects.equals(targetId, admin.getUserId())) {
                throw new AdminActionRefusedException("You cannot revoke your own sessions with this action.");
            }
            recorder.record(AuditEventType.ADMIN_SESSION_REVOKED, admin.getUserId(), null,
                    AuditReasonCode.SESSIONS_REVOKED.name());
            return ActionResult.DONE;
        }));
        sessionExpirer.accept(targetId);
    }

    @Override
    public UserRow createUser(CaseVaultUserPrincipal admin, CreateUserRequestDto request) {
        requireAdmin(admin);
        if (request == null) {
            throw new AdminActionRefusedException("Invalid user request.");
        }
        String username = request.getUsername() != null ? request.getUsername().trim() : "";
        String email = request.getEmail() != null ? request.getEmail().trim() : "";
        Role role = request.getRole();
        String password = request.getPassword();

        if (username.length() < 3 || username.length() > 50 || !username.matches("^[a-zA-Z0-9_.-]+$")) {
            throw new AdminActionRefusedException("Username must be 3-50 alphanumeric characters, dots, underscores or hyphens.");
        }
        if (email.isBlank() || email.length() > 100 || !email.contains("@")) {
            throw new AdminActionRefusedException("Valid email address required.");
        }
        if (role == null) {
            throw new AdminActionRefusedException("Role is required.");
        }

        try {
            PasswordPolicyValidator.validate(password);
        } catch (RuntimeException e) {
            throw new AdminActionRefusedException(e.getMessage());
        }

        return locked(admin, () -> transactionTemplate.execute(status -> {
            requireActiveActor(admin);

            if (userRepository.findByUsername(username).isPresent()) {
                throw new AdminActionRefusedException("Username '" + username + "' is already in use.");
            }
            if (userRepository.findByEmail(email).isPresent()) {
                throw new AdminActionRefusedException("Email '" + email + "' is already registered.");
            }

            Organisation organisation = null;
            if (role != Role.AUDITOR_ADMIN) {
                if (request.getOrganisationId() == null || request.getOrganisationId().isBlank()) {
                    throw new AdminActionRefusedException("Organisation is required for role " + role.name() + ".");
                }
                organisation = organisationRepository.findById(request.getOrganisationId())
                        .orElseThrow(() -> new AdminActionRefusedException("Selected organisation not found."));
            } else if (request.getOrganisationId() != null && !request.getOrganisationId().isBlank()) {
                organisation = organisationRepository.findById(request.getOrganisationId()).orElse(null);
            }

            Instant now = now();
            String passwordHash = passwordEncoder.encode(password);
            User newUser = new User(
                    UUID.randomUUID().toString(),
                    organisation,
                    username,
                    passwordHash,
                    role,
                    email,
                    true,
                    now
            );
            User saved = userRepository.save(newUser);

            recorder.record(AuditEventType.ADMIN_ACCOUNT_CREATED, admin.getUserId(), null,
                    AuditReasonCode.CREATED_BY_ADMIN.name());

            return toRow(saved, now);
        }));
    }

    @Override
    public ActionResult delete(CaseVaultUserPrincipal admin, String userId) {
        requireAdmin(admin);
        String targetId = requireShape(userId);
        ActionResult result = locked(admin, () -> transactionTemplate.execute(status -> {
            requireActiveActor(admin);
            User target = userRepository.findById(targetId)
                    .orElseThrow(() -> new ResourceNotFoundException("Not found"));

            if (Objects.equals(target.getId(), admin.getUserId())) {
                throw new AdminActionRefusedException("You cannot delete your own account.");
            }

            if (target.getRole() == Role.AUDITOR_ADMIN) {
                long activeAdmins = userRepository.lockActiveByRole(Role.AUDITOR_ADMIN).size();
                if (activeAdmins <= 1 && target.isEnabled()) {
                    throw new AdminActionRefusedException("The last active administrator cannot be deleted.");
                }
            }

            if (caseRepository.existsByOwner_Id(targetId) || caseRepository.existsByAssignedAnalyst_Id(targetId)) {
                throw new AdminActionRefusedException("Cannot delete user with linked cases. Disable the account instead.");
            }
            if (evidenceRepository.existsByUploadedBy_Id(targetId)) {
                throw new AdminActionRefusedException("Cannot delete user with uploaded evidence. Disable the account instead.");
            }
            if (caseNoteRepository.existsByAuthor_Id(targetId)) {
                throw new AdminActionRefusedException("Cannot delete user with case investigation notes. Disable the account instead.");
            }
            if (remediationActionRepository.existsByCreatedBy_Id(targetId)) {
                throw new AdminActionRefusedException("Cannot delete user with created remediation actions. Disable the account instead.");
            }
            if (reportRepository.existsByAuthor_Id(targetId) || reportRepository.existsByApprovedBy_Id(targetId)) {
                throw new AdminActionRefusedException("Cannot delete user with authored or approved reports. Disable the account instead.");
            }

            userRepository.delete(target);

            recorder.record(AuditEventType.ADMIN_ACCOUNT_DELETED, admin.getUserId(), null,
                    AuditReasonCode.DELETED_BY_ADMIN.name());
            return ActionResult.DONE;
        }));

        if (result == ActionResult.DONE) {
            sessionExpirer.accept(targetId);
        }
        return result;
    }

    @Override
    public List<OrganisationSummary> listOrganisations(CaseVaultUserPrincipal admin) {
        requireAdmin(admin);
        return organisationRepository.findAll().stream()
                .map(org -> new OrganisationSummary(org.getId(), org.getName(), org.getCode()))
                .sorted(java.util.Comparator.comparing(OrganisationSummary::name, String.CASE_INSENSITIVE_ORDER))
                .toList();
    }

    @Override
    public HealthView health(CaseVaultUserPrincipal admin) {
        requireAdmin(admin);
        boolean db;
        try {
            db = userRepository.count() >= 0;
        } catch (RuntimeException e) {
            db = false;
        }
        boolean storage = evidenceStore.isWritable();
        AuditQueryService.ChainSummary summary = auditStatus.chainSummary();
        String state;
        if (summary.verification() == null) {
            state = "Not verified yet";
        } else if (summary.verification().valid()) {
            state = "Chain valid";
        } else {
            state = "Chain BROKEN at sequence " + summary.verification().firstBrokenSequenceNo();
        }
        return new HealthView(db, storage, state, summary.head() == null ? null : summary.head().sequenceNo());
    }

    // ---- helpers ----

    /** Runs the action alone; refusals are audited as ACCESS_DENIED / ADMIN_REFUSED after the rollback. */
    private <T> T locked(CaseVaultUserPrincipal admin, java.util.function.Supplier<T> action) {
        adminLock.lock();
        try {
            return action.get();
        } catch (AdminActionRefusedException refused) {
            recorder.record(AuditEventType.ACCESS_DENIED, admin.getUserId(), null,
                    AuditReasonCode.ADMIN_REFUSED.name());
            throw refused;
        } finally {
            adminLock.unlock();
        }
    }

    /** The acting admin must still be an enabled AUDITOR_ADMIN in the database at the time of the action. */
    private void requireActiveActor(CaseVaultUserPrincipal admin) {
        User actor = userRepository.findById(admin.getUserId()).orElse(null);
        if (actor == null || !actor.isEnabled() || actor.getRole() != Role.AUDITOR_ADMIN) {
            throw new ResourceNotFoundException("Not found");
        }
    }

    private static void expireSessions(SessionRegistry sessionRegistry, String userId) {
        for (Object principal : sessionRegistry.getAllPrincipals()) {
            if (principal instanceof CaseVaultUserPrincipal p && Objects.equals(p.getUserId(), userId)) {
                for (SessionInformation info : sessionRegistry.getAllSessions(principal, false)) {
                    info.expireNow();
                }
            }
        }
    }

    private void requireAdmin(CaseVaultUserPrincipal admin) {
        if (admin == null || admin.getRole() != Role.AUDITOR_ADMIN) {
            if (admin != null) {
                recorder.record(AuditEventType.ACCESS_DENIED, admin.getUserId(), null,
                        AuditReasonCode.NOT_VISIBLE.name());
            }
            throw new ResourceNotFoundException("Not found");
        }
    }

    private static String requireShape(String id) {
        if (id == null || !UUID_SHAPE.matcher(id).matches()) {
            throw new ResourceNotFoundException("Not found");
        }
        return id;
    }

    private User find(String id) {
        return userRepository.findById(requireShape(id))
                .orElseThrow(() -> new ResourceNotFoundException("Not found"));
    }

    private static UserRow toRow(User u, Instant now) {
        return new UserRow(u.getId(), u.getUsername(), u.getRole().name(),
                u.getOrganisation() == null ? "" : u.getOrganisation().getCode(),
                u.isEnabled(), u.isAccountLocked(now), u.getStatusChangedAt());
    }

    private static int clamp(String raw, int fallback, int min, int max, int absent) {
        if (raw == null || raw.isBlank() || raw.length() > 12) {
            return absent;
        }
        try {
            long value = Long.parseLong(raw.trim());
            if (value < min && min == 1) {
                return fallback;
            }
            return (int) Math.max(min, Math.min(max, value));
        } catch (NumberFormatException e) {
            return absent;
        }
    }

    private static Instant now() {
        return Instant.now().truncatedTo(ChronoUnit.MILLIS);
    }
}
