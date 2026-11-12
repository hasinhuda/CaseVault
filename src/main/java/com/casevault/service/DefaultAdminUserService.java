package com.casevault.service;

import com.casevault.exception.AdminActionRefusedException;
import com.casevault.exception.ResourceNotFoundException;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
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
    private final java.util.function.Consumer<String> sessionExpirer;
    private final AuditEventRecorder recorder;
    private final EvidenceStore evidenceStore;
    private final AuditStatusProvider auditStatus;
    private final TransactionTemplate transactionTemplate;
    private final ReentrantLock adminLock = new ReentrantLock(true);

    public DefaultAdminUserService(UserRepository userRepository, SessionRegistry sessionRegistry,
                                   AuditEventRecorder recorder, EvidenceStore evidenceStore,
                                   AuditStatusProvider auditStatus,
                                   PlatformTransactionManager transactionManager) {
        this.userRepository = userRepository;
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
