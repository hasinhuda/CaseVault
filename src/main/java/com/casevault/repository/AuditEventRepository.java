package com.casevault.repository;

import com.casevault.model.AuditEvent;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Append-only repository. It extends the marker {@link Repository} (not CrudRepository) so that no delete or
 * bulk-update method exists. {@code save} can only insert because {@link AuditEvent} is "new" until persisted.
 */
public interface AuditEventRepository extends Repository<AuditEvent, UUID> {

    AuditEvent save(AuditEvent event);

    Optional<AuditEvent> findFirstByOrderBySequenceNoDesc();

    List<AuditEvent> findBySequenceNoGreaterThanOrderBySequenceNoAsc(long sequenceNo, Pageable page);

    long count();
}
