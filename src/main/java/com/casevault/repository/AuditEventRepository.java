package com.casevault.repository;

import com.casevault.model.AuditEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.Repository;

import java.time.Instant;
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

    /**
     * Filtered, newest-first read for the auditor view. Fully parameterised (no string building, no LIKE). The
     * "any" flags avoid null-typed parameters, which are unreliable across databases. Sorting is fixed in the query.
     */
    @Query("select e from AuditEvent e where (:anyType = true or e.eventType = :eventType) "
            + "and (:anyUser = true or e.userId = :userId) "
            + "and e.occurredAt >= :fromInclusive and e.occurredAt < :toExclusive "
            + "order by e.sequenceNo desc")
    Page<AuditEvent> findFiltered(@Param("anyType") boolean anyType, @Param("eventType") String eventType,
                                  @Param("anyUser") boolean anyUser, @Param("userId") UUID userId,
                                  @Param("fromInclusive") Instant fromInclusive,
                                  @Param("toExclusive") Instant toExclusive, Pageable page);
}
