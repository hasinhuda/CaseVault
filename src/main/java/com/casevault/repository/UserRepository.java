package com.casevault.repository;

import com.casevault.model.Role;
import com.casevault.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    long countByRole(Role role);
    java.util.List<User> findByRoleAndEnabledTrue(Role role);

    /** Row-locks every active user of the role (fixed order) so concurrent disable decisions are serialised. */
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT u FROM User u WHERE u.role = :role AND u.enabled = true ORDER BY u.id")
    java.util.List<User> lockActiveByRole(@Param("role") Role role);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE User u SET u.failedLoginAttempts = u.failedLoginAttempts + 1, u.updatedAt = :now WHERE u.id = :userId")
    void incrementFailedAttempts(@Param("userId") String userId, @Param("now") Instant now);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE User u SET u.failedLoginAttempts = :attempts, u.lockedUntil = :lockedUntil, u.updatedAt = :now WHERE u.id = :userId")
    void lockUserAccount(@Param("userId") String userId, @Param("attempts") int attempts, @Param("lockedUntil") Instant lockedUntil, @Param("now") Instant now);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE User u SET u.failedLoginAttempts = 0, u.lockedUntil = NULL, u.updatedAt = :now WHERE u.id = :userId")
    void resetFailedAttempts(@Param("userId") String userId, @Param("now") Instant now);
}

