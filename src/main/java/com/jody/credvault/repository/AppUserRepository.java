package com.jody.credvault.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.jody.credvault.model.AppUser;

/**
 * Spring Data writes the SQL for these methods from their names, always as
 * parameterized queries.
 */
public interface AppUserRepository extends JpaRepository<AppUser, UUID> {

    Optional<AppUser> findByUsername(String username);

    boolean existsByUsername(String username);
}
