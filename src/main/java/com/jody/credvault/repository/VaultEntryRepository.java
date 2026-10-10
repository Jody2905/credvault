package com.jody.credvault.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.jody.credvault.model.VaultEntry;

public interface VaultEntryRepository extends JpaRepository<VaultEntry, UUID> {

    List<VaultEntry> findByOwner_IdOrderByTitleAsc(UUID ownerId);

    /**
     * The ownership check is part of the query itself:
     * WHERE id = ? AND owner_id = ?. An entry that belongs to someone else
     * simply isn't found. This prevents IDOR (insecure direct object
     * reference), where changing an ID in a URL exposes another user's data.
     */
    Optional<VaultEntry> findByIdAndOwner_Id(UUID id, UUID ownerId);

    long countByOwner_Id(UUID ownerId);
}
