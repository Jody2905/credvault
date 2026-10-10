package com.jody.credvault.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.jody.credvault.model.AuditAction;
import com.jody.credvault.model.AuditEvent;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    /** Newest first. IDs only ever increase, so ordering by ID is ordering by time. */
    List<AuditEvent> findByUsernameOrderByIdDesc(String username);

    List<AuditEvent> findTop100ByOrderByIdDesc();

    long countByUsernameAndAction(String username, AuditAction action);
}
