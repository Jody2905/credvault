package com.jody.credvault.service;

import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.jody.credvault.model.AuditAction;
import com.jody.credvault.model.AuditEvent;
import com.jody.credvault.repository.AuditEventRepository;

@Service
public class AuditService {

    private final AuditEventRepository events;

    public AuditService(AuditEventRepository events) {
        this.events = events;
    }

    /**
     * REQUIRES_NEW runs this in its own separate transaction, committed straight away.
     *
     * Why it matters: a failed login throws an exception, which rolls back the
     * surrounding transaction. Without REQUIRES_NEW the "UNLOCK_FAILED" record
     * would be rolled back too, and failed attempts, the thing you most want
     * to see, would vanish from the audit trail.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(String username, AuditAction action, boolean success,
                       UUID entryId, String detail) {
        events.save(new AuditEvent(username, action, success, entryId, detail));
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> historyFor(String username) {
        return events.findByUsernameOrderByIdDesc(username);
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> recent() {
        return events.findTop100ByOrderByIdDesc();
    }
}
