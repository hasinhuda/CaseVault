package com.casevault.service;

/** Read-only view of the last in-memory chain verification, used by the health page. Never verifies by itself. */
public interface AuditStatusProvider {

    AuditQueryService.ChainSummary chainSummary();
}
