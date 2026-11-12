-- PostgreSQL only (loaded through the {vendor} Flyway location; H2 has no such location).
-- Rejects UPDATE, DELETE and TRUNCATE on audit_events for every role, including the application role.
-- Residual risk: the table owner or a superuser can still DROP the trigger. See docs/adr/0005-audit-chain.md.
CREATE FUNCTION audit_events_reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_reject_mutation();

CREATE TRIGGER trg_audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_reject_mutation();
