-- Migration 043: Add referential integrity to edges table
--
-- The edges table is polymorphic (source_type/target_type determine which
-- table source_id/target_id reference). PostgreSQL doesn't support conditional
-- FKs, so we use a trigger to enforce referential integrity at write time.
--
-- Evidence:
-- - edges table currently allows dangling references (no FK constraints)
-- - submit_packet now creates SUPPORTS/USES_EVIDENCE edges atomically
-- - consistency requires that edge endpoints actually exist
--
-- Reasoning:
-- - Trigger-based validation is the standard PostgreSQL pattern for
--   polymorphic referential integrity
-- - Validates both source and target on INSERT and UPDATE
-- - Raises a clear error with the offending entity type and ID
-- - 'node' type is excluded from validation (no backing table, unused in practice)

CREATE OR REPLACE FUNCTION validate_edge_reference(
    entity_id UUID,
    entity_type VARCHAR
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN CASE entity_type
        WHEN 'claim'    THEN EXISTS (SELECT 1 FROM claims WHERE id = entity_id)
        WHEN 'agent'    THEN EXISTS (SELECT 1 FROM agents WHERE id = entity_id)
        WHEN 'evidence' THEN EXISTS (SELECT 1 FROM evidence WHERE id = entity_id)
        WHEN 'trace'    THEN EXISTS (SELECT 1 FROM reasoning_traces WHERE id = entity_id)
        WHEN 'paper'    THEN EXISTS (SELECT 1 FROM papers WHERE id = entity_id)
        WHEN 'analysis' THEN EXISTS (SELECT 1 FROM analyses WHERE id = entity_id)
        WHEN 'node'     THEN TRUE  -- no backing table; skip validation
        ELSE FALSE
    END;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION trigger_validate_edge_refs()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT validate_edge_reference(NEW.source_id, NEW.source_type) THEN
        RAISE EXCEPTION 'Edge source references nonexistent % with id %',
            NEW.source_type, NEW.source_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    IF NOT validate_edge_reference(NEW.target_id, NEW.target_type) THEN
        RAISE EXCEPTION 'Edge target references nonexistent % with id %',
            NEW.target_type, NEW.target_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER edges_validate_refs
    BEFORE INSERT OR UPDATE ON edges
    FOR EACH ROW
    EXECUTE FUNCTION trigger_validate_edge_refs();

-- Also add a CASCADE-style cleanup: when a referenced entity is deleted,
-- remove any edges pointing to/from it. This mirrors ON DELETE CASCADE behavior.

CREATE OR REPLACE FUNCTION cascade_delete_edges()
RETURNS TRIGGER AS $$
BEGIN
    DELETE FROM edges
    WHERE (source_id = OLD.id AND source_type = TG_ARGV[0])
       OR (target_id = OLD.id AND target_type = TG_ARGV[0]);
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER claims_cascade_edges
    BEFORE DELETE ON claims
    FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('claim');

CREATE TRIGGER agents_cascade_edges
    BEFORE DELETE ON agents
    FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('agent');

CREATE TRIGGER evidence_cascade_edges
    BEFORE DELETE ON evidence
    FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('evidence');

CREATE TRIGGER traces_cascade_edges
    BEFORE DELETE ON reasoning_traces
    FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('trace');

CREATE TRIGGER papers_cascade_edges
    BEFORE DELETE ON papers
    FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('paper');

CREATE TRIGGER analyses_cascade_edges
    BEFORE DELETE ON analyses
    FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('analysis');
