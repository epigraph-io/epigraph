-- Migration 055: replace the static edges CHECK with a registry FK, and make
-- validate_edge_reference registry-driven for non-core types (Phase 2).
--
-- EVIDENCE
-- Migration 054 established the `entity_types` registry as the single source
-- of truth. But two hardcoded gates still exist:
--   1. the static CHECK `edges_entity_types_valid` (migration 020) — a frozen
--      20-type allowlist that must be re-migrated for every new type; and
--   2. `validate_edge_reference` (migration 025) — a CASE whose `ELSE FALSE`
--      arm silently rejects synthesis/coalition/propaganda_technique, so a
--      synthesis edge cannot be written end-to-end (epigraph #344 follow-up).
--
-- DECISION
-- (A) Replace the static CHECK with FKs from edges.source_type /
--     edges.target_type to entity_types(type_name). Validity becomes
--     registry-derived and auto-updating: registering a type in the API makes
--     its edges insertable with no schema migration. The FK is added
--     NOT VALID then VALIDATE CONSTRAINT to avoid the AccessExclusive
--     full-table rewrite lock (source/target are varchar(50); FK viable).
--     The seeded registry is a SUPERSET of the old CHECK's 20 types (it adds
--     synthesis/coalition/propaganda_technique), so no currently-valid edge
--     is regressed by the swap.
-- (B) Rewrite validate_edge_reference: KEEP the hardcoded fast-path arms for
--     the ~20 core types (zero plpgsql cost on the hot path — `node => TRUE`
--     stays UNCHANGED per the locked decision), and change ONLY the `ELSE`
--     branch to a registry-driven dynamic EXISTS. Net effect:
--     synthesis/coalition/propaganda_technique are now existence-checked via
--     the registry; the 20 current types are byte-for-byte unchanged.
--
-- INJECTION SAFETY
-- The dynamic arm reads schema_name/table_name/id_column from entity_types
-- (constrained at rest by the migration-054 CHECK regexes), quotes them with
-- %I (quote_ident) in format(), and binds entity_id via USING $1 (never
-- interpolated). to_regclass() takes a bound-shaped text value.

-- ── (A) swap the static CHECK for registry FKs ──────────────────────────────
ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_entity_types_valid;

ALTER TABLE edges
    ADD CONSTRAINT edges_source_type_fkey
    FOREIGN KEY (source_type) REFERENCES entity_types(type_name) NOT VALID;
ALTER TABLE edges
    ADD CONSTRAINT edges_target_type_fkey
    FOREIGN KEY (target_type) REFERENCES entity_types(type_name) NOT VALID;

ALTER TABLE edges VALIDATE CONSTRAINT edges_source_type_fkey;
ALTER TABLE edges VALIDATE CONSTRAINT edges_target_type_fkey;

-- ── (B) registry-driven ELSE arm for validate_edge_reference ────────────────
CREATE OR REPLACE FUNCTION validate_edge_reference(entity_id UUID, entity_type CHARACTER VARYING)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    et            RECORD;
    regclass_name text;
    result        boolean;
BEGIN
    -- Hardcoded fast-path arms for the ~20 core types: no plpgsql cost, no
    -- registry lookup on the hot path. `node => TRUE` is preserved verbatim.
    -- NOTE: this is an ASSIGNMENT (`result := CASE ... END;`), not
    -- `RETURN CASE ... END INTO result` — `RETURN` takes no `INTO` clause in
    -- plpgsql (that would be a parse-level syntax error aborting the whole
    -- migration). The immediately-following `IF result IS NOT NULL` returns the
    -- fast-path result; a NULL (the `ELSE NULL` arm) falls through to the
    -- registry-driven path below.
    result := CASE entity_type
        WHEN 'claim'              THEN EXISTS (SELECT 1 FROM claims WHERE id = entity_id)
        WHEN 'agent'              THEN EXISTS (SELECT 1 FROM agents WHERE id = entity_id)
        WHEN 'evidence'           THEN EXISTS (SELECT 1 FROM evidence WHERE id = entity_id)
        WHEN 'trace'              THEN EXISTS (SELECT 1 FROM reasoning_traces WHERE id = entity_id)
        WHEN 'paper'              THEN EXISTS (SELECT 1 FROM papers WHERE id = entity_id)
        WHEN 'analysis'           THEN EXISTS (SELECT 1 FROM analyses WHERE id = entity_id)
        WHEN 'activity'           THEN EXISTS (SELECT 1 FROM activities WHERE id = entity_id)
        WHEN 'source_artifact'    THEN EXISTS (SELECT 1 FROM source_artifacts WHERE id = entity_id)
        WHEN 'span'               THEN EXISTS (SELECT 1 FROM agent_spans WHERE id = entity_id)
        WHEN 'entity'             THEN EXISTS (SELECT 1 FROM entities WHERE id = entity_id)
        WHEN 'task'               THEN EXISTS (SELECT 1 FROM tasks WHERE id = entity_id)
        WHEN 'event'              THEN EXISTS (SELECT 1 FROM events WHERE id = entity_id)
        WHEN 'experiment'         THEN EXISTS (SELECT 1 FROM experiments WHERE id = entity_id)
        WHEN 'experiment_result'  THEN EXISTS (SELECT 1 FROM experiment_results WHERE id = entity_id)
        WHEN 'workflow'           THEN EXISTS (SELECT 1 FROM workflows WHERE id = entity_id)
        WHEN 'perspective'        THEN EXISTS (SELECT 1 FROM perspectives WHERE id = entity_id)
        WHEN 'community'          THEN EXISTS (SELECT 1 FROM communities WHERE id = entity_id)
        WHEN 'context'            THEN EXISTS (SELECT 1 FROM contexts WHERE id = entity_id)
        WHEN 'frame'              THEN EXISTS (SELECT 1 FROM frames WHERE id = entity_id)
        WHEN 'node'               THEN TRUE
        ELSE NULL  -- fall through to the registry-driven path below
    END;

    IF result IS NOT NULL THEN
        RETURN result;
    END IF;

    -- Registry-driven path for non-core types (synthesis/coalition/
    -- propaganda_technique and any API-registered type).
    SELECT schema_name, table_name, id_column, is_optional
      INTO et
      FROM entity_types
     WHERE type_name = entity_type;

    IF NOT FOUND THEN
        RETURN false;            -- unknown type (FK should already have rejected)
    END IF;
    IF et.table_name IS NULL THEN
        RETURN false;            -- table-less type (node handled above; defensive)
    END IF;

    -- Foreign/absent-tolerant: if the backing table is absent, an optional
    -- type resolves to "does not exist" (false); a non-optional type also
    -- returns false here (never fabricate existence for a missing owned table
    -- in the trigger — the loud/owned failure surfaces at the app layer).
    regclass_name := et.schema_name || '.' || et.table_name;
    IF to_regclass(regclass_name) IS NULL THEN
        RETURN false;
    END IF;

    -- Dynamic EXISTS with quoted identifiers (%I) and a bound entity_id.
    -- Optional-type query errors are swallowed to false (belt-and-suspenders
    -- around races / permission quirks on foreign tables).
    BEGIN
        EXECUTE format(
            'SELECT EXISTS(SELECT 1 FROM %I.%I WHERE %I = $1)',
            et.schema_name, et.table_name, et.id_column
        )
        INTO result
        USING entity_id;
        RETURN result;
    EXCEPTION WHEN OTHERS THEN
        RETURN false;
    END;
END;
$$;
