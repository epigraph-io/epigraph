-- ===================================================================
-- 217-undo.sql: take migration 217 (factors written by the database's own
-- triggers, backlog a2c5f714) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- READ FIRST. Once undone, every application session can again INSERT,
-- UPDATE and DELETE any belief-propagation factor directly, over any pair of
-- claims, and both factor triggers run as the session again (an RLS-hidden
-- superseded endpoint then reads as current and is minted over). Undo only
-- after rolling back whatever needed 217; no binary needs it, so the undo
-- has no binary ordering of its own.
--
-- WHAT IT DOES
--   1. Restores 077's table grants on `public.factors` to `epigraph_app`
--      (INSERT, UPDATE, DELETE; SELECT was never revoked) and drops 217's
--      column grant on `frame_id` first, so no column ACL is left behind.
--   2. Restores migration 038's `public.auto_create_factor_from_edge()` and
--      001's `public.deactivate_superseded_factors()` byte for byte, with
--      `CREATE OR REPLACE` (never DROP, which would drop the two triggers):
--      SECURITY INVOKER, no pinned search_path.
--   3. Gives both back to the owner of `public.factors` (the role that ran
--      001 and 038) and restores PUBLIC's EXECUTE.
--
-- WHAT IT LEAVES: 217's `_sqlx_migrations` row, and every factor as it
-- stands. Re-introducing 217 is a NEW migration (or a re-run of 217's text,
-- which is idempotent). This file is idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE UPDATE (frame_id) ON public.factors FROM epigraph_app';
        EXECUTE 'GRANT INSERT, UPDATE, DELETE ON public.factors TO epigraph_app';
    END IF;
END $$;

-- Migration 038's body, verbatim.
CREATE OR REPLACE FUNCTION public.auto_create_factor_from_edge()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE
    ft  VARCHAR;
    fwd DOUBLE PRECISION;
    rev DOUBLE PRECISION;
    pot JSONB;
    var_ids UUID[];
    matcher_score DOUBLE PRECISION;
BEGIN
    IF NEW.source_type != 'claim' OR NEW.target_type != 'claim' THEN
        RETURN NEW;
    END IF;

    -- Skip edges involving superseded claims (unchanged from migration 090).
    IF EXISTS (SELECT 1 FROM claims WHERE id = NEW.source_id AND COALESCE(is_current, true) = false)
       OR EXISTS (SELECT 1 FROM claims WHERE id = NEW.target_id AND COALESCE(is_current, true) = false) THEN
        RETURN NEW;
    END IF;

    SELECT factor_type, forward_strength, reverse_strength
    INTO ft, fwd, rev
    FROM edge_to_factor_type(NEW.relationship);

    IF ft IS NULL THEN
        RETURN NEW;
    END IF;

    -- Matcher-derived evidential_support edges carry their own per-edge
    -- strength in properties.score. Use it (clamped to [0, 1]) instead of
    -- the constant fallback so calibration of the matcher flows through.
    IF ft = 'evidential_support'
       AND NEW.properties ? 'source'
       AND NEW.properties->>'source' = 'cross_source_matcher'
       AND NEW.properties ? 'score' THEN
        matcher_score := (NEW.properties->>'score')::double precision;
        IF matcher_score IS NOT NULL THEN
            fwd := GREATEST(0.0, LEAST(1.0, matcher_score));
            rev := fwd;
        END IF;
    END IF;

    IF ft = 'mutual_exclusion' THEN
        pot := '{}';
    ELSIF ft = 'directional_support' THEN
        pot := jsonb_build_object(
            'forward_strength', fwd,
            'reverse_strength', rev,
            'source_var', NEW.source_id::text
        );
    ELSE
        pot := jsonb_build_object('strength', fwd);
    END IF;

    IF NEW.source_id < NEW.target_id THEN
        var_ids := ARRAY[NEW.source_id, NEW.target_id];
    ELSE
        var_ids := ARRAY[NEW.target_id, NEW.source_id];
    END IF;

    INSERT INTO factors (factor_type, variable_ids, potential, description, properties)
    VALUES (
        ft,
        var_ids,
        pot,
        format('Auto-generated from %s edge %s', NEW.relationship, NEW.id),
        jsonb_build_object(
            'source_edge_id', NEW.id,
            'relationship', NEW.relationship,
            'edge_source_id', NEW.source_id,
            'edge_target_id', NEW.target_id
        )
    )
    ON CONFLICT DO NOTHING;

    RETURN NEW;
END;
$$;

-- Migration 001's body, verbatim.
CREATE OR REPLACE FUNCTION public.deactivate_superseded_factors()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF NEW.is_current = false AND COALESCE(OLD.is_current, true) = true THEN
        DELETE FROM factors WHERE NEW.id = ANY(variable_ids);
    END IF;
    RETURN NEW;
END;
$$;

DO $$
DECLARE v_owner text;
BEGIN
    SELECT pg_catalog.pg_get_userbyid(c.relowner) INTO v_owner
      FROM pg_catalog.pg_class c WHERE c.oid = 'public.factors'::regclass;
    EXECUTE format('ALTER FUNCTION public.auto_create_factor_from_edge() OWNER TO %I', v_owner);
    EXECUTE format('ALTER FUNCTION public.deactivate_superseded_factors() OWNER TO %I', v_owner);
END $$;

GRANT EXECUTE ON FUNCTION public.auto_create_factor_from_edge() TO PUBLIC;
GRANT EXECUTE ON FUNCTION public.deactivate_superseded_factors() TO PUBLIC;

COMMIT;
