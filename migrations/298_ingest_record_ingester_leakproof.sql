-- 298: a LEAKPROOF accessor for an ingest record's ingester, so the disclosure
-- core's ingest-record probe can be an index condition under row security
-- (spec docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md,
-- sections 6.1 and 11.1; operator ruling C6).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 295's ingest-record arm compares `(r.properties ->> 'ingested_by')` with the
-- bound agent's id. The core is a maintenance-owned definer and `edges` is
-- FORCE RLS, so in the definer frame the probe runs under edges' policy, and
-- PostgreSQL evaluates a qual that is not LEAKPROOF only AFTER the policy qual:
-- it can be no index condition. jsonb's `->>` (and a uuid-to-text cast on a
-- Var) are not leakproof, so 294's expression index was never usable there.
-- Measured on the section 11 harness shape: the probe fell back to
-- `idx_edges_created_at` and took 198 s per core evaluation.
--
-- ===================================================================
-- 2. WHAT IT ADDS
-- ===================================================================
--
-- `public.epigraph_ingest_record_ingester(jsonb) RETURNS text`: `SELECT
-- p ->> 'ingested_by'`, `LANGUAGE sql IMMUTABLE LEAKPROOF PARALLEL SAFE SECURITY INVOKER`,
-- `SET search_path = pg_catalog, pg_temp`.
--   * LEAKPROOF is TRUE of it: `->>` on any jsonb with a constant text key
--     returns the member or NULL and never raises, so the function reveals
--     nothing about a row through an error or a side effect. It returns TEXT,
--     never a uuid: a cast could raise with the value in its message.
--   * The SET clause keeps it from being inlined: an inlined body is the bare
--     `->>` again, which is not leakproof. (It also satisfies 271's ratchet.)
--   * IMMUTABLE, so 299 can index it.
--   * EXECUTE stays with PUBLIC: it is a pure function of its argument and
--     reads no table, and EVERY role that inserts an `edges` row initialises
--     the index expression and is ACL-checked for it (the application role's
--     ingest walk included).
--   * Owner `epigraph_maintenance` when present (the attribute survives the
--     owner change; only a superuser can set it again).
--
-- PRECONDITION (LKP01, 42501): only a superuser may declare a function
-- LEAKPROOF. The migration runner is a superuser on every deployment (212,
-- 238); on a runner that is not, this refuses with nothing changed instead of
-- creating a non-leakproof accessor that would silently reproduce the 198 s
-- probe.
--
-- UNDO: `DROP FUNCTION public.epigraph_ingest_record_ingester(jsonb)` after
-- 300's undo and dropping 299's index.
SET LOCAL lock_timeout = '3s';

DO $$
BEGIN
    IF NOT COALESCE((SELECT r.rolsuper FROM pg_catalog.pg_roles r
                      WHERE r.rolname = current_user), false) THEN
        RAISE EXCEPTION 'LKP01: 298 declares a LEAKPROOF function, which only a superuser may '
                        'do; run the migrations as a superuser; nothing was changed'
            USING ERRCODE = '42501';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_ingest_record_ingester(p_properties jsonb)
RETURNS text
LANGUAGE sql IMMUTABLE LEAKPROOF PARALLEL SAFE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT p_properties ->> 'ingested_by'
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_ingest_record_ingester(jsonb) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 298 accessor '
                     'stays owned by the migration runner.';
    END IF;
END $$;
