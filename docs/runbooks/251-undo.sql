-- ===================================================================
-- 251-undo.sql: take migration 251 (the NOLOGIN owner of the retracted-BBA
-- guards, backlog 6bdac68f) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- READ FIRST. Once undone, a maintenance login can again write a row of
-- `mass_function_purge_grants` and then delete a retracted mass function with
-- no `mass_functions.purge` audit row, and can again clear a retraction (set
-- `epigraph.mf_unretract_id` and UPDATE the retract columns to NULL) with no
-- `mass_functions.unretract` audit row: 194's and 184's documented residual.
-- The purge and the un-retract keep working for their callers either way.
--
-- WHAT IT DOES
--   * Restores migration 184's body of
--     `public.epigraph_mass_function_retract_guard()` byte for byte with
--     `CREATE OR REPLACE` (never DROP, which would drop the four triggers that
--     call it), stating 184's `search_path = pg_catalog, public`.
--   * Re-owns `epigraph_mf_purge_granted(uuid)`,
--     `epigraph_purge_mass_functions(uuid[], text)` and
--     `epigraph_unretract_mass_function(uuid, text, uuid, uuid)` to
--     `epigraph_maintenance`, and re-grants EXECUTE to the maintenance role
--     (OWNER TO rewrites the old owner's entry to the new owner).
--   * Revokes every privilege of `epigraph_bba_guard_owner` on the grant table
--     and gives `epigraph_maintenance` 194's SELECT, INSERT, DELETE back.
--   * Drops `public.epigraph_bba_guard_owner_faults()`.
--
-- WHAT IT LEAVES: the role `epigraph_bba_guard_owner` (roles are
-- cluster-wide, and another database of the cluster may still own objects
-- through it), and 251's `_sqlx_migrations` row. Once no database of the
-- cluster has 251 applied, drop the role by hand as a superuser:
--     DROP ROLE epigraph_bba_guard_owner;
-- Re-introducing 251 is a NEW migration (or a re-run of 251's text, whose
-- precondition accepts the guard body this file restores). Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

-- Migration 184's body, verbatim.
CREATE OR REPLACE FUNCTION public.epigraph_mass_function_retract_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public AS $$
BEGIN
    -- R-103: no session or frame re-writes a retracted row's assessment.
    IF TG_ARGV[0] = 'rewrite' THEN
        RAISE EXCEPTION 'RT07: mass function % is retracted; a write to its key (claim, frame, '
            'source agent, perspective) is refused until it is un-retracted; nothing was written',
            OLD.id
            USING ERRCODE = '42501', DETAIL = OLD.id::text;
    END IF;
    -- R-103: only section 2b's definer clears a retraction.
    IF TG_ARGV[0] = 'clear' THEN
        IF public.epigraph_definer_bypass()
           AND current_setting('epigraph.mf_unretract_id', true) = OLD.id::text THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'RT06: a retracted mass function is made live again only through '
            'epigraph_unretract_mass_function (which records who, why and an audit row); '
            'nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF public.epigraph_bypass() OR public.epigraph_definer_bypass() THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'RT06: a mass function is retracted only through '
        'epigraph_retract_mass_function (which records the retractor and an audit row); '
        'nothing was written'
        USING ERRCODE = '42501';
END $$;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_mf_purge_granted(uuid) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_purge_mass_functions(uuid[], text) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_unretract_mass_function(uuid, text, uuid, uuid) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_purge_mass_functions(uuid[], text) TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_unretract_mass_function(uuid, text, uuid, uuid) TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT, DELETE ON public.mass_function_purge_grants TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_bba_guard_owner') THEN
        EXECUTE 'REVOKE ALL ON public.mass_function_purge_grants FROM epigraph_bba_guard_owner';
    END IF;
END $$;

COMMENT ON TABLE public.mass_function_purge_grants IS
    'Migration 194 (H10): one row names one mass_functions id that the purge definer is about to '
    'delete in THIS transaction (xact_id). Written and cleared only by '
    'epigraph_purge_mass_functions; read only through epigraph_mf_purge_granted. The application '
    'role holds no privilege on it.';

DROP FUNCTION IF EXISTS public.epigraph_bba_guard_owner_faults();

COMMIT;
