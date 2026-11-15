-- ===================================================================
-- 228-undo.sql: take migration 228 (mass_functions.locality_tag widened to
-- varchar(64)) back out, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST. Narrowing back to varchar(20) fails if any row holds a tag
-- longer than 20 characters, so this file refuses up front and writes
-- nothing; decide what those rows' tags should be first (count them with
-- `SELECT locality_tag, count(*) FROM mass_functions
--   WHERE char_length(locality_tag) > 20 GROUP BY 1`). Re-tag only the
-- UNretracted ones. A RETRACTED row cannot be re-tagged (184's rewrite guard
-- refuses RT07) and cannot be plainly deleted (194's delete guard refuses
-- SR09); the only supported way to clear one is 194's
-- `epigraph_purge_mass_functions(ids, reason)` (maintenance role only), which
-- deletes the retracted row from `mass_functions` and keeps a copy only in a
-- `security_events` entry. So once any retracted row holds a
-- tag over 20 characters, treat 228 as FORWARD-ONLY: undo would mean
-- purging retracted evidence or bypassing the guards by hand, which this
-- runbook does not describe and does not endorse. Roll every binary that accepts a
-- tag over 20 characters back first, or a write in between can re-block the
-- undo. Unlike the widening, the narrowing re-checks every row, so it holds
-- ACCESS EXCLUSIVE on `mass_functions` for a full table scan.
--
-- WHAT IT DOES: drops 184's `mass_functions_retracted_rewrite_guard`, narrows
-- the column to varchar(20) and re-creates the trigger with 184's definition
-- verbatim (PostgreSQL refuses ALTER COLUMN TYPE on a column a trigger's WHEN
-- reads).
--
-- WHAT IT LEAVES: 228's `_sqlx_migrations` row. Re-widening is a NEW
-- migration (or a re-run of 228's text). Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM public.mass_functions WHERE char_length(locality_tag) > 20;
    IF n > 0 THEN
        RAISE EXCEPTION '228-undo: % mass_functions row(s) hold a locality_tag over 20 characters; '
            're-tag the unretracted ones before narrowing the column (a retracted one cannot be '
            're-tagged: see this file''s header, 228 may be forward-only); nothing was changed', n;
    END IF;
END $$;

DROP TRIGGER IF EXISTS mass_functions_retracted_rewrite_guard ON public.mass_functions;

ALTER TABLE public.mass_functions
    ALTER COLUMN locality_tag TYPE varchar(20);

-- 184's definition, verbatim.
CREATE TRIGGER mass_functions_retracted_rewrite_guard
    BEFORE UPDATE ON public.mass_functions
    FOR EACH ROW
    WHEN (OLD.retracted_at IS NOT NULL
          AND (NEW.masses, NEW.conflict_k, NEW.combination_method, NEW.source_strength,
               NEW.locality_tag, NEW.evidence_id, NEW.created_at)
              IS DISTINCT FROM
              (OLD.masses, OLD.conflict_k, OLD.combination_method, OLD.source_strength,
               OLD.locality_tag, OLD.evidence_id, OLD.created_at))
    EXECUTE FUNCTION public.epigraph_mass_function_retract_guard('rewrite');

COMMIT;
