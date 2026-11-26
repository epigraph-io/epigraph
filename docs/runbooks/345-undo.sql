-- ===================================================================
-- 311-undo.sql: take migration 311 (no application writes on `bp_messages`
-- or `factors.frame_id`, backlog 9a9d6850) back out, in ONE transaction, on
-- the migration (superuser) DSN.
--
-- READ FIRST. Once undone, every application session can again INSERT,
-- UPDATE and DELETE any belief-propagation message and move any factor into
-- any frame. Roll the API binary back FIRST: a 311 binary promotes a
-- hypothesis through `epigraph_promote_hypothesis_factors`, which this drops
-- (every promotion then answers 500, 42883). A binary from before 311 runs
-- the direct `UPDATE factors SET frame_id`, which the restored column grant
-- admits.
--
-- Run it BEFORE `217-undo.sql` if both are undone.
--
-- WHAT IT DOES
--   1. Restores 077's INSERT, UPDATE and DELETE on `public.bp_messages` to
--      `epigraph_app` (SELECT was never revoked; TRUNCATE was never granted).
--   2. Drops `public.epigraph_promote_hypothesis_factors(uuid)`.
--   3. Restores 217's column grant `UPDATE (frame_id) ON public.factors`.
--
-- WHAT IT LEAVES: 311's `_sqlx_migrations` row, and every row as it stands
-- (311 wrote none). Re-introducing 311 is a NEW migration (or a re-run of
-- 311's text, which is idempotent). This file is idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT INSERT, UPDATE, DELETE ON public.bp_messages TO epigraph_app';
    END IF;
END $$;

DROP FUNCTION IF EXISTS public.epigraph_promote_hypothesis_factors(uuid);

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT UPDATE (frame_id) ON public.factors TO epigraph_app';
    END IF;
END $$;

COMMIT;
