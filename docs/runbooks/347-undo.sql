-- ===================================================================
-- 347-undo.sql: take migration 347 (`harvester_enriched_concepts` under
-- tenancy and FORCEd row security; backlog f214b84e) back out, in ONE
-- transaction, on the migration (superuser or maintenance) DSN.
--
-- ROLL THE BINARY BACK FIRST. A binary built with 347 lists
-- `harvester_enriched_concepts` in `FORCE_PROTECTED_SET` and refuses to serve
-- where the table exists un-FORCEd.
--
-- WHAT IT DOES:
--   * REFUSES (42501, nothing changed) unless the session reads every row:
--     the maintenance role (`epigraph_bypass()`) or a superuser/BYPASSRLS
--     login. The table is FORCEd, so any other session, the table's owner
--     included, counts only public rows and its own groups' rows, would find
--     no private concept and go on to publish every other group's;
--   * drops the root trigger and the owner guard (347 added no function: both
--     run 074's and 115's shared bodies, which stay);
--   * drops both policies, then NO FORCE and DISABLE row security;
--   * drops the three constraints and both columns.
--
-- WHAT IT LEAVES:
--   * every concept row, with its tenancy columns gone: the table is readable
--     to every application session again, the posture it had before 347. A
--     concept written `('group', G)` after 347 becomes readable to everyone,
--     so the file REFUSES (55000, nothing changed) while one exists; move or
--     delete those rows first, deliberately;
--   * no `tenancy_exempt` row: 347 found none to remove;
--   * 347's `_sqlx_migrations` row. Re-introducing the posture is a NEW
--     migration, never a re-run of 347;
--   * `harvester_enriched_concepts` in `docs/runbooks/079-undo.sql`'s list:
--     `NO FORCE` on a table that is not FORCEd is a no-op.
--
-- Idempotent: a second run changes nothing (the private-row refusal runs only
-- while 347's columns exist).
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

-- The session must read every concept (row security is FORCEd on the table).
DO $$
BEGIN
    IF NOT (public.epigraph_bypass()
            OR COALESCE((SELECT rolsuper OR rolbypassrls FROM pg_catalog.pg_roles
                          WHERE rolname = current_user), false)) THEN
        RAISE EXCEPTION '347-undo: run as the maintenance role or a superuser; the refusal '
                        'below must see every group''s concepts. Nothing was changed.'
            USING ERRCODE = '42501';
    END IF;
END $$;

-- The data guard (only while 347's columns exist; a second run skips it).
DO $$
DECLARE n bigint;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'harvester_enriched_concepts'
                  AND column_name = 'visibility') THEN
        EXECUTE 'SELECT count(*) FROM public.harvester_enriched_concepts '
                'WHERE visibility = ''group'''
           INTO n;
        IF n > 0 THEN
            RAISE EXCEPTION '347-undo: % harvester_enriched_concepts row(s) are group-private; '
                            'a pre-347 schema has nowhere to keep that and would publish them. '
                            'Nothing was changed.', n
                USING ERRCODE = '55000';
        END IF;
    END IF;
END $$;

DROP TRIGGER IF EXISTS harvester_enriched_concepts_require_tenancy
    ON public.harvester_enriched_concepts;
DROP TRIGGER IF EXISTS harvester_enriched_concepts_owner_immutable
    ON public.harvester_enriched_concepts;

DROP POLICY IF EXISTS harvester_enriched_concepts_tenancy ON public.harvester_enriched_concepts;
DROP POLICY IF EXISTS harvester_enriched_concepts_delete_owner
    ON public.harvester_enriched_concepts;

ALTER TABLE public.harvester_enriched_concepts NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.harvester_enriched_concepts DISABLE ROW LEVEL SECURITY;

ALTER TABLE public.harvester_enriched_concepts
    DROP CONSTRAINT IF EXISTS harvester_enriched_concepts_group_needs_real_group,
    DROP CONSTRAINT IF EXISTS harvester_enriched_concepts_owner_group_fkey,
    DROP CONSTRAINT IF EXISTS harvester_enriched_concepts_visibility_check,
    DROP COLUMN IF EXISTS owner_group_id,
    DROP COLUMN IF EXISTS visibility;

COMMIT;
