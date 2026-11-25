-- ===================================================================
-- 313-undo.sql: take migration 313 (`harvester_enriched_concepts` under
-- tenancy and FORCEd row security; backlog f214b84e) back out, in ONE
-- transaction, on the migration (superuser or maintenance) DSN.
--
-- ROLL THE BINARY BACK FIRST. A binary built with 313 lists
-- `harvester_enriched_concepts` in `FORCE_PROTECTED_SET` and refuses to serve
-- where the table exists un-FORCEd.
--
-- WHAT IT DOES:
--   * drops the root trigger and the owner guard (313 added no function: both
--     run 074's and 115's shared bodies, which stay);
--   * drops both policies, then NO FORCE and DISABLE row security;
--   * drops the three constraints and both columns.
--
-- WHAT IT LEAVES:
--   * every concept row, with its tenancy columns gone: the table is readable
--     to every application session again, the posture it had before 313. A
--     concept written `('group', G)` after 313 becomes readable to everyone,
--     so the file REFUSES (55000, nothing changed) while one exists; move or
--     delete those rows first, deliberately;
--   * no `tenancy_exempt` row: 313 found none to remove;
--   * 313's `_sqlx_migrations` row. Re-introducing the posture is a NEW
--     migration, never a re-run of 313;
--   * `harvester_enriched_concepts` in `docs/runbooks/079-undo.sql`'s list:
--     `NO FORCE` on a table that is not FORCEd is a no-op.
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE n bigint;
BEGIN
    SELECT count(*) INTO n FROM public.harvester_enriched_concepts
     WHERE visibility = 'group';
    IF n > 0 THEN
        RAISE EXCEPTION '313-undo: % harvester_enriched_concepts row(s) are group-private; '
                        'a pre-313 schema has nowhere to keep that and would publish them. '
                        'Nothing was changed.', n
            USING ERRCODE = '55000';
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
