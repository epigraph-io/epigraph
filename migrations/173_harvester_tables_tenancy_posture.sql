-- 173: bring harvester_sources and harvester_audit_reports under tenancy
-- (ruling R-66, backlog 90d7baf0; closes backlog 154efca2, ledger F-089-B).
--
-- EVIDENCE
-- `harvester_sources` and `harvester_audit_reports` carried neither
-- `visibility` nor `owner_group_id` and had no row security, so every
-- application session read every row whatever group the source document or
-- the extraction audit belonged to. Both are FK neighbours of the tier-A
-- `harvester_fragments`, which migration 062 registered by hand: a fragment
-- belongs to a source (`harvester_fragments.source_id`) and an audit report
-- is about a fragment (`harvester_audit_reports.fragment_id`). Neither is
-- found by `tenancy_coverage.rs`'s generators (no `claim_id`, no FK to
-- `claims`). Migration 118 section 6 revoked every application write on both;
-- the application role still SELECTs.
--
-- An earlier revision of this file only DECLARED that posture, with one
-- `tenancy_exempt` row per table and an open residual, and said that a later
-- change giving either table a posture of its own must rewrite or delete its
-- row in the same file. R-66 rules that the tables are tenanted, not dropped.
-- This file is that change, rewritten in place: it was applied to throwaway
-- databases only, never to a deployed one, so no checksum is recorded
-- anywhere that matters (a throwaway that applied the earlier text refuses
-- to migrate and is dropped, not repaired).
--
-- CHANGE: the tier-A posture of `harvester_fragments`, transcribed.
--   1. Both tenancy columns, NOT NULL with no DEFAULT (074's end state).
--      Existing rows are DERIVED, never defaulted (section 2): an audit
--      report takes its fragment's `(owner_group_id, visibility)`; a source
--      takes its fragments' pair when they all agree. A source with no
--      fragment, or whose fragments disagree, has no owner this file can
--      name, so the migration refuses (HVT01), names the counts and changes
--      nothing; resolve those sources (delete one with no fragment, or make
--      its fragments agree) and re-run.
--   2. 062's three constraints, `<t>_visibility_check`,
--      `<t>_owner_group_fkey` (ON DELETE RESTRICT) and
--      `<t>_group_needs_real_group`, VALIDATED at creation (076's end state).
--   3. The write side (074). A source has no parent at INSERT time, as a
--      fragment has none, so it gets 074's root trigger
--      `harvester_sources_require_tenancy` (`epigraph_root_require_tenancy`):
--      the writer declares both columns, or a seed-role session is stamped
--      `('public', seed)`, or the INSERT raises 23502. An audit report is a
--      derivation of its fragment, so `harvester_audit_reports_inherit_tenancy`
--      stamps the fragment's pair on every INSERT, over any declaration, as
--      070 arm (c) does for the claim-derived tables: a report is never more
--      readable than the fragment it audits.
--   4. Row security (077, 079, 115): ENABLE and FORCE; `<t>_tenancy`, the
--      FOR ALL policy 077 gives the owned tier-A tables (read: public or a
--      session group; write: a writable group; both bypass disjuncts first);
--      `<t>_delete_owner`, 115's RESTRICTIVE FOR DELETE on the writable set;
--      `<t>_owner_immutable`, 115's guard on `owner_group_id`.
--   5. The two `tenancy_exempt` rows go: a covered table keeps none.
--
-- NOT CHANGED: grants. The application role keeps SELECT and still holds no
-- INSERT, UPDATE or DELETE on either table (118 section 6). No elevated read
-- arm (126) is added: a custodian's elevated session reads these rows only
-- where their tenancy admits it, which is narrower than `harvester_fragments`
-- and is recorded as such in `elevation_arms_census.rs`.
--
-- ROW SECURITY AND THE DERIVATION. `harvester_fragments` is FORCEd, so the
-- derivation's read of it is filtered for a migrator that is neither a
-- superuser nor a maintenance login. A filtered read derives nothing for a
-- private fragment's rows and HVT01 refuses; it cannot stamp a wrong owner.
--
-- DEPLOY ORDER: apply before, or with, the API binary that lists both tables
-- in `FORCE_PROTECTED_SET`. That binary refuses to serve on a database where
-- the two tables exist and are not FORCEd (`rls_verdict`'s partial-FORCE
-- refusal); an older binary on a migrated database is unaffected.
--
-- UNDO (as the table owner, in one transaction): drop the two triggers, the
-- three policies and the owner guard per table, `NO FORCE` and `DISABLE` row
-- security, drop the three constraints and both columns per table, drop
-- `epigraph_audit_report_inherit_tenancy()`, and drop both names from
-- `docs/runbooks/079-undo.sql`. The tables then have the posture they had
-- before this file, with no registry row.
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. THE COLUMNS, NULLABLE UNTIL THE DERIVATION HAS RUN
--
-- DRIFT GUARD (062's): a column of either name in another shape is not this
-- file's, and ADD COLUMN IF NOT EXISTS would pass it silently.
-- ===================================================================
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT table_name, column_name, data_type
               FROM information_schema.columns
              WHERE table_schema = 'public'
                AND table_name IN ('harvester_sources', 'harvester_audit_reports')
                AND column_name IN ('owner_group_id', 'visibility')
    LOOP
        IF (r.column_name = 'owner_group_id' AND r.data_type <> 'uuid')
        OR (r.column_name = 'visibility' AND r.data_type <> 'character varying') THEN
            RAISE EXCEPTION 'public.%.% already exists as %, a shape 173 did not create. '
                            'Reconcile by hand, then re-run.',
                r.table_name, r.column_name, r.data_type;
        END IF;
    END LOOP;
END $$;

ALTER TABLE public.harvester_sources
    ADD COLUMN IF NOT EXISTS owner_group_id uuid,
    ADD COLUMN IF NOT EXISTS visibility character varying(16);
ALTER TABLE public.harvester_audit_reports
    ADD COLUMN IF NOT EXISTS owner_group_id uuid,
    ADD COLUMN IF NOT EXISTS visibility character varying(16);

-- ===================================================================
-- 2. DERIVE EXISTING ROWS FROM THEIR FRAGMENTS, OR REFUSE
-- ===================================================================
UPDATE public.harvester_audit_reports r
   SET owner_group_id = f.owner_group_id,
       visibility     = f.visibility
  FROM public.harvester_fragments f
 WHERE f.id = r.fragment_id
   AND (r.owner_group_id IS NULL OR r.visibility IS NULL);

UPDATE public.harvester_sources s
   SET owner_group_id = d.owner_group_id,
       visibility     = d.visibility
  FROM (SELECT f.source_id,
               (array_agg(f.owner_group_id))[1] AS owner_group_id,
               (array_agg(f.visibility))[1]     AS visibility
          FROM public.harvester_fragments f
         GROUP BY f.source_id
        HAVING count(DISTINCT f.owner_group_id::text || '/' || f.visibility) = 1) d
 WHERE d.source_id = s.id
   AND (s.owner_group_id IS NULL OR s.visibility IS NULL);

DO $$
DECLARE n_sources bigint; n_reports bigint;
BEGIN
    SELECT count(*) INTO n_sources FROM public.harvester_sources
     WHERE owner_group_id IS NULL OR visibility IS NULL;
    SELECT count(*) INTO n_reports FROM public.harvester_audit_reports
     WHERE owner_group_id IS NULL OR visibility IS NULL;
    IF n_sources > 0 OR n_reports > 0 THEN
        RAISE EXCEPTION 'HVT01: migration 173 cannot derive an owner for % harvester_sources '
                        'row(s) (no fragment, or fragments of more than one '
                        '(owner_group_id, visibility)) and % harvester_audit_reports row(s) '
                        '(fragment not readable to the migrator); nothing was changed. '
                        'Resolve those sources (delete one with no fragment, or make its '
                        'fragments agree), run as a superuser or maintenance login, and '
                        're-run.', n_sources, n_reports
            USING ERRCODE = '23502';
    END IF;
END $$;

ALTER TABLE public.harvester_sources
    ALTER COLUMN owner_group_id SET NOT NULL,
    ALTER COLUMN visibility SET NOT NULL;
ALTER TABLE public.harvester_audit_reports
    ALTER COLUMN owner_group_id SET NOT NULL,
    ALTER COLUMN visibility SET NOT NULL;

-- ===================================================================
-- 3. 062's CONSTRAINTS, VALIDATED AT CREATION
--
-- CONRELID-QUALIFIED guards, as 062's: `conname` is unique per relation, not
-- per database.
-- ===================================================================
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['harvester_sources', 'harvester_audit_reports'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conrelid = format('public.%I', t)::regclass
                          AND conname = t || '_visibility_check') THEN
            EXECUTE format(
              'ALTER TABLE public.%I ADD CONSTRAINT %I
                 CHECK (visibility IN (''public'',''group''))',
              t, t || '_visibility_check');
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conrelid = format('public.%I', t)::regclass
                          AND conname = t || '_owner_group_fkey') THEN
            EXECUTE format(
              'ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (owner_group_id)
                 REFERENCES public.groups(id) ON DELETE RESTRICT',
              t, t || '_owner_group_fkey');
        END IF;
        -- ('group', world) and ('group', seed) are rows nobody can read back:
        -- both groups are memberless by design (062).
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conrelid = format('public.%I', t)::regclass
                          AND conname = t || '_group_needs_real_group') THEN
            EXECUTE format(
              'ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (
                  visibility <> ''group''
                  OR owner_group_id NOT IN (
                       ''00000000-0000-0000-0000-000000000000''::uuid,
                       ''00000000-0000-0000-0000-00000000dead''::uuid))',
              t, t || '_group_needs_real_group');
        END IF;
    END LOOP;
END $$;

-- ===================================================================
-- 4. THE WRITE SIDE
-- ===================================================================
-- A source: 074's root body, unchanged and already maintenance-owned.
DROP TRIGGER IF EXISTS harvester_sources_require_tenancy ON public.harvester_sources;
CREATE TRIGGER harvester_sources_require_tenancy BEFORE INSERT ON public.harvester_sources
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_root_require_tenancy();

-- An audit report: its fragment's pair, whatever the writer declared. A
-- definer so that the read of the FORCEd `harvester_fragments` finds the
-- fragment for any writer (the FK has already established that it exists),
-- as 074's derived body reads `claims`. It returns nothing to the caller.
CREATE OR REPLACE FUNCTION public.epigraph_audit_report_inherit_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE g uuid; v character varying(16);
BEGIN
    SELECT f.owner_group_id, f.visibility INTO g, v
      FROM public.harvester_fragments f WHERE f.id = NEW.fragment_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'epigraph tenancy: harvester_audit_reports.fragment_id=% references '
                        'a nonexistent fragment', NEW.fragment_id
            USING ERRCODE = '23503';
    END IF;
    NEW.owner_group_id := g;
    NEW.visibility     := v;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_audit_report_inherit_tenancy() FROM PUBLIC;
DROP TRIGGER IF EXISTS harvester_audit_reports_inherit_tenancy ON public.harvester_audit_reports;
CREATE TRIGGER harvester_audit_reports_inherit_tenancy
    BEFORE INSERT ON public.harvester_audit_reports
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_audit_report_inherit_tenancy();

-- ===================================================================
-- 5. ROW SECURITY: 077's owned policy, 079's FORCE, 115's DELETE rule and
--    owner guard, per table, in their words.
-- ===================================================================
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['harvester_sources', 'harvester_audit_reports'] LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);

        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', t || '_tenancy', t);
        EXECUTE format($f$
            CREATE POLICY %I ON public.%I FOR ALL TO PUBLIC
                USING (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR visibility = 'public'
                    OR owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]))
                WITH CHECK (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]))
        $f$, t || '_tenancy', t);

        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', t || '_delete_owner', t);
        EXECUTE format($f$
            CREATE POLICY %I ON public.%I AS RESTRICTIVE FOR DELETE TO PUBLIC
                USING (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]))
        $f$, t || '_delete_owner', t);

        EXECUTE format('DROP TRIGGER IF EXISTS %I ON public.%I', t || '_owner_immutable', t);
        EXECUTE format(
          'CREATE TRIGGER %I BEFORE UPDATE OF owner_group_id ON public.%I
             FOR EACH ROW
             WHEN (OLD.owner_group_id IS DISTINCT FROM NEW.owner_group_id)
             EXECUTE FUNCTION public.epigraph_owner_immutable_guard()',
          t || '_owner_immutable', t);
    END LOOP;
END $$;

-- ===================================================================
-- 6. THE REGISTRY: a covered table keeps no exemption.
-- ===================================================================
DELETE FROM public.tenancy_exempt
 WHERE table_name IN ('harvester_sources', 'harvester_audit_reports');

-- ===================================================================
-- 7. OWNERSHIP. Guarded on the role, as 074's section 6.
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_audit_report_inherit_tenancy() '
                'OWNER TO epigraph_maintenance';
    END IF;
END $$;
