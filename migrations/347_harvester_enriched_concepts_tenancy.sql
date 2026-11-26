-- 347: bring harvester_enriched_concepts under tenancy (backlog f214b84e),
-- the posture migration 173 gave the other harvester tables.
--
-- EVIDENCE
-- `harvester_enriched_concepts` (001) carries neither `visibility` nor
-- `owner_group_id` and has no row security, so every application session
-- reads every concept (its name, canonical name, latent definition and
-- embedding), whatever group wrote it. Migration 118 section 6 revoked every
-- application write; the application role still SELECTs. It is the one
-- harvester table 173 left out, and no generator in `tenancy_coverage.rs`
-- finds it (no `claim_id`, no FK to `claims`, no FK to or from
-- `harvester_fragments`).
--
-- THE TABLE HAS NO PARENT. Unlike `harvester_audit_reports` (a report is
-- about a fragment), a concept has no foreign key in or out: nothing names
-- the fragment, source or claim it was enriched from. So there is nothing to
-- derive a row's owner from at INSERT, nothing to follow when a parent is
-- re-tenanted, and nothing to derive an existing row from. The posture is
-- therefore `harvester_sources`'s half of 173, the parentless root:
--
--   1. Both tenancy columns, NOT NULL with no DEFAULT (074's end state).
--      Existing rows are stamped `('public', world)`: that is what every
--      reader saw before this file (246's precedent for `papers`), so nothing
--      becomes more readable and nothing a reader could read is hidden.
--   2. 062's three constraints, `<t>_visibility_check`, `<t>_owner_group_fkey`
--      (ON DELETE RESTRICT) and `<t>_group_needs_real_group`, VALIDATED at
--      creation (076's end state).
--   3. The write side (074): `harvester_enriched_concepts_require_tenancy`
--      (`epigraph_root_require_tenancy`, unchanged and already
--      maintenance-owned): the writer declares both columns, or a seed-role
--      session is stamped `('public', seed)`, or the INSERT raises 23502.
--   4. Row security (077, 079, 115), 173's words: ENABLE and FORCE;
--      `<t>_tenancy`, the FOR ALL policy 077 gives the owned tier-A tables
--      (read: public or a session group; write: a writable group; both
--      bypass disjuncts first); `<t>_delete_owner`, 115's RESTRICTIVE FOR
--      DELETE on the writable set; `<t>_owner_immutable`, 115's guard.
--   5. Any `tenancy_exempt` row goes: a covered table keeps none. (Measured:
--      no migration ever registered one; the DELETE makes the end state
--      independent of that.)
--
-- NOT CHANGED: grants. The application role keeps SELECT and still holds no
-- INSERT, UPDATE or DELETE (118 section 6). No elevated read arm (126): an
-- elevated session reads these rows only where its tenancy admits, as for
-- 173's two tables (`elevation_arms_census.rs`). No function is added or
-- re-stated, so no definer register entry is owed.
--
-- PRIVILEGE: apply as the maintenance role or a superuser. Owning the table
-- is not enough: the two triggers need EXECUTE on 074's
-- `epigraph_root_require_tenancy()` and 115's
-- `epigraph_owner_immutable_guard()` (both revoked from PUBLIC), the FK needs
-- REFERENCES on `groups`, and section 6 deletes from `tenancy_exempt`. No
-- derivation reads a FORCEd table (the backfill runs before row security is
-- enabled here), so 173's reads-every-row check has no counterpart.
--
-- DEPLOY ORDER: apply before, or with, the API binary that lists the table in
-- `FORCE_PROTECTED_SET`. That binary refuses to serve on a database where the
-- table exists and is not FORCEd (`rls_verdict`'s partial-FORCE refusal); an
-- older binary on a migrated database is unaffected (it writes no concept).
--
-- UNDO: `docs/runbooks/347-undo.sql`.
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. THE COLUMNS, NULLABLE UNTIL THE BACKFILL HAS RUN
--
-- DRIFT GUARD (062's): a column of either name in another shape is not this
-- file's, and ADD COLUMN IF NOT EXISTS would pass it silently.
-- ===================================================================
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT column_name, data_type
               FROM information_schema.columns
              WHERE table_schema = 'public'
                AND table_name = 'harvester_enriched_concepts'
                AND column_name IN ('owner_group_id', 'visibility')
    LOOP
        IF (r.column_name = 'owner_group_id' AND r.data_type <> 'uuid')
        OR (r.column_name = 'visibility' AND r.data_type <> 'character varying') THEN
            RAISE EXCEPTION 'public.harvester_enriched_concepts.% already exists as %, a '
                            'shape 347 did not create. Reconcile by hand, then re-run.',
                r.column_name, r.data_type;
        END IF;
    END LOOP;
END $$;

ALTER TABLE public.harvester_enriched_concepts
    ADD COLUMN IF NOT EXISTS owner_group_id uuid,
    ADD COLUMN IF NOT EXISTS visibility character varying(16);

-- ===================================================================
-- 2. BACKFILL: what every reader saw before this file
-- ===================================================================
UPDATE public.harvester_enriched_concepts
   SET owner_group_id = COALESCE(owner_group_id, '00000000-0000-0000-0000-000000000000'::uuid),
       visibility     = COALESCE(visibility, 'public')
 WHERE owner_group_id IS NULL OR visibility IS NULL;

ALTER TABLE public.harvester_enriched_concepts
    ALTER COLUMN owner_group_id SET NOT NULL,
    ALTER COLUMN visibility SET NOT NULL;

-- ===================================================================
-- 3. 062's CONSTRAINTS, VALIDATED AT CREATION
--
-- CONRELID-QUALIFIED guards, as 062's: `conname` is unique per relation, not
-- per database.
-- ===================================================================
DO $$
DECLARE t constant text := 'harvester_enriched_concepts';
BEGIN
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
END $$;

-- ===================================================================
-- 4. THE WRITE SIDE: 074's root body, unchanged and already
--    maintenance-owned. A concept has no parent to inherit from.
-- ===================================================================
DROP TRIGGER IF EXISTS harvester_enriched_concepts_require_tenancy
    ON public.harvester_enriched_concepts;
CREATE TRIGGER harvester_enriched_concepts_require_tenancy
    BEFORE INSERT ON public.harvester_enriched_concepts
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_root_require_tenancy();

-- ===================================================================
-- 5. ROW SECURITY: 077's owned policy, 079's FORCE, 115's DELETE rule and
--    owner guard, in 173's words.
-- ===================================================================
ALTER TABLE public.harvester_enriched_concepts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.harvester_enriched_concepts FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS harvester_enriched_concepts_tenancy ON public.harvester_enriched_concepts;
CREATE POLICY harvester_enriched_concepts_tenancy ON public.harvester_enriched_concepts
    FOR ALL TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR visibility = 'public'
        OR owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]));

DROP POLICY IF EXISTS harvester_enriched_concepts_delete_owner
    ON public.harvester_enriched_concepts;
CREATE POLICY harvester_enriched_concepts_delete_owner ON public.harvester_enriched_concepts
    AS RESTRICTIVE FOR DELETE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]));

DROP TRIGGER IF EXISTS harvester_enriched_concepts_owner_immutable
    ON public.harvester_enriched_concepts;
CREATE TRIGGER harvester_enriched_concepts_owner_immutable
    BEFORE UPDATE OF owner_group_id ON public.harvester_enriched_concepts
    FOR EACH ROW
    WHEN (OLD.owner_group_id IS DISTINCT FROM NEW.owner_group_id)
    EXECUTE FUNCTION public.epigraph_owner_immutable_guard();

-- ===================================================================
-- 6. THE REGISTRY: a covered table keeps no exemption.
-- ===================================================================
DELETE FROM public.tenancy_exempt WHERE table_name = 'harvester_enriched_concepts';
