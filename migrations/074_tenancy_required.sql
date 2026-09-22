-- 074_tenancy_required.sql -- D1's teeth: tenancy is DECLARED, never defaulted.
-- PR-16 of the multi-user tenancy series.
--
-- NUMBERING. Plan §3 and the PR-16 *Files* line both say "migrations
-- 070/071/072". Those three files exist on disk and are applied: 070/071 are
-- PR-12's, 072/073 are PR-13's. `migrations/README.md`'s post-shift table is
-- authoritative and assigns PR-16 074 (this file), 075 and 076. Editing an
-- applied migration is a checksum mismatch, which panics the api binary on
-- restart -- so the plan's numbers are not a naming preference, they are an
-- outage. The plan's *body* for this file is at FINAL-PLAN.md's
-- "070_tenancy_required.sql -- D1's teeth" heading; use the body, not the
-- number.
--
-- WHAT THIS FILE DOES, IN ORDER:
--   1. Replaces 070's TRANSITION trigger bodies with the final, IS NULL-keyed,
--      RAISE-terminated forms.
--   2. Adds the same enforcement to the OTHER 24 tier-A tables, which the plan
--      covers in a single prose sentence ("Analogous *_require_tenancy triggers
--      are created on every other tier-A table") and which is in fact 23 new
--      BEFORE ROW triggers. See "WHY 23 MORE TRIGGERS" below -- this is the
--      largest correction in this migration and it is not optional.
--   3. Adds `claims_block_widening` (the sealed guard + the declassification
--      guard).
--   4. Drops 062's DEFAULTs on all 25 tier-A tables.
--
-- ONE-WAY DOOR. Undo script: docs/runbooks/074-undo.sql, executed as the table
-- OWNER. Read it before applying this file to anything you cannot rebuild.
--
-- DEPLOY ORDERING (plan §9.2, ops F10) -- THE LARGEST OUTAGE RISK IN THE SERIES.
-- This migration does NOT ship in the same deploy step as the code. Three
-- steps, in order:
--   (i)   deploy the binaries carrying the patched INSERT call sites, with
--         074/075/076 NOT applied;
--   (ii)  observe 070's `tenancy_undeclared_writes` counter flat at zero for
--         24 hours;
--   (iii) then apply 074, then 075, then 076, as three separate steps.
-- During any rolling deploy that skipped (ii), the previous pods still run
-- `ClaimRepository::create` without the columns and every claim write raises
-- 23502 the instant this file commits.
--
-- Idempotent: CREATE OR REPLACE FUNCTION, DROP TRIGGER IF EXISTS before every
-- CREATE TRIGGER, and `DROP DEFAULT` on a column with no default is a no-op.
-- sqlx records no row for a failed migration, so a lock_timeout abort must be
-- recoverable by re-running the file.
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- WHY 23 MORE TRIGGERS, AND WHY THE 17 STATEMENT-LEVEL ONES CANNOT COVER THIS
--
-- Measured on the schema this file targets, the 25 tier-A tables partition by
-- trigger timing as:
--
--   BEFORE ROW INSERT   : claims (claims_require_tenancy), edges (edges_tenancy)
--   AFTER  STATEMENT INS: 17 x *_inherit_tenancy (migration 070 arm (c))
--   NONE                : 6 -- communities, contexts, frames,
--                         harvester_fragments, perspectives, recall_events
--
-- `NOT NULL` is checked at HEAP-INSERT time, which is AFTER a BEFORE ROW
-- trigger has run and BEFORE any AFTER STATEMENT trigger fires. So the moment
-- section 4 below drops the defaults:
--
--   * the 17 AFTER-STATEMENT tables raise 23502 and their inherit trigger
--     NEVER FIRES -- arm (c) cannot save them, it runs too late;
--   * the 6 trigger-less tables raise 23502 with no mechanism at all.
--
-- `edges` is genuinely safe: `edges_tenancy` is BEFORE ROW and every branch of
-- 072's body assigns both columns unconditionally (the one early RETURN is
-- gated on `NEW.visibility = 'group'`, which is false when the value is NULL).
-- That is why plan §4.6's "edges need no call-site edits" survives.
--
-- Hence two new generic BEFORE ROW bodies below:
--   epigraph_derived_require_tenancy() -- the 17, inheriting via claim_id
--   epigraph_root_require_tenancy()    -- the 6, which have no parent at all
--
-- The 6 roots are the reason 9 production statements need an explicit
-- declaration; the PR-16 *Files* line names none of them. They are listed in
-- docs/tenancy.md#declaring-visibility-on-write.
-- ===================================================================

-- ===================================================================
-- 1. claims -- the final form. Replaces 070's transition body.
--
-- Ordering is what makes this work: column defaults are materialised when the
-- tuple is built (BEFORE this trigger runs), and NOT NULL is checked at
-- heap-insert (AFTER it). With the default dropped, NEW.visibility is NULL
-- inside the trigger, so the trigger can fill it or raise, and NOT NULL
-- remains as a backstop against a bug in this function.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_claims_require_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE g uuid; v character varying(16);
BEGIN
    -- ===============================================================
    -- ARM ORDER IS A CORRECTION TO THE PLAN, AND IT IS LOAD-BEARING.
    --
    -- Plan §3's 074 body puts "fully declared by the writer" FIRST and the
    -- predecessor arms after it. MEASURED on a throwaway database: with that
    -- order, an INSERT that binds `supersedes = <a group-private claim>` AND
    -- declares ('public', world) is accepted -- arm 1 returns before the
    -- no-widening check in arm 2 is ever reached. That is a one-statement
    -- declassification of any claim the writer can name, and §8.2's own
    -- acceptance criterion ("explicit 'public' successor over a group
    -- predecessor -> 42501") could not have held.
    --
    -- So the PARENT arms run first. A declaration still wins on the value
    -- (COALESCE keeps what the writer named); what it cannot do is escape the
    -- comparison against the parent.
    -- ===============================================================

    -- 1. Determinate inheritance from a predecessor.
    --    ClaimRepository::supersede binds `supersedes` and deliberately does
    --    NOT declare tenancy -- this arm is what stops a supersede from
    --    silently declassifying its predecessor.
    IF NEW.supersedes IS NOT NULL THEN
        SELECT c.owner_group_id, c.visibility INTO g, v
          FROM public.claims c WHERE c.id = NEW.supersedes;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'epigraph tenancy: claims.supersedes=% does not exist',
                NEW.supersedes USING ERRCODE = '23503';
        END IF;
        NEW.owner_group_id := COALESCE(NEW.owner_group_id, g);
        NEW.visibility     := COALESCE(NEW.visibility,     v);
        IF v = 'group' AND NEW.visibility = 'public' THEN
            RAISE EXCEPTION 'epigraph tenancy: claim % supersedes group-private claim % '
                            'and may not be public', NEW.id, NEW.supersedes
                USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    END IF;

    -- 2. Determinate inheritance within a step lineage (evolve_step and
    --    ingest-executor add_step: no `supersedes`, links via step_lineage_id
    --    plus an edge). Also ahead of the "fully declared" arm, for the same
    --    reason: a declared 'public' step in a group-private lineage is the
    --    same declassification through a different door.
    IF NEW.step_lineage_id IS NOT NULL THEN
        SELECT c.owner_group_id, c.visibility INTO g, v
          FROM public.claims c
         WHERE c.step_lineage_id = NEW.step_lineage_id AND c.id <> NEW.id
         ORDER BY c.created_at DESC LIMIT 1;
        IF FOUND THEN
            NEW.owner_group_id := COALESCE(NEW.owner_group_id, g);
            NEW.visibility     := COALESCE(NEW.visibility,     v);
            IF v = 'group' AND NEW.visibility = 'public' THEN
                RAISE EXCEPTION 'epigraph tenancy: claim % is in a group-private step '
                                'lineage and may not be public', NEW.id
                    USING ERRCODE = '42501';
            END IF;
            RETURN NEW;
        END IF;
    END IF;

    -- 3. Fully declared by the writer, with no parent that could contradict it.
    IF NEW.visibility IS NOT NULL AND NEW.owner_group_id IS NOT NULL THEN
        RETURN NEW;
    END IF;

    -- 4. Seed-role escape hatch. ROLE MEMBERSHIP, not a GUC an app can SET.
    --    session_user, NOT current_user (inside this SECURITY DEFINER frame
    --    current_user is the function owner). The EXISTS guard is required
    --    because pg_has_role on a nonexistent role RAISES 42704 (ops F4).
    --
    --    STAMPS THE SEED GROUP, NOT WORLD (sec F14). §8.2 A4 asserts
    --    count(*) FROM claims WHERE owner_group_id = <world> is 0, and the
    --    deferred strong CHECK (owner_group_id <> world) could never ship
    --    while this arm stamped world. Seed also makes escape-hatch rows
    --    greppable: SELECT count(*) FROM claims WHERE owner_group_id =
    --    '00000000-0000-0000-0000-00000000dead'.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_seed')
       AND pg_has_role(session_user, 'epigraph_seed', 'MEMBER') THEN
        -- ('group', seed) is a black hole -- 062's *_group_needs_real_group
        -- CHECK forbids it, and seed is memberless by design. Refuse with a
        -- diagnosable message rather than letting it surface as a 23514.
        IF NEW.visibility = 'group' AND NEW.owner_group_id IS NULL THEN
            RAISE EXCEPTION 'epigraph tenancy: visibility=''group'' was declared on claims '
                            'without an owner_group_id. The seed escape hatch cannot supply '
                            'one: the seed group is memberless, so (''group'', seed) is a row '
                            'nobody can read back.'
                USING ERRCODE = '23502',
                      HINT = 'See docs/tenancy.md#declaring-visibility-on-write';
        END IF;
        NEW.owner_group_id := COALESCE(NEW.owner_group_id,
            '00000000-0000-0000-0000-00000000dead'::uuid);
        NEW.visibility := COALESCE(NEW.visibility, 'public');
        RETURN NEW;
    END IF;

    -- 5. Undeclared. D1: fail, never default.
    RAISE EXCEPTION
        'epigraph tenancy: INSERT INTO claims without an explicit (visibility, '
        'owner_group_id) declaration and no inheritable parent. Name both columns, '
        'or set claims.supersedes. id=%, agent_id=%', NEW.id, NEW.agent_id
        USING ERRCODE = '23502',
              HINT = 'See docs/tenancy.md#declaring-visibility-on-write';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_claims_require_tenancy() FROM PUBLIC;
DROP TRIGGER IF EXISTS claims_require_tenancy ON public.claims;
CREATE TRIGGER claims_require_tenancy BEFORE INSERT ON public.claims
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_claims_require_tenancy();

-- ===================================================================
-- 2. The 17 claim-derived tables -- inherit via claim_id, BEFORE ROW.
--
-- NO NO-WIDENING GUARD HERE, DELIBERATELY. Migration 070 arm (c) is
-- unconditional by design -- its own comment says so at length and
-- `tenancy_triggers.rs::each_of_the_eight_section_2_4_tables_inherits_from_its_claim`
-- pins it. A BEFORE ROW guard that AFTER STATEMENT then overwrites would be a
-- control that reads green and does nothing, which is worse than no control.
-- This function's only job is to make the row INSERTABLE with a value that
-- arm (c) will then confirm.
--
-- Generic over 17 tables. PL/pgSQL resolves NEW.<field> per invocation against
-- the actual row type, so one body serves them all; every table in the array
-- carries claim_id, visibility and owner_group_id (verified against
-- information_schema before this file was written).
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_derived_require_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE g uuid; v character varying(16);
BEGIN
    IF NEW.visibility IS NOT NULL AND NEW.owner_group_id IS NOT NULL THEN
        RETURN NEW;
    END IF;

    IF NEW.claim_id IS NOT NULL THEN
        SELECT c.owner_group_id, c.visibility INTO g, v
          FROM public.claims c WHERE c.id = NEW.claim_id;
        IF FOUND THEN
            NEW.owner_group_id := COALESCE(NEW.owner_group_id, g);
            NEW.visibility     := COALESCE(NEW.visibility,     v);
            RETURN NEW;
        END IF;
        -- Orphan. 070 arm (c) raises 23503 for this at statement level; raising
        -- here too means the diagnosis names the row, not the statement.
        RAISE EXCEPTION 'epigraph tenancy: %.claim_id=% references a nonexistent claim',
            TG_TABLE_NAME, NEW.claim_id USING ERRCODE = '23503';
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_seed')
       AND pg_has_role(session_user, 'epigraph_seed', 'MEMBER') THEN
        IF NEW.visibility = 'group' AND NEW.owner_group_id IS NULL THEN
            RAISE EXCEPTION 'epigraph tenancy: visibility=''group'' declared on % with no '
                            'owner_group_id and no parent claim to inherit one from',
                TG_TABLE_NAME
                USING ERRCODE = '23502',
                      HINT = 'See docs/tenancy.md#declaring-visibility-on-write';
        END IF;
        NEW.owner_group_id := COALESCE(NEW.owner_group_id,
            '00000000-0000-0000-0000-00000000dead'::uuid);
        NEW.visibility := COALESCE(NEW.visibility, 'public');
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'epigraph tenancy: INSERT INTO % without an explicit (visibility, '
        'owner_group_id) declaration and with claim_id NULL, so there is no parent '
        'to inherit from. Name both columns, or set claim_id.', TG_TABLE_NAME
        USING ERRCODE = '23502',
              HINT = 'See docs/tenancy.md#declaring-visibility-on-write';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_derived_require_tenancy() FROM PUBLIC;

-- The SAME 17 as 070 arm (c)'s `inheritors` array and arm (d)'s `derived`
-- array. That identity is the point: (c) stamps on INSERT after the fact, this
-- one makes the INSERT legal in the first place, and (d) re-stamps on UPDATE.
-- A literal array rather than a catalog loop, for 070's stated reasons: two
-- relations carrying claim_id are VIEWS (a statement trigger on a view is
-- rejected outright) and two more are tenancy_exempt with no columns to fill.
DO $$
DECLARE t text;
        inheritors text[] := ARRAY[
          'evidence','triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance','challenges','reasoning_traces',
          'experiment_triples','experiment_entity_mentions','claim_clusters',
          'claim_cluster_membership','claim_neighborhood_membership',
          'claim_signature_revocations'];
BEGIN
    FOREACH t IN ARRAY inheritors LOOP
        IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND c.relname = t AND c.relkind = 'r')
        THEN
            EXECUTE format('DROP TRIGGER IF EXISTS %I ON public.%I',
                           t || '_require_tenancy', t);
            EXECUTE format(
              'CREATE TRIGGER %I BEFORE INSERT ON public.%I
                 FOR EACH ROW EXECUTE FUNCTION public.epigraph_derived_require_tenancy()',
              t || '_require_tenancy', t);
        END IF;
    END LOOP;
END $$;

-- ===================================================================
-- 3. The 6 roots -- no parent, so the declaration is the only source.
--
-- frames / contexts / perspectives / communities are 062's "D1 roots".
-- recall_events is keyed on the QUERYING agent, not on a claim.
-- harvester_fragments hangs off harvester_claim_provenance, which is inserted
-- AFTER the fragment it references -- so at INSERT time it has no parent
-- either, and 070 arm (d) is what re-stamps it when the claim's tenancy
-- changes.
--
-- These six are why 9 production statements gain an explicit declaration in
-- this PR. Test-suite inserts are absorbed by the seed arm, exactly as arm 4
-- on `claims` absorbs theirs.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_root_require_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF NEW.visibility IS NOT NULL AND NEW.owner_group_id IS NOT NULL THEN
        RETURN NEW;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_seed')
       AND pg_has_role(session_user, 'epigraph_seed', 'MEMBER') THEN
        IF NEW.visibility = 'group' AND NEW.owner_group_id IS NULL THEN
            RAISE EXCEPTION 'epigraph tenancy: visibility=''group'' declared on % with no '
                            'owner_group_id; the seed group is memberless and cannot own it',
                TG_TABLE_NAME
                USING ERRCODE = '23502',
                      HINT = 'See docs/tenancy.md#declaring-visibility-on-write';
        END IF;
        NEW.owner_group_id := COALESCE(NEW.owner_group_id,
            '00000000-0000-0000-0000-00000000dead'::uuid);
        NEW.visibility := COALESCE(NEW.visibility, 'public');
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'epigraph tenancy: INSERT INTO % without an explicit (visibility, '
        'owner_group_id) declaration. This table has no parent to inherit from, so '
        'the writer must name both columns.', TG_TABLE_NAME
        USING ERRCODE = '23502',
              HINT = 'See docs/tenancy.md#declaring-visibility-on-write';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_root_require_tenancy() FROM PUBLIC;

DO $$
DECLARE t text;
        roots text[] := ARRAY[
          'frames','contexts','perspectives','communities',
          'harvester_fragments','recall_events'];
BEGIN
    FOREACH t IN ARRAY roots LOOP
        IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND c.relname = t AND c.relkind = 'r')
        THEN
            EXECUTE format('DROP TRIGGER IF EXISTS %I ON public.%I',
                           t || '_require_tenancy', t);
            EXECUTE format(
              'CREATE TRIGGER %I BEFORE INSERT ON public.%I
                 FOR EACH ROW EXECUTE FUNCTION public.epigraph_root_require_tenancy()',
              t || '_require_tenancy', t);
        END IF;
    END LOOP;
END $$;

-- ===================================================================
-- 4. Widening is a separate, audited operation (D4's inverse).
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_claims_block_widening() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- (a) THE SEALED GUARD, UNCONDITIONAL AND WITH NO GUC OVERRIDE (sec F11).
    --     Seal-then-declassify would otherwise yield a PUBLIC row whose content
    --     is a '[sealed:uuid]' stub, embedding NULL, and ciphertext no reader is
    --     entitled to -- permanently unreadable, and with content_hash no longer
    --     agreeing with content. `epigraph.allow_declassify` does NOT reach this
    --     arm, by design: the admin declassification surface sets that GUC.
    IF NEW.visibility = 'public'
       AND EXISTS (SELECT 1 FROM public.claim_encryption WHERE claim_id = NEW.id) THEN
        RAISE EXCEPTION 'epigraph tenancy: claim % is SEALED and cannot be made '
                        'public. Unseal first, then declassify.', NEW.id
            USING ERRCODE = '42501';
    END IF;
    -- (b) Ordinary declassification guard.
    IF OLD.visibility = 'group' AND NEW.visibility = 'public'
       AND COALESCE(current_setting('epigraph.allow_declassify', true), '') <> 'yes' THEN
        RAISE EXCEPTION 'epigraph tenancy: refusing to declassify claim % from group to '
                        'public. Use the admin declassification surface.', OLD.id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_claims_block_widening() FROM PUBLIC;
DROP TRIGGER IF EXISTS claims_block_widening ON public.claims;
CREATE TRIGGER claims_block_widening BEFORE UPDATE OF visibility ON public.claims
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_claims_block_widening();

-- ===================================================================
-- 5. THE DEFAULTS GO.
--
-- DROP DEFAULT is a catalog-only change: instant, no rewrite. Rows already
-- written keep their attmissingval; only FUTURE inserts lose the fallback.
-- Idempotent: DROP DEFAULT on a column with no default is a no-op.
--
-- The array is 062's tier_a array, verbatim.
--
-- `agents.profile_visibility` IS DELIBERATELY NOT DROPPED -- CORRECTION TO THE
-- PLAN. Plan §3's 074 body adds
--     ALTER TABLE public.agents ALTER COLUMN profile_visibility DROP DEFAULT;
-- immediately after this loop. Three measured reasons not to:
--   (1) `agents` is tier B and carries a `tenancy_exempt` row -- identity has
--       to render authorship on a public claim, which is why it never got
--       owner_group_id at all;
--   (2) NO trigger fills it. There is no inheritance arm and no seed arm for
--       agents, so dropping the default converts every INSERT INTO agents in
--       the tree -- production and ~180 fixtures -- into a bare 23502 with no
--       recovery path;
--   (3) §8.2 A1's filter is `column_name IN ('visibility','owner_group_id')`,
--       so A1 neither requires this nor would prove it if it were done.
-- Deferring it is therefore not a gap in D1's tier-A charter. 076 still
-- VALIDATEs `agents_profile_visibility_check`, so the vocabulary is enforced;
-- what is deferred is only the absence of a fallback, and it needs a trigger
-- of its own before it can ship.
-- ===================================================================
DO $$
DECLARE t text;
        tier_a text[] := ARRAY[
          'claims','evidence','edges',
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance',
          'challenges','reasoning_traces','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations',
          'harvester_fragments',
          'frames','contexts','perspectives','communities',
          'recall_events'
        ];
BEGIN
    FOREACH t IN ARRAY tier_a LOOP
        IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND c.relname = t AND c.relkind = 'r')
        THEN
            EXECUTE format('ALTER TABLE public.%I ALTER COLUMN visibility DROP DEFAULT', t);
            EXECUTE format('ALTER TABLE public.%I ALTER COLUMN owner_group_id DROP DEFAULT', t);
        END IF;
    END LOOP;
END $$;

-- ===================================================================
-- 6. RE-OWN THE SECURITY DEFINER BODIES TO epigraph_maintenance.
--
-- CREATE OR REPLACE preserves ownership, so the five functions 070 already
-- re-owned stay owned. The TWO NEW bodies do not, and they read `claims`
-- through their own table's policies once PR-17 FORCEs RLS: an app-owned
-- epigraph_derived_require_tenancy() would get a filtered read of `claims`,
-- take the NOT FOUND branch, and raise 23503 on a parent that plainly exists.
-- That is a write outage, not a leak, but it is exactly as avoidable.
--
-- Guarded on role existence for 070's stated reason: 060 creates the role
-- inside a DO block that only RAISE NOTICEs on insufficient_privilege, and a
-- hard failure here would turn a missing role into a permanent deploy outage
-- (a failed migration records no row, so the next restart re-runs it).
-- `epigraph-tenancy-backfill verify` is where the outcome is asserted.
-- ===================================================================
DO $$
DECLARE f text;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        FOREACH f IN ARRAY ARRAY[
            'public.epigraph_claims_require_tenancy()',
            'public.epigraph_derived_require_tenancy()',
            'public.epigraph_root_require_tenancy()'] LOOP
            EXECUTE format('ALTER FUNCTION %s OWNER TO epigraph_maintenance', f);
        END LOOP;
    END IF;
END $$;
