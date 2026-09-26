-- 113: the seed escape hatch requires an EXPLICIT grant of `epigraph_seed`,
-- and a superuser write that is not a seed gets its author's declaration.
-- (backlog 0512ca33, batch R2.)
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- Migration 074's three `*_require_tenancy` bodies take the seed arm, which
-- stamps an undeclared row `('public', <seed group 00000000-...-dead>)`
-- instead of raising 23502, when
--
--     pg_has_role(session_user, 'epigraph_seed', 'MEMBER')
--
-- holds. `pg_has_role` is TRUE FOR EVERY SUPERUSER, whatever
-- `pg_auth_members` says: a superuser is treated as a member of every role.
-- So every connection whose session user is a superuser takes the hatch,
-- although nobody was ever granted `epigraph_seed`. The seed group is
-- memberless by design (074 section 1), so each such row is owned by a group
-- no principal belongs to. Today those rows are `public`, so they are
-- mis-attributed rather than lost; the moment one is privatised it becomes
-- unreadable by every principal. Measured on a deployed database
-- 2026-09-22: 56 `claims` and 46 `evidence` rows owned by the seed group,
-- all written after the tenancy migrations were applied, through services
-- whose DSN names a superuser.
--
-- Measured on a throwaway database at head (110), superuser `epigraph`, with
-- ZERO `pg_auth_members` rows for `epigraph_seed`:
--
--     pg_has_role('epigraph',     'epigraph_seed', 'MEMBER') = true
--     pg_has_role('epigraph_app', 'epigraph_seed', 'MEMBER') = false
--
-- and an undeclared `INSERT INTO claims` on the superuser session landed on
-- `('public', 00000000-0000-0000-0000-00000000dead)`.
--
-- ===================================================================
-- 1. WHAT CHANGES
-- ===================================================================
--
-- (a) `public.epigraph_session_is_seed()` — TRUE only when `session_user` IS
--     `epigraph_seed` or reaches it through a chain of `pg_auth_members`
--     grants. It never calls `pg_has_role` and never reads `rolsuper`, so a
--     superuser is a seed only if it was granted the role like anyone else.
--     The role-existence guard is kept (074 ops F4): with no `epigraph_seed`
--     role the answer is false, not an error.
--
-- (b) The three bodies take the seed arm on that function instead of on
--     `pg_has_role`. Nothing else in the seed arm changes.
--
-- (c) `epigraph_claims_require_tenancy` gains ONE arm after the seed arm: a
--     SUPERUSER session that is not a seed gets the declaration
--     `ClaimRepository::default_decl_for_author` gives an undeclared write on
--     the application path — the author's ACTING operator's personal group
--     (`epigraph_operator_actor`, 107) if it has one, else the author's own
--     personal group (`epigraph_ensure_personal_group`, 105), and
--     `visibility = 'public'` unless the writer named one. Resolved through
--     the same two definers, in the same order, so the kernel and the Rust
--     write path cannot give one author two owners. 105's refusals propagate:
--     an author whose only personal-group rows are revoked (RVK01), or whose
--     personal did is squatted (RVK02), is REFUSED here exactly as it is on
--     the application path, rather than stamped somewhere nobody chose.
--
--     Why superusers get a declaration and every other role still raises: D1
--     ("tenancy is declared, never defaulted") is about writes whose principal
--     nobody is responsible for. The rows this file exists for came from
--     writers that DID name an author (`claims.agent_id` is NOT NULL) over a
--     DSN that happens to be a superuser — services whose credential split
--     has not been done yet. Raising would turn today's mis-attribution into a
--     write outage for them; stamping the seed group is the bug. The author's
--     own group is the one answer the rest of the system already gives that
--     writer. An `epigraph_app` or `epigraph_maintenance` session is unchanged:
--     undeclared, it raises 23502.
--
-- (d) The derived and root bodies get (b) only. A superuser that is not a
--     seed and writes an undeclared row there RAISES 23502, like any other
--     non-seed writer:
--       * derived (17 tables): every one carries `claim_id NOT NULL`, and a
--         row with a claim inherits BEFORE the seed arm is reached, so the
--         seed arm there is only ever reached by a row that the NOT NULL
--         constraint refuses anyway. There is no case to derive.
--       * roots (frames, contexts, perspectives, communities,
--         harvester_fragments, recall_events): four have no author column at
--         all, and the other two (`perspectives.owner_agent_id`,
--         `recall_events.agent_id`) are nullable. There is no author
--         declaration to give, so the D1 answer stands. Every in-tree
--         production statement that writes a root names both columns
--         (`docs/tenancy.md#declaring-visibility-on-write`; measured on this
--         tree, the only undeclared root INSERTs are test fixtures). What this
--         can break is an OUT-OF-TREE or pre-tenancy binary that writes a root
--         undeclared over a superuser DSN: today its row lands on the seed
--         group, after this file it is refused. The deploy note for 113 in
--         `migrations/README.md` says how to measure that before applying.
--
-- ===================================================================
-- 2. THE OTHER `pg_has_role(..., 'MEMBER')` SITES, MEASURED AND KEPT
-- ===================================================================
--
-- Every function in `public` whose source calls `pg_has_role` at head (110):
--
--   epigraph_bypass()                 session_user, 'epigraph_maintenance'
--   epigraph_definer_bypass()         current_user, 'epigraph_maintenance'
--   epigraph_claims_require_tenancy() session_user, 'epigraph_seed'   <- this file
--   epigraph_derived_require_tenancy() session_user, 'epigraph_seed'  <- this file
--   epigraph_root_require_tenancy()   session_user, 'epigraph_seed'   <- this file
--
-- and no RLS policy calls it directly. The two bypass functions are
-- DELIBERATELY left superuser-inclusive:
--
--   * `epigraph_bypass()` answers "may this session act across every group?"
--     A superuser already bypasses row security (FORCE included) and every
--     GRANT, so a false answer would not take any authority away; it would
--     only make the guard triggers that exempt `epigraph_bypass()` (108's
--     `groups_identity_immutable`, 109's `group_memberships_*` guards) refuse
--     the migration runner and administrative repairs, which run as a
--     superuser.
--   * `epigraph_definer_bypass()` asks about `current_user`, which inside a
--     definer frame is the FUNCTION OWNER. A superuser-owned body reaches
--     every table anyway; `epigraph-tenancy-backfill verify` already treats
--     a superuser owner as passing for exactly that reason.
--
-- The seed arm is different in kind: it does not ask "may this session do
-- more?", it CHOOSES AN OWNER for the row. Superuser implication there does
-- not grant authority the session lacked; it silently decides who owns data.
-- That is why only the seed arm changes.
--
-- ===================================================================
-- 3. WHAT THIS DOES NOT DO
-- ===================================================================
--
-- THE TEST HARNESS. `#[sqlx::test]` connects as a superuser, and ~35 fixture
-- INSERTs into the root tables (and many claim fixtures) name no tenancy
-- columns, relying on the seed arm. Until this file that reliance was on
-- superuser implication; from here it needs the grant the tenancy plan always
-- named ("`epigraph_seed` granted to the test harness pools"): CI issues
-- `GRANT epigraph_seed TO epigraph` after migrating, and
-- `tenancy_required.rs::the_harness_role_can_take_the_seed_escape_hatch`
-- names the grant when it is missing. A production cluster must hold NO such
-- grant for a service login; that is what this file makes load-bearing.
--
-- It does not move the rows already stamped. `epigraph-operator reown-seed`
-- re-derives each one's owner, dry-run by default, under a manifest that
-- `reown-reverse` undoes. It does not change any deployment's DSN: moving a
-- superuser-DSN service onto the application role is an operator step.
--
-- Ownership: CREATE OR REPLACE preserves the owner and the ACL of the three
-- bodies (074 section 6 re-owned them to `epigraph_maintenance`; 074's REVOKE
-- FROM PUBLIC stands). They stay SECURITY DEFINER.
-- `epigraph_session_is_seed()` is a plain invoker function: it reads only
-- `pg_roles` and `pg_auth_members`, which every role can read, and it reports
-- only on the CALLER's own session user, so it is left EXECUTE-able by PUBLIC,
-- as `epigraph_bypass()` is, for the API's boot posture probe.
--
-- Idempotent: CREATE OR REPLACE only.
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- (a) Explicit membership of `epigraph_seed`.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_session_is_seed() RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE SET search_path = pg_catalog, pg_temp AS $$
    WITH RECURSIVE seed AS (
        SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = 'epigraph_seed'
    ),
    -- Every role that reaches `epigraph_seed` through GRANTs: its direct
    -- members, then their members, and so on. UNION de-duplicates, so the walk
    -- terminates (PostgreSQL also refuses circular grants).
    members(oid) AS (
        SELECT m.member FROM pg_catalog.pg_auth_members m JOIN seed s ON m.roleid = s.oid
        UNION
        SELECT m.member FROM pg_catalog.pg_auth_members m JOIN members x ON m.roleid = x.oid
    )
    SELECT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_roles me, seed s
         WHERE me.rolname = session_user
           AND (me.oid = s.oid OR me.oid IN (SELECT oid FROM members))
    );
$$;

-- ===================================================================
-- (b) + (c) claims.
--
-- 074's body verbatim except: arm 4's condition, and the new arm 4b.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_claims_require_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE g uuid; v character varying(16);
BEGIN
    -- Arm order is 074's and is load-bearing (074 section 1): the PARENT arms
    -- run before the "fully declared" arm, so a declaration cannot escape the
    -- comparison against its parent.

    -- 1. Determinate inheritance from a predecessor.
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

    -- 2. Determinate inheritance within a step lineage.
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

    -- 4. Seed escape hatch: an EXPLICIT grant of epigraph_seed (this file,
    --    section 1a), never superuser implication. Otherwise 074's arm 4.
    IF public.epigraph_session_is_seed() THEN
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

    -- 4b. A superuser that is not a seed: the author's own declaration, as
    --     `ClaimRepository::default_decl_for_author` resolves it (section 1c).
    IF COALESCE((SELECT r.rolsuper FROM pg_catalog.pg_roles r
                  WHERE r.rolname = session_user), false) THEN
        SELECT a.operator_group_id INTO g
          FROM public.epigraph_operator_actor(NEW.agent_id) a;
        IF g IS NULL THEN
            g := public.epigraph_ensure_personal_group(NEW.agent_id);
        END IF;
        NEW.owner_group_id := COALESCE(NEW.owner_group_id, g);
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

-- ===================================================================
-- (b) the 17 claim-derived tables. 074's body verbatim except the seed test.
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
        RAISE EXCEPTION 'epigraph tenancy: %.claim_id=% references a nonexistent claim',
            TG_TABLE_NAME, NEW.claim_id USING ERRCODE = '23503';
    END IF;

    IF public.epigraph_session_is_seed() THEN
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

-- ===================================================================
-- (b) the 6 roots. 074's body verbatim except the seed test.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_root_require_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF NEW.visibility IS NOT NULL AND NEW.owner_group_id IS NOT NULL THEN
        RETURN NEW;
    END IF;

    IF public.epigraph_session_is_seed() THEN
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
