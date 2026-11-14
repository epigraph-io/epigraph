-- 216: the tenancy seed escape hatch requires an EXPLICIT grant of
-- `epigraph_seed`. Being a superuser no longer counts. (backlog 0512ca33)
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- Migration 074's three `*_require_tenancy` bodies take a seed arm, which
-- stamps an undeclared row `('public', <seed group 00000000-...-dead>)`
-- instead of raising 23502, when
--
--     pg_has_role(session_user, 'epigraph_seed', 'MEMBER')
--
-- holds. `pg_has_role` is TRUE FOR EVERY SUPERUSER, whatever
-- `pg_auth_members` says: PostgreSQL treats a superuser as a member of every
-- role. So every session whose session user is a superuser takes the hatch,
-- although nobody was granted `epigraph_seed`, and each such row is owned by a
-- group that is memberless by design (074 section 1). While the row is
-- `public` it is mis-attributed rather than lost; the moment it is made
-- group-private it becomes unreadable by every principal.
--
-- Measured on a throwaway database at head (209), superuser `epigraph`, with
-- ZERO `pg_auth_members` rows for `epigraph_seed`:
--
--     pg_has_role('epigraph',     'epigraph_seed', 'MEMBER') = true
--     pg_has_role('epigraph_app', 'epigraph_seed', 'MEMBER') = false
--
-- and an undeclared `INSERT INTO claims` on a superuser session landed on
-- `('public', 00000000-0000-0000-0000-00000000dead)`
-- (`crates/epigraph-db/tests/seed_escape_explicit_membership.rs`).
--
-- The latest definitions of the three bodies are 074's: no later migration
-- re-states them (153 and 176 mention them; neither redefines them).
--
-- ===================================================================
-- 1. WHAT CHANGES
-- ===================================================================
--
-- (a) `public.epigraph_session_is_seed()`: TRUE only when `session_user` IS
--     `epigraph_seed` or reaches it through a chain of `pg_auth_members`
--     grants each of which CONFERS the role (`inherit_option OR
--     set_option`). It never calls `pg_has_role` and never reads `rolsuper`,
--     so a superuser is a seed only if it was granted the role like anyone
--     else. With no `epigraph_seed` role it answers false, never raises (the
--     reason 074 guarded `pg_has_role` with an EXISTS, ops F4).
--
--     An ADMIN-only edge (`admin_option` true, `inherit_option` and
--     `set_option` both false) is NOT followed. It lets its holder administer
--     the role's membership, not act as the role, and PostgreSQL 16 writes one
--     on its own in a case nobody chose (a non-superuser CREATEROLE role that
--     creates a role gets an ADMIN-only grant back to it).
--     `pg_has_role(..., 'MEMBER')` counts that edge, so following it would be
--     the same implication in another form. The holder can still GRANT the
--     role to itself; that is an explicit act, and then it passes like any
--     other grant.
--
--     `inherit_option` and `set_option` are PostgreSQL 16 columns. This file
--     requires PostgreSQL 16 or later (CI and the documented deployments run
--     16); on 15 the CREATE FUNCTION below fails and nothing is applied.
--
-- (b) The three bodies take the seed arm on that function instead of on
--     `pg_has_role`. Each is 074's body byte for byte except the arm's
--     condition (and, in the claims body, the arm's comment). A superuser
--     session that holds no grant and writes an undeclared row now gets what
--     every other non-seed writer gets: 23502.
--
--     That is deliberate, and it is a choice: the alternative is to give a
--     superuser's undeclared claim its author's own group. Raising keeps D1
--     ("tenancy is declared, never defaulted") with no second defaulting
--     rule in the kernel that would have to track the application's
--     (`ClaimRepository`'s) default-visibility resolution as that changes.
--
-- ===================================================================
-- 2. THE OTHER `pg_has_role` SITES, KEPT
-- ===================================================================
--
-- `epigraph_bypass()` (session_user, maintenance) and
-- `epigraph_definer_bypass()` (current_user, maintenance) stay
-- superuser-inclusive on purpose. They answer "may this session act across
-- every group?", and a superuser already bypasses row security and every
-- GRANT, so a false answer would take no authority away; it would only make
-- the guard triggers that exempt them refuse the migration runner and
-- administrative repairs. The seed arm is different in kind: it does not
-- grant more, it CHOOSES AN OWNER for the row. Superuser implication there
-- silently decides who owns data. That is why only the seed arm changes.
--
-- 089/115's `epigraph_inherit_fragment_tenancy_stmt()` has no seed arm (its
-- latest body, 115, gates on `epigraph_bypass()` and re-stamps sentinel-owned
-- fragments); seed-stamped fragments come from 074's root arm, changed here.
--
-- ===================================================================
-- 3. WHAT THIS DOES NOT DO
-- ===================================================================
--
-- THE TEST HARNESS. `#[sqlx::test]` connects as a superuser, and many
-- fixtures insert claims and root rows without naming the tenancy columns,
-- relying on the seed arm. Until this file that reliance was on superuser
-- implication; from here it needs the grant the tenancy plan always named
-- ("`epigraph_seed` granted to the test harness pools"). `epigraph-migrate`
-- issues `GRANT epigraph_seed TO <its session user>` after a successful run
-- when `EPIGRAPH_MIGRATE_GRANT_SEED_TO_SELF` is set, which CI's job env sets.
-- `tenancy_required.rs::the_harness_role_can_take_the_seed_escape_hatch`
-- names the remedy when the grant is missing. A deployed cluster must hold
-- NO such grant for a service login; that is what this file makes
-- load-bearing.
--
-- It does not move the rows already stamped onto the seed group (operator
-- data work), and it changes no deployment's DSN.
--
-- DEPLOY PRECONDITION. Applying this file turns a superuser-DSN writer's
-- undeclared write from a silent seed stamp into 23502. Before applying it,
-- measure the recent seed-stamped rows per tier-A table (the audit query in
-- 074 section 1: `owner_group_id = '00000000-0000-0000-0000-00000000dead'`,
-- by `created_at`), and move every writer still producing them onto a role
-- that declares tenancy. See `migrations/README.md`, entry 216.
--
-- Ownership: CREATE OR REPLACE preserves the owner and ACL of the three
-- bodies (074 section 6 re-owned them to `epigraph_maintenance`; 074's REVOKE
-- FROM PUBLIC stands). They stay SECURITY DEFINER with their 074
-- search_path. `epigraph_session_is_seed()` is a plain invoker function: it
-- reads only `pg_roles` and `pg_auth_members`, which every role can read, and
-- reports only on the CALLER's own session user, so it keeps PUBLIC's default
-- EXECUTE, as `epigraph_bypass()` does. The three bodies run as
-- `epigraph_maintenance` and call it through that grant.
--
-- Undo: docs/runbooks/216-undo.sql. Idempotent: CREATE OR REPLACE only.
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- (a) Explicit membership of `epigraph_seed`.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_session_is_seed() RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE SET search_path = pg_catalog, pg_temp AS $$
    WITH RECURSIVE seed AS (
        SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = 'epigraph_seed'
    ),
    -- Every role that reaches `epigraph_seed` through grants: its direct
    -- members, then their members, and so on. UNION de-duplicates, so the walk
    -- terminates (PostgreSQL also refuses circular grants). Only edges that
    -- confer the role are followed (section 1a).
    members(oid) AS (
        SELECT m.member FROM pg_catalog.pg_auth_members m JOIN seed s ON m.roleid = s.oid
         WHERE m.inherit_option OR m.set_option
        UNION
        SELECT m.member FROM pg_catalog.pg_auth_members m JOIN members x ON m.roleid = x.oid
         WHERE m.inherit_option OR m.set_option
    )
    SELECT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_roles me, seed s
         WHERE me.rolname = session_user
           AND (me.oid = s.oid OR me.oid IN (SELECT oid FROM members))
    );
$$;

-- ===================================================================
-- (b) claims. 074's body except arm 4's condition and comment.
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
    --    current_user is the function owner). Since migration 216 the
    --    membership is an EXPLICIT grant chain to epigraph_seed
    --    (epigraph_session_is_seed()); a superuser is no longer a member by
    --    implication. The function answers false, never raises, when the role
    --    does not exist (ops F4).
    --
    --    STAMPS THE SEED GROUP, NOT WORLD (sec F14). §8.2 A4 asserts
    --    count(*) FROM claims WHERE owner_group_id = <world> is 0, and the
    --    deferred strong CHECK (owner_group_id <> world) could never ship
    --    while this arm stamped world. Seed also makes escape-hatch rows
    --    greppable: SELECT count(*) FROM claims WHERE owner_group_id =
    --    '00000000-0000-0000-0000-00000000dead'.
    IF public.epigraph_session_is_seed() THEN
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

-- ===================================================================
-- (b) the 17 claim-derived tables. 074's body except the seed condition.
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
-- (b) the parentless roots. 074's body except the seed condition.
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
