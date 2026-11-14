-- ===================================================================
-- 216-undo.sql: take migration 216 (the tenancy seed escape hatch requires an
-- explicit grant of `epigraph_seed`) back out, in ONE transaction, on the
-- migration (superuser) DSN.
--
-- READ FIRST: THIS RE-OPENS BACKLOG 0512ca33. After it, every superuser
-- session takes the seed escape hatch again through `pg_has_role`
-- implication, so its undeclared claims, root rows and parentless derived
-- rows are silently stamped ('public', <memberless seed group>) instead of
-- raising 23502. Run it only to unblock a write outage that 216 caused, and
-- move the writer onto a role that declares tenancy before re-applying.
--
-- No binary needs rolling back first: a 216 binary's boot probe
-- (`epigraph_db::repos::seed_posture`) asks 074's question when
-- `epigraph_session_is_seed()` does not exist.
--
-- WHAT IT DOES:
--   * re-states 074's `epigraph_claims_require_tenancy()`,
--     `epigraph_derived_require_tenancy()` and `epigraph_root_require_tenancy()`
--     byte for byte; `CREATE OR REPLACE` keeps their owner and ACL;
--   * drops `epigraph_session_is_seed()`, which 216 created.
--
-- WHAT IT LEAVES:
--   * every row as it stands (216 moved none);
--   * any `GRANT epigraph_seed TO ...` issued meanwhile, e.g. by
--     `epigraph-migrate` with `EPIGRAPH_MIGRATE_GRANT_SEED_TO_SELF` (list them:
--     SELECT member::regrole FROM pg_auth_members
--      WHERE roleid = 'epigraph_seed'::regrole);
--   * 216's `_sqlx_migrations` row. Re-introducing 216's change is a NEW
--     migration, never a re-run of 216.
-- Idempotent: a second run changes nothing.
-- Tested by crates/epigraph-db/tests/seed_escape_explicit_membership.rs
-- (`the_216_undo_returns_the_catalog_below_216`).
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

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

DROP FUNCTION IF EXISTS public.epigraph_session_is_seed();

COMMIT;
