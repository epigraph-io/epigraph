-- 362: the caller-reachable refusals of the three *_require_tenancy trigger
-- bodies carry a refusal code (backlog baac4c90, the follow-up 176 left for
-- these bodies).
--
-- 176 coded the designed refusals an application session can reach and
-- skipped the three *_require_tenancy bodies because another change was
-- restating them at the time; 216 is that restatement and the latest
-- definition of all three. This file restates each from 216's text with
-- CREATE OR REPLACE, and only RAISE statements differ, in 176's style: a code
-- is prefixed to the message and the SQLSTATE (ERRCODE) is kept, so every
-- caller that branches on the SQLSTATE answers as before.
--
-- CODED (each an INSERT by the application role on a tier-A table reaches it):
--   * TEN03 epigraph_claims_require_tenancy, undeclared (23502). The new
--     row's id and agent_id move from the MESSAGE to DETAIL.
--   * TEN04 epigraph_derived_require_tenancy, a claim_id that names no claim
--     (23503). The claim id moves from the MESSAGE to DETAIL.
--   * TEN05 epigraph_derived_require_tenancy, undeclared with claim_id NULL
--     (23502).
--   * TEN06 epigraph_root_require_tenancy, undeclared (23502).
-- Each message names only a table and the fix; row ids go in DETAIL, which
-- the HTTP reply withholds. A 23503 that carries a listed code is answered as
-- the caller's input refusal (400 with the message) instead of the generic
-- foreign-key answer; an uncoded 23503 keeps the generic answer.
--
-- NOT CODED, as in 176:
--   * epigraph_claims_require_tenancy's predecessor arm (23503 for a
--     supersedes that names no claim, 42501 for a public successor of a
--     group-private claim) and its step-lineage arm (42501): a code would let
--     the caller tell a missing claim from a private one;
--   * the seed escape-hatch arms (23502) of all three bodies: only a session
--     user with an explicit grant of epigraph_seed reaches them, never the
--     application role.
--
-- CREATE OR REPLACE keeps each function's owner, ACL, SECURITY mode,
-- volatility and search_path; outside the four RAISE statements the bodies
-- are byte-identical to 216's (pinned by
-- crates/epigraph-db/tests/caller_refusal_codes_restatement.rs, which compares
-- the catalog of a database before 362 with the same database at 362). A
-- later migration that restates one of these bodies must start from 362's
-- text or it drops the codes.
--
-- Undo: docs/runbooks/362-undo.sql. Idempotent: CREATE OR REPLACE only.
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- epigraph_claims_require_tenancy: 216's body. Coded: TEN03 (undeclared,
-- 23502; the row ids move to DETAIL). Uncoded: the predecessor and
-- step-lineage arms, and the seed arm.
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
        'TEN03: epigraph tenancy: INSERT INTO claims without an explicit (visibility, '
        'owner_group_id) declaration and no inheritable parent. Name both columns, '
        'or set claims.supersedes.'
        USING ERRCODE = '23502',
              DETAIL = format('id=%s, agent_id=%s', NEW.id, NEW.agent_id),
              HINT = 'See docs/tenancy.md#declaring-visibility-on-write';
END $$;

-- ===================================================================
-- epigraph_derived_require_tenancy: 216's body. Coded: TEN04 (the orphan
-- arm, 23503; the claim id moves to DETAIL), TEN05 (undeclared, 23502).
-- Uncoded: the seed arm.
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
        RAISE EXCEPTION 'TEN04: epigraph tenancy: %.claim_id references a nonexistent claim',
            TG_TABLE_NAME USING ERRCODE = '23503',
            DETAIL = format('claim_id=%s', NEW.claim_id);
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
        'TEN05: epigraph tenancy: INSERT INTO % without an explicit (visibility, '
        'owner_group_id) declaration and with claim_id NULL, so there is no parent '
        'to inherit from. Name both columns, or set claim_id.', TG_TABLE_NAME
        USING ERRCODE = '23502',
              HINT = 'See docs/tenancy.md#declaring-visibility-on-write';
END $$;

-- ===================================================================
-- epigraph_root_require_tenancy: 216's body. Coded: TEN06 (undeclared,
-- 23502). Uncoded: the seed arm.
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
        'TEN06: epigraph tenancy: INSERT INTO % without an explicit (visibility, '
        'owner_group_id) declaration. This table has no parent to inherit from, so '
        'the writer must name both columns.', TG_TABLE_NAME
        USING ERRCODE = '23502',
              HINT = 'See docs/tenancy.md#declaring-visibility-on-write';
END $$;
