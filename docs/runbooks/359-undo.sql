-- ===================================================================
-- 359-undo.sql: take migration 359 (refusal codes TEN03-TEN06 on the three
-- *_require_tenancy trigger bodies) back out, in ONE transaction, on the
-- migration (superuser) DSN.
--
-- No binary needs rolling back first: a 359 binary answers an uncoded
-- tenancy refusal as it did before 359 (an uncoded 23503 is
-- `ForeignKeyViolation`, an uncoded 23502 the redacted database error), so
-- after this file the refusals simply lose their codes again.
--
-- WHAT IT DOES:
--   * REFUSES (55000, nothing changed) unless each of the three bodies is
--     359's or already 216's (md5 of `prosrc`), so a body a later migration
--     re-stated is never silently reverted;
--   * re-states 216's `epigraph_claims_require_tenancy()`,
--     `epigraph_derived_require_tenancy()` and `epigraph_root_require_tenancy()`
--     byte for byte; `CREATE OR REPLACE` keeps their owner and ACL.
--
-- WHAT IT LEAVES: 359's `_sqlx_migrations` row. Re-introducing the codes is a
-- NEW migration, never a re-run of 359.
-- Idempotent: a second run changes nothing.
-- Tested by crates/epigraph-db/tests/caller_refusal_codes_restatement.rs
-- (`the_359_undo_returns_the_bodies_below_359`).
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $guard$
DECLARE
    v_name text;
    v_md5  text;
BEGIN
    FOR v_name, v_md5 IN
        SELECT p.proname::text, md5(p.prosrc)
          FROM pg_catalog.pg_proc p
         WHERE p.pronamespace = 'public'::regnamespace
           AND p.proname IN ('epigraph_claims_require_tenancy',
                             'epigraph_derived_require_tenancy',
                             'epigraph_root_require_tenancy')
    LOOP
        IF v_md5 NOT IN (
            -- 359's bodies
            '34ae82be5d1b42d134e5826b656d848e',
            'b783f07bdb965b7eb81da698ec188af8',
            '1fbf62e96f37ddf0cf25055e9e6d5839',
            -- 216's bodies
            'f7b1d866f389d2ab9d92c214c3bdd91c',
            'e2bfce6d72f7ddc4fdbe887239b0e130',
            '892f65582789246ab3aeaf29213957a2')
        THEN
            RAISE EXCEPTION '359-undo: % (prosrc md5 %) is neither 359''s nor 216''s body; '
                            'a later migration re-stated it, so this undo would revert that '
                            'change. Nothing was changed.', v_name, v_md5
                USING ERRCODE = '55000';
        END IF;
    END LOOP;
END $guard$;

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

COMMIT;
