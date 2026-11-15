-- 227: a seal and a publicize of the same claim can no longer both commit
-- (backlog e8f9c07e).
--
-- ===================================================================
-- 0. THE RACE
-- ===================================================================
--
-- Two triggers hold "a sealed claim is never public":
--
--   * `claim_encryption_no_public_sealed` (081, coded PRV01 by 176), BEFORE
--     INSERT OR UPDATE on `claim_encryption`, reads `claims.visibility` and
--     refuses a seal while the claim is public;
--   * `claims_block_widening` (074), BEFORE UPDATE OF visibility on `claims`,
--     refuses `visibility = 'public'` while a `claim_encryption` row exists.
--
-- Each one read the other table with a plain SELECT. Under READ COMMITTED
-- neither sees the other's uncommitted write, and nothing made one wait for
-- the other:
--
--   * PUBLICIZE FIRST. The publicize's UPDATE holds the claim row's lock and
--     has passed 074's check. The seal's INSERT reads the committed (not yet
--     public) visibility and passes PRV01; its FK check takes only KEY SHARE,
--     which an UPDATE of a non-key column does not block. The seal's own
--     `UPDATE claims` (statement 2 of `seal_claims_conn`) then waits on the
--     publicize, follows the row to its new, public version, and does not
--     fire 074 (it sets no visibility). Both commit.
--   * SEAL FIRST, before the seal's `UPDATE claims`. The ciphertext row is
--     uncommitted, so 074's EXISTS sees nothing; the publicize commits, then
--     the seal reaches its UPDATE and commits too.
--
-- Either way the database ends up holding a PUBLIC claim whose content is the
-- seal sentinel and whose ciphertext no public reader can open: the state
-- 074's header (sec F11) calls permanently unreadable.
--
-- ===================================================================
-- 1. THE FIX: the seal trigger LOCKS the claim row it reads
-- ===================================================================
--
-- `SELECT ... FOR SHARE OF c` conflicts with the publicize's row lock (an
-- UPDATE of a non-key column takes FOR NO KEY UPDATE), so:
--
--   * PUBLICIZE FIRST: the seal's read waits for the publicize to end. When
--     it commits, READ COMMITTED re-reads the row's newest version, which is
--     public, and PRV01 refuses the seal.
--   * SEAL FIRST: the seal holds FOR SHARE on the claim row from its first
--     statement to its commit. The publicize's UPDATE waits for that lock
--     BEFORE its row trigger fires (PostgreSQL locks the target row and then
--     runs BEFORE ROW triggers on the version it locked). 074's EXISTS is a
--     new statement of a VOLATILE plpgsql function, so it takes a fresh
--     snapshot, sees the committed ciphertext row, and refuses. 074 therefore
--     needs no change, and this file does not touch it.
--
-- Both orderings are pinned against the 176 body (where they commit a public
-- sealed claim) and against this body (where they are refused), by
-- crates/epigraph-db/tests/sealed_public_race.rs.
--
-- THE LOCK UNDER ROW SECURITY. The function stays SECURITY INVOKER, as 081
-- wrote it, so the read is still the caller's. A locking read applies the
-- table's UPDATE policies as well as its SELECT policies, and needs UPDATE
-- privilege on `claims`. On today's policy set the two read the same rows (the
-- tier-A `claims_tenancy` policy is FOR ALL, so a public claim passes its
-- USING for UPDATE as for SELECT; 126's restrictive `claims_elevated_no_update`
-- hides rows only from an elevated session, which 126 also refuses any
-- `claim_encryption` write). Every role that may write `claim_encryption`
-- holds UPDATE on `claims` (measured on a fresh database by the test above).
-- So that no future policy can make this check refuse LESS than 176's, a
-- locked read that finds no row falls back to 176's unlocked read: the
-- refusal set is never smaller than before, and is larger only by the race.
-- A row the caller's SELECT policies hide is neither read nor locked, as
-- before, so the lock is no existence oracle.
--
-- WHAT DOES NOT CHANGE: owner, ACL (EXECUTE revoked from PUBLIC by 081),
-- SECURITY INVOKER, volatility, no `proconfig`; the trigger
-- `claim_encryption_no_public_sealed` itself; PRV01's text and SQLSTATE
-- (42501), so every caller that maps it answers as before.
--
-- COST: a seal holds FOR SHARE on each claim it seals until it commits. A seal
-- already takes each claim's row lock in its statement 2, so this moves that
-- wait earlier rather than adding one. A multi-claim seal and a multi-claim
-- publicize that reach the same claims in opposite orders can deadlock; one is
-- aborted with 40P01 and nothing is half-written.
--
-- ===================================================================
-- RE-STATING A SHARED BODY
-- ===================================================================
-- This re-states 176's body. A migration applied before this one that also
-- re-states `epigraph_no_public_sealed` would be silently reverted here, so
-- the GUARD below refuses unless the live body is exactly 176's (md5 of
-- `prosrc`). The migration that lands second must take the higher number,
-- re-state the MERGED body, and make its own undo restore the merged
-- predecessor. Undo: docs/runbooks/227-undo.sql (same guard, on this body).

SET LOCAL lock_timeout = '3s';

DO $$
DECLARE v_src text;
BEGIN
    SELECT md5(p.prosrc) INTO v_src FROM pg_catalog.pg_proc p
     WHERE p.oid = 'public.epigraph_no_public_sealed()'::regprocedure;
    IF v_src IS DISTINCT FROM '0f48e208547eb393e1d4b5565f32571a' THEN
        RAISE EXCEPTION '227: epigraph_no_public_sealed (prosrc md5 %) is not the body 227 '
                        'builds on (176''s). A migration before 227 re-stated it; re-stating '
                        'it here would revert that change. Re-state the MERGED body in the '
                        'later migration', v_src
              USING ERRCODE = '55000';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_no_public_sealed() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE v text;
BEGIN
    -- 227: lock the claim row, so a concurrent publicize either finishes
    -- first (and this re-reads its public version) or waits for this seal to
    -- commit (and 074's check then sees the ciphertext row).
    SELECT c.visibility INTO v FROM public.claims c WHERE c.id = NEW.claim_id FOR SHARE OF c;
    IF NOT FOUND THEN
        -- Never refuse less than 176: a row the locking read cannot see
        -- (UPDATE policies, or none) is read as 176 read it.
        SELECT c.visibility INTO v FROM public.claims c WHERE c.id = NEW.claim_id;
    END IF;
    IF v = 'public' THEN
        RAISE EXCEPTION 'PRV01: privatization: refusing to seal claim % while it is '
                        'visibility=public. Restrict first, then seal.', NEW.claim_id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
