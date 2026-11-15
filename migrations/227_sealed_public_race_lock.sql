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
-- `SELECT ... FOR NO KEY UPDATE OF c` conflicts with the publicize's row lock
-- (an UPDATE of a non-key column takes the same FOR NO KEY UPDATE), so:
--
--   * PUBLICIZE FIRST: the seal's read waits for the publicize to end. When
--     it commits, READ COMMITTED re-reads the row's newest version, which is
--     public, and PRV01 refuses the seal.
--   * SEAL FIRST: the seal holds the claim row's lock from its first
--     statement to its commit. The publicize's UPDATE waits for that lock
--     BEFORE its row trigger fires (PostgreSQL locks the target row and then
--     runs BEFORE ROW triggers on the version it locked). 074's EXISTS is a
--     new statement of a VOLATILE plpgsql function, so it takes a fresh
--     snapshot, sees the committed ciphertext row, and refuses. 074 therefore
--     needs no change, and this file does not touch it.
--
-- Both orderings are pinned against the 176 body (where they commit a public
-- sealed claim) and against this body (where they are refused), for a raw
-- `UPDATE claims` and for 206's shipped `epigraph_publicize_claims` (which,
-- seal first, waits in its pre-lock and then classifies the claim
-- `refused_sealed`), by crates/epigraph-db/tests/sealed_public_race.rs.
--
-- WHY NOT FOR SHARE. FOR SHARE also conflicts with the publicize, but two
-- concurrent writers of the SAME seal can both hold it. `seal_claims_conn`
-- makes a re-delivered commit a no-op with `ON CONFLICT (claim_id) DO
-- NOTHING`, and the BEFORE trigger fires before the conflict check. The
-- second writer would take FOR SHARE, then wait on the first's uncommitted
-- unique-index entry, while the first's statement 2 (`UPDATE claims`) waits on
-- the second's FOR SHARE: a deadlock (measured; pinned by
-- `a_redelivered_seal_is_a_no_op_not_a_deadlock`). The privatization route
-- does not reach this: `begin_batch_conn` takes a transaction-scoped advisory
-- lock before `seal_claims_conn` runs, so two deliveries through it queue on
-- that lock. A raw `claim_encryption` writer that skips the advisory lock
-- does reach it. The deciding reason is that FOR NO KEY UPDATE is the lock
-- statement 2 and 206's publicize pre-lock already take, so this adds no new
-- kind of lock: the second writer waits in its trigger until the first
-- commits, and its INSERT is then the no-op it was before. It still does not
-- conflict with the KEY SHARE an FK check takes.
--
-- THE LOCK UNDER ROW SECURITY. The function stays SECURITY INVOKER, as 081
-- wrote it, so the read is still the caller's. A locking read applies the
-- table's UPDATE policies as well as its SELECT policies, and needs UPDATE
-- privilege on `claims`. On today's policy set the two read the same rows (the
-- tier-A `claims_tenancy` policy is FOR ALL, so a public claim passes its
-- USING for UPDATE as for SELECT; 126's restrictive `claims_elevated_no_update`
-- hides rows only from an elevated session, which 126 also refuses any
-- `claim_encryption` write). Every role that may write `claim_encryption`
-- holds UPDATE on `claims` (measured on a fresh database by
-- `sealed_public_race.rs::every_role_that_may_seal_may_lock_the_claim_row`).
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
-- COST: a seal holds each claim's row lock from its INSERT until it commits.
-- A seal already took that same lock in its statement 2, so this moves the
-- wait earlier (into statement 1) rather than adding a new kind of lock. A
-- caller that sets `lock_timeout` (the route sets 3s) now sees a 55P03 at
-- statement 1 where it used to see it at statement 2. Lock ORDER: statement 1
-- locks the claims in the order the client sent them; statement 2 locked them
-- in planner order, which was never sorted either. A multi-claim seal and a
-- multi-claim publicize (206 locks `ORDER BY c.id`) that reach the same claims
-- in opposite orders could deadlock before 227 and still can; one is aborted
-- with 40P01 and nothing is half-written. 227 does not introduce this.
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
    SELECT c.visibility INTO v FROM public.claims c WHERE c.id = NEW.claim_id
       FOR NO KEY UPDATE OF c;
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
