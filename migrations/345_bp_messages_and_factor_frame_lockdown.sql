-- 345: the application role writes neither `bp_messages` nor `factors.frame_id`
-- (backlog 9a9d6850). A promotion moves its hypothesis's factors through one
-- narrow maintenance-owned definer.
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- 217 took INSERT, UPDATE, DELETE and TRUNCATE on `factors` from
-- `epigraph_app` and recorded what it left:
--
--   "the application role can still move any factor between frames
--   (`frame_id`), and `bp_messages` stays application-writable (118's
--   derived-BP allowlist entry)"
--
-- and it granted `UPDATE (frame_id) ON public.factors` back for the hypothesis
-- promote route. `factors` and `bp_messages` have no row security, so with
-- those two grants any application session (any holder of the request DSN)
-- could:
--
--   * move any factor, on any claims, into any frame
--     (`UPDATE factors SET frame_id = ..`), which changes which frame's
--     propagation reads it;
--   * INSERT, rewrite or DELETE any belief-propagation message, on any
--     factor (`bp_messages` has no tenancy and 077 granted it all four).
--
-- Both steer belief propagation over claims the session does not own.
--
-- ===================================================================
-- 1. THE WRITERS, ENUMERATED (measured on this tree)
-- ===================================================================
--
--   `bp_messages`
--     FactorRepository::upsert_bp_message /     INSERT  no caller outside the
--       ::clear_bp_messages                     UPDATE  table-lockdown test
--                                               DELETE
--     match-candidate retirement (repos/        DELETE  maintenance connection
--       match_candidate.rs `retire_conn`, the           (117's DELETE grant)
--       `retire_match_candidates` CLI), the
--       r131 undo, the frame-delete operator
--   `factors.frame_id`
--     API hypothesis promote (routes/           UPDATE  application role, the
--       hypothesis.rs)                                  request transaction
--     hypothesis CLI (`hypothesis promote`)     UPDATE  maintenance connection
--                                                       (`MaintenancePool`)
--
-- Belief propagation keeps its messages in memory: no propagation path, on
-- either role, writes `bp_messages` today.
--
-- ===================================================================
-- 2. WHAT THIS FILE DOES
-- ===================================================================
--
--   1. `epigraph_app` loses INSERT, UPDATE, DELETE and TRUNCATE on
--      `public.bp_messages`. It keeps SELECT (the BP message reads). No
--      definer replaces the write: there is no application writer to route,
--      and any definer the application role could EXECUTE to write a message
--      would re-open the write this closes. The maintenance role keeps
--      070's INSERT / UPDATE and 117's DELETE.
--   2. `public.epigraph_promote_hypothesis_factors(claim) RETURNS bigint`,
--      SECURITY DEFINER on `pg_catalog, pg_temp`, owned by
--      `epigraph_maintenance`, EXECUTE for `epigraph_app` (and the
--      maintenance role) only. It moves the factors that name `claim` from
--      the `hypothesis_assessment` frame to `research_validity`, and nothing
--      else: both frames are resolved by name inside the body (the caller
--      names neither), and only factors over the named claim move. It
--      refuses (nothing moved):
--        * BPF01 (42501) unless the session writes the claim: a privileged
--          session, or the claim's owner group is one of the session's
--          writable groups (`epigraph_session_writes_node`, the claims
--          update policy's own owner arm, 115/117);
--        * BPF02 (55000) unless the claim's `hypothesis_status` is
--          `promoted` (the route writes it first, in the same transaction);
--        * BPF03 (P0002) when either frame is missing;
--        * 22004 for a NULL claim.
--      The write check comes first, so a session that does not write the
--      claim learns nothing about it (absent, unpromoted and foreign answer
--      alike).
--   3. `epigraph_app` loses 217's `UPDATE (frame_id)` on `public.factors`,
--      so it holds no write of any kind on `factors`. The maintenance role
--      keeps 070's UPDATE (the CLI promotion and the operator tools).
--
-- WHAT IS CLOSED: an application session moving a factor it has no claim to
-- (any frame, any factor), and any application write of a BP message.
--
-- NOT CHANGED: a session that writes a promoted hypothesis can move that
-- hypothesis's factors from `hypothesis_assessment` to `research_validity`,
-- including factors that also name claims it does not own. That is the
-- promotion's own effect, unchanged from 217 (where the route ran the same
-- UPDATE directly). The writable groups the check reads are the session's
-- stamp, as every owner-scoped policy reads them.
--
-- ===================================================================
-- 3. DEPLOY AND UNDO
-- ===================================================================
--
-- Deploy order: migration and API binary TOGETHER. An API binary from before
-- 345 runs the promote route's direct `UPDATE factors SET frame_id` and is
-- refused 42501 after 345 (every promotion of a hypothesis answers 500 and
-- rolls back); a 345 API binary calls the definer and is refused 42883 before
-- 345. The CLI is unaffected (maintenance connection). Nothing in this
-- repository writes `bp_messages` on the application role.
--
-- UNDO: `docs/runbooks/345-undo.sql`. Run it BEFORE `217-undo.sql` if both
-- are undone (217's undo grants table-level writes back on `factors`; 345's
-- re-grants the `frame_id` column 217 left).
--
-- Slot 345 was assigned by the 2026-11-25 backlog triage.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. `bp_messages`
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.bp_messages FROM epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- 2. THE PROMOTION'S FACTOR MOVE
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_promote_hypothesis_factors(p_claim uuid)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_status text;
    v_hyp    uuid;
    v_rv     uuid;
    v_moved  bigint;
BEGIN
    IF p_claim IS NULL THEN
        RAISE EXCEPTION 'epigraph_promote_hypothesis_factors: a claim is required'
            USING ERRCODE = '22004';
    END IF;
    IF NOT (public.epigraph_bypass()
            OR public.epigraph_session_writes_node(p_claim, 'claim')) THEN
        RAISE EXCEPTION 'BPF01: this session does not write claim %, so it may not move its '
                        'factors', p_claim
            USING ERRCODE = '42501';
    END IF;
    SELECT c.properties->>'hypothesis_status' INTO v_status
      FROM public.claims c
     WHERE c.id = p_claim;
    IF v_status IS DISTINCT FROM 'promoted' THEN
        RAISE EXCEPTION 'BPF02: claim % is not a promoted hypothesis; its factors stay in '
                        'their frame', p_claim
            USING ERRCODE = '55000';
    END IF;
    SELECT f.id INTO v_hyp FROM public.frames f WHERE f.name = 'hypothesis_assessment';
    SELECT f.id INTO v_rv FROM public.frames f WHERE f.name = 'research_validity';
    IF v_hyp IS NULL OR v_rv IS NULL THEN
        RAISE EXCEPTION 'BPF03: the hypothesis_assessment and research_validity frames must '
                        'both exist'
            USING ERRCODE = 'P0002';
    END IF;
    UPDATE public.factors
       SET frame_id = v_rv
     WHERE frame_id = v_hyp
       AND p_claim = ANY (variable_ids);
    GET DIAGNOSTICS v_moved = ROW_COUNT;
    RETURN v_moved;
END $$;

REVOKE EXECUTE ON FUNCTION public.epigraph_promote_hypothesis_factors(uuid) FROM PUBLIC;
-- Under a non-member owner its `claims` and `frames` reads are filtered as
-- the caller's would be, and under an owner without UPDATE on `factors`
-- every promotion is refused 42501 (loud); `epigraph-tenancy-backfill verify`
-- checks the owner (DEFERRED_DEFINER_FUNCTIONS) and the app grant
-- (OPERATOR_FUNCTION_GRANTS).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_promote_hypothesis_factors(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_promote_hypothesis_factors(uuid) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_promote_hypothesis_factors(uuid) '
                'TO epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- 3. `factors.frame_id`
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE UPDATE (frame_id) ON public.factors FROM epigraph_app';
    END IF;
END $$;
