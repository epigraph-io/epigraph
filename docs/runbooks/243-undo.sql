-- ===================================================================
-- 243-undo.sql: take migration 243 (a non-owner's re-point of a public
-- claim's belief cache off a frame whose every input is inadmissible) back
-- out, in ONE transaction, on the migration (superuser) DSN.
--
-- WHAT IT DOES: re-states `epigraph_foreign_belief_cache` with 114's body,
-- verbatim, on 190's path (`pg_catalog, public, pg_temp`; NOT 114's original
-- `pg_catalog, public`, which `definer_search_path_ratchet.rs` refuses).
-- CREATE OR REPLACE keeps the owner and the grants. A precondition refuses
-- (55000, nothing changed) unless the function still carries 243's body.
--
-- WHAT IT LEAVES:
--   * every cache 243 re-pointed, and its `claims.foreign_aggregate_write`
--     audit row (`action = 'belief_cache_repoint'`; 082: immutable). Each
--     such cache is the owner rule's own fold, which a maintenance recompute
--     would also write, so there is nothing to put back. List them with:
--       SELECT created_at, agent_id, details->>'claim_id',
--              details->'before'->>'belief_frame_id',
--              details->'after'->>'belief_frame_id'
--         FROM public.security_events
--        WHERE event_type = 'claims.foreign_aggregate_write'
--          AND details->>'action' = 'belief_cache_repoint';
--   * 243's `_sqlx_migrations` row. Re-introducing the arm is a NEW
--     migration, never a re-run of 243.
--
-- After it, a non-owner's recompute of a claim in the 0296077b shape is
-- declined again, and the claim keeps the narrowed evidence's fold until a
-- privileged recompute runs (`recompute_beliefs` on the maintenance DSN).
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_found text;
BEGIN
    SELECT md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_foreign_belief_cache(uuid, double precision, '
                                   'double precision, double precision, double precision, '
                                   'double precision, uuid)');
    IF v_found IS DISTINCT FROM 'bb583f1b40975d33b09c769cf9324b65' THEN
        RAISE EXCEPTION '243-undo: epigraph_foreign_belief_cache is not 243''s body (md5 '
                        'bb583f1b40975d33b09c769cf9324b65); found md5 %. Nothing was changed', COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_foreign_belief_cache(
    p_claim uuid, p_belief double precision, p_plausibility double precision,
    p_mass_on_empty double precision, p_pignistic_prob double precision,
    p_mass_on_missing double precision, p_belief_frame_id uuid)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE v_owner uuid := public.epigraph_foreign_aggregate_target(p_claim);
        v_before jsonb; v_after jsonb; v_frame uuid; v_cached boolean;
BEGIN
    -- The cache carries ONE frame's combination (`belief_frame_id`). A non-owner
    -- may refresh it on THAT frame (every writer's BBAs there, recombined), or
    -- SEED it when the claim has no cache at all; it may NOT re-point it to
    -- another frame -- e.g. one it just created, holding only its own BBA --
    -- which would replace the claim's cross-writer combination on its own
    -- authority. Which frame carries a claim's belief is the owner's decision.
    -- A refused write is a no-op (0), not an error: the BBA is stored either way.
    --
    -- A cache with NO frame recorded (written before `belief_frame_id` existed:
    -- the common shape among older claims) is "frame unknown", never "no cache":
    -- treating it as seedable would let one non-owner BBA overwrite it and then
    -- own the frame (review finding W1). So a seed needs every cache column NULL,
    -- and it lands only on the canonical `binary_truth` frame, the designated
    -- summary frame; a non-owner cannot make a frame of its own choosing the one
    -- that carries a claim's belief. Backfilling `belief_frame_id` for older
    -- caches is a maintenance recompute, not this path.
    SELECT c.belief_frame_id,
           (c.belief IS NOT NULL OR c.plausibility IS NOT NULL
            OR c.pignistic_prob IS NOT NULL OR c.classification IS NOT NULL)
      INTO v_frame, v_cached
      FROM public.claims c WHERE c.id = p_claim;
    IF v_frame IS NULL THEN
        IF v_cached THEN RETURN 0; END IF;
        IF NOT EXISTS (SELECT 1 FROM public.frames f
                        WHERE f.id = p_belief_frame_id AND f.name = 'binary_truth') THEN
            RETURN 0;
        END IF;
    ELSIF v_frame IS DISTINCT FROM p_belief_frame_id THEN
        RETURN 0;
    END IF;
    -- A cached triple no mass function can represent is refused rather than
    -- stored: Bel <= BetP <= Pl (the `claims_*_bounds` checks bound each value
    -- to [0, 1] but do not order them).
    IF p_belief IS NOT NULL AND p_plausibility IS NOT NULL AND p_pignistic_prob IS NOT NULL
       AND NOT (p_belief <= p_pignistic_prob + 1e-9
                AND p_pignistic_prob <= p_plausibility + 1e-9) THEN
        RAISE EXCEPTION 'FA05: belief % / pignistic % / plausibility % is not an ordered '
            'DS triple; nothing was written', p_belief, p_pignistic_prob, p_plausibility
            USING ERRCODE = '22023';
    END IF;
    SELECT jsonb_build_object('belief', c.belief, 'plausibility', c.plausibility,
                              'pignistic_prob', c.pignistic_prob,
                              'mass_on_empty', c.mass_on_empty,
                              'mass_on_missing', c.mass_on_missing,
                              'belief_frame_id', c.belief_frame_id)
      INTO v_before FROM public.claims c WHERE c.id = p_claim;
    v_after := jsonb_build_object('belief', p_belief, 'plausibility', p_plausibility,
                                  'pignistic_prob', p_pignistic_prob,
                                  'mass_on_empty', p_mass_on_empty,
                                  'mass_on_missing', p_mass_on_missing,
                                  'belief_frame_id', p_belief_frame_id);
    UPDATE public.claims
       SET belief = p_belief, plausibility = p_plausibility, mass_on_empty = p_mass_on_empty,
           pignistic_prob = p_pignistic_prob, mass_on_missing = p_mass_on_missing,
           belief_frame_id = p_belief_frame_id, updated_at = now()
     WHERE id = p_claim;
    IF v_before IS DISTINCT FROM v_after THEN
        PERFORM public.epigraph_foreign_aggregate_audit(
            p_claim, v_owner, 'belief_cache', v_before, v_after);
    END IF;
    RETURN 1;
END $$;

COMMIT;
