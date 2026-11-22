-- 243: a non-owner's recompute may re-point a public claim's belief cache off
-- a frame whose every input is inadmissible, to the frame the cache-owner rule
-- elects (backlog 0296077b).
--
-- ===================================================================
-- 1. WHY
--
-- Shape: a public claim whose cache records `binary_truth` (114's
-- `claims.belief_frame_id`), holding a fold that includes a BBA citing
-- evidence later NARROWED (hidden from the public: `hide-evidence`, 110's
-- pin). `claim_validity` holds the claim's only input that may still enter its
-- cache (`derivation_scope::cache_admissible_predicate`: every source at least
-- as widely readable as the claim). The cache-owner rule
-- (`MassFunctionRepository::cache_owner_frame_for_claim`, backlog 8d720490
-- (1)) therefore names `claim_validity`, and a recompute folds it.
--
-- On the application role a recompute by anyone but the claim's owner goes
-- through 114's `epigraph_foreign_belief_cache`, which refreshes the cache
-- only on the frame it records and so declined that write (0). The recompute
-- correctly reported `false`, but the cache kept the fold of the hidden
-- evidence: every reader of the public claim was served a value derived from
-- evidence it can no longer read, until a privileged (maintenance) recompute
-- ran. Most public claims are WORLD-owned (114 section 0), so on the request
-- path NOBODY is the owner. Pinned as a KNOWN RESIDUAL by
-- `epigraph-mcp/tests/recompute_vacates_inadmissible_only_cache.rs`
-- (`an_admissible_input_on_another_frame_takes_the_cache`).
--
-- ===================================================================
-- 2. THE ARM
--
-- `epigraph_foreign_belief_cache` keeps every 114 rule and adds ONE re-point.
-- A non-owner may move the cache from the recorded frame R to frame P when ALL
-- of these hold, each read with the definer's rights (the whole graph, so a
-- caller that cannot see an input of R cannot make R look empty):
--
--   (R1) the claim is not a compound (193's `epigraph_claim_is_compound`):
--        the owner rule gives a compound no owner frame at all;
--   (R2) R holds no admissible combine input: the cache is a fold of nothing
--        any reader of the claim may read, and the owner rule has already
--        moved off it (its admissible-first key);
--   (R3) P is `binary_truth` with an admissible combine input, or
--        `claim_validity` with an admissible combine input while
--        `binary_truth` has none: the frame the owner rule elects in that
--        state (its ranks 1 and 2; rank 3, the recorded frame, is R, which
--        R2 rules out).
--
-- "Combine input" and "admissible" are the owner rule's own spellings,
-- inlined: cached combination rows (`cached_combination_predicate`), retracted
-- rows and ingest template rows (`ingest_template_predicate`) are not inputs,
-- and admissibility is `cache_admissible_predicate`.
-- `epigraph-db/tests/foreign_cache_repoint.rs` asserts the function body
-- carries each of the three Rust-generated predicates verbatim (whitespace
-- aside), so a change on the Rust side fails that test until a migration
-- re-states this body.
--
-- Everything else is refused (0, nothing written), exactly as 114 refuses
-- it: a re-point to a frame of the writer's own choosing (any frame but the
-- two canonical names), a re-point off a frame that still holds an
-- admissible input (the cross-writer combination 114 protects), and a
-- re-point to `claim_validity` while `binary_truth` has an admissible input.
-- The values are still the caller's, as for 114's refresh on the recorded
-- frame (114 section 0, "WHY THE DEFINER TAKES THE CACHE VALUES FROM THE
-- CALLER"); this file widens only WHICH frame, never what may be written.
-- 114's classification definer needs no change: it writes a verdict on the
-- frame the cache records, which after the re-point is P.
--
-- An accepted re-point is audited as every 114 cache write is, with
-- `action = 'belief_cache_repoint'` (the before/after carry both frames).
--
-- NOT COVERED (fail-closed, left to a privileged recompute as before):
--   * a VACATE that needs a re-point (no frame of the claim has an admissible
--     input, and the owner rule elects a frame other than R): R3 needs an
--     admissible input on P;
--   * an owner-rule election of a non-canonical frame (rank 4, the first
--     writer): R3 names the canonical frames only;
--   * a frameless legacy cache (114's "frame unknown"): unchanged;
--   * a re-point off a recorded frame that still holds an admissible input,
--     even to `binary_truth`, which the owner rule ranks above it (R2 is
--     stricter than the rule there): that fold leaks nothing, and which frame
--     carries it stays the owner's call, as in 114.
--   * Nothing here runs at the narrowing act itself: the cache is cleared of
--     the hidden fold at the claim's next recompute on any session (an edge,
--     an evidence write, `routes::assess`, a bulk recompute), not by the hide.
--
-- ===================================================================
-- 3. PRECONDITION, PATH, OWNER, GRANTS
--
-- The body is 114's with the arm above, a `v_target` / `v_action`
-- declaration, the audit action taken from `v_action`, and two comment lines;
-- no other byte changed. It refuses to apply over any body other than 114's
-- (md5 of `prosrc`; 190 changed only the path). The path stays 190's
-- `pg_catalog, public, pg_temp`, so the function stays in
-- `definer_search_path_ratchet.rs`'s `PUBLIC_PATH_REGISTER`. CREATE OR
-- REPLACE keeps the owner (`epigraph_maintenance`) and the grants
-- (`epigraph_app`, `epigraph_maintenance`); this file grants nothing.
--
-- ===================================================================
-- UNDO: `docs/runbooks/243-undo.sql` (re-states 114's body on 190's path).
-- ===================================================================

SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_found text;
BEGIN
    SELECT md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_foreign_belief_cache(uuid, double precision, '
                                   'double precision, double precision, double precision, '
                                   'double precision, uuid)');
    IF v_found IS DISTINCT FROM 'fadd978562eecfd45e5e3c3d7a2462f4' THEN
        RAISE EXCEPTION '243: epigraph_foreign_belief_cache is not the body 243 re-states '
                        '(114''s, md5 fadd978562eecfd45e5e3c3d7a2462f4); found md5 %. Another '
                        'migration re-bodied it; nothing was changed', COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
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
        v_target text; v_action text := 'belief_cache';
BEGIN
    -- The cache carries ONE frame's combination (`belief_frame_id`). A non-owner
    -- may refresh it on THAT frame (every writer's BBAs there, recombined), or
    -- SEED it when the claim has no cache at all; it may NOT re-point it to
    -- another frame -- e.g. one it just created, holding only its own BBA --
    -- which would replace the claim's cross-writer combination on its own
    -- authority. Which frame carries a claim's belief is the owner's decision.
    -- (243: one exception, the owner rule's own re-point off a recorded frame
    -- whose every input is inadmissible; see the ELSIF arm below.)
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
        -- 243: the ONE re-point a non-owner may make. Every condition is read
        -- here with the definer's rights (the whole graph, not the caller's
        -- view), and each is the cache-owner rule's own
        -- (`MassFunctionRepository::cache_owner_frame_for_claim`): the
        -- combine inputs exclude cached combination rows, retracted rows and
        -- ingest template rows, and an input is admissible by
        -- `derivation_scope::cache_admissible_predicate`. All of:
        --   (R1) the claim is not a compound (it has no owner frame at all);
        --   (R2) the RECORDED frame holds no admissible input, so the cache
        --        is a fold of nothing any reader of the claim may read (the
        --        narrowed-evidence leak, backlog 0296077b) and the owner rule
        --        has already moved the cache off it;
        --   (R3) the new frame is `binary_truth` with an admissible input, or
        --        `claim_validity` with an admissible input while
        --        `binary_truth` has none: the frame the owner rule elects.
        -- Anything else stays a no-op (0), as in 114: a frame of the writer's
        -- own choosing never carries a claim's belief.
        SELECT f.name INTO v_target FROM public.frames f WHERE f.id = p_belief_frame_id;
        IF v_target IS NULL OR v_target NOT IN ('binary_truth', 'claim_validity') THEN
            RETURN 0;
        END IF;
        IF public.epigraph_claim_is_compound(p_claim) THEN
            RETURN 0;
        END IF;
        IF EXISTS (
            SELECT 1
              FROM public.mass_functions mf
              JOIN public.frames f ON f.id = mf.frame_id
              JOIN public.claims c ON c.id = mf.claim_id
             WHERE mf.claim_id = p_claim AND mf.frame_id = v_frame
               AND NOT COALESCE(mf.source_agent_id IS NULL AND mf.perspective_id IS NULL
                     AND (mf.combination_method IN ('Conjunctive', 'Dempster', 'YagerOpen', 'YagerClosed', 'DuboisPrade', 'Inagaki', 'TbmConjunctive', 'cached_unfolded')
                          OR mf.combination_method LIKE 'cautious+%'), false)
               AND mf.retracted_at IS NULL
               AND NOT COALESCE(f.name = 'research_validity'
                     AND mf.combination_method IS NULL
                     AND abs(COALESCE(mf.source_strength, 0) - 0.3) < 0.000001
                     AND COALESCE((mf.masses->>'0,1')::float8, 0) >= 0.8, false)
               AND (mf.retracted_at IS NULL
                 AND (mf.visibility = 'public'
                      OR (c.visibility <> 'public' AND mf.owner_group_id = c.owner_group_id))
                 AND (mf.evidence_id IS NULL
                      OR EXISTS (SELECT 1 FROM evidence e
                                  WHERE e.id = mf.evidence_id
                                    AND (e.visibility = 'public'
                                         OR (c.visibility <> 'public'
                                             AND e.owner_group_id = c.owner_group_id))))
                 AND (mf.combination_method IS DISTINCT FROM 'edge_factor'
                      OR mf.perspective_id IS NULL
                      OR EXISTS (SELECT 1 FROM edges ed
                                  WHERE ed.id = mf.perspective_id
                                    AND (ed.visibility = 'public'
                                         OR (c.visibility <> 'public'
                                             AND ed.owner_group_id = c.owner_group_id
                                             AND ed.co_owner_group_id IS NULL))
                                    AND EXISTS (SELECT 1 FROM claims s
                                                 WHERE s.id = ed.source_id
                                                   AND (s.visibility = 'public'
                                                        OR (c.visibility <> 'public'
                                                            AND s.owner_group_id = c.owner_group_id))))))) THEN
            RETURN 0;
        END IF;
        IF NOT EXISTS (
            SELECT 1
              FROM public.mass_functions mf
              JOIN public.frames f ON f.id = mf.frame_id
              JOIN public.claims c ON c.id = mf.claim_id
             WHERE mf.claim_id = p_claim AND mf.frame_id = p_belief_frame_id
               AND NOT COALESCE(mf.source_agent_id IS NULL AND mf.perspective_id IS NULL
                     AND (mf.combination_method IN ('Conjunctive', 'Dempster', 'YagerOpen', 'YagerClosed', 'DuboisPrade', 'Inagaki', 'TbmConjunctive', 'cached_unfolded')
                          OR mf.combination_method LIKE 'cautious+%'), false)
               AND mf.retracted_at IS NULL
               AND NOT COALESCE(f.name = 'research_validity'
                     AND mf.combination_method IS NULL
                     AND abs(COALESCE(mf.source_strength, 0) - 0.3) < 0.000001
                     AND COALESCE((mf.masses->>'0,1')::float8, 0) >= 0.8, false)
               AND (mf.retracted_at IS NULL
                 AND (mf.visibility = 'public'
                      OR (c.visibility <> 'public' AND mf.owner_group_id = c.owner_group_id))
                 AND (mf.evidence_id IS NULL
                      OR EXISTS (SELECT 1 FROM evidence e
                                  WHERE e.id = mf.evidence_id
                                    AND (e.visibility = 'public'
                                         OR (c.visibility <> 'public'
                                             AND e.owner_group_id = c.owner_group_id))))
                 AND (mf.combination_method IS DISTINCT FROM 'edge_factor'
                      OR mf.perspective_id IS NULL
                      OR EXISTS (SELECT 1 FROM edges ed
                                  WHERE ed.id = mf.perspective_id
                                    AND (ed.visibility = 'public'
                                         OR (c.visibility <> 'public'
                                             AND ed.owner_group_id = c.owner_group_id
                                             AND ed.co_owner_group_id IS NULL))
                                    AND EXISTS (SELECT 1 FROM claims s
                                                 WHERE s.id = ed.source_id
                                                   AND (s.visibility = 'public'
                                                        OR (c.visibility <> 'public'
                                                            AND s.owner_group_id = c.owner_group_id))))))) THEN
            RETURN 0;
        END IF;
        IF v_target = 'claim_validity'
           AND EXISTS (
            SELECT 1
              FROM public.mass_functions mf
              JOIN public.frames f ON f.id = mf.frame_id
              JOIN public.claims c ON c.id = mf.claim_id
             WHERE mf.claim_id = p_claim AND f.name = 'binary_truth'
               AND NOT COALESCE(mf.source_agent_id IS NULL AND mf.perspective_id IS NULL
                     AND (mf.combination_method IN ('Conjunctive', 'Dempster', 'YagerOpen', 'YagerClosed', 'DuboisPrade', 'Inagaki', 'TbmConjunctive', 'cached_unfolded')
                          OR mf.combination_method LIKE 'cautious+%'), false)
               AND mf.retracted_at IS NULL
               AND NOT COALESCE(f.name = 'research_validity'
                     AND mf.combination_method IS NULL
                     AND abs(COALESCE(mf.source_strength, 0) - 0.3) < 0.000001
                     AND COALESCE((mf.masses->>'0,1')::float8, 0) >= 0.8, false)
               AND (mf.retracted_at IS NULL
                 AND (mf.visibility = 'public'
                      OR (c.visibility <> 'public' AND mf.owner_group_id = c.owner_group_id))
                 AND (mf.evidence_id IS NULL
                      OR EXISTS (SELECT 1 FROM evidence e
                                  WHERE e.id = mf.evidence_id
                                    AND (e.visibility = 'public'
                                         OR (c.visibility <> 'public'
                                             AND e.owner_group_id = c.owner_group_id))))
                 AND (mf.combination_method IS DISTINCT FROM 'edge_factor'
                      OR mf.perspective_id IS NULL
                      OR EXISTS (SELECT 1 FROM edges ed
                                  WHERE ed.id = mf.perspective_id
                                    AND (ed.visibility = 'public'
                                         OR (c.visibility <> 'public'
                                             AND ed.owner_group_id = c.owner_group_id
                                             AND ed.co_owner_group_id IS NULL))
                                    AND EXISTS (SELECT 1 FROM claims s
                                                 WHERE s.id = ed.source_id
                                                   AND (s.visibility = 'public'
                                                        OR (c.visibility <> 'public'
                                                            AND s.owner_group_id = c.owner_group_id))))))) THEN
            RETURN 0;
        END IF;
        v_action := 'belief_cache_repoint';
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
            p_claim, v_owner, v_action, v_before, v_after);
    END IF;
    RETURN 1;
END $$;
