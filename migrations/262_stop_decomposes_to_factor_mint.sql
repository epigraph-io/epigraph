-- 262: the edge INSERT trigger stops minting a BP factor for a
-- `decomposes_to` edge (backlog 444b1f4a; atom-level belief SPEC §6.2, D3).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- `auto_create_factor_from_edge` (217's maintenance-owned definer) maps every
-- claim-to-claim edge through `edge_to_factor_type`, which maps
-- `decomposes_to` to `directional_support` (0.0 forward, 0.6 reverse, 175's
-- row). Read by BP that factor carries an atom's evidence into its compound
-- and back (an echo D3 forbids), so every BP loader filters it out with
-- `repos::factor::bp_readable_factor_sql`. That filter decides a LEGACY
-- (unkeyed) row by reading `edges` under the caller's row security, so a
-- caller who cannot see the decomposition still reads the row. Minting the
-- rows at all is what keeps that residual open, and it also lets a
-- `decomposes_to` row take the `(type, pair, frame)` slot
-- (`idx_factors_type_vars_frame`) a later parallel `supports` / `refines`
-- edge on the same pair would have used, so that edge got no BP coupling.
--
-- ===================================================================
-- 1. WHAT THIS FILE DOES
-- ===================================================================
--
--   1. Refuses (`55000`, nothing applied) unless the trigger function is
--      still 217's body (md5 of `prosrc`), so it never overwrites a body
--      another migration changed.
--   2. Re-states 217's body with ONE addition: an early `RETURN NEW` for a
--      `decomposes_to` edge (any case). Everything else (the FCT01 guard,
--      SECURITY DEFINER, the pinned search_path, the mapping, potentials,
--      description, properties, the superseded-endpoint skip, ON CONFLICT DO
--      NOTHING) is 217's, unchanged. CREATE OR REPLACE keeps the owner
--      (`epigraph_maintenance`) and the EXECUTE revocations; they are
--      re-asserted below anyway.
--
-- NOT CHANGED HERE:
--   * `edge_to_factor_type` keeps its `decomposes_to` row: graph views,
--     clustering weights and the atlas flow read the mapping for edge
--     weights, not for factors.
--   * Existing `decomposes_to` factors (keyed and legacy) are NOT deleted by
--     this migration. Deleting them is an operator step with an exported
--     manifest and a restore path: the `decomposes_to_factor_sweep` binary
--     (epigraph-cli), run on the maintenance connection, dry run first.
--   * `REGENERATE_EDGE_FACTORS_SQL` (repos/claim.rs, the dedup and supersede
--     cascades' set form of this body) skips `decomposes_to` in the same
--     change, so the cascades mint none either.
--
-- UNDO: `docs/runbooks/262-undo.sql` (re-states 217's body).

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 2. PRECONDITION: the body this file re-states is 217's
-- ===================================================================
DO $$
DECLARE
    v_mint text;
BEGIN
    SELECT md5(p.prosrc) INTO v_mint FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.auto_create_factor_from_edge()');
    IF v_mint IS DISTINCT FROM 'b98f7326df4cc26924091dc61a8289f3' THEN
        RAISE EXCEPTION '262: auto_create_factor_from_edge is not the body 262 re-states '
                        '(217''s, md5 b98f7326df4cc26924091dc61a8289f3); found md5 %. Another '
                        'migration re-bodied it; nothing was changed', COALESCE(v_mint, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
END $$;

-- ===================================================================
-- 3. THE EDGE MINT, without `decomposes_to`
-- ===================================================================
CREATE OR REPLACE FUNCTION public.auto_create_factor_from_edge()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    ft  VARCHAR;
    fwd DOUBLE PRECISION;
    rev DOUBLE PRECISION;
    pot JSONB;
    var_ids UUID[];
    matcher_score DOUBLE PRECISION;
BEGIN
    -- 217: only the edges table's own AFTER INSERT row trigger.
    IF TG_RELID <> 'public.edges'::pg_catalog.regclass
       OR TG_OP <> 'INSERT' OR TG_LEVEL <> 'ROW' OR TG_WHEN <> 'AFTER' THEN
        RAISE EXCEPTION 'FCT01: auto_create_factor_from_edge runs only as the AFTER INSERT row trigger on public.edges'
            USING ERRCODE = '42501';
    END IF;

    IF NEW.source_type != 'claim' OR NEW.target_type != 'claim' THEN
        RETURN NEW;
    END IF;

    -- 262: a decomposition is not a BP coupling (atom-level belief SPEC
    -- §6.2, D3): a compound is a query over its atoms, so no factor is
    -- minted for a `decomposes_to` edge, in any spelling.
    IF pg_catalog.lower(NEW.relationship) = 'decomposes_to' THEN
        RETURN NEW;
    END IF;

    -- Skip edges involving superseded claims (unchanged from migration 090).
    IF EXISTS (SELECT 1 FROM public.claims WHERE id = NEW.source_id AND COALESCE(is_current, true) = false)
       OR EXISTS (SELECT 1 FROM public.claims WHERE id = NEW.target_id AND COALESCE(is_current, true) = false) THEN
        RETURN NEW;
    END IF;

    SELECT factor_type, forward_strength, reverse_strength
    INTO ft, fwd, rev
    FROM public.edge_to_factor_type(NEW.relationship);

    IF ft IS NULL THEN
        RETURN NEW;
    END IF;

    -- Matcher-derived evidential_support edges carry their own per-edge
    -- strength in properties.score. Use it (clamped to [0, 1]) instead of
    -- the constant fallback so calibration of the matcher flows through.
    IF ft = 'evidential_support'
       AND NEW.properties ? 'source'
       AND NEW.properties->>'source' = 'cross_source_matcher'
       AND NEW.properties ? 'score' THEN
        matcher_score := (NEW.properties->>'score')::double precision;
        IF matcher_score IS NOT NULL THEN
            fwd := GREATEST(0.0, LEAST(1.0, matcher_score));
            rev := fwd;
        END IF;
    END IF;

    IF ft = 'mutual_exclusion' THEN
        pot := '{}';
    ELSIF ft = 'directional_support' THEN
        pot := pg_catalog.jsonb_build_object(
            'forward_strength', fwd,
            'reverse_strength', rev,
            'source_var', NEW.source_id::text
        );
    ELSE
        pot := pg_catalog.jsonb_build_object('strength', fwd);
    END IF;

    IF NEW.source_id < NEW.target_id THEN
        var_ids := ARRAY[NEW.source_id, NEW.target_id];
    ELSE
        var_ids := ARRAY[NEW.target_id, NEW.source_id];
    END IF;

    INSERT INTO public.factors (factor_type, variable_ids, potential, description, properties)
    VALUES (
        ft,
        var_ids,
        pot,
        pg_catalog.format('Auto-generated from %s edge %s', NEW.relationship, NEW.id),
        pg_catalog.jsonb_build_object(
            'source_edge_id', NEW.id,
            'relationship', NEW.relationship,
            'edge_source_id', NEW.source_id,
            'edge_target_id', NEW.target_id
        )
    )
    ON CONFLICT DO NOTHING;

    RETURN NEW;
END;
$$;

-- ===================================================================
-- 4. EXECUTE (re-asserted; CREATE OR REPLACE keeps owner and ACL)
-- ===================================================================
REVOKE EXECUTE ON FUNCTION public.auto_create_factor_from_edge() FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.auto_create_factor_from_edge() FROM epigraph_app';
    END IF;
END $$;
