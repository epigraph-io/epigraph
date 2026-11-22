-- ===================================================================
-- 262-undo.sql: take migration 262 back out, in ONE transaction, on the
-- migration (superuser) DSN.
--
-- WHAT IT DOES: re-states 217's `auto_create_factor_from_edge` body verbatim
-- (CREATE OR REPLACE keeps owner and grants), so a new `decomposes_to` edge
-- mints its `directional_support` factor again.
--
-- WHAT IT LEAVES:
--   * every `decomposes_to` edge inserted while 262 was applied stays without
--     a factor (the trigger fires on INSERT only). BP filters such factors
--     out anyway (`bp_readable_factor_sql`), so nothing BP reads changes.
--   * the factors `decomposes_to_factor_sweep --apply` deleted. Those come
--     back only from the sweep's manifest:
--       decomposes_to_factor_sweep --restore <manifest.jsonl>          (dry run)
--       decomposes_to_factor_sweep --restore <manifest.jsonl> --apply
--   * 262's `_sqlx_migrations` row. Re-introducing the skip is a NEW
--     migration, never a re-run of 262.
--
-- The precondition refuses unless the live body is 262's (md5 of `prosrc`).
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_mint text;
BEGIN
    SELECT md5(p.prosrc) INTO v_mint FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.auto_create_factor_from_edge()');
    IF v_mint IS DISTINCT FROM '3420cbc025d6c3fd827006ea4da4094c' THEN
        RAISE EXCEPTION '262-undo: auto_create_factor_from_edge is not 262''s body (md5 %); nothing was changed',
                        COALESCE(v_mint, '(absent)')
            USING ERRCODE = '55000';
    END IF;
END $$;

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

REVOKE EXECUTE ON FUNCTION public.auto_create_factor_from_edge() FROM PUBLIC;

COMMIT;
