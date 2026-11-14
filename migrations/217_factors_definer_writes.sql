-- 217: belief-propagation factors are written by the database's own triggers,
-- never by an application statement (backlog a2c5f714).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- 077 granted `epigraph_app` SELECT/INSERT/UPDATE/DELETE on every table, and
-- `factors` has no row security, so any application session could INSERT a
-- factor naming any two claims (another writer's edge and its endpoints
-- included), UPDATE an existing factor's `variable_ids` / `potential`, or
-- DELETE it. Factors feed belief propagation, so each of those moves belief
-- on claims the session does not own. The only barrier was Rust-side
-- (`require_privileged_session` in the superseded-edge factor regeneration).
-- 118 left `factors` on the app-role table ratchet's allowlist because its
-- writers were invoker triggers running as the application role.
--
-- ===================================================================
-- 1. THE WRITERS, ENUMERATED (measured on this tree)
-- ===================================================================
--
--   edges_auto_factor (AFTER INSERT ON edges)   INSERT  application role,
--       `auto_create_factor_from_edge()`                 invoker until here
--   claims_deactivate_factors (AFTER UPDATE OF  DELETE  application role,
--       is_current ON claims),                           invoker until here
--       `deactivate_superseded_factors()`
--   API hypothesis promote (routes/hypothesis)  UPDATE  application role,
--       `UPDATE factors SET frame_id ..`        frame_id the request transaction
--   supersede / dedup cascades over             INSERT  privileged (maintenance)
--       REGENERATE_EDGE_FACTORS_SQL, the        DELETE  connection only
--       un-mark's stale-factor DELETE, the
--       factorless-edge mint (`r131_factor_mint`)
--       and its undo, the match-
--       candidate retirement, the hypothesis
--       CLI, the frame-delete operator
--   `FactorRepository::insert`                  INSERT  no caller outside tests
--
-- `backfill_factors` writes mass functions and edge rows, not `factors`.
--
-- ===================================================================
-- 2. WHAT THIS FILE DOES
-- ===================================================================
--
--   1. Re-states both trigger functions as SECURITY DEFINER on 172's form
--      (`search_path = pg_catalog, pg_temp`, every public object qualified),
--      owned by `epigraph_maintenance`. The mint body is 038's, unchanged in
--      meaning (mapping, matcher-score override, potentials, description,
--      properties, the superseded-endpoint skip, ON CONFLICT DO NOTHING), so
--      REGENERATE_EDGE_FACTORS_SQL still restates it. The deactivate body is
--      001's. A factor is still minted exactly when the session's edge INSERT
--      passes the edges policies: the authority is the edge write.
--   2. Each body refuses to run on any table but its own (`TG_RELID`), and
--      EXECUTE on both is revoked from PUBLIC and from the application role.
--      CREATE TRIGGER checks EXECUTE on the function, and firing does not, so
--      the real triggers keep working while no session can attach either
--      definer to a temporary table of its own and mint, as the maintenance
--      role, a factor over any pair it names.
--   3. `epigraph_app` loses INSERT, UPDATE, DELETE and TRUNCATE on
--      `public.factors`, and gets UPDATE back on `frame_id` alone, for the
--      hypothesis promote route. The REVOKE comes first: a table-level REVOKE
--      also revokes that privilege's column grants.
--   4. Refuses (`FCT02`, nothing applied) when the database carries any
--      other trigger that writes `factors` as a role step 3 leaves without
--      that write (§7): one attached outside these migrations, which §1
--      cannot enumerate.
--
-- As the definers' owner the mint now reads `claims` through
-- `epigraph_definer_bypass()`. That is not observable from an application
-- session: 001's invoker `validate_edge_reference` already refuses an edge to
-- an endpoint the session cannot see, so every endpoint the mint reads is one
-- the session could read too (measured: such an INSERT fails "Edge target
-- references nonexistent claim").
--
-- NOT CHANGED HERE: the application role can still move any factor between
-- frames (`frame_id`), and `bp_messages` stays application-writable (118's
-- derived-BP allowlist entry); a session can still mint a factor through an
-- edge it is allowed to write between claims it does not own, which is edge
-- write authority, not factor authority.
--
-- UNDO: `docs/runbooks/217-undo.sql`.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 3. THE EDGE MINT
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
-- 4. THE RETIREMENT CLEAR
-- ===================================================================
CREATE OR REPLACE FUNCTION public.deactivate_superseded_factors()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- 217: only the claims table's own AFTER UPDATE row trigger.
    IF TG_RELID <> 'public.claims'::pg_catalog.regclass
       OR TG_OP <> 'UPDATE' OR TG_LEVEL <> 'ROW' OR TG_WHEN <> 'AFTER' THEN
        RAISE EXCEPTION 'FCT01: deactivate_superseded_factors runs only as the AFTER UPDATE row trigger on public.claims'
            USING ERRCODE = '42501';
    END IF;

    IF NEW.is_current = false AND COALESCE(OLD.is_current, true) = true THEN
        DELETE FROM public.factors WHERE NEW.id = ANY(variable_ids);
    END IF;
    RETURN NEW;
END;
$$;

-- ===================================================================
-- 5. EXECUTE AND OWNERSHIP
-- ===================================================================
REVOKE EXECUTE ON FUNCTION public.auto_create_factor_from_edge() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.deactivate_superseded_factors() FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.auto_create_factor_from_edge() FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.deactivate_superseded_factors() FROM epigraph_app';
    END IF;
END $$;

-- Under a non-member owner the mint's INSERT is refused (every edge insert
-- fails 42501, closed and loud) and its `claims` read is RLS-filtered;
-- `epigraph-tenancy-backfill verify` checks the owner (DEFERRED_DEFINER_FUNCTIONS).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        ALTER FUNCTION public.auto_create_factor_from_edge() OWNER TO epigraph_maintenance;
        ALTER FUNCTION public.deactivate_superseded_factors() OWNER TO epigraph_maintenance;
    END IF;
END $$;

-- ===================================================================
-- 6. THE TABLE GRANTS
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.factors FROM epigraph_app';
        EXECUTE 'GRANT UPDATE (frame_id) ON public.factors TO epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- 7. NO OTHER TRIGGER WRITES `factors` ON A ROLE THAT CAN NO LONGER
-- ===================================================================
-- §1's enumeration is of this tree. A database can also carry a trigger
-- attached outside these migrations (a legacy hand-applied schema put an
-- invoker `INSERT INTO factors` trigger on `public.edges`). After §6 such a
-- trigger fails 42501 inside the application statement that fires it, so the
-- edge or claim write itself aborts. Refuse here instead, loudly and with
-- nothing applied: every non-internal trigger, on any table, other than the
-- two above, whose function's definition writes `factors` and that runs as a
-- role without INSERT, UPDATE and DELETE on it (an invoker, or a definer
-- whose owner lacks them). Reads of `factors` are not flagged. The check runs
-- after §6 so the privileges it reads are this migration's own.
DO $$
DECLARE
    offenders text;
BEGIN
    SELECT pg_catalog.string_agg(
               pg_catalog.format('%s on %s (%s)', t.tgname, t.tgrelid::pg_catalog.regclass,
                                 t.tgfoid::pg_catalog.regprocedure),
               '; ' ORDER BY t.tgname, t.tgrelid)
      INTO offenders
      FROM pg_catalog.pg_trigger t
      JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
     WHERE NOT t.tgisinternal
       AND t.tgfoid NOT IN ('public.auto_create_factor_from_edge()'::pg_catalog.regprocedure,
                            'public.deactivate_superseded_factors()'::pg_catalog.regprocedure)
       -- The CASE keeps pg_get_functiondef off aggregates (it raises on
       -- them, and the planner may test this before the join): a trigger
       -- function is always prokind 'f'.
       AND (CASE WHEN p.prokind = 'f' THEN pg_catalog.pg_get_functiondef(p.oid) END) ~*
           '\m(insert\s+into|update|delete\s+from|truncate(\s+table)?)\s+(only\s+)?("?public"?\s*\.\s*)?"?factors\M'
       AND (NOT p.prosecdef
            OR NOT (pg_catalog.has_table_privilege(p.proowner, 'public.factors', 'INSERT')
                    AND pg_catalog.has_table_privilege(p.proowner, 'public.factors', 'UPDATE')
                    AND pg_catalog.has_table_privilege(p.proowner, 'public.factors', 'DELETE')));
    IF offenders IS NOT NULL THEN
        RAISE EXCEPTION 'FCT02: trigger(s) outside this migration write public.factors as a role that loses that write here: %', offenders
            USING ERRCODE = '55000',
                  HINT = 'Drop each trigger, or make its function a SECURITY DEFINER owned by epigraph_maintenance, then re-run this migration.';
    END IF;
END $$;
