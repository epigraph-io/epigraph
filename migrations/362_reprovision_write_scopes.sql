-- 362_reprovision_write_scopes.sql
-- The audited bulk re-provision of `edges:write` and `evidence:write` to every
-- ACTIVE OAuth client that already holds `claims:write`, AND to the live
-- refresh chains of those clients, with its exact reverse (backlog c841b15f).
--
-- ===================================================================
-- 1. WHY
--
-- The MCP scope remap (backlog c2dbcf27) will require `edges:write` for the
-- edge writers and `evidence:write` for the evidence writers, where today
-- both need only `claims:write`. Many clients that write claims hold neither,
-- so the remap is gated on re-provisioning them first.
--
-- Granting on `oauth_clients` alone does not reach an agent that is already
-- connected. The refresh grant issues the PRESENTED token's stored scopes
-- narrowed to the client's `granted_scopes` (`token.rs::refresh_scopes`; the
-- rotation definer keeps the same intersection for the successor, 140/172),
-- so a chain minted before the grant keeps its old scope set for as long as
-- it keeps rotating. Each such chain must have the two scopes added to its
-- stored `refresh_tokens.scopes` too.
--
-- ===================================================================
-- 2. THE FORWARD VERB
--
-- `epigraph_reprovision_write_scopes(p_scopes text[], p_reason text,
--   p_operator jsonb)` returns one row per client it changed.
--
--   * `p_scopes` must be a non-empty, duplicate-free subset of
--     {`edges:write`, `evidence:write`}: anything else (an admin-only scope,
--     `platform:admin`, any other write scope) is refused 22023 and nothing
--     is written. The set is closed in the body, so no argument can make
--     this verb grant an admin-only scope.
--   * A client is a candidate when `status = 'active'` and its
--     `granted_scopes` holds `claims:write`. A suspended, revoked or pending
--     client is never read for update and never changed.
--   * For a candidate, each scope of `p_scopes` it lacks is APPENDED (in
--     `p_scopes` order) to `allowed_scopes` and to `granted_scopes`
--     separately; every existing element keeps its place.
--   * Each LIVE refresh token of the candidate (`revoked_at IS NULL AND
--     expires_at > now()`) whose stored scopes hold `claims:write` gets the
--     missing scopes appended the same way. A chain whose consent never
--     included `claims:write` is not widened.
--   * A candidate with nothing to add anywhere is skipped (no row, no audit):
--     a re-run after a complete run changes nothing.
--   * Each changed client gets ONE `security_events` row,
--     `oauth.write_scopes_reprovisioned` (118 reserves the `oauth.` prefix to
--     a privileged session or a maintenance-owned definer frame): the client,
--     both arrays before and after, the changed chains' family ids and token
--     count, the reason, the caller-supplied operator facts and the database
--     login (`session_user`, recorded here, not taken from the caller).
--     Per-token before/after arrays are RETURNED (for the operator's undo
--     manifest), not stored in the audit row.
--   * Rows are locked `FOR UPDATE` (clients, then each client's tokens) and
--     changed from the state the lock read.
--
-- A rotation that is in flight while the verb runs can insert a successor
-- the verb's snapshot does not see (its scopes are the old token's narrowed
-- to the grant as the rotation read it). The verb is idempotent, so the
-- runbook re-runs its dry run after an apply and expects zero clients.
--
-- ===================================================================
-- 3. THE REVERSE VERB
--
-- `epigraph_reprovision_write_scopes_reverse(p_client, p_allowed_before,
--   p_granted_before, p_allowed_after, p_granted_after, p_chains, p_reason,
--   p_operator)` undoes ONE client of a forward run from its manifest line:
--
--   * Every recorded `after` array must be its `before` array followed only by
--     `edges:write` / `evidence:write` (the forward verb's exact shape), else
--     22023 and nothing is written. So a reverse only ever REMOVES the scopes
--     the forward verb appended; a crafted manifest cannot grant or strip
--     anything else.
--   * The client's arrays are set back to `before` only while both still
--     equal the recorded `after` (compare-and-swap): `restored`. Already equal
--     to `before`: `already`. Anything else (changed since): `held`, left
--     alone, its chains included. No such client: `missing`.
--   * For a `restored` or `already` client, each recorded chain is matched
--     by FAMILY (`COALESCE(family_id, id)`), so a successor minted by a
--     rotation after the forward run is reversed too (the rotation keeps the
--     stored order, 140): every live token of the family whose scopes equal
--     the recorded `after` is set to `before`. A live token of a recorded
--     family that still holds a scope the run appended afterwards (it no
--     longer equals `after`, or its client was held) is counted `held`.
--   * One `security_events` row, `oauth.write_scopes_reprovision_reversed`,
--     per call: the client, its outcome, the token counts, the reason, the
--     operator facts and `session_user`.
--
-- ===================================================================
-- 4. WHO MAY CALL THEM
--
-- Both are SECURITY DEFINER, owned by `epigraph_maintenance`, on
-- `pg_catalog, pg_temp` with every public object qualified, EXECUTE for the
-- maintenance role only (not PUBLIC, not `epigraph_app`), and each body
-- refuses 42501 unless the SESSION is privileged (`epigraph_bypass()`, which
-- reads `session_user`, or a superuser), as 356's verbs do. The maintenance
-- role already holds UPDATE on `oauth_clients` and `refresh_tokens` and
-- INSERT on `security_events` (070/077), which the definer frame uses.
-- `epigraph-operator reprovision-write-scopes` is the reviewed caller.
--
-- ===================================================================
-- 5. TENANCY
--
-- No table is added or changed. `oauth_clients`, `refresh_tokens` and
-- `security_events` keep their columns, grants and policies.
--
-- ===================================================================
-- 6. UNDO
--
-- `docs/runbooks/362-undo.sql` drops both functions. It does NOT take back
-- scopes a run granted: run `epigraph-operator reprovision-write-scopes
-- --reverse --manifest <file> --apply` for each applied manifest FIRST.

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_reprovision_write_scopes(
    p_scopes text[], p_reason text, p_operator jsonb)
RETURNS TABLE (
    out_client uuid,
    out_client_key text,
    out_client_name text,
    out_client_type text,
    out_agent_id uuid,
    out_allowed_before text[],
    out_granted_before text[],
    out_allowed_after text[],
    out_granted_after text[],
    out_chains jsonb,
    out_audit_event_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_closed constant text[] := ARRAY['edges:write', 'evidence:write'];
    c record;
    t record;
    v_allowed text[];
    v_granted text[];
    v_scopes text[];
    v_chains jsonb;
    v_families jsonb;
    v_audit uuid;
BEGIN
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'epigraph_reprovision_write_scopes: only a maintenance session '
                        're-provisions client scopes'
            USING ERRCODE = '42501';
    END IF;
    IF p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_reprovision_write_scopes: a reason is required'
            USING ERRCODE = '22004';
    END IF;
    IF p_scopes IS NULL OR cardinality(p_scopes) = 0
       OR array_position(p_scopes, NULL) IS NOT NULL
       OR NOT (p_scopes <@ v_closed)
       OR (SELECT count(DISTINCT s) FROM unnest(p_scopes) AS u(s)) <> cardinality(p_scopes) THEN
        RAISE EXCEPTION 'epigraph_reprovision_write_scopes: the scopes must be a non-empty, '
                        'duplicate-free subset of {edges:write, evidence:write}; got %. Nothing '
                        'was written', p_scopes
            USING ERRCODE = '22023';
    END IF;

    FOR c IN
        SELECT oc.id, oc.client_id::text AS client_key, oc.client_name::text AS client_name,
               oc.client_type::text AS client_type, oc.agent_id, oc.status::text AS status,
               COALESCE(oc.allowed_scopes, ARRAY[]::text[]) AS allowed_scopes,
               COALESCE(oc.granted_scopes, ARRAY[]::text[]) AS granted_scopes
          FROM public.oauth_clients oc
         WHERE oc.status = 'active'
           AND 'claims:write' = ANY (oc.granted_scopes)
         ORDER BY oc.id
           FOR UPDATE OF oc
    LOOP
        v_allowed := c.allowed_scopes || ARRAY(
            SELECT u.s FROM unnest(p_scopes) WITH ORDINALITY AS u(s, ord)
             WHERE NOT (u.s = ANY (c.allowed_scopes)) ORDER BY u.ord);
        v_granted := c.granted_scopes || ARRAY(
            SELECT u.s FROM unnest(p_scopes) WITH ORDINALITY AS u(s, ord)
             WHERE NOT (u.s = ANY (c.granted_scopes)) ORDER BY u.ord);

        v_chains := '[]'::jsonb;
        FOR t IN
            SELECT rt.id, COALESCE(rt.family_id, rt.id) AS family, rt.scopes
              FROM public.refresh_tokens rt
             WHERE rt.client_id = c.id
               AND rt.revoked_at IS NULL
               AND rt.expires_at > now()
               AND 'claims:write' = ANY (rt.scopes)
               AND NOT (rt.scopes @> p_scopes)
             ORDER BY rt.id
               FOR UPDATE OF rt
        LOOP
            v_scopes := t.scopes || ARRAY(
                SELECT u.s FROM unnest(p_scopes) WITH ORDINALITY AS u(s, ord)
                 WHERE NOT (u.s = ANY (t.scopes)) ORDER BY u.ord);
            UPDATE public.refresh_tokens SET scopes = v_scopes WHERE id = t.id;
            v_chains := v_chains || jsonb_build_array(jsonb_build_object(
                'id', t.id, 'family', t.family,
                'before', to_jsonb(t.scopes), 'after', to_jsonb(v_scopes)));
        END LOOP;

        IF v_allowed = c.allowed_scopes AND v_granted = c.granted_scopes
           AND jsonb_array_length(v_chains) = 0 THEN
            CONTINUE;
        END IF;
        IF v_allowed <> c.allowed_scopes OR v_granted <> c.granted_scopes THEN
            UPDATE public.oauth_clients
               SET allowed_scopes = v_allowed, granted_scopes = v_granted, updated_at = now()
             WHERE id = c.id;
        END IF;

        SELECT COALESCE(jsonb_agg(DISTINCT e -> 'family'), '[]'::jsonb) INTO v_families
          FROM jsonb_array_elements(v_chains) AS e;
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('oauth.write_scopes_reprovisioned', c.agent_id, true,
                jsonb_build_object(
                    'tool', 'epigraph-operator',
                    'command', 'reprovision-write-scopes',
                    'session_user', session_user::text,
                    'operator', COALESCE(p_operator, '{}'::jsonb),
                    'reason', p_reason,
                    'scopes', to_jsonb(p_scopes),
                    'client', jsonb_build_object(
                        'id', c.id, 'client_id', c.client_key, 'client_name', c.client_name,
                        'client_type', c.client_type, 'status', c.status,
                        'agent_id', c.agent_id),
                    'before', jsonb_build_object('allowed_scopes', to_jsonb(c.allowed_scopes),
                                                 'granted_scopes', to_jsonb(c.granted_scopes)),
                    'after', jsonb_build_object('allowed_scopes', to_jsonb(v_allowed),
                                                'granted_scopes', to_jsonb(v_granted)),
                    'refresh_tokens_widened', jsonb_array_length(v_chains),
                    'refresh_families', v_families))
        RETURNING id INTO v_audit;

        out_client := c.id;
        out_client_key := c.client_key;
        out_client_name := c.client_name;
        out_client_type := c.client_type;
        out_agent_id := c.agent_id;
        out_allowed_before := c.allowed_scopes;
        out_granted_before := c.granted_scopes;
        out_allowed_after := v_allowed;
        out_granted_after := v_granted;
        out_chains := v_chains;
        out_audit_event_id := v_audit;
        RETURN NEXT;
    END LOOP;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_reprovision_write_scopes(text[], text, jsonb)
    FROM PUBLIC;
COMMENT ON FUNCTION public.epigraph_reprovision_write_scopes(text[], text, jsonb) IS
    'Migration 362: add edges:write / evidence:write to every active claims:write client '
    '(allowed_scopes, granted_scopes) and to its live claims:write refresh tokens; one '
    'oauth.write_scopes_reprovisioned audit row per changed client. Maintenance only.';

CREATE OR REPLACE FUNCTION public.epigraph_reprovision_write_scopes_reverse(
    p_client uuid, p_allowed_before text[], p_granted_before text[],
    p_allowed_after text[], p_granted_after text[], p_chains jsonb,
    p_reason text, p_operator jsonb)
RETURNS TABLE (
    out_client_state text,
    out_tokens_restored integer,
    out_tokens_held integer,
    out_audit_event_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_closed constant text[] := ARRAY['edges:write', 'evidence:write'];
    v_cur record;
    v_state text;
    v_restored integer := 0;
    v_held integer := 0;
    v_rows integer;
    v_before text[];
    v_after text[];
    e jsonb;
    v_audit uuid;
BEGIN
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'epigraph_reprovision_write_scopes_reverse: only a maintenance session '
                        'reverses a re-provision'
            USING ERRCODE = '42501';
    END IF;
    IF p_client IS NULL OR p_allowed_before IS NULL OR p_granted_before IS NULL
       OR p_allowed_after IS NULL OR p_granted_after IS NULL OR p_chains IS NULL
       OR jsonb_typeof(p_chains) <> 'array'
       OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_reprovision_write_scopes_reverse: the client, its four '
                        'arrays, the chains array and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    -- The forward verb's shape, and only it: `after` is `before` followed by
    -- closed-set scopes. A line of any other shape would make the reverse
    -- grant or strip something the forward run never touched.
    IF NOT (cardinality(p_allowed_after) >= cardinality(p_allowed_before)
            AND p_allowed_after[1:cardinality(p_allowed_before)] = p_allowed_before
            AND p_allowed_after[cardinality(p_allowed_before) + 1:cardinality(p_allowed_after)]
                <@ v_closed)
       OR NOT (cardinality(p_granted_after) >= cardinality(p_granted_before)
            AND p_granted_after[1:cardinality(p_granted_before)] = p_granted_before
            AND p_granted_after[cardinality(p_granted_before) + 1:cardinality(p_granted_after)]
                <@ v_closed) THEN
        RAISE EXCEPTION 'epigraph_reprovision_write_scopes_reverse: client %''s recorded arrays '
                        'are not a re-provision (after must be before followed only by '
                        'edges:write / evidence:write). Nothing was written', p_client
            USING ERRCODE = '22023';
    END IF;
    FOR e IN SELECT x FROM jsonb_array_elements(p_chains) AS j(x) LOOP
        IF jsonb_typeof(e -> 'family') IS DISTINCT FROM 'string'
           OR jsonb_typeof(e -> 'before') IS DISTINCT FROM 'array'
           OR jsonb_typeof(e -> 'after') IS DISTINCT FROM 'array' THEN
            RAISE EXCEPTION 'epigraph_reprovision_write_scopes_reverse: a recorded chain of '
                            'client % is malformed (%). Nothing was written', p_client, e
                USING ERRCODE = '22023';
        END IF;
        v_before := ARRAY(SELECT jsonb_array_elements_text(e -> 'before'));
        v_after := ARRAY(SELECT jsonb_array_elements_text(e -> 'after'));
        IF NOT (cardinality(v_after) >= cardinality(v_before)
                AND v_after[1:cardinality(v_before)] = v_before
                AND v_after[cardinality(v_before) + 1:cardinality(v_after)] <@ v_closed) THEN
            RAISE EXCEPTION 'epigraph_reprovision_write_scopes_reverse: a recorded chain of '
                            'client % is not a re-provision (%). Nothing was written',
                            p_client, e
                USING ERRCODE = '22023';
        END IF;
    END LOOP;

    SELECT oc.id, oc.agent_id, oc.client_id::text AS client_key,
           COALESCE(oc.allowed_scopes, ARRAY[]::text[]) AS allowed_scopes,
           COALESCE(oc.granted_scopes, ARRAY[]::text[]) AS granted_scopes
      INTO v_cur
      FROM public.oauth_clients oc WHERE oc.id = p_client FOR UPDATE OF oc;
    IF NOT FOUND THEN
        v_state := 'missing';
    ELSIF v_cur.allowed_scopes = p_allowed_after AND v_cur.granted_scopes = p_granted_after
          AND (p_allowed_after <> p_allowed_before OR p_granted_after <> p_granted_before) THEN
        UPDATE public.oauth_clients
           SET allowed_scopes = p_allowed_before, granted_scopes = p_granted_before,
               updated_at = now()
         WHERE id = p_client;
        v_state := 'restored';
    ELSIF v_cur.allowed_scopes = p_allowed_before AND v_cur.granted_scopes = p_granted_before THEN
        v_state := 'already';
    ELSE
        v_state := 'held';
    END IF;

    -- A held (or missing) client is left alone entirely, its chains
    -- included: narrowing the chains of a client someone changed since would
    -- second-guess that change. Its chains still carrying an appended scope
    -- are counted held below.
    FOR e IN SELECT x FROM jsonb_array_elements(p_chains) AS j(x)
                     WHERE v_state IN ('restored', 'already') LOOP
        v_before := ARRAY(SELECT jsonb_array_elements_text(e -> 'before'));
        v_after := ARRAY(SELECT jsonb_array_elements_text(e -> 'after'));
        UPDATE public.refresh_tokens rt
           SET scopes = v_before
         WHERE rt.client_id = p_client
           AND COALESCE(rt.family_id, rt.id) = (e ->> 'family')::uuid
           AND rt.revoked_at IS NULL AND rt.expires_at > now()
           AND rt.scopes = v_after;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        v_restored := v_restored + v_rows;
    END LOOP;
    -- Held: a live token of a recorded family that still carries a scope the
    -- run appended to that family (a restored token carries `before`, which
    -- lacks every appended scope by the shape check above).
    SELECT count(*)::integer INTO v_held
      FROM public.refresh_tokens rt
     WHERE rt.client_id = p_client
       AND rt.revoked_at IS NULL AND rt.expires_at > now()
       AND EXISTS (
           SELECT 1 FROM jsonb_array_elements(p_chains) AS j(x)
            WHERE (j.x ->> 'family')::uuid = COALESCE(rt.family_id, rt.id)
              AND rt.scopes && ARRAY(
                  SELECT jsonb_array_elements_text(j.x -> 'after')
                  EXCEPT
                  SELECT jsonb_array_elements_text(j.x -> 'before')));

    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('oauth.write_scopes_reprovision_reversed',
            CASE WHEN v_state = 'missing' THEN NULL ELSE v_cur.agent_id END, true,
            jsonb_build_object(
                'tool', 'epigraph-operator',
                'command', 'reprovision-write-scopes --reverse',
                'session_user', session_user::text,
                'operator', COALESCE(p_operator, '{}'::jsonb),
                'reason', p_reason,
                'client', jsonb_build_object('id', p_client),
                'client_state', v_state,
                'restore_to', jsonb_build_object('allowed_scopes', to_jsonb(p_allowed_before),
                                                 'granted_scopes', to_jsonb(p_granted_before)),
                'refresh_tokens_restored', v_restored,
                'refresh_tokens_held', v_held))
    RETURNING id INTO v_audit;

    out_client_state := v_state;
    out_tokens_restored := v_restored;
    out_tokens_held := v_held;
    out_audit_event_id := v_audit;
    RETURN NEXT;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_reprovision_write_scopes_reverse(
    uuid, text[], text[], text[], text[], jsonb, text, jsonb) FROM PUBLIC;
COMMENT ON FUNCTION public.epigraph_reprovision_write_scopes_reverse(
    uuid, text[], text[], text[], text[], jsonb, text, jsonb) IS
    'Migration 362: undo one client of epigraph_reprovision_write_scopes from its manifest '
    'line, compare-and-swap (arrays restored only while they still equal the recorded after; '
    'chains by family). One oauth.write_scopes_reprovision_reversed audit row. Maintenance only.';

-- ===================================================================
-- OWNERSHIP AND GRANTS, guarded as every such block since 060 is. The two
-- verbs run as the maintenance role (it already holds the DML they issue,
-- 070/077) and only the maintenance role may call them.
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_reprovision_write_scopes(text[], text, jsonb) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_reprovision_write_scopes_reverse('
                'uuid, text[], text[], text[], text[], jsonb, text, jsonb) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_reprovision_write_scopes('
                'text[], text, jsonb) TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_reprovision_write_scopes_reverse('
                'uuid, text[], text[], text[], text[], jsonb, text, jsonb) '
                'TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 362 '
                     're-provision verbs stay owned by the migrating role and only a superuser '
                     'session can call them';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_reprovision_write_scopes('
                'text[], text, jsonb) FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_reprovision_write_scopes_reverse('
                'uuid, text[], text[], text[], text[], jsonb, text, jsonb) FROM epigraph_app';
    END IF;
END $$;
