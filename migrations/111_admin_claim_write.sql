-- 111: the audited admin path for `claims:admin` cross-group claim writes
-- (batch H-b, D2; operator decision 2026-09-25).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- A `claims:admin` caller may relabel or patch a claim owned by a group it is
-- not a writer of (retiring another agent's backlog item is the common case).
-- Migration 077's `claims_tenancy` WITH CHECK admits an UPDATE only when the
-- ROW's `owner_group_id` is in the session's writable set, so on a clean schema
-- that write is refused whatever the token says. Two earlier answers were both
-- wrong, and this file replaces them:
--
--   * An HTTP revision stamped the transaction with the claim AUTHOR's viewer,
--     "borrowing" the author's write authority. Measured by the batch H-a
--     review on config A: an admin that is only a READER of a team group
--     relabelled that group's private claims, and the database recorded the
--     AUTHOR as the principal of an act the admin performed.
--   * #505 then made `PATCH /api/v1/claims/:id/labels` caller-only, so the
--     admin write is simply refused on a clean schema (and admitted on
--     production's schema only by the orphan `claims_privacy` policy, which R3
--     drops). That is the interim state this file ends.
--
-- The decision: a `claims:admin` write into a group the admin cannot write
-- goes through ONE explicit, audited path that records the ADMIN as the
-- principal. Never the author's stamp.
--
-- ===================================================================
-- 1. THE FUNCTION
-- ===================================================================
--
-- `epigraph_admin_patch_claim(client, jti, claim, action, add, remove, props,
-- trace)` applies a label add/remove, a shallow properties merge and a trace
-- relink to ONE claim, with exactly the semantics of
-- `ClaimRepository::update_labels_conn` (union then remove, DISTINCT, sorted)
-- and `patch_claim_atomic_conn` (`properties || $props`, trace replaced when
-- given). In ONE statement sequence it:
--
--   (a) RE-CHECKS THE ADMIN GRANT SERVER-SIDE. The caller (the MCP or API
--       server) has already checked `claims:admin` on the validated token; the
--       function re-checks it against the RECORD the token was minted from:
--       `oauth_clients` row `p_client_id` (the token's `sub`) must be
--       `status = 'active'`, carry `claims:admin` in `granted_scopes` (what
--       `oauth/token.rs` mints scopes from), and be bound to the session
--       principal (`agent_id = epigraph_principal_id()`). So a client that was
--       suspended, or had `claims:admin` withdrawn, after its token was minted
--       loses this path immediately, and a token that is not an admin
--       principal's cannot be presented for one.
--   (b) THE PRINCIPAL IS THE ADMIN. The admin is read from the session's
--       `epigraph.principal_id` (the caller stamps its transaction from the
--       ADMIN's own viewer), never taken as a parameter, and a NULL principal
--       is refused. The claim's author is recorded as the TARGET, never as the
--       actor.
--   (c) WRITES THE AUDIT EVENT. One `security_events` row
--       (`event_type = 'claims.admin_write'`, `agent_id` = the admin, append-
--       only and immutable since 082) naming the admin, the token (`client_id`,
--       `jti`), the action, the target claim, its author and owning group, and
--       the labels / properties / trace before and after. The write and its
--       audit row commit together or not at all.
--
-- It works whatever the orphan `*_privacy` policies say, which is the point:
-- `claims` is FORCEd (079), and the body writes it under
-- `epigraph_definer_bypass()`, i.e. because its OWNER is a member of
-- `epigraph_maintenance` — not because any permissive policy admits it. It is
-- therefore unchanged by R3.
--
-- ===================================================================
-- 2. WHAT IT DELIBERATELY DOES NOT DO
-- ===================================================================
--
--   * It does not decide WHEN the admin path applies. The servers route here
--     only when the ownership gate admitted the caller through its
--     `claims:admin` arm AND the claim's owning group is not in the caller's
--     own writable set; every other write stays on the caller's own stamp.
--   * It does not supersede. Supersession inserts a replacement row, re-points
--     edges and writes a version row; carrying all of that into a definer is a
--     separate decision, so a `claims:admin` supersede into a group the admin
--     cannot write stays refused (on a clean schema) with nothing written.
--   * It validates no label text. `reject_unexpanded_labels` runs in the
--     caller, before this is reached, exactly as it does for the ordinary path.
--
-- ===================================================================
-- 3. OWNERSHIP AND GRANTS
-- ===================================================================
--
-- Same template as 107 section 6: OWNER TO epigraph_maintenance (so
-- `epigraph_definer_bypass()` is true inside the frame), REVOKE from PUBLIC,
-- EXECUTE granted to `epigraph_app` (the servers call it) and to
-- `epigraph_maintenance`. Guarded, because the roles exist in a deployed
-- cluster and not in every throwaway; pinned in CI by
-- `schema_contract.rs::migration_111_admin_write_definer_is_owned_and_granted`
-- and at deploy by `tenancy_backfill.rs::DEFERRED_DEFINER_FUNCTIONS`. A wrong,
-- non-bypassing OWNER fails CLOSED: the UPDATE is then RLS-filtered to zero rows
-- and the function raises ADM04 (not found), writing nothing. (A superuser
-- owner — what the guarded `OWNER TO` leaves behind when the role is absent and
-- the migrator is a superuser — bypasses RLS and works; the catalog pins are
-- what catch it.)

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_admin_patch_claim(
    p_client_id     uuid,
    p_token_jti     uuid,
    p_claim_id      uuid,
    p_action        text,
    p_add_labels    text[],
    p_remove_labels text[],
    p_properties    jsonb,
    p_trace_id      uuid)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_admin        uuid := public.epigraph_principal_id();
    v_author       uuid;
    v_owner_group  uuid;
    v_before_labels text[];
    v_before_props  jsonb;
    v_before_trace  uuid;
    v_after_labels  text[];
    v_after_props   jsonb;
    v_after_trace   uuid;
BEGIN
    IF v_admin IS NULL THEN
        RAISE EXCEPTION 'ADM01: the admin claim write needs the session principal '
            '(epigraph.principal_id) set to the admin; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF p_action IS NULL
       OR p_action NOT IN ('update_labels', 'patch_claim', 'resolve_backlog_item') THEN
        RAISE EXCEPTION 'ADM03: unknown admin claim action %', p_action
            USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.oauth_clients c
         WHERE c.id = p_client_id
           AND c.agent_id = v_admin
           AND c.status = 'active'
           AND 'claims:admin' = ANY (c.granted_scopes)) THEN
        RAISE EXCEPTION 'ADM02: principal % holds no active claims:admin grant through '
            'client %; nothing was written', v_admin, p_client_id
            USING ERRCODE = '42501';
    END IF;

    SELECT c.agent_id, c.owner_group_id, COALESCE(c.labels, ARRAY[]::text[]),
           COALESCE(c.properties, '{}'::jsonb), c.trace_id
      INTO v_author, v_owner_group, v_before_labels, v_before_props, v_before_trace
      FROM public.claims c
     WHERE c.id = p_claim_id
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ADM04: claim % not found; nothing was written', p_claim_id
            USING ERRCODE = 'P0002';
    END IF;

    UPDATE public.claims c
       SET labels = (
               SELECT COALESCE(array_agg(DISTINCT l ORDER BY l), ARRAY[]::text[])
                 FROM (SELECT unnest(v_before_labels)
                       UNION
                       SELECT unnest(COALESCE(p_add_labels, ARRAY[]::text[]))) AS u(l)
                WHERE l <> ALL (COALESCE(p_remove_labels, ARRAY[]::text[]))),
           properties = CASE WHEN p_properties IS NULL THEN c.properties
                             ELSE COALESCE(c.properties, '{}'::jsonb) || p_properties END,
           trace_id = COALESCE(p_trace_id, c.trace_id),
           updated_at = now()
     WHERE c.id = p_claim_id
    RETURNING COALESCE(c.labels, ARRAY[]::text[]), COALESCE(c.properties, '{}'::jsonb),
              c.trace_id
      INTO v_after_labels, v_after_props, v_after_trace;

    INSERT INTO public.security_events (event_type, agent_id, success, details, correlation_id)
    VALUES (
        'claims.admin_write',
        v_admin,
        true,
        jsonb_build_object(
            'action',         p_action,
            'admin_agent_id', v_admin,
            'client_id',      p_client_id,
            'token_jti',      p_token_jti,
            'claim_id',       p_claim_id,
            'claim_author',   v_author,
            'owner_group_id', v_owner_group,
            'before', jsonb_build_object(
                'labels', to_jsonb(v_before_labels),
                'properties', v_before_props,
                'trace_id', v_before_trace),
            'after', jsonb_build_object(
                'labels', to_jsonb(v_after_labels),
                'properties', v_after_props,
                'trace_id', v_after_trace)),
        left(p_token_jti::text, 64));

    RETURN jsonb_build_object(
        'labels',        to_jsonb(v_after_labels),
        'properties',    v_after_props,
        'trace_id',      v_after_trace,
        'before_labels', to_jsonb(v_before_labels),
        'before_properties', v_before_props,
        'before_trace_id',   v_before_trace);
END
$$;

REVOKE EXECUTE ON FUNCTION public.epigraph_admin_patch_claim(
    uuid, uuid, uuid, text, text[], text[], jsonb, uuid) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_admin_patch_claim('
                'uuid, uuid, uuid, text, text[], text[], jsonb, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_admin_patch_claim('
                'uuid, uuid, uuid, text, text[], text[], jsonb, uuid) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_admin_patch_claim('
                'uuid, uuid, uuid, text, text[], text[], jsonb, uuid) '
                'TO epigraph_app';
    END IF;
END $$;
