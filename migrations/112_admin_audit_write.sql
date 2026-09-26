-- 112: the audit row for an admin write that needs no definer of its own
-- (batch H-b review; the workflow admin arm of H3).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- A cross-owner workflow mutation (`add_step`, `delete_step`, a new generation
-- of another agent's lineage) admitted through the `claims:admin` arm writes
-- its rows on the `workflow-ingest-system` stamp, which can already write them:
-- nothing needs to cross a group boundary, so 111's claim definer does not
-- apply. What D2 still requires is (a) the grant re-checked against the token's
-- client record, never the scope alone, and (b) an audit event naming the
-- admin, the token, the target and what was written, committed with the write.
--
-- (b) cannot be an ordinary INSERT on that transaction. `security_events_append`
-- (077 section 11) admits an attributed row only when `agent_id` is the SESSION
-- principal, and the session principal there is the system agent, not the
-- admin. MEASURED on config A through the real binary: the first revision's
-- audit INSERT was refused `new row violates row-level security policy for
-- table "security_events"`, which rolled the admin's write back with it.
-- Attributing the row to the system agent, or to no one, would record the
-- wrong principal for the one act this audit exists to attribute.
--
-- ===================================================================
-- 1. THE FUNCTION
-- ===================================================================
--
-- `epigraph_admin_audit_write(client, jti, admin, event_type, details)`:
--
--   (a) RE-CHECKS THE GRANT with 111's exact predicate: `oauth_clients` row
--       `p_client_id` (the token's `sub`) is `status = 'active'`, carries
--       `claims:admin` in `granted_scopes`, and is bound to `p_admin`
--       (`agent_id = p_admin`). Refused `ADM02` otherwise, writing nothing.
--       The admin is a PARAMETER here, not `epigraph_principal_id()` as in 111,
--       because the caller's session is stamped from the system agent; the
--       client-record binding is what ties the named admin to the token.
--   (b) WRITES ONE `security_events` ROW (`agent_id` = the admin, success,
--       `details` = the caller's facts plus admin / client / jti, correlation =
--       the jti), under `epigraph_definer_bypass()`, on the caller's
--       transaction: it commits or rolls back with the write it records.
--   (c) ONLY A CLOSED SET OF EVENT TYPES: `workflows.admin_write`. A new admin
--       audit event is a new decision and a new line here (`ADM03`).
--
-- It does not decide WHEN an admin write is one (the servers do: the workflow
-- gate admitted the caller through its admin arm and not as the submitter or
-- its operator), and it writes nothing but the audit row.
--
-- ===================================================================
-- 2. OWNERSHIP AND GRANTS
-- ===================================================================
--
-- 111's template: OWNER TO epigraph_maintenance (so `epigraph_definer_bypass()`
-- is true inside the frame), REVOKE from PUBLIC, EXECUTE to `epigraph_app` and
-- `epigraph_maintenance`, guarded because the roles exist in a deployed cluster
-- and not in every throwaway. Pinned by
-- `schema_contract.rs::migration_112_admin_audit_definer_is_owned_and_granted`
-- and `tenancy_backfill.rs::DEFERRED_DEFINER_FUNCTIONS`. A wrong,
-- non-bypassing owner fails CLOSED: the INSERT is then refused by
-- `security_events_append` and the admin write rolls back with it.

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_admin_audit_write(
    p_client_id  uuid,
    p_token_jti  uuid,
    p_admin      uuid,
    p_event_type text,
    p_details    jsonb)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_admin IS NULL THEN
        RAISE EXCEPTION 'ADM01: the admin audit write needs the admin agent; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF p_event_type IS NULL OR p_event_type NOT IN ('workflows.admin_write') THEN
        RAISE EXCEPTION 'ADM03: unknown admin audit event type %', p_event_type
            USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.oauth_clients c
         WHERE c.id = p_client_id
           AND c.agent_id = p_admin
           AND c.status = 'active'
           AND 'claims:admin' = ANY (c.granted_scopes)) THEN
        RAISE EXCEPTION 'ADM02: principal % holds no active claims:admin grant through '
            'client %; nothing was written', p_admin, p_client_id
            USING ERRCODE = '42501';
    END IF;

    INSERT INTO public.security_events (event_type, agent_id, success, details, correlation_id)
    VALUES (
        p_event_type,
        p_admin,
        true,
        COALESCE(p_details, '{}'::jsonb) || jsonb_build_object(
            'admin_agent_id', p_admin,
            'client_id',      p_client_id,
            'token_jti',      p_token_jti),
        left(p_token_jti::text, 64));
END
$$;

REVOKE EXECUTE ON FUNCTION public.epigraph_admin_audit_write(uuid, uuid, uuid, text, jsonb)
    FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_admin_audit_write(uuid, uuid, uuid, text, jsonb) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_admin_audit_write('
                'uuid, uuid, uuid, text, jsonb) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_admin_audit_write('
                'uuid, uuid, uuid, text, jsonb) TO epigraph_app';
    END IF;
END $$;
