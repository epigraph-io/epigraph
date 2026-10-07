-- Migration 128: the ADMIN-SCOPE ARMING SWITCH, shipped UNARMED (elevation
-- plan EL-9, DESIGN 6.5).
--
-- ===================================================================
-- 1. THE MODEL
--
-- The admin-only scopes (`claims:admin`, `clients:admin`,
-- `entity-types:write`, `groups:admin`, `instance:admin`:
-- `epigraph_core::canonical_scopes::ADMIN_ONLY_SCOPES`) are STANDING
-- authority today: a client whose `granted_scopes` hold one mints it on
-- every token. DESIGN 6.5 replaces that with elevation: strip them at every
-- mint, treat them as absent at every check, and let a live elevation
-- session stand in. Doing that at deploy would break every consumer that
-- still relies on a standing admin scope, so the rule ships behind a switch
-- this file installs OFF:
--
--   * `admin_scope_enforcement`: ONE row (the migration seeds it, unarmed).
--     `armed`, and who changed it, when and why.
--   * `epigraph_admin_scopes_armed()`: the switch, read by the token
--     endpoint's mint chokepoint (`oauth::scopes::grantable`), by the
--     registration and client-approval routes and by the operator CLI.
--     Later batches read it too (the check chokepoint, the standing read
--     arms).
--   * `epigraph_set_admin_scope_enforcement(armed, reason)`: arm or disarm,
--     maintenance only, with a reason. `epigraph-operator arm-admin-scopes` /
--     `disarm-admin-scopes` call it.
--   * `epigraph_record_admin_scope_would_strip(client, grant, scopes)`: the
--     MEASUREMENT that decides when arming is safe. While unarmed, a mint that
--     carries an admin-only scope keeps it and records one
--     `oauth.admin_scope_would_strip` event naming the client, the grant and
--     the scopes an armed database would have stripped, at most one per
--     client per hour. Arming waits for those events to read zero over a
--     soak window (the operator's runbook).
--
-- ARMED, a mint strips every admin-only scope (the elevate grant keeps only
-- read scopes plus `platform:admin` either way), and registration, client
-- approval and `epigraph-operator grant-client-scope` refuse to hand one out.
-- UNARMED, every one of them behaves exactly as before, and the mint records
-- the would-strip measurement.
--
-- ===================================================================
-- 2. WHO MAY CHANGE IT, AND WHAT IS RECORDED
--
-- Unlike 122's operator-binding arming, this switch goes BOTH ways: disarming
-- is the rollback for a consumer arming broke. Both directions are audited,
-- whatever path made them:
--
--   * The application role holds SELECT on the row and nothing else (077's
--     default privileges are taken back below), and may not EXECUTE the
--     setter. The application cannot arm or disarm.
--   * The maintenance role holds SELECT and UPDATE of `armed` and `reason`
--     only. A BEFORE UPDATE guard (ADS01) refuses an update that does not
--     change `armed`, or carries an empty reason, and stamps `changed_at` /
--     `changed_by` itself (`now()`, `session_user`), so a direct maintenance
--     UPDATE cannot forge either. It refuses INSERT and DELETE for EVERY
--     login, a superuser included: the row is seeded once, here, and never
--     goes away.
--   * An AFTER UPDATE trigger writes one `platform.admin_scopes_armed` or
--     `platform.admin_scopes_disarmed` event (123's reserved `platform.`
--     prefix: the application cannot forge one) for every change, the
--     setter's and a direct statement's alike.
--
-- THE WOULD-STRIP EVENT IS A DEFINER'S. `oauth.` is a privileged event prefix
-- (118, `security_events_oauth_privileged`), so the application cannot write
-- `oauth.admin_scope_would_strip` itself; the token endpoint calls the
-- recorder, which:
--   * records nothing once armed (nothing is kept to measure);
--   * names one of the fixed grant labels, and only scopes the client holds
--     in `granted_scopes` (22023 otherwise), so an application session can
--     add no event about a client or scope that is not real;
--   * records at most one event per client per hour (an advisory lock per
--     client serialises concurrent mints), which bounds both the noise and
--     any deliberate flooding.
--
-- WHAT THE SWITCH CANNOT PROVE. It is a row the maintenance DSN may change;
-- the audit says who (the database login) and when, not which person. An
-- application-DSN holder can read it, which discloses nothing secret.
--
-- ===================================================================
-- 3. DEPLOY AND UNDO
--
-- Inert until armed: applying this file changes no mint, no route and no
-- CLI verb's outcome (the binaries that read the switch find it unarmed).
-- Binaries built before it never read it. A binary built with it treats a
-- database WITHOUT this file as unarmed (the switch cannot have been
-- armed there), so the deploy order is free. Arming is a separate
-- operator step (docs/deploy.md, "The admin-scope arming switch").
-- Undo: docs/runbooks/128-undo.sql (records a disarm first if armed).
-- **Applied to a throwaway database only, NOT to any deployed database.**

SET LOCAL lock_timeout = '3s';

-- The switch (section 1). One row, seeded below and never deleted. No
-- `visibility` / `owner_group_id`: it is control state, not a tenant row, so
-- (as 122's arming record) its protection is the grant set and the guard,
-- not row security.
CREATE TABLE IF NOT EXISTS public.admin_scope_enforcement (
    singleton  boolean PRIMARY KEY DEFAULT true
        CONSTRAINT admin_scope_enforcement_singleton CHECK (singleton),
    armed      boolean NOT NULL DEFAULT false,
    changed_at timestamptz NOT NULL DEFAULT now(),
    changed_by text NOT NULL DEFAULT session_user,
    reason     text NOT NULL
        CONSTRAINT admin_scope_enforcement_reason CHECK (btrim(reason) <> '')
);
REVOKE ALL ON public.admin_scope_enforcement FROM PUBLIC;

-- The seed: UNARMED. `WHERE NOT EXISTS` (not ON CONFLICT) so that a re-run
-- inserts no row at all and so never meets the INSERT refusal below.
INSERT INTO public.admin_scope_enforcement (singleton, armed, reason)
SELECT true, false, 'migration 128: shipped unarmed'
 WHERE NOT EXISTS (SELECT 1 FROM public.admin_scope_enforcement);

-- The guard (section 2): no INSERT, no DELETE, for anyone; an UPDATE must
-- change `armed` and carry a reason, and its stamp is the guard's.
CREATE OR REPLACE FUNCTION public.epigraph_admin_scope_enforcement_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        RAISE EXCEPTION 'ADS01: admin_scope_enforcement holds one row, seeded by migration 128; '
            'arm or disarm it with epigraph_set_admin_scope_enforcement(armed, reason)'
            USING ERRCODE = '42501';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'ADS01: the admin-scope switch row is never deleted; disarm it with '
            'epigraph_set_admin_scope_enforcement(false, reason)'
            USING ERRCODE = '42501';
    END IF;
    IF NEW.armed IS NOT DISTINCT FROM OLD.armed THEN
        RAISE EXCEPTION 'ADS01: an update of admin_scope_enforcement must arm or disarm it '
            '(armed is already %)', OLD.armed
            USING ERRCODE = '42501';
    END IF;
    IF NEW.reason IS NULL OR btrim(NEW.reason) = '' THEN
        RAISE EXCEPTION 'ADS01: arming or disarming admin scopes needs a reason'
            USING ERRCODE = '22023';
    END IF;
    NEW.singleton  := true;
    NEW.changed_at := now();
    NEW.changed_by := session_user;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_admin_scope_enforcement_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS admin_scope_enforcement_guard ON public.admin_scope_enforcement;
CREATE TRIGGER admin_scope_enforcement_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.admin_scope_enforcement
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_admin_scope_enforcement_guard();

-- The audit (section 2): one `platform.` event per change, whatever path.
CREATE OR REPLACE FUNCTION public.epigraph_admin_scope_enforcement_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES (CASE WHEN NEW.armed THEN 'platform.admin_scopes_armed'
                 ELSE 'platform.admin_scopes_disarmed' END,
            NULL, true,
            jsonb_build_object('armed', NEW.armed, 'was_armed', OLD.armed,
                               'reason', NEW.reason, 'recorded_by', session_user,
                               'changed_at', NEW.changed_at));
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_admin_scope_enforcement_audit() FROM PUBLIC;

DROP TRIGGER IF EXISTS admin_scope_enforcement_audit ON public.admin_scope_enforcement;
CREATE TRIGGER admin_scope_enforcement_audit
    AFTER UPDATE ON public.admin_scope_enforcement
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_admin_scope_enforcement_audit();

-- Is the database ARMED? False while the row says so, and false with no row
-- at all (only a superuser that disabled the guard could remove it).
CREATE OR REPLACE FUNCTION public.epigraph_admin_scopes_armed()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT COALESCE((SELECT e.armed FROM public.admin_scope_enforcement e), false)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_admin_scopes_armed() FROM PUBLIC;

-- Arm (`true`) or disarm (`false`), with a reason. Maintenance only (EXECUTE
-- is granted to no other role, and the body re-checks the session login).
-- Asking for the state the switch is already in changes nothing and records
-- nothing (`changed` = false).
CREATE OR REPLACE FUNCTION public.epigraph_set_admin_scope_enforcement(
    p_armed boolean, p_reason text)
RETURNS TABLE (changed boolean, armed boolean, changed_at timestamptz, changed_by text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_was boolean;
BEGIN
    IF NOT public.epigraph_bypass() THEN
        RAISE EXCEPTION 'ADS02: only a maintenance session may arm or disarm admin scopes'
            USING ERRCODE = '42501';
    END IF;
    IF p_armed IS NULL THEN
        RAISE EXCEPTION 'ADS02: armed must be true or false' USING ERRCODE = '22023';
    END IF;
    IF p_reason IS NULL OR btrim(p_reason) = '' THEN
        RAISE EXCEPTION 'ADS02: arming or disarming admin scopes needs a reason'
            USING ERRCODE = '22023';
    END IF;
    SELECT e.armed INTO STRICT v_was FROM public.admin_scope_enforcement e FOR UPDATE;
    IF v_was IS DISTINCT FROM p_armed THEN
        UPDATE public.admin_scope_enforcement e
           SET armed = p_armed, reason = p_reason
         WHERE e.singleton;
    END IF;
    RETURN QUERY
    SELECT v_was IS DISTINCT FROM p_armed, e.armed, e.changed_at, e.changed_by
      FROM public.admin_scope_enforcement e;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_set_admin_scope_enforcement(boolean, text)
    FROM PUBLIC;

-- The measurement (section 2). Returns whether an event was written.
CREATE OR REPLACE FUNCTION public.epigraph_record_admin_scope_would_strip(
    p_client uuid, p_grant text, p_scopes text[])
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_client_id text;
    v_agent     uuid;
    v_granted   text[];
BEGIN
    IF public.epigraph_admin_scopes_armed() THEN
        RETURN false;
    END IF;
    IF p_grant IS NULL OR p_grant NOT IN ('authorization_code', 'refresh_token',
                                          'client_credentials', 'external_assertion',
                                          'device') THEN
        RAISE EXCEPTION 'ADS03: % is not a grant the token endpoint mints with', p_grant
            USING ERRCODE = '22023';
    END IF;
    IF p_scopes IS NULL OR cardinality(p_scopes) = 0 THEN
        RAISE EXCEPTION 'ADS03: a would-strip record names at least one scope'
            USING ERRCODE = '22023';
    END IF;
    SELECT c.client_id, c.agent_id, c.granted_scopes
      INTO v_client_id, v_agent, v_granted
      FROM public.oauth_clients c
     WHERE c.id = p_client;
    IF NOT FOUND OR NOT (p_scopes <@ COALESCE(v_granted, '{}'::text[])) THEN
        RAISE EXCEPTION 'ADS03: client % does not hold every scope named', p_client
            USING ERRCODE = '22023';
    END IF;
    -- One event per client per hour; concurrent mints of one client queue here.
    PERFORM pg_advisory_xact_lock(hashtextextended('epigraph.admin_scope_would_strip:'
                                                   || p_client::text, 0));
    IF EXISTS (SELECT 1 FROM public.security_events s
                WHERE s.event_type = 'oauth.admin_scope_would_strip'
                  AND s.created_at > now() - interval '1 hour'
                  AND s.details ->> 'client' = p_client::text) THEN
        RETURN false;
    END IF;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('oauth.admin_scope_would_strip', v_agent, true,
            jsonb_build_object('client', p_client, 'client_id', v_client_id,
                               'grant', p_grant,
                               'scopes', to_jsonb(ARRAY(SELECT DISTINCT unnest(p_scopes)
                                                         ORDER BY 1)),
                               'window', '1 hour'));
    RETURN true;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_record_admin_scope_would_strip(uuid, text, text[])
    FROM PUBLIC;

-- ===================================================================
-- OWNERSHIP AND GRANTS (guarded, as every such block since 060 is)
--
-- Every function is owned by the maintenance role, so the triggers' and the
-- recorder's frames pass `epigraph_definer_bypass()` (the `platform.` and
-- `oauth.` event prefixes, `security_events`' read policy). 077's default
-- privileges handed the application role DML on the new table: taken back,
-- leaving SELECT. The maintenance role holds SELECT and UPDATE of the two
-- columns a change names; the guard stamps the rest.
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_admin_scope_enforcement_guard() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_admin_scope_enforcement_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_admin_scopes_armed() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_set_admin_scope_enforcement(boolean, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_record_admin_scope_would_strip(uuid, text, '
                'text[]) OWNER TO epigraph_maintenance';
        EXECUTE 'REVOKE ALL ON public.admin_scope_enforcement FROM epigraph_maintenance';
        EXECUTE 'GRANT SELECT ON public.admin_scope_enforcement TO epigraph_maintenance';
        EXECUTE 'GRANT UPDATE (armed, reason) ON public.admin_scope_enforcement '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_admin_scopes_armed(), '
                'public.epigraph_set_admin_scope_enforcement(boolean, text), '
                'public.epigraph_record_admin_scope_would_strip(uuid, text, text[]) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.admin_scope_enforcement FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.admin_scope_enforcement TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_set_admin_scope_enforcement(boolean, text) FROM epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_admin_scopes_armed(), '
                'public.epigraph_record_admin_scope_would_strip(uuid, text, text[]) '
                'TO epigraph_app';
    END IF;
END $$;
