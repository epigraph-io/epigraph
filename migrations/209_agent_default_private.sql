-- 209: an agent's default can be PRIVATE, and a live human operator can set
-- the default of an agent it operates (operator ruling 2026-11-12; spec
-- docs/tenancy/claim-visibility-controls.md section 7).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- 206 resolves a write that names no visibility through D-V1's chain: the
-- agent's own default team, else its live human's default team, else the
-- agent's only writable team, else private. An operated agent (an epiclaw
-- container agent, the recorder, a stdio MCP agent) writes every team its
-- human writes (D-V3), so once the human sets a default team, or writes only
-- one team, every agent it operates writes there too, and the team's members
-- read it. The ruling: "epiclaw defaults to my private group". An agent whose
-- default is PRIVATE lands a no-visibility write in its home group (its
-- operator's personal group for an operated agent, `default_decl_for_author`
-- -> `operator_group_id`; its own personal group otherwise), whatever its
-- human's default and however many teams it may write. An explicit
-- visibility on the write still wins.
--
-- ===================================================================
-- 1. THE REPRESENTATION: agents.default_private boolean
-- ===================================================================
--
-- A NOT NULL boolean beside 062's `default_group_id`, with a CHECK that the
-- two are never both set. The three states are (false, NULL) "no default of
-- its own, inherit", (false, T) "team T", (true, NULL) "private".
--
-- Not a sentinel in `default_group_id`. The FK to `groups` rules out a
-- made-up id, and the only real group that could mean "private" is the home
-- group itself. Every reader that does not know the convention (206's
-- `resolve_visibility_choice`, an old binary during the rollout, any later
-- caller of `epigraph_default_group`) would read that home group as a STALE
-- team, because a personal group is never one of `epigraph_writable_teams`,
-- skip it and fall through to the human's default team: the leak this
-- migration exists to close. The home group also moves when the operator link
-- changes, so the sentinel could point at the wrong person's group. A
-- separate flag is ignored by an old reader in the same way, but it can
-- never be mistaken for a team. Not a `default_visibility text` column either:
-- D-V1 says a default never resolves to public, and a boolean cannot be
-- widened into 'public' by a later caller.
--
-- `epigraph_app` gets no UPDATE on the column: 118's column-level grant on
-- `agents` names display_name, labels, orcid, ror_id, properties and
-- updated_at only, so the definer below is the only way to write it, as
-- 206's is for `default_group_id`.
--
-- ===================================================================
-- 2. THE FUNCTIONS
-- ===================================================================
--
--   1. epigraph_default_private(agent)                READ  the agent's own flag
--   2. epigraph_set_agent_default_group(agent, group, private)
--                                                     WRITE the agent's default:
--                                                           by itself, or by its
--                                                           live human operator
--   3. epigraph_set_default_group(group)              206's write, re-stated to
--                                                     delegate to (2) for the
--                                                     principal itself
--
-- Each is SECURITY DEFINER on 172's path (`pg_catalog, pg_temp`, every public
-- name qualified), EXECUTE revoked from PUBLIC and granted to `epigraph_app`,
-- owned by `epigraph_maintenance` (section 5), exactly as 206's. The write
-- switches to `public, pg_temp` around its write statements only (206 section
-- 0, THE WRITE WINDOW) and keeps no state in a temporary relation.
--
-- 206's `epigraph_default_group` is NOT re-stated. It still answers "the
-- agent's own team, else its live human's", and the private flag is applied
-- before it by its one caller (`ClaimRepository::resolve_visibility_choice`).

ALTER TABLE public.agents
    ADD COLUMN IF NOT EXISTS default_private boolean NOT NULL DEFAULT false;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'agents_default_private_or_group'
                      AND conrelid = 'public.agents'::regclass) THEN
        ALTER TABLE public.agents
            ADD CONSTRAINT agents_default_private_or_group
            CHECK (NOT default_private OR default_group_id IS NULL);
    END IF;
END $$;

COMMENT ON COLUMN public.agents.default_private IS
    'Migration 209: the agent''s default visibility is PRIVATE (its home group) for a claim '
    'write that names no visibility, ahead of its live human''s default team and of the '
    'single-writable-team fallback. Never set together with default_group_id. Written only '
    'through epigraph_set_agent_default_group.';

-- ===================================================================
-- 3. epigraph_default_private(agent)
-- ===================================================================
-- The agent's own flag. False for NULL or an unknown agent. Its caller asks it
-- for the agent and, when the agent sets nothing usable, for the live human
-- (`epigraph_human_of(agent, true)`), so a human whose own default is private
-- passes that on to the agents that inherit its default.
CREATE OR REPLACE FUNCTION public.epigraph_default_private(p_agent uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT COALESCE((SELECT a.default_private FROM public.agents a WHERE a.id = p_agent), false)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_default_private(uuid) FROM PUBLIC;

-- ===================================================================
-- 4. epigraph_set_agent_default_group(agent, group, private)
-- ===================================================================
-- Sets `p_agent`'s default: a team (`p_group`), private (`p_private`), or
-- neither (both NULL/false: clear, so it inherits its human's again). Both at
-- once is refused (VIS03).
--
-- WHO MAY. The session principal (`epigraph_principal_id()`, never an
-- argument; 206 section 0) when it is:
--   'self'     -- `p_agent` itself; or
--   'operator' -- a registered, live human operator
--                 (`epigraph_is_human_operator`, 122) holding a LIVE,
--                 non-retired `operator_links` row for `p_agent` (107). A
--                 retired link names who owns a retired identity's claims and
--                 confers no authority over it (107 section 7), so it does not
--                 admit this. Neither does 149's author-binding allowance,
--                 which binds an agent's writes to a human without a link.
-- Anyone else: VIS05 (42501), nothing changed, and the refusal does not say
-- whether `p_agent` exists.
--
-- A TEAM must be one of `epigraph_writable_teams(p_agent)`: the agent's own
-- writer/admin membership or its live human's (D-V3), checked for the AGENT
-- whose default it becomes, not for the caller (VIS02). It is checked again at
-- every write (206: a default that stopped being writable is ignored).
--
-- AUDIT. One `security_events` row per call, `agent.default_group_set`,
-- attributed to the CALLER (`agent_id` = principal: 077's
-- `security_events_append` binds a principal's rows to itself), with the
-- target, how the caller was admitted, and the previous and new values.
--
-- The row is locked before the previous values are read, and the UPDATE must
-- move exactly that one row before the audit row is written (an UPDATE that
-- row security filtered out would otherwise audit a change that did not
-- happen).
CREATE OR REPLACE FUNCTION public.epigraph_set_agent_default_group(
    p_agent uuid, p_group uuid, p_private boolean)
RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_private boolean := COALESCE(p_private, false);
    v_via text;
    v_prev_group uuid;
    v_prev_private boolean;
    v_moved bigint := 0;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'VIS01: setting a default needs an authenticated principal; '
                        'nothing was changed' USING ERRCODE = '42501';
    END IF;
    IF p_agent IS NULL THEN
        RAISE EXCEPTION 'VIS03: setting a default needs the agent it is for; nothing was changed'
            USING ERRCODE = '22023';
    END IF;
    IF v_private AND p_group IS NOT NULL THEN
        RAISE EXCEPTION 'VIS03: a default is a team or private, not both; nothing was changed'
            USING ERRCODE = '22023';
    END IF;

    IF p_agent = v_principal THEN
        v_via := 'self';
    ELSIF public.epigraph_is_human_operator(v_principal)
          AND EXISTS (SELECT 1 FROM public.operator_links l
                       WHERE l.agent_id = p_agent
                         AND l.operator_id = v_principal
                         AND NOT l.retired) THEN
        v_via := 'operator';
    ELSE
        RAISE EXCEPTION 'VIS05: only the agent itself, or the live human operator that holds a '
                        'live (not retired) operator link to it, may set its default; nothing '
                        'was changed' USING ERRCODE = '42501';
    END IF;

    IF p_group IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM public.epigraph_writable_teams(p_agent) t WHERE t.group_id = p_group)
    THEN
        RAISE EXCEPTION 'VIS02: group % is not a team agent % may write (writer or admin, its '
                        'own or its live human''s); nothing was changed', p_group, p_agent
            USING ERRCODE = '42501';
    END IF;

    SELECT a.default_group_id, a.default_private INTO v_prev_group, v_prev_private
      FROM public.agents a WHERE a.id = p_agent FOR UPDATE;

    PERFORM pg_catalog.set_config('search_path', 'public, pg_temp', true);  -- 206 section 0
    UPDATE public.agents
       SET default_group_id = p_group, default_private = v_private
     WHERE id = p_agent;
    GET DIAGNOSTICS v_moved = ROW_COUNT;
    IF v_moved <> 1 THEN
        RAISE EXCEPTION 'VIS06: the default of agent % was not changed (% rows); nothing was '
                        'changed', p_agent, v_moved USING ERRCODE = '55000';
    END IF;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('agent.default_group_set', v_principal, true,
            jsonb_build_object('target_agent_id', p_agent,
                               'via', v_via,
                               'operator_id', CASE WHEN v_via = 'operator'
                                                   THEN v_principal END,
                               'previous', v_prev_group,
                               'previous_private', COALESCE(v_prev_private, false),
                               'default_group_id', p_group,
                               'default_private', v_private,
                               'migration', 209, 'session_user', session_user::text));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);
    RETURN v_via;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_set_agent_default_group(uuid, uuid, boolean)
    FROM PUBLIC;

-- ===================================================================
-- 4b. epigraph_set_default_group(group): 206's write, delegating
-- ===================================================================
-- Same signature, same answer (the group it set), same refusals (VIS01 with
-- no principal, VIS02 for a team the principal may not write), and still one
-- `agent.default_group_set` row per call, now written by (2). Re-stated
-- because the CHECK above refuses a team over a private default: setting a
-- team, or clearing, through this function now also clears the flag.
CREATE OR REPLACE FUNCTION public.epigraph_set_default_group(p_group uuid)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_principal uuid := public.epigraph_principal_id();
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'VIS01: setting a default team needs an authenticated principal; '
                        'nothing was changed' USING ERRCODE = '42501';
    END IF;
    PERFORM public.epigraph_set_agent_default_group(v_principal, p_group, false);
    RETURN p_group;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_set_default_group(uuid) FROM PUBLIC;

-- ===================================================================
-- 5. OWNERSHIP AND GRANTS (206 section 6's guarded form)
-- ===================================================================
-- `CREATE OR REPLACE` keeps 206's owner and grants on the re-stated setter;
-- they are re-asserted here so a database whose 206 ran without the roles
-- converges too.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_default_private(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_set_agent_default_group(uuid, uuid, boolean) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_set_default_group(uuid) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 209 function '
                     'bodies stay owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_default_private(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_set_agent_default_group('
                'uuid, uuid, boolean) TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_set_default_group(uuid) '
                'TO epigraph_app';
    END IF;
END $$;
