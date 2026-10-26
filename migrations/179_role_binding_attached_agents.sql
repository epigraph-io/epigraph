-- 179: a group-role binding mode that admits the role HOLDER and the role's
-- ATTACHED agents only.
--
-- ===================================================================
-- 1. WHAT THIS ADDS
--
-- 165 binds a non-elevating role R to a group G in one of two shapes: the
-- live holder of R only (`include_agents = false`), or the holder AND every
-- agent REGISTERED TO the holder (an acting live link or a live client
-- allowance, `include_agents = true`). The second shape admits every agent
-- the holder ever linked, including agents that have nothing to do with the
-- role (a fleet identity that runs an unrelated job for the same human).
--
-- This file adds a third shape, recorded as a new column
-- `group_role_bindings.attached_agents boolean NOT NULL DEFAULT false`:
--
--   while binding B = (G, R, member_role, attached_agents) is live at t,
--   principal P is a `member_role` member of G iff
--     (1) P is a registered human holding a LIVE assignment of R at t
--         (165's arm 1, unchanged); or
--     (3) P is an agent with a LIVE ATTACHMENT to R at t in 166's
--         `role_agents` (not detached, `valid_from <= t < valid_to`) that
--         COUNTS (below), AND P's human by 165's agent arm (the operator of
--         its ACTING live link, or the human of its live client allowance)
--         holds a LIVE assignment of R at t.
--
-- Which attachments count:
--   * an attachment an operator made for P itself (`inherited_from` NULL)
--     counts as it is, wherever P runs (the operator's act names P);
--   * a SUCCESSION COPY (166 step 5b at registration, or 166's attach-time
--     lineage follow; `inherited_from` set) counts only when P runs in ONE
--     group folder (`agent_prompt_snapshots`), and that folder is one that
--     the identity the operator attached runs in: the agent of the ROOT row
--     of the `inherited_from` chain (the operator's own attachment).
-- So a successor in the same folder (a prompt or model change of the job
-- the operator attached) keeps the group; and these admit nothing, although
-- 166 attaches them all (an attachment there only ever refuses):
--   * a SHARED successor: an identity that also runs in another group folder
--     (a fleet container of the same human registered as a successor; 166
--     flags it `shared_identity`), now or at any later registration;
--   * a successor registered in a DIFFERENT folder than the attached
--     identity's, shared or not;
--   * any later copy of such a copy outside the attached identity's folder.
-- The folder test reads every snapshot P has, at any time (not only up to
-- t): a successor that once ran elsewhere does not count again.
--
-- (3) is 165's arm 2 narrowed to the agents attached to the bound role. It
-- needs a live holder, and that holder must be the agent's OWN human: an
-- agent attached to R while R is held by someone else is not admitted (the
-- same rule 166's ROL01 applies to the agent's writes, so reads and writes
-- agree). An agent registered to the holder but not attached to R is not
-- admitted. A membership through (3) therefore lapses, with no job, when the
-- holder's assignment ends (or its window closes), when the attachment is
-- detached or its window closes, when the agent's link is retired or its
-- acting row revoked, and when the binding ends.
--
-- `attached_agents` and `include_agents` are never both true
-- (`group_role_bindings_one_agent_mode`). The three modes:
--   holder_only        include_agents = false, attached_agents = false
--   registered_agents  include_agents = true,  attached_agents = false (165)
--   attached_agents    include_agents = false, attached_agents = true  (179)
-- An existing binding takes the column's default (false) and keeps 165's
-- meaning exactly; a reader that does not know the column sees an attached
-- binding as holder-only (it under-grants, never over-grants).
--
-- 166 says an attachment "only ever refuses, so a copy never grants the
-- child anything", and copies an attachment to every registered successor,
-- a shared one included, for that reason. In THIS mode an attachment is part
-- of a grant (read, and write at `writer`), so that premise no longer holds
-- for a binding in the attached mode; the copy rule above is what bounds it.
-- 166's registration and lineage follow are not changed: every copy still
-- refuses (ROL01) as 166 says; only which copies also grant is decided here.
-- A DETACH does not follow the lineage (166): to take the group from a
-- whole lineage, detach every attached identity of it (each copy included),
-- or end the binding.
--
-- ===================================================================
-- 2. WHERE THE RULE LIVES
--
-- ONE function is re-stated: `epigraph_role_derived_memberships(uuid,
-- timestamptz)` (165's body plus the attached arm). Every reader asks it:
-- the viewer's group set (`epigraph_live_memberships`, 165), the claims-path
-- writer scope (`epigraph_require_writer_scope`, 165's derived arm as
-- re-stated by 166), and the roster (`epigraph_group_role_roster`, which
-- enumerates every agent linked to or allowed for a holder and keeps the ones
-- the derivation admits). None of those three is re-stated here.
--
-- Two of 165's table triggers are re-stated so the new column is held like
-- every other field:
--   * `epigraph_group_role_bindings_guard_update`: `attached_agents` joins
--     the tuple an end must leave unchanged (a binding's mode never changes;
--     end it and bind anew);
--   * `epigraph_group_role_bindings_audit`: the bind/unbind row records
--     `attached_agents` and the mode name (`agent_mode`), so an attached
--     binding's audit row does not read as holder-only.
--
-- The precondition below refuses (55000, nothing changed) unless each of the
-- three bodies is 165's, by md5 of `prosrc`, so applying this file over a
-- later re-statement cannot drop that migration's delta. Any edit to one of
-- those 165 bodies must update the expected value here.
--
-- ===================================================================
-- 3. THE VERBS
--
-- 165's verbs keep their signatures and bodies (the boolean
-- `p_include_agents`: true = registered_agents, false = holder_only). Two
-- OVERLOADS take the mode by name instead, on the same rules (maintenance
-- only, reader|writer, one live binding per (group, role), GRB01-GRB03):
--
--   epigraph_bind_group_role(role text, group uuid, member_role text,
--                            agent_mode text, reason text)          -> binding
--   epigraph_define_group_role(key text, description text, group uuid,
--                              member_role text, agent_mode text,
--                              reason text)                         -> binding
--
-- An unknown mode is refused 22023 before anything is written. A typed
-- boolean argument still resolves to 165's signature; an untyped string
-- literal resolves to the text overload (PostgreSQL prefers the string
-- category), where `'true'` is refused as an unknown mode, never read as a
-- boolean. A client that caches prepared statements by SQL TEXT (sqlx does,
-- per connection) must not send both overloads through one text: a bare
-- `$4` prepared for one argument type is reused for the other and the
-- parameter is mis-decoded (measured: a boolean `false` sent into a
-- statement prepared for the text overload fails 22021). Cast the argument
-- (`$4::text` / `$4::boolean`), as the operator CLI does.
--
-- GRB01 is NOT relaxed: a role that elevates or reads the audit trail (123's
-- `role:platform-custodian`, `role:auditor`) still cannot be bound in any
-- mode. A group private to the holder of such a role and that role's agents
-- is made with a NON-ELEVATING role the same human holds, its agents
-- attached to THAT role.
--
-- ===================================================================
-- 4. WHAT THIS DOES NOT CHANGE
--
--   * `role_agents` grants nothing outside this mode: an attachment admits
--     an agent to a group only through a binding in this mode, only while
--     the agent's own human holds the role, and a succession copy only under
--     the folder rule (section 1). Under 165's modes and in 166's ROL01 it
--     still only refuses.
--   * 166's ROL01 write refusal, its may-run question and its registration
--     copy are untouched.
--   * The membership door (122's `epigraph_operator_writes_group`) stays
--     direct-only, as 165 left it.
--
-- ===================================================================
-- UNDO
--
-- End (or keep, holder-only) every binding with attached_agents = true
-- first; then re-state 165's bodies of `epigraph_role_derived_memberships`,
-- `epigraph_group_role_bindings_guard_update` and
-- `epigraph_group_role_bindings_audit` (CREATE OR REPLACE keeps owner and
-- grants), and:
-- DROP FUNCTION IF EXISTS public.epigraph_define_group_role(text, text, uuid, text, text, text);
-- DROP FUNCTION IF EXISTS public.epigraph_bind_group_role(text, uuid, text, text, text);
-- ALTER TABLE public.group_role_bindings
--     DROP CONSTRAINT IF EXISTS group_role_bindings_one_agent_mode,
--     DROP COLUMN IF EXISTS attached_agents;
-- (Audit rows keep their `agent_mode` key: 082, immutable.)
-- **Applied to throwaway databases only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- Precondition: 166's `role_agents` exists (the attached arm reads it), and
-- the three functions this file RE-STATES still carry 165's bodies.
-- -------------------------------------------------------------------
DO $$
DECLARE
    v_found text;
    v_check record;
BEGIN
    IF to_regclass('public.role_agents') IS NULL THEN
        RAISE EXCEPTION '179: public.role_agents is absent; apply 166 first (nothing was changed)'
            USING ERRCODE = '55000';
    END IF;
    FOR v_check IN
        SELECT * FROM (VALUES
            ('public.epigraph_role_derived_memberships(uuid, timestamptz)',
             '86bbb75e74864b90fa09bda0d35c3fc7'),
            ('public.epigraph_group_role_bindings_guard_update()',
             'ec9ff51052af84d669cb204d73791f94'),
            ('public.epigraph_group_role_bindings_audit()',
             '01dd3e1be658e0b8bc16de14b47dd20f')
        ) AS c(signature, expected)
    LOOP
        SELECT md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
         WHERE p.oid = to_regprocedure(v_check.signature);
        IF v_found IS DISTINCT FROM v_check.expected THEN
            RAISE EXCEPTION '179: % is not the body 179 re-states (165''s, md5 %); found md5 %. '
                            'Another migration re-bodied it, or 165 is not applied; nothing was '
                            'changed', v_check.signature, v_check.expected,
                            COALESCE(v_found, '(absent)')
                USING ERRCODE = '55000',
                      HINT = 'Apply a reconciling migration that re-states the function with '
                             'every delta instead of this one.';
        END IF;
    END LOOP;
END $$;

-- -------------------------------------------------------------------
-- The mode column. A constant default fires no trigger and rewrites no row;
-- every existing binding keeps 165's meaning.
-- -------------------------------------------------------------------
ALTER TABLE public.group_role_bindings
    ADD COLUMN attached_agents boolean NOT NULL DEFAULT false;
ALTER TABLE public.group_role_bindings
    ADD CONSTRAINT group_role_bindings_one_agent_mode
    CHECK (NOT (include_agents AND attached_agents));

-- 165's update guard; delta: `attached_agents` in the unchanged tuple.
CREATE OR REPLACE FUNCTION public.epigraph_group_role_bindings_guard_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF NOT public.epigraph_bypass() THEN
        RAISE EXCEPTION 'group_role_bindings: only a maintenance session ends a binding'
            USING ERRCODE = '42501';
    END IF;
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'group_role_bindings: binding % has ended, and an end is final; '
                        'nothing was changed', OLD.id USING ERRCODE = '55000';
    END IF;
    IF NEW.revoked_at IS NULL
       OR NEW.revoked_reason IS NULL OR length(btrim(NEW.revoked_reason)) = 0
       OR (NEW.id, NEW.group_id, NEW.role, NEW.member_role, NEW.include_agents,
           NEW.attached_agents, NEW.reason, NEW.created_at, NEW.created_by)
          IS DISTINCT FROM
          (OLD.id, OLD.group_id, OLD.role, OLD.member_role, OLD.include_agents,
           OLD.attached_agents, OLD.reason, OLD.created_at, OLD.created_by) THEN
        RAISE EXCEPTION 'group_role_bindings: a binding is only ever ended (revoked_at and a '
                        'revoked_reason set); nothing was changed' USING ERRCODE = '55000',
              HINT = 'End it with epigraph-operator end-group-role-binding and bind anew.';
    END IF;
    NEW.revoked_at := now();
    NEW.revoked_by := session_user;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_group_role_bindings_guard_update() FROM PUBLIC;

-- 165's audit; delta: the row names the mode (`attached_agents` and
-- `agent_mode`), and `migration` names the body that wrote it.
CREATE OR REPLACE FUNCTION public.epigraph_group_role_bindings_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES (CASE TG_OP WHEN 'INSERT' THEN 'platform.group_role_bound'
                       ELSE 'platform.group_role_unbound' END,
            NULL, true,
            jsonb_build_object('binding_id', NEW.id, 'group_id', NEW.group_id,
                               'role', NEW.role, 'member_role', NEW.member_role,
                               'include_agents', NEW.include_agents,
                               'attached_agents', NEW.attached_agents,
                               'agent_mode', CASE
                                   WHEN NEW.include_agents THEN 'registered_agents'
                                   WHEN NEW.attached_agents THEN 'attached_agents'
                                   ELSE 'holder_only' END,
                               'reason', CASE TG_OP WHEN 'INSERT' THEN NEW.reason
                                                    ELSE NEW.revoked_reason END,
                               'recorded_by', session_user::text,
                               -- 164's acting process (the shared login
                               -- names no person); NULL when not set.
                               'actor', public.epigraph_team_group_actor(),
                               'migration', 179));
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_group_role_bindings_audit() FROM PUBLIC;

-- -------------------------------------------------------------------
-- The mode verbs (maintenance only). 165's boolean signatures stay.
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_bind_group_role(
    p_role text, p_group uuid, p_member_role text, p_agent_mode text, p_reason text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_id uuid;
BEGIN
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'epigraph_bind_group_role: only a maintenance session binds a role to '
                        'a group' USING ERRCODE = '42501';
    END IF;
    IF p_role IS NULL OR p_group IS NULL OR p_member_role IS NULL OR p_agent_mode IS NULL
       OR p_reason IS NULL OR btrim(p_reason) = '' THEN
        RAISE EXCEPTION 'epigraph_bind_group_role: a role, a group, a member role, an agent '
                        'mode and a reason are required' USING ERRCODE = '22004';
    END IF;
    IF p_agent_mode NOT IN ('holder_only', 'registered_agents', 'attached_agents') THEN
        RAISE EXCEPTION 'epigraph_bind_group_role: agent mode % is not holder_only, '
                        'registered_agents or attached_agents', p_agent_mode
            USING ERRCODE = '22023';
    END IF;
    IF p_member_role NOT IN ('reader', 'writer') THEN
        RAISE EXCEPTION 'epigraph_bind_group_role: member role % is not reader or writer; a '
                        'role never confers admin', p_member_role USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM public.group_role_bindings b
                WHERE b.group_id = p_group AND b.role = p_role AND b.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'epigraph_bind_group_role: role % is already bound to group %; end '
                        'that binding first', p_role, p_group USING ERRCODE = '55000';
    END IF;
    INSERT INTO public.group_role_bindings (group_id, role, member_role, include_agents,
                                            attached_agents, reason)
    VALUES (p_group, p_role, p_member_role, p_agent_mode = 'registered_agents',
            p_agent_mode = 'attached_agents', p_reason)
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_bind_group_role(text, uuid, text, text, text)
    FROM PUBLIC;

-- 165's define with the mode by name; it binds through the mode verb above.
CREATE OR REPLACE FUNCTION public.epigraph_define_group_role(
    p_key text, p_description text, p_group uuid, p_member_role text,
    p_agent_mode text, p_reason text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_node uuid := gen_random_uuid();
BEGIN
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'epigraph_define_group_role: only a maintenance session defines a '
                        'role' USING ERRCODE = '42501';
    END IF;
    IF p_key IS NULL OR p_description IS NULL OR btrim(p_description) = '' THEN
        RAISE EXCEPTION 'epigraph_define_group_role: a key and a description are required'
            USING ERRCODE = '22004';
    END IF;
    IF p_key !~ '^role:[a-z][a-z0-9-]*$' THEN
        RAISE EXCEPTION 'epigraph_define_group_role: % is not a role key (role:<lowercase>)',
                        p_key USING ERRCODE = '22023';
    END IF;
    IF p_member_role IS NULL OR p_member_role NOT IN ('reader', 'writer') THEN
        RAISE EXCEPTION 'epigraph_define_group_role: member role % is not reader or writer; a '
                        'role never confers admin', p_member_role USING ERRCODE = '22023';
    END IF;
    -- Refused before the catalog is written (the bind below would refuse it
    -- too, but only after the role node and catalog row were inserted).
    IF p_agent_mode IS NULL
       OR p_agent_mode NOT IN ('holder_only', 'registered_agents', 'attached_agents') THEN
        RAISE EXCEPTION 'epigraph_define_group_role: agent mode % is not holder_only, '
                        'registered_agents or attached_agents', p_agent_mode
            USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM public.platform_roles r WHERE r.key = p_key) THEN
        RAISE EXCEPTION 'GRB03: role % is already in the catalog; bind it with '
                        'epigraph_bind_group_role instead', p_key
            USING ERRCODE = 'GRB03';
    END IF;
    -- The role's graph node: a key whose private half exists nowhere (123).
    INSERT INTO public.agents (id, public_key, display_name, agent_type, role, labels)
    VALUES (v_node, uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()),
            p_key, 'role', 'custom', ARRAY['role', 'platform-role']);
    INSERT INTO public.platform_roles (key, elevates, reads_audit, role_node_id, description)
    VALUES (p_key, false, false, v_node, p_description);
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('platform.role_defined', NULL, true,
            jsonb_build_object('role', p_key, 'role_node_id', v_node,
                               'description', p_description, 'elevates', false,
                               'reads_audit', false, 'group_id', p_group,
                               'agent_mode', p_agent_mode,
                               'reason', p_reason, 'recorded_by', session_user::text,
                               'actor', public.epigraph_team_group_actor(),
                               'migration', 179));
    RETURN public.epigraph_bind_group_role(p_key, p_group, p_member_role, p_agent_mode,
                                           p_reason);
END $$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_define_group_role(text, text, uuid, text, text, text) FROM PUBLIC;

-- -------------------------------------------------------------------
-- The derivation (165's body); delta: the attached arm (section 1, (3)).
-- The candidate humans are unchanged; a binding in the attached mode admits
-- an agent candidate only when the agent itself holds a live attachment to
-- the BOUND role that counts (an operator's own attachment, or a succession
-- copy under the folder rule). The holder test below is shared by every arm,
-- so the attached agent's own human must hold the role at `p_at`.
-- `role_agents` and `agent_prompt_snapshots` are FORCEd and admit this
-- maintenance-owned definer frame; under any other owner they read no row
-- and the arm admits nobody (fail-closed). The copy chain is acyclic (166's
-- guard refuses an `inherited_from` that does not exist yet, so a row never
-- names itself); UNION stops the walk regardless.
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_role_derived_memberships(
    p_agent uuid, p_at timestamptz)
RETURNS TABLE (group_id uuid, role text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    WITH candidates (human, via_agent) AS (
        SELECT p_agent, false
        UNION ALL
        SELECT o.operator_id, true FROM public.epigraph_operator_actor(p_agent) o
        UNION ALL
        SELECT a.h, true FROM public.epigraph_allowlisted_operator(p_agent) AS a(h)
         WHERE a.h IS NOT NULL
    )
    SELECT DISTINCT b.group_id, b.member_role
      FROM public.group_role_bindings b
      JOIN public.groups g ON g.id = b.group_id AND g.status = 'active'
      JOIN candidates c
        ON (NOT c.via_agent
            OR b.include_agents
            -- 179: the attached mode admits an agent ATTACHED to the bound
            -- role (166), live at `p_at`; a detached row counts at no instant.
            -- An operator's own attachment (no `inherited_from`) counts as
            -- is. A succession COPY counts only when the agent runs in ONE
            -- group folder, and that folder is one the identity the operator
            -- attached (the root of the copy chain) runs in: a shared
            -- successor, a successor in another folder and a copy of their
            -- copies admit nothing (section 1).
            OR (b.attached_agents
                AND EXISTS (SELECT 1 FROM public.role_agents ra
                             WHERE ra.agent_id = p_agent AND ra.role = b.role
                               AND ra.detached_at IS NULL
                               AND ra.valid_from <= p_at
                               AND (ra.valid_to IS NULL OR p_at < ra.valid_to)
                               AND (ra.inherited_from IS NULL
                                    OR EXISTS (
                                        WITH RECURSIVE chain (id, agent_id, inherited_from) AS (
                                            SELECT r.id, r.agent_id, r.inherited_from
                                              FROM public.role_agents r
                                             WHERE r.id = ra.inherited_from
                                            UNION
                                            SELECT r.id, r.agent_id, r.inherited_from
                                              FROM public.role_agents r
                                              JOIN chain ch ON r.id = ch.inherited_from
                                        ),
                                        folders AS (
                                            SELECT DISTINCT s.group_folder
                                              FROM public.agent_prompt_snapshots s
                                             WHERE s.agent_id = p_agent
                                        )
                                        SELECT 1
                                          FROM chain root
                                          JOIN public.agent_prompt_snapshots rs
                                            ON rs.agent_id = root.agent_id
                                         WHERE root.inherited_from IS NULL
                                           AND (SELECT count(*) FROM folders) = 1
                                           AND rs.group_folder IN (SELECT f.group_folder
                                                                     FROM folders f))))))
     WHERE p_agent IS NOT NULL AND p_at IS NOT NULL
       AND b.created_at <= p_at AND (b.revoked_at IS NULL OR p_at < b.revoked_at)
       AND public.epigraph_live_role_assignment(c.human, b.role, p_at) IS NOT NULL
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_derived_memberships(uuid, timestamptz)
    FROM PUBLIC;

-- -------------------------------------------------------------------
-- Ownership and grants, guarded as every such block since 060 is. Each
-- ALTER/GRANT names its function literally (tenancy_backfill.rs's static
-- re-own scan reads these statements).
-- -------------------------------------------------------------------
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_group_role_bindings_guard_update() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_group_role_bindings_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION '
                'public.epigraph_bind_group_role(text, uuid, text, text, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION '
                'public.epigraph_define_group_role(text, text, uuid, text, text, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION '
                'public.epigraph_role_derived_memberships(uuid, timestamptz) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_bind_group_role(text, uuid, text, text, text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_define_group_role(text, text, uuid, text, text, text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_role_derived_memberships(uuid, timestamptz) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_bind_group_role(text, uuid, text, text, text) '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_define_group_role(text, text, uuid, text, text, text) '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_role_derived_memberships(uuid, timestamptz) FROM epigraph_app';
    END IF;
END $$;
