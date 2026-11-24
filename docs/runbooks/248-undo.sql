-- ===================================================================
-- 248-undo.sql: take migration 248 (the attach verb's register-first
-- refusal, and may_run answering an application session only about its own
-- stamped principal) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- WHAT IT DOES: re-states the two bodies 248 replaced, verbatim from 166
-- (CREATE OR REPLACE keeps owner and grants):
--   * `epigraph_attach_agent_to_role` (166's body: attaches any agent the
--     guards admit, including one the host has not registered yet, whose
--     first registration then aborts AID09);
--   * `epigraph_role_agent_may_run`   (166's body: answers any session
--     holding EXECUTE about any agent).
--
-- WHAT IT LEAVES: every attachment written in between (each is an ordinary
-- 166 row), and 248's `_sqlx_migrations` row. Re-introducing either rule is
-- a NEW migration, never a re-run of 248.
--
-- No binary needs rolling back first: the repository's stamped ask works on
-- both bodies. The reverse order matters: to roll `epigraph-mcp-full` back
-- to a build without 248's repository change, run this undo FIRST; an older
-- binary asks may_run unstamped, and under 248's body every boot on an
-- application login is refused 42501.
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_attach_agent_to_role(
    p_role text, p_agent uuid, p_valid_from timestamptz, p_valid_to timestamptz,
    p_reason text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_id uuid;
BEGIN
    IF p_role IS NULL OR p_agent IS NULL OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_attach_agent_to_role: the role, the agent and a reason are '
                        'required'
            USING ERRCODE = '22004';
    END IF;
    INSERT INTO public.role_agents (role, agent_id, valid_from, valid_to, reason)
    VALUES (p_role, p_agent, COALESCE(p_valid_from, now()), p_valid_to, p_reason)
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_role_agent_may_run(p_agent uuid)
RETURNS TABLE (may_run boolean, role text, holder uuid, reason text)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT g.may_run, g.role, g.holder, g.reason
      FROM public.epigraph_role_agent_gate(p_agent, clock_timestamp()) g
$$;

COMMIT;
