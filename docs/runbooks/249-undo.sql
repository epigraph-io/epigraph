-- ===================================================================
-- 249-undo.sql: take migration 249 (the role-attached derivation answers a
-- past instant from what was recorded by then) back out, in ONE transaction,
-- on the migration (superuser) DSN.
--
-- READ FIRST. Once undone, the derivation again reads every detach,
-- succession and attachment whenever it was recorded: a detach made after an
-- instant T again takes the group from the detached identity, and from every
-- copy chained through its row or descending from it, at T too; a revert or
-- edit registered after T with a detached parent again cuts the identity off
-- at T; a row made by name dated back before T again admits its agent at T.
-- The roster at a past instant (`epigraph-operator group-roster --at`)
-- changes with those records again. Every answer at the present instant is
-- the same under both bodies.
--
-- WHAT IT DOES
--   * Restores migration 195's body of `epigraph_role_derived_memberships`
--     byte for byte (CREATE OR REPLACE keeps owner, ACL and `search_path`);
--   * drops 249's index `idx_role_agents_agent_role` (195's body reads
--     through 166's partial index and does not need it).
--
-- ORDER: newest first. Run this BEFORE `195-undo.sql`, which refuses a 249
-- body.
--
-- WHAT IT LEAVES: 249's `_sqlx_migrations` row. No row was written by 249.
-- Re-introducing the rule is a NEW migration, never a re-run of 249.
-- Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

-- Precondition: the derivation is 249's body (or already 195's: a second
-- run). Any other body means a LATER migration re-stated it, and restoring
-- 195's would silently drop that migration's delta: undo it first.
DO $$
DECLARE
    v_found text;
BEGIN
    SELECT md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_role_derived_memberships(uuid, timestamptz)');
    IF v_found IS NULL OR v_found NOT IN ('58caa9ae65e89485b4fac1bb26959fdd',   -- 249's
                                          '1c5c6925547d6aa0d0a54e718ce6bd47') THEN -- 195's
        RAISE EXCEPTION '249-undo: public.epigraph_role_derived_memberships(uuid, timestamptz) '
                        'has md5 %, neither 249''s body nor 195''s. A later migration re-stated '
                        'it; undo that one first (nothing was changed)', COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000';
    END IF;
END $$;

-- 195's body, byte for byte.
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
            -- copies admit nothing (section 1). Every row of the copy
            -- chain, the root included, must be live at `p_at`: a detach
            -- anywhere above a copy revokes it. 195: and a detach CUTS OFF the
            -- lineage below it: no copy counts for an agent that holds a
            -- detached row for the role, or that descends from one along
            -- `agent_succession` through agents with no live row made by
            -- name, nor through a copy held by such an agent.
            OR (b.attached_agents
                AND EXISTS (SELECT 1 FROM public.role_agents ra
                             WHERE ra.agent_id = p_agent AND ra.role = b.role
                               AND ra.detached_at IS NULL
                               AND ra.valid_from <= p_at
                               AND (ra.valid_to IS NULL OR p_at < ra.valid_to)
                               AND (ra.inherited_from IS NULL
                                    OR EXISTS (
                                        -- Every hop must be live at `p_at`
                                        -- (not detached, inside its window),
                                        -- the root included: a dead hop ends
                                        -- the walk before the root, and a
                                        -- walk that reaches no root admits
                                        -- nothing.
                                        WITH RECURSIVE chain (id, agent_id, inherited_from) AS (
                                            SELECT hop.id, hop.agent_id, hop.inherited_from
                                              FROM public.role_agents hop
                                             WHERE hop.id = ra.inherited_from
                                               AND hop.detached_at IS NULL
                                               AND hop.valid_from <= p_at
                                               AND (hop.valid_to IS NULL OR p_at < hop.valid_to)
                                            UNION
                                            SELECT hop.id, hop.agent_id, hop.inherited_from
                                              FROM public.role_agents hop
                                              JOIN chain ch ON hop.id = ch.inherited_from
                                             WHERE hop.detached_at IS NULL
                                               AND hop.valid_from <= p_at
                                               AND (hop.valid_to IS NULL OR p_at < hop.valid_to)
                                        ),
                                        -- 195: the agents this copy's answer
                                        -- rests on: the agent asked about and
                                        -- the agent of every COPY on the chain
                                        -- (a row made by name is never judged).
                                        judged (agent_id) AS (
                                            SELECT ra.agent_id
                                            UNION
                                            SELECT ch.agent_id FROM chain ch
                                             WHERE ch.inherited_from IS NOT NULL
                                        ),
                                        -- 195: and what they descend from:
                                        -- up `agent_succession` (every
                                        -- recorded parent, a revert's
                                        -- included), through parents that hold
                                        -- no live row made by name at `p_at`.
                                        -- An agent the operator attached by
                                        -- name ends the walk.
                                        lineage (agent_id) AS (
                                            SELECT j.agent_id FROM judged j
                                            UNION
                                            SELECT s.parent_agent_id
                                              FROM lineage l
                                              JOIN public.agent_succession s
                                                ON s.child_agent_id = l.agent_id
                                             WHERE NOT EXISTS (
                                                       SELECT 1 FROM public.role_agents dr
                                                        WHERE dr.agent_id = s.parent_agent_id
                                                          AND dr.role = ra.role
                                                          AND dr.inherited_from IS NULL
                                                          AND dr.detached_at IS NULL
                                                          AND dr.valid_from <= p_at
                                                          AND (dr.valid_to IS NULL
                                                               OR p_at < dr.valid_to))
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
                                                                     FROM folders f)
                                           -- 195: a detach is sticky and cuts
                                           -- off the lineage: no agent judged
                                           -- or reached holds a detached row
                                           -- for the role, at any time.
                                           AND NOT EXISTS (
                                                   SELECT 1
                                                     FROM lineage l
                                                     JOIN public.role_agents dd
                                                       ON dd.agent_id = l.agent_id
                                                    WHERE dd.role = ra.role
                                                      AND dd.detached_at IS NOT NULL))))))
     WHERE p_agent IS NOT NULL AND p_at IS NOT NULL
       AND b.created_at <= p_at AND (b.revoked_at IS NULL OR p_at < b.revoked_at)
       AND public.epigraph_live_role_assignment(c.human, b.role, p_at) IS NOT NULL
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_derived_memberships(uuid, timestamptz)
    FROM PUBLIC;

DROP INDEX IF EXISTS public.idx_role_agents_agent_role;

COMMIT;
