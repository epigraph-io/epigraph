-- Migration 234: an operated agent READS the teams its live human reads.
--
-- Owner decision (2026-11-21, operator in the main ops session): "Our various
-- people need their agents to have read authority." This is the READ
-- counterpart of owner decision D-V3 (2026-11-05, migration 206), "an operated
-- agent writes where its human writes", which `epigraph_writable_teams` and
-- `Viewer::with_team_write_grant` implement for one team per write.
--
-- Before this migration an operated agent (a stdio `epigraph-mcp` signer
-- live-linked to a human through `epigraph-operator link`) resolved its READ
-- set from its OWN live memberships only (`Viewer::resolve` ->
-- `epigraph_live_memberships(agent)`): its own personal group and the writer
-- row the link adds in its human's personal group. It could write a claim
-- into one of its human's teams (D-V3) and then not read that claim back:
-- `get_claim` answered "not found" for a claim the same process had just
-- written (measured 2026-11-21 on prod, kit 94057a3d).
--
-- `epigraph_readable_teams(agent)` answers the TEAM groups an agent may read,
-- with how it may, exactly as `epigraph_writable_teams` does for writing:
--   'own'      -- the agent itself holds a live membership of ANY role;
--   'operator' -- the agent's LIVE human (`epigraph_human_of(p_agent, true)`,
--                 a different agent) holds a live DIRECT membership of ANY role
--                 (reader, writer or admin): the agent reads where its human
--                 reads.
-- DIRECT only: a `group_memberships` row of the human that is not revoked. A
-- group the human reaches only through a ROLE BINDING (165's
-- `epigraph_role_derived_memberships`) is NOT followed here: whether the
-- human's agents reach a role-bound group is that binding's own decision
-- (179's `agent_mode`: `holder_only`, `registered_agents`, `attached_agents`),
-- and an agent the binding admits already carries the group in its OWN live
-- memberships (the 'own' arm). Following the human's derived memberships
-- would hand a `holder_only` group to every agent of the holder
-- (`group_role_membership.rs` pins that it must not).
-- Only teams: an active group of kind 'team' or 'community'. A human's
-- personal group is already in the agent's set through the link's writer row;
-- world and seed groups are never added. A RETIRED link adds nothing
-- (`epigraph_human_of(p_agent, true)` names only a live link's human), and a
-- revoked membership of the human adds nothing (`epigraph_live_memberships`).
--
-- WHAT THIS DOES NOT CHANGE.
-- * Writing. `Viewer::resolve` puts the 'operator' teams in the READ set only,
--   never in the writable set; a team write still goes through
--   `epigraph_writable_teams` and `with_team_write_grant` (one team per write,
--   writer/admin humans only).
-- * The row policies. 077's `claims_tenancy` admits a read when
--   `owner_group_id = ANY (epigraph_session_groups())`, the stamped
--   `epigraph.group_ids`. The stamp is a transport, not an authority boundary
--   (OD-19: an application-DSN holder can set it), so the authority this
--   function adds is exercised by the binaries that stamp what it answers.
--   A binary that predates this migration simply does not ask: no authority
--   is added anywhere until both are deployed.
-- * HTTP. An OAuth principal is never operated (token issuance refuses an
--   operated agent), and `request_viewer` refuses a viewer to an operated
--   HTTP principal outside a live delegation, so in practice this widens the
--   stdio read set of operated agents. A delegated run token that is admitted
--   reads where its principal's live human reads, which is the delegation's
--   intent.

CREATE OR REPLACE FUNCTION public.epigraph_readable_teams(p_agent uuid)
RETURNS TABLE (group_id uuid, via text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    WITH own AS (
        SELECT m.group_id FROM public.epigraph_live_memberships(p_agent) m
    ), h AS (
        SELECT public.epigraph_human_of(p_agent, true) AS human
    ), hm AS (
        SELECT m.group_id
          FROM h
          JOIN public.group_memberships m ON m.agent_id = h.human
         WHERE h.human IS NOT NULL AND h.human <> p_agent
           AND m.revoked_at IS NULL
    )
    SELECT g.id,
           CASE WHEN g.id IN (SELECT o.group_id FROM own o) THEN 'own' ELSE 'operator' END
      FROM public.groups g
     WHERE p_agent IS NOT NULL
       AND g.kind IN ('team', 'community')
       AND g.status = 'active'
       AND (g.id IN (SELECT o.group_id FROM own o)
            OR g.id IN (SELECT x.group_id FROM hm x))
     ORDER BY g.id
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_readable_teams(uuid) FROM PUBLIC;

-- OWNERSHIP AND GRANTS: exactly as 206 section 6 does for
-- `epigraph_writable_teams` (guarded; without the maintenance role the body
-- stays owned by the migration runner).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_readable_teams(uuid) OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 234 function '
                     'body stays owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_readable_teams(uuid) TO epigraph_app';
    END IF;
END $$;
