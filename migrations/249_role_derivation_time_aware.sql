-- 249_role_derivation_time_aware.sql
-- The role-attached derivation answers a past instant from what was recorded
-- by then: a later detach, succession or attachment does not change it.
--
-- ===================================================================
-- 1. WHY
--
-- `epigraph_role_derived_memberships(agent, at)` answers whether an agent
-- held a group through a role binding at an instant. Its attached arm (179,
-- re-stated by 195) read every detach, every succession and every
-- attachment whenever it was recorded:
--   * a detached row counted at no instant (179), so detaching an identity
--     also took the group from it, and from every copy chained through its
--     row, at every PAST instant;
--   * the sticky detach (195) cut an identity off when it, or an ancestor
--     the lineage walk reaches, held a detached row "at any time", so a
--     detach made later reached back too;
--   * the lineage walk followed every `agent_succession` edge, so a revert
--     or edit registered later (an identity registered again with a
--     detached parent) cut the identity off at past instants too;
--   * a row made by name may be dated up to a minute back (166's guard), so
--     an attach made after an instant could admit an agent at that instant.
-- So the answer for an instant T (the roster's `--at`, an audit of who held
-- the group then) changed after T. Measured on 195's body: attach Q by
-- name, register P below it, note T, detach Q; the derivation for Q and P
-- at T then answered nothing, although both held the group at T.
--
-- ===================================================================
-- 2. THE RULE
--
-- A record counts at `p_at` when it was RECORDED by `p_at`:
--   * an attachment (a row made by name or a copy) from its `created_at`;
--   * a detach from its `detached_at`: a row is live at `p_at` only when it
--     is not detached or was detached after `p_at`, and an agent holds a
--     detached row for the sticky rule only when that row was detached at or
--     before `p_at`;
--   * a succession from its `attested_at`.
-- Everything else in 179's and 195's rule is unchanged, so at any instant
-- at or after every detach the answer is exactly 195's: a detach is sticky
-- per identity and cuts off the lineage below it from the moment it is made.
-- A hop is always recorded before the copy that names it (`inherited_from`
-- is a foreign key), and a row's detach after its creation, so the hop and
-- sticky reads need no `created_at` test of their own.
--
-- THE PRESENT. An instant at or after the asking transaction's start
-- (`p_at >= now()`) is the present: every record the snapshot sees counts,
-- whatever its timestamp. The timestamps are transaction starts
-- (`created_at`, `detached_at` and `attested_at` all default to, or are
-- checked equal to, `now()`), so a detach another session committed after
-- this transaction began carries a timestamp after this transaction's
-- `now()`. Without this clause a gate that asks at `now()` (the viewer's
-- group set, 165; the personal-group writer, 235) would still admit an
-- identity whose detach it can already see. With it, every live gate
-- answers exactly as under 195 (they all ask at `now()` or
-- `clock_timestamp()`, never earlier), and only an instant before the
-- asking transaction began is answered from the record.
--
-- LIMITS (unchanged by this file):
--   * the folder test (179) still reads every snapshot an agent has, at any
--     time: a copy holder that registers in a second folder later loses the
--     group at past instants too (179's "a successor that once ran
--     elsewhere does not count again");
--   * the operator link (`epigraph_operator_actor`), the client allowance
--     (`epigraph_allowlisted_operator`) and the group's status
--     (`groups.status = 'active'`) are read as they stand now, not at `p_at`:
--     suspending or deprovisioning a group later empties the answer (and the
--     roster's `--at`) for every earlier instant;
--   * a timestamp is its writer's transaction start, not its commit: a
--     record dated at or before T that commits after T changes the answer
--     for T once it commits, as it always did;
--   * `agent_succession.attested_at` is written by the registration definer
--     (its default, `now()`); a privileged session inserting a row by hand
--     could date it back.
--
-- THE INDEX. The row asked about is now read whether or not it is detached
-- (a row detached after `p_at` still counts at `p_at`), so 166's partial
-- index `idx_role_agents_live (agent_id, role) WHERE detached_at IS NULL` no
-- longer serves that read. Without an index on `(agent_id, role)` the
-- planner's estimate for the body grew 80- to 400-fold (measured on
-- PostgreSQL 16, empty tables: 0.54M for 195's body, 47M to 214M for this
-- body by the instant bound, as a standalone statement), and every call
-- paid a JIT compile (0.55 to 0.8 s per call, measured; 4 ms with JIT off,
-- and under 195 with it on). This
-- file adds the plain index `idx_role_agents_agent_role (agent_id, role)`;
-- with it the estimate is 0.64M and a call takes 3 to 4 ms, as under 195. It
-- also serves the sticky read of detached rows, which 195 read without an
-- index.
--
-- ===================================================================
-- 3. RE-STATEMENT
--
-- One body, re-stated whole from 195's, each delta marked `249`:
-- `epigraph_role_derived_memberships(uuid, timestamptz)`. A precondition
-- refuses (55000, nothing changed) unless it still carries 195's body (md5
-- of `prosrc` 1c5c6925547d6aa0d0a54e718ce6bd47), so applying this file over
-- a later re-statement can never drop that migration's delta. Signature,
-- owner, ACL, volatility and `search_path` (`public, pg_temp`) are
-- unchanged; CREATE OR REPLACE keeps owner and ACL, and this file grants
-- nothing. A later migration that re-states it starts from this file's body.
-- The index is created in this transaction (`role_agents` holds one row per
-- attachment and copy, so the build is short; writers of `role_agents` wait
-- for it, under the 3 s lock timeout below).
--
-- ===================================================================
-- 4. UNDO
--
-- `docs/runbooks/249-undo.sql` restores 195's body byte for byte
-- (md5-guarded: it refuses over any body but 249's or 195's). Run it BEFORE
-- `195-undo.sql`, which refuses a 249 body. It drops the index too. After an
-- undo, a later detach or succession again changes the answer for an earlier
-- instant.
--
-- DEPLOY: no binary depends on it (no signature changes); apply with any
-- migrator that carries it. Order: after 195.

SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- Precondition: the derivation still carries 195's body.
-- -------------------------------------------------------------------
DO $$
DECLARE
    v_found text;
BEGIN
    SELECT md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_role_derived_memberships(uuid, timestamptz)');
    IF v_found IS DISTINCT FROM '1c5c6925547d6aa0d0a54e718ce6bd47' THEN
        RAISE EXCEPTION '249: public.epigraph_role_derived_memberships(uuid, timestamptz) is not '
                        'the body 249 re-states (195''s, md5 1c5c6925547d6aa0d0a54e718ce6bd47); '
                        'found md5 %. Another migration re-bodied it, or 195 is not applied; '
                        'nothing was changed', COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with '
                         'every delta instead of this one.';
    END IF;
END $$;

-- -------------------------------------------------------------------
-- The index the time-aware read of the row asked about needs (section 2).
-- -------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_role_agents_agent_role
    ON public.role_agents (agent_id, role);

-- -------------------------------------------------------------------
-- The derivation (195's body); delta: every detach, attachment and
-- succession counts from when it was recorded (section 2).
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
            -- role (166), live at `p_at`. 249: a row counts from when it was
            -- recorded and a detach from when it was made, so an answer for
            -- an instant before either is not changed by it (below).
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
                               -- 249: recorded by `p_at` and not detached at
                               -- `p_at`. An instant at or after this
                               -- transaction's start (`now()`) is the present:
                               -- every row and detach this snapshot sees
                               -- counts, so a live gate is never behind a
                               -- detach another session already committed.
                               AND (ra.created_at <= p_at OR p_at >= now())
                               AND (ra.detached_at IS NULL
                                    OR (p_at < ra.detached_at AND p_at < now()))
                               AND ra.valid_from <= p_at
                               AND (ra.valid_to IS NULL OR p_at < ra.valid_to)
                               AND (ra.inherited_from IS NULL
                                    OR EXISTS (
                                        -- Every hop must be live at `p_at`
                                        -- (not detached, inside its window),
                                        -- the root included: a dead hop ends
                                        -- the walk before the root, and a
                                        -- walk that reaches no root admits
                                        -- nothing. 249: a hop's detach counts
                                        -- from when it was made (a hop is
                                        -- always recorded before the copy
                                        -- that names it).
                                        WITH RECURSIVE chain (id, agent_id, inherited_from) AS (
                                            SELECT hop.id, hop.agent_id, hop.inherited_from
                                              FROM public.role_agents hop
                                             WHERE hop.id = ra.inherited_from
                                               AND (hop.detached_at IS NULL
                                                    OR (p_at < hop.detached_at
                                                        AND p_at < now()))
                                               AND hop.valid_from <= p_at
                                               AND (hop.valid_to IS NULL OR p_at < hop.valid_to)
                                            UNION
                                            SELECT hop.id, hop.agent_id, hop.inherited_from
                                              FROM public.role_agents hop
                                              JOIN chain ch ON hop.id = ch.inherited_from
                                             WHERE (hop.detached_at IS NULL
                                                    OR (p_at < hop.detached_at
                                                        AND p_at < now()))
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
                                        -- name ends the walk. 249: only the
                                        -- successions attested by `p_at`, and
                                        -- a row made by name ends it from when
                                        -- it was recorded until its detach.
                                        lineage (agent_id) AS (
                                            SELECT j.agent_id FROM judged j
                                            UNION
                                            SELECT s.parent_agent_id
                                              FROM lineage l
                                              JOIN public.agent_succession s
                                                ON s.child_agent_id = l.agent_id
                                             WHERE (s.attested_at <= p_at
                                                    OR p_at >= now())
                                               AND NOT EXISTS (
                                                       SELECT 1 FROM public.role_agents dr
                                                        WHERE dr.agent_id = s.parent_agent_id
                                                          AND dr.role = ra.role
                                                          AND dr.inherited_from IS NULL
                                                          AND (dr.created_at <= p_at
                                                               OR p_at >= now())
                                                          AND (dr.detached_at IS NULL
                                                               OR (p_at < dr.detached_at
                                                                   AND p_at < now()))
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
                                           -- for the role. 249: one detached by
                                           -- `p_at`; from then on, at every
                                           -- later instant, as 195 has it.
                                           AND NOT EXISTS (
                                                   SELECT 1
                                                     FROM lineage l
                                                     JOIN public.role_agents dd
                                                       ON dd.agent_id = l.agent_id
                                                    WHERE dd.role = ra.role
                                                      AND dd.detached_at IS NOT NULL
                                                      AND (dd.detached_at <= p_at
                                                           OR p_at >= now())))))))
     WHERE p_agent IS NOT NULL AND p_at IS NOT NULL
       AND b.created_at <= p_at AND (b.revoked_at IS NULL OR p_at < b.revoked_at)
       AND public.epigraph_live_role_assignment(c.human, b.role, p_at) IS NOT NULL
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_derived_memberships(uuid, timestamptz)
    FROM PUBLIC;
