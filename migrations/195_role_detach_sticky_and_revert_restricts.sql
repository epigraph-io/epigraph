-- 195_role_detach_sticky_and_revert_restricts.sql
-- A detach is sticky per identity and cuts off the lineage below it, a revert
-- always restricts, and the attach-time lineage follow chains its copies.
--
-- ===================================================================
-- 1. WHY
--
-- 179's attached mode makes a role attachment (166's `role_agents`) a GRANT:
-- a binding in that mode admits the role's attached agents to its group. 179
-- revokes a lineage's grant on a detach by walking each copy's
-- `inherited_from` chain: a copy counts only while every row it was copied
-- through is un-detached and inside its window. 180 added two guards to the
-- registration's copy (166's step 5b): never copy a parent row whose chain
-- reaches a row of the child (the CHAIN guard), and never copy onto an
-- identity the parent is recorded as having succeeded (the REVERSE-PAIR
-- guard). Both were measured insufficient, in opposite directions (the
-- first and fourth bullets), 166's follow hid part of every lineage it
-- copied from 179's walk (the second), and a detach of the identity a job
-- runs did not reach the job's next identity (the third):
--
--   * A detach is recorded on one ROW, but it is the operator's act on an
--     IDENTITY, and a later copy whose chain does not pass through that row
--     re-admitted the identity. Two paths, both from the documented restore
--     ("detach the running identity's stale copy, attach it by name"):
--       (a) a MULTI-HOP revert: attach A; B and C succeed it; detach A;
--           restore C by name; the job reverts to A with C named as parent.
--           C's new row is a root, so neither 180 guard trips, and A was
--           admitted again, read and write;
--       (b) the ATTACH-TIME FOLLOW: attach A; B succeeds it; detach A; the
--           job reverts to A (180 withholds the copy); restore B by name.
--           166's lineage follow walks B's successors, which now include A
--           ("A succeeded B"), and A, holding no un-detached row, got a
--           whole-window copy of B's new root and was admitted again;
--     and, one step further, any successor registered from such a copy (a
--     LEARNED.md edit after the revert) inherited the group through it.
--   * 166's attach-time follow FLATTENED its copies: every successor down
--     the lineage, however deep, got a copy naming the new attachment
--     itself, so the chain walk never saw the identities in between. The
--     same final lineage then answered differently by the order it was
--     built in: a successor D of a detached identity A was admitted once an
--     ancestor of A was attached by name ((b) above plus one prompt edit
--     before the restore; or, with no revert, attach A, detach A, D succeeds
--     A, attach A's predecessor), and detaching A AFTER an ancestor's attach
--     revoked nothing the follow had copied below A, while the same lineage
--     built by the registration (each copy naming its parent's row) was
--     revoked both times.
--   * A detach is the operator's act on the identity a JOB runs, but a
--     copy's chain names only the rows it was copied through, not the
--     identities the agent was registered from. So detaching the running
--     identity A did not cut off the job: when it reverted a prompt edit
--     and the revert was registered (the earlier identity P's key again,
--     naming A as its parent), P, never detached and still holding the
--     live copy it inherited before the detach, kept the group, read and
--     write; and a successor registered from two parents, one of them
--     detached, was admitted or not by which parent its copy happened to
--     name, so the same final lineage answered differently by the order it
--     was built in.
--   * The reverse-pair guard withheld the copy from an identity that was
--     NEVER detached, and an attachment is also 166's RESTRICTION (`ROL01`,
--     may-run). So after the operator attached B by name, a revert to A
--     left A outside the role: while the role had no holder, the reverted
--     job ran and wrote freely while B could not. Under 166 the copy held A.
--
-- ===================================================================
-- 2. THE RULES
--
-- A DETACH IS STICKY AND CUTS OFF THE LINEAGE (the derivation,
-- `epigraph_role_derived_memberships`): call an agent CUT OFF from a role
-- when it holds ANY detached row for the role (at any time), or when it has
-- a parent in `agent_succession` (any recorded parent, a revert's included)
-- that is cut off and holds no live DIRECT row for the role at `p_at`. In
-- the attached arm, a SUCCESSION COPY (`inherited_from` set) admits nothing
--   * to a cut-off agent; and
--   * to any agent whose copy chain passes through a COPY held by a cut-off
--     agent (a dead hop).
-- Equivalently: walk up `agent_succession` from the agent asked about and
-- from the agent of every copy on its chain, through parents that hold no
-- live row made by name; the copy counts only if no agent judged or reached
-- holds a detached row for the role. Up to the first identity on the way
-- that holds a live row made by name, the answer does not depend on the
-- order the registrations, attaches and detaches came in, nor on which
-- parent a copy happens to chain through. That identity ends the walk, so an
-- identity below it is judged by its own copy chain: out when the chain runs
-- through a detached row, in when it names the row made by name or chains
-- through a clean parent. The documented restore (a detached identity
-- attached by name again) is the usual case: its successor registered before
-- the detach holds a copy of its old, now detached copy and stays out; one
-- registered after the restore is in, with the same succession edges,
-- detached rows and rows made by name.
-- The walk reads only the successions the registration recorded: a revert
-- counts only when it is registered (the earlier identity's key again, naming
-- the identity it reverts from as parent), and a job's next identity is below
-- the one that ran only when it is registered with that one as its parent. A
-- job that goes back to an identity without that registration records no
-- edge, so that identity is judged by the parents it was registered from
-- before, and keeps its old copy when they are clean; an edit or revert
-- registered with a parent other than the identity the group's lane ran last
-- (a host that keys the parent per model) is judged by that parent the same
-- way. So the cut-off reaches the whole job only from a host that keys
-- succession on the group's lane: the lane's newest identity, whatever model,
-- is the parent of every edit or revert. Until then, a detach cuts a job off
-- only when EVERY live row made by name for the role is detached that any
-- identity the host may run for the group holds, or that any of their live
-- copies chains up to, not only the one at the top of the running identity's
-- chain: after a documented restore the running identity holds its own row
-- made by name, and an earlier identity whose copy roots at an older one
-- keeps the group, read and write, when the job goes back to it unregistered.
-- A DIRECT attachment (`inherited_from` NULL, the operator's own act naming
-- the identity) counts as before wherever it sits, as the row asked about or
-- as a chain's root, even when its agent also holds a detached row, and an
-- agent holding a live one ends the walk up the lineage. So:
--   * an identity the operator detached is admitted again only by attaching
--     it by name;
--   * a detach of the identity a job runs cuts off the job: its later
--     identities (prompt edits) and an earlier identity it reverts to (one
--     that still holds a live copy), each registered with the identity that
--     ran as its parent (above), are out, however many registrations later,
--     until the operator attaches the identity that runs by name;
--   * but an identity the operator attached by name keeps the group through
--     that row, also when the job reverts to it: to cut such a job off,
--     detach that identity too;
--   * the documented restore still works: detach the running identity's
--     stale copy, attach it by name; it and its later successors (copies
--     whose root is that direct row) are members again;
--   * a successor of a detached identity's copy must be attached by name
--     too, if it is to be a member.
-- Limits: the walk follows `agent_succession`, so a copy written by hand for
-- an agent with no recorded succession is judged by its chain alone (its
-- dead hops still count). Detached rows are read without an index (166's
-- `idx_role_agents_live` covers un-detached rows only); `role_agents` holds
-- one row per attachment and copy, so the read stays small.
-- Everything else in 179's rule is unchanged: the holder test, the one-folder
-- rule, the live-hop chain walk, the binding window.
--
-- A REVERT ALWAYS RESTRICTS (the registration,
-- `epigraph_register_agent_identity`, step 5b): 180's reverse-pair guard is
-- dropped and the chain guard is kept. A parent row whose chain reaches a row
-- of the child is still never copied back onto it (that would hand back the
-- very attachment the operator detached); any other parent row is copied, a
-- revert's included, so the reverted identity is held by the role's
-- restriction exactly as its parent is. Whether that copy also grants is the
-- derivation's question: it does only for an identity never detached.
-- `role_attachments_withheld` in the registration's audit row now counts the
-- chain guard's rows only.
--
-- THE FOLLOW CHAINS (166's attach-time lineage follow,
-- `epigraph_role_agents_follow_lineage`): each successor's copy names the
-- row of the identity it SUCCEEDED, never the new attachment past it,
-- exactly as the registration's step 5b names its parent's row. The walk
-- goes breadth first along `agent_succession`, each identity once, at its
-- shortest distance from the attached one; a successor's predecessor is a
-- parent on the level above. Each gap is split by that predecessor's rows
-- over the window (the copies this walk writes for it, or its own
-- un-detached rows where it had no gap), and each piece names the row that
-- covers it. So the derivation's chain walk sees every identity in between:
--   * a detached identity in between is a dead hop (the sticky rule), so its
--     successors regain nothing through an ancestor's attachment;
--   * a later detach of an identity in between revokes what was copied
--     through it (179's rule), whichever order the lineage was built in;
--   * a successor whose predecessor already holds a row of its own chains
--     through that row, so it is admitted exactly when it would have been
--     had it registered after that row existed.
-- A successor with two parents on the level above has its copy chained
-- through ONE of them (one `inherited_from` chain names one path): a parent
-- that holds a detached row for the role, or was itself reached through one,
-- comes first, then the lowest id. Which one it is does not decide whether a
-- detach reaches the successor while no identity on the way holds a live row
-- made by name; once the detached parent is attached by name again (the
-- documented restore), it does: a copy chained through its old copy stays
-- out, one through the clean parent is in (the walk stops at the row made by
-- name, above).
-- The follow still copies into every GAP of every successor, a detached
-- successor included: its copy restricts (166), and under the sticky rule
-- grants it nothing. Skipping it would take the restriction away from that
-- identity and from every later successor registered from it, which is the
-- escape the third bullet of section 1 describes. The copies are written in
-- one INSERT, in walk order, so a copy's source row is visible to the
-- insert guard before the copy (an out-of-order write fails ROL02, loud);
-- their own firings find every successor covered and write nothing. 166's
-- skip of a successor that "inherited this row before" is dropped: it never
-- fired for a row inserted in the same statement as its copies, and only
-- left a hand INSERT's successor partly uncovered.
--
-- ===================================================================
-- 3. RE-STATEMENTS
--
-- Three bodies, each re-stated whole from the latest one, each delta marked
-- `195`:
--   * `epigraph_role_derived_memberships(uuid, timestamptz)` from 179's body;
--   * `epigraph_register_agent_identity(bytea, uuid, text, text, text, bytea,
--     jsonb)` from 180's body (no migration between 180 and this file
--     re-states it);
--   * `epigraph_role_agents_follow_lineage()` from 166's body (no migration
--     between 166 and this file re-states it).
-- A precondition refuses (55000, nothing changed) unless each still carries
-- that body (md5 of `prosrc`), so applying this file over a later
-- re-statement can never drop that migration's delta. Signature, owner, ACL,
-- volatility and `search_path` (`public, pg_temp`, `pg_temp` last as 190
-- requires) are unchanged; CREATE OR REPLACE keeps owner and ACL, and this
-- file grants nothing. A later migration that re-states any of the three
-- starts from this file's body.
--
-- ===================================================================
-- 4. UNDO
--
-- `docs/runbooks/195-undo.sql` restores 179's derivation, 180's
-- registration and 166's follow byte for byte (md5-guarded: it refuses over
-- any body but 195's or the one it restores). Run it BEFORE `180-undo.sql`,
-- which refuses a 195 registration. After an undo, a detached identity can
-- be re-admitted by a later copy again, a job whose running identity was
-- detached keeps the group through a revert to an earlier copy holder
-- again, a revert onto a predecessor of an
-- identity attached by name is withheld (unrestricted) again, and the follow
-- flattens again: detach any such copy, or attach the running identity by
-- name, by hand. The rows written while 195 was in force stay as written
-- (append-only), chained copies included.
--
-- DEPLOY: no binary depends on it (no signature changes); apply with any
-- migrator that carries it. Before attaching any further identity to a role.

SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- Precondition: 166's `role_agents` exists, and all three functions still
-- carry the bodies this file re-states (179's derivation, 180's
-- registration, 166's follow).
-- -------------------------------------------------------------------
DO $$
DECLARE
    v_found text;
    v_check record;
BEGIN
    IF to_regclass('public.role_agents') IS NULL THEN
        RAISE EXCEPTION '195: public.role_agents is absent; apply 166 first (nothing was changed)'
            USING ERRCODE = '55000';
    END IF;
    FOR v_check IN
        SELECT * FROM (VALUES
            ('public.epigraph_role_derived_memberships(uuid, timestamptz)',
             '65bd0fc12e34b4172607dd2864fb7f66', '179'),
            ('public.epigraph_register_agent_identity(bytea, uuid, text, text, text, bytea, jsonb)',
             'c31ae71f307a0573716e51fe17aa5dc8', '180'),
            ('public.epigraph_role_agents_follow_lineage()',
             'f273e115ab880c9ff2cf7e2bab2f6060', '166')
        ) AS c(signature, expected, origin)
    LOOP
        SELECT md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
         WHERE p.oid = to_regprocedure(v_check.signature);
        IF v_found IS DISTINCT FROM v_check.expected THEN
            RAISE EXCEPTION '195: % is not the body 195 re-states (%''s, md5 %); found md5 %. '
                            'Another migration re-bodied it, or % is not applied; nothing was '
                            'changed', v_check.signature, v_check.origin, v_check.expected,
                            COALESCE(v_found, '(absent)'), v_check.origin
                USING ERRCODE = '55000',
                      HINT = 'Apply a reconciling migration that re-states the function with '
                             'every delta instead of this one.';
        END IF;
    END LOOP;
END $$;

-- -------------------------------------------------------------------
-- The derivation (179's body); delta: the sticky detach that cuts off the
-- lineage (section 2). In the attached arm a succession copy counts for
-- nothing when its agent, or the agent of any copy on its chain, holds a
-- detached row for the role or descends from such an agent through agents
-- with no live row made by name. Direct rows are never judged, and an agent
-- holding a live one ends the walk up the lineage.
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

-- ===================================================================
-- The registration (180's body); delta: step 5b keeps the chain guard only
-- (section 2: a revert always restricts).
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_register_agent_identity(
    p_identity_pubkey bytea,
    p_parent_agent    uuid,
    p_model           text,
    p_prompt_hash     text,
    p_group_folder    text,
    p_signing_pubkey  bytea,
    p_snapshot        jsonb)
RETURNS TABLE (agent_id uuid,
               agent_created boolean,
               succession_created boolean,
               snapshot_id uuid,
               snapshot_created boolean,
               signing_key_registered boolean,
               operator_id uuid,
               inherited boolean,
               link_live boolean,
               inherit_reason text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
#variable_conflict use_column
DECLARE
    c_files      constant text[] := ARRAY['identity_md', 'global_claude_md',
                                          'group_claude_md', 'learned_md'];
    v_child      uuid;
    v_props      jsonb;
    v_parent     uuid := p_parent_agent;
    v_created    boolean := false;
    v_succ_rows  integer := 0;
    v_snapshot   uuid;
    v_snap_new   boolean := false;
    v_key_new    boolean := false;
    v_parent_op  uuid;
    v_child_op   uuid;
    v_inherited  boolean := false;
    v_reason     text;
    v_in_prompt  jsonb;
    v_refused    text[] := '{}';
    v_blob       bytea[] := ARRAY[NULL, NULL, NULL, NULL]::bytea[];
    v_entry      jsonb;
    v_hash       bytea;
    v_size       integer;
    v_stored     integer;
    v_unknown    text[];
    v_live       boolean;
    v_link_live  boolean;
    v_personal   uuid;
    v_fk         record;
    v_hit        boolean;
    v_binding    text;
    v_bound      bytea;
    v_rec_model  text;
    v_rec_hash   text;
    v_roles_new  integer := 0;  -- 166
    v_shared     boolean := false;  -- 166
    v_withheld   integer := 0;  -- 180
    i            integer;
BEGIN
    -- Inputs.
    IF p_identity_pubkey IS NULL OR octet_length(p_identity_pubkey) <> 32 THEN
        RAISE EXCEPTION 'epigraph_register_agent_identity: the identity public key must be 32 bytes'
            USING ERRCODE = '22023';
    END IF;
    IF p_model IS NULL OR btrim(p_model) = '' OR length(p_model) > 255 THEN
        RAISE EXCEPTION 'epigraph_register_agent_identity: a model is required'
            USING ERRCODE = '22023';
    END IF;
    IF p_prompt_hash IS NULL OR p_prompt_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'epigraph_register_agent_identity: the prompt hash must be 64 lowercase hex '
                        'characters'
            USING ERRCODE = '22023';
    END IF;
    IF p_group_folder IS NULL OR p_group_folder = '' OR length(p_group_folder) > 255 THEN
        RAISE EXCEPTION 'epigraph_register_agent_identity: a group folder is required'
            USING ERRCODE = '22023';
    END IF;
    IF p_signing_pubkey IS NOT NULL AND octet_length(p_signing_pubkey) <> 32 THEN
        RAISE EXCEPTION 'epigraph_register_agent_identity: the signing public key must be 32 bytes'
            USING ERRCODE = '22023';
    END IF;
    IF p_signing_pubkey = p_identity_pubkey THEN
        RAISE EXCEPTION 'epigraph_register_agent_identity: the signing key must not be the '
                        'identity key'
            USING ERRCODE = '22023';
    END IF;
    IF p_snapshot IS NULL OR jsonb_typeof(p_snapshot) <> 'object' THEN
        RAISE EXCEPTION 'epigraph_register_agent_identity: the snapshot must be a JSON object'
            USING ERRCODE = '22023';
    END IF;
    SELECT array_agg(k ORDER BY k) INTO v_unknown
      FROM jsonb_object_keys(p_snapshot) AS k
     WHERE k <> ALL (c_files || ARRAY['in_prompt', 'runner_version', 'host_sha']);
    IF v_unknown IS NOT NULL THEN
        RAISE EXCEPTION 'epigraph_register_agent_identity: unknown snapshot keys %', v_unknown
            USING ERRCODE = '22023';
    END IF;
    v_in_prompt := p_snapshot -> 'in_prompt';
    IF v_in_prompt IS NULL OR jsonb_typeof(v_in_prompt) <> 'object' THEN
        RAISE EXCEPTION 'epigraph_register_agent_identity: snapshot.in_prompt must be a JSON object'
            USING ERRCODE = '22023';
    END IF;

    -- Every link write and every registration, one at a time (107 section 10).
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));

    -- The parent. Equal to the child (same key): no lineage to record.
    IF v_parent IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM public.agents a WHERE a.id = v_parent) THEN
            RAISE EXCEPTION 'epigraph_register_agent_identity: parent % does not exist', v_parent
                USING ERRCODE = '22023';
        END IF;
        IF EXISTS (SELECT 1 FROM public.agents a
                    WHERE a.id = v_parent AND a.public_key = p_identity_pubkey) THEN
            v_parent := NULL;
        -- 180: a legacy fleet identity (agent_type 'human' by the old create
        -- path's column default, a LIVE operator link, a backfilled
        -- identity-legacy key, and no human marker) is an LLM agent too; see
        -- `epigraph_is_legacy_fleet_parent`.
        ELSIF (NOT EXISTS (SELECT 1 FROM public.agents a
                            WHERE a.id = v_parent
                              AND (a.key_kind = 'derived' OR a.properties ? 'llm_model')
                              AND a.agent_type IS DISTINCT FROM 'human')
               AND NOT public.epigraph_is_legacy_fleet_parent(v_parent))  -- 180
              OR public.epigraph_is_human_operator(v_parent) THEN
            RAISE EXCEPTION 'AID03: parent % is not an LLM agent', v_parent
                USING ERRCODE = 'AID03',
                      HINT = 'A parent is the identity the host last registered for this group.';
        END IF;
    END IF;

    -- 1. Find or create the agent by its identity key.
    SELECT a.id, a.properties INTO v_child, v_props
      FROM public.agents a WHERE a.public_key = p_identity_pubkey;
    IF v_child IS NULL THEN
        INSERT INTO public.agents (public_key, agent_type, key_kind, properties)
        VALUES (p_identity_pubkey, 'llm', 'derived',
                jsonb_build_object('llm_model', p_model, 'llm_prompt_hash', p_prompt_hash,
                                   'source', 'epiclaw'))
        RETURNING id INTO v_child;
        v_created := true;
    ELSE
        IF NOT EXISTS (SELECT 1 FROM public.agent_succession s WHERE s.child_agent_id = v_child)
           AND NOT EXISTS (SELECT 1 FROM public.agent_prompt_snapshots s
                            WHERE s.agent_id = v_child)
           AND EXISTS (SELECT 1 FROM public.claims c WHERE c.agent_id = v_child) THEN
            RAISE EXCEPTION 'AID05: agent % has authored claims and was never registered; it is '
                            'not an EpiClaw identity to adopt', v_child
                USING ERRCODE = 'AID05';
        END IF;
        -- AID09: a never-registered agent is adopted only when it is FRESH,
        -- decided by a GENERIC scan rather than a list, so a binding table
        -- added later fails closed without touching this function. Fresh means
        -- no row in any table references the agent through a foreign key into
        -- `agents`, except:
        --   * its GENUINE personal group (`kind 'personal'`, the personal
        --     did_key, created by the agent itself) and its own membership of
        --     that group, which is the shape epigraph-mcp creates when it meets
        --     an identity before the host registers it;
        --   * its own `identity-legacy` key (the 161 backfill);
        --   * audit rows (`security_events`), which bind nothing;
        --   * `claims`, which AID05 already decides.
        -- It also refuses the two bindings no foreign key into `agents` can
        -- see: being an OAuth client's owner, and sharing the personal group
        -- with any other member.
        IF NOT EXISTS (SELECT 1 FROM public.agent_succession s WHERE s.child_agent_id = v_child)
           AND NOT EXISTS (SELECT 1 FROM public.agent_prompt_snapshots s
                            WHERE s.agent_id = v_child) THEN
            SELECT g.id INTO v_personal
              FROM public.groups g
             WHERE g.did_key = 'did:epigraph:personal:' || v_child::text
               AND g.kind = 'personal'
               AND g.created_by_agent_id = v_child;
            FOR v_fk IN
                SELECT c.conrelid AS rel, a.attname AS col
                  FROM pg_catalog.pg_constraint c
                  JOIN pg_catalog.pg_attribute a
                    ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
                 WHERE c.contype = 'f'
                   AND c.confrelid = 'public.agents'::regclass
                   AND array_length(c.conkey, 1) = 1
                   AND c.conrelid NOT IN ('public.security_events'::regclass,
                                          'public.claims'::regclass)
                 ORDER BY c.conrelid::regclass::text, a.attname
            LOOP
                -- A table this owner cannot read is not "unbound": fail closed.
                BEGIN
                EXECUTE format(
                    'SELECT EXISTS (SELECT 1 FROM %s WHERE %I = $1%s)',
                    v_fk.rel::regclass, v_fk.col,
                    CASE
                        WHEN v_fk.rel = 'public.groups'::regclass
                            THEN ' AND id IS DISTINCT FROM $2'
                        WHEN v_fk.rel = 'public.group_memberships'::regclass
                            THEN ' AND group_id IS DISTINCT FROM $2'
                        WHEN v_fk.rel = 'public.agent_keys'::regclass
                             AND v_fk.col = 'agent_id'
                            THEN ' AND key_type <> ''identity-legacy'''
                        ELSE ''
                    END)
                  INTO v_hit
                  USING v_child, v_personal;
                EXCEPTION WHEN insufficient_privilege THEN
                    v_hit := true;
                END;
                IF v_hit THEN
                    v_binding := v_fk.rel::regclass::text || '.' || v_fk.col;
                    EXIT;
                END IF;
            END LOOP;
            IF v_binding IS NULL AND EXISTS (SELECT 1 FROM public.oauth_clients oc
                                            WHERE oc.owner_id = v_child) THEN
                v_binding := 'oauth_clients.owner_id';
            END IF;
            IF v_binding IS NULL AND v_personal IS NOT NULL
               AND EXISTS (SELECT 1 FROM public.group_memberships m
                            WHERE m.group_id = v_personal AND m.agent_id <> v_child) THEN
                v_binding := 'another member of its personal group';
            END IF;
            IF v_binding IS NOT NULL THEN
                RAISE EXCEPTION 'AID09: agent % was never registered and is not fresh (bound '
                                'through %); it is not an EpiClaw identity to adopt',
                                v_child, v_binding
                    USING ERRCODE = 'AID09';
            END IF;
        END IF;
        -- What the identity was registered under: its earliest snapshot.
        SELECT s.model, s.prompt_hash INTO v_rec_model, v_rec_hash
          FROM public.agent_prompt_snapshots s
         WHERE s.agent_id = v_child
         ORDER BY s.first_seen, s.id
         LIMIT 1;
        IF FOUND AND (v_rec_model IS DISTINCT FROM p_model
                      OR v_rec_hash IS DISTINCT FROM p_prompt_hash) THEN
            RAISE EXCEPTION 'epigraph_register_agent_identity: agent % is registered under another '
                            'model or prompt hash; the identity key is a function of both',
                            v_child
                USING ERRCODE = '22023';
        END IF;
        -- Display only, re-asserted (and only written when it differs, so a
        -- repeat start writes nothing here).
        IF v_props ->> 'llm_model' IS DISTINCT FROM p_model
           OR v_props ->> 'llm_prompt_hash' IS DISTINCT FROM p_prompt_hash THEN
            UPDATE public.agents a
               SET properties = COALESCE(a.properties, '{}'::jsonb)
                                || jsonb_build_object('llm_model', p_model,
                                                      'llm_prompt_hash', p_prompt_hash),
                   updated_at = now()
             WHERE a.id = v_child;
        END IF;
    END IF;

    -- 2. The blobs, then the snapshot (D4).
    FOR i IN 1 .. 4 LOOP
        v_entry := p_snapshot -> c_files[i];
        CONTINUE WHEN v_entry IS NULL OR jsonb_typeof(v_entry) = 'null';
        IF jsonb_typeof(v_entry) <> 'object' THEN
            RAISE EXCEPTION 'epigraph_register_agent_identity: snapshot.% must be null or an object',
                            c_files[i]
                USING ERRCODE = '22023';
        END IF;
        IF v_entry ? 'refused' THEN
            IF v_entry <> '{"refused": true}'::jsonb THEN
                RAISE EXCEPTION 'epigraph_register_agent_identity: a refused file is exactly '
                                '{"refused": true} (snapshot.%)', c_files[i]
                    USING ERRCODE = '22023';
            END IF;
            v_refused := v_refused || c_files[i];
            CONTINUE;
        END IF;
        IF (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(v_entry) AS k)
           IS DISTINCT FROM ARRAY['blob_hash', 'codec', 'content', 'raw_size']
           OR v_entry ->> 'codec' IS DISTINCT FROM 'zstd'
           OR NOT COALESCE(v_entry ->> 'blob_hash' ~ '^[0-9a-f]{64}$', false)
           OR jsonb_typeof(v_entry -> 'raw_size') IS DISTINCT FROM 'number'
           OR NOT COALESCE(v_entry ->> 'content' ~ '^([0-9a-f]{2})+$', false) THEN
            RAISE EXCEPTION 'epigraph_register_agent_identity: snapshot.% must be '
                            '{blob_hash: 64 hex, raw_size: integer, codec: "zstd", content: hex}',
                            c_files[i]
                USING ERRCODE = '22023';
        END IF;
        v_hash := decode(v_entry ->> 'blob_hash', 'hex');
        v_size := (v_entry ->> 'raw_size')::integer;
        INSERT INTO public.agent_prompt_blobs (blob_hash, codec, raw_size, content)
        VALUES (v_hash, 'zstd', v_size, decode(v_entry ->> 'content', 'hex'))
        ON CONFLICT (blob_hash) DO NOTHING;
        IF NOT FOUND THEN
            SELECT b.raw_size INTO v_stored FROM public.agent_prompt_blobs b
             WHERE b.blob_hash = v_hash;
            IF v_stored IS DISTINCT FROM v_size THEN
                RAISE EXCEPTION 'epigraph_register_agent_identity: blob % is stored with a '
                                'different size; refusing to record it',
                                v_entry ->> 'blob_hash'
                    USING ERRCODE = '22023';
            END IF;
        END IF;
        v_blob[i] := v_hash;
    END LOOP;

    INSERT INTO public.agent_prompt_snapshots
           (agent_id, group_folder, model, prompt_hash, identity_md, global_claude_md,
            group_claude_md, learned_md, in_prompt, blob_refused, runner_version, host_sha)
    VALUES (v_child, p_group_folder, p_model, p_prompt_hash, v_blob[1], v_blob[2],
            v_blob[3], v_blob[4], v_in_prompt, v_refused,
            p_snapshot ->> 'runner_version', p_snapshot ->> 'host_sha')
    ON CONFLICT ON CONSTRAINT agent_prompt_snapshots_one_per_state DO NOTHING
    RETURNING id INTO v_snapshot;
    IF v_snapshot IS NOT NULL THEN
        v_snap_new := true;
    ELSE
        SELECT s.id INTO v_snapshot
          FROM public.agent_prompt_snapshots s
         WHERE s.agent_id = v_child AND s.group_folder = p_group_folder AND s.model = p_model
           AND s.identity_md IS NOT DISTINCT FROM v_blob[1]
           AND s.global_claude_md IS NOT DISTINCT FROM v_blob[2]
           AND s.group_claude_md IS NOT DISTINCT FROM v_blob[3]
           AND s.learned_md IS NOT DISTINCT FROM v_blob[4]
           AND s.in_prompt = v_in_prompt AND s.blob_refused = v_refused;
        UPDATE public.agent_prompt_snapshots s
           SET last_seen = GREATEST(s.last_seen, now())
         WHERE s.id = v_snapshot;
    END IF;

    -- 3. The succession, and the display parent.
    IF v_parent IS NOT NULL THEN
        INSERT INTO public.agent_succession (child_agent_id, parent_agent_id, group_folder,
                                             snapshot_id)
        VALUES (v_child, v_parent, p_group_folder, v_snapshot)
        ON CONFLICT DO NOTHING;
        GET DIAGNOSTICS v_succ_rows = ROW_COUNT;
        UPDATE public.agents a SET parent_agent_id = v_parent, updated_at = now()
         WHERE a.id = v_child AND a.parent_agent_id IS NULL;
    END IF;

    -- 4. The signing key (D2). The same key again is a no-op and is checked
    -- against nothing else, so a copy of it that someone records elsewhere
    -- once it is public cannot block the identity. A fresh binding must be
    -- bound nowhere as an attested key (this agent's rotated or revoked keys
    -- included: a key is never re-activated) and be no agent's identity key.
    IF p_signing_pubkey IS NOT NULL THEN
        SELECT k.public_key INTO v_bound
          FROM public.agent_keys k
         WHERE k.agent_id = v_child AND k.key_type = 'signing' AND k.status = 'active';
        IF v_bound IS NULL THEN
            IF EXISTS (SELECT 1 FROM public.agent_keys k
                        WHERE k.public_key = p_signing_pubkey
                          AND lower(btrim(k.key_type)) IN ('signing', 'identity-legacy'))
               OR EXISTS (SELECT 1 FROM public.agents a WHERE a.public_key = p_signing_pubkey) THEN
                RAISE EXCEPTION 'epigraph_register_agent_identity: the signing key is already bound '
                                '(to another agent, or to this one before a rotation or revocation)'
                    USING ERRCODE = '22023';
            END IF;
            INSERT INTO public.agent_keys (agent_id, public_key, key_type, status)
            VALUES (v_child, p_signing_pubkey, 'signing', 'active');
            v_key_new := true;
        ELSIF v_bound <> p_signing_pubkey THEN
            RAISE EXCEPTION 'AID08: agent % already has a different active signing key; nothing '
                            'was recorded', v_child
                USING ERRCODE = 'AID08',
                      HINT = 'Revoking a bound signing key is a maintenance act; the host then '
                             'registers its new key.';
        END IF;
    END IF;

    -- 5. Inherit the link.
    v_child_op := public.epigraph_human_of(v_child, false);
    IF v_parent IS NULL THEN
        v_reason := 'no_parent';
    ELSE
        v_parent_op := public.epigraph_human_of(v_parent, true);
        IF v_parent_op IS NULL THEN
            v_reason := CASE WHEN EXISTS (SELECT 1 FROM public.operator_links l
                                           WHERE l.agent_id = v_parent AND l.retired)
                             THEN 'parent_link_retired'
                             ELSE 'parent_unlinked' END;
        ELSIF v_child_op IS NULL
              AND EXISTS (SELECT 1 FROM public.agent_prompt_snapshots s
                           WHERE s.agent_id = v_child AND s.group_folder <> p_group_folder) THEN
            -- A SHARED identity (it already runs in another group) that nobody
            -- has linked: whichever group's parent named it first would decide
            -- the operator of every group running it, and a container chooses
            -- its next identity through its own LEARNED.md. Record the lineage,
            -- link nothing; a shared identity is linked by a manual act.
            v_reason := 'shared_identity';
        ELSIF v_child_op IS NULL THEN
            -- The link body's own refusals (55000: 107's shared-signer
            -- fingerprint, single hop, one operator ever) refuse the LINK, not
            -- the registration. Their inputs include OPERATED_BY edges, which
            -- any application session can write, so letting one abort the
            -- call would let a container stop its group starting. The block
            -- rolls back only the body's own writes.
            BEGIN
                SELECT b.link_live INTO v_live
                  FROM public.epigraph_link_operator_body(
                           v_child, v_parent_op,
                           jsonb_build_object('source', 'epigraph_register_agent_identity',
                                              'inherited_from', v_parent,
                                              'group_folder', p_group_folder)) b;
                -- The body recorded the link (the child had none): that is
                -- the inheritance, live or not; `link_live` below says which.
                v_inherited := true;
                IF NOT COALESCE(v_live, false) THEN
                    v_reason := 'link_not_live';
                END IF;
            EXCEPTION WHEN SQLSTATE '55000' THEN
                v_reason := 'link_refused';
            END;
        ELSIF v_child_op = v_parent_op THEN
            -- Linked to the same operator already; a RETIRED link cannot
            -- write, which the host must hear about rather than "linked".
            v_reason := CASE WHEN EXISTS (SELECT 1 FROM public.operator_links l
                                           WHERE l.agent_id = v_child AND l.retired)
                             THEN 'child_link_retired'
                             ELSE 'already_linked' END;
        ELSE
            RAISE EXCEPTION 'AID07: agent % is linked to operator %, but its parent % is live-linked '
                            'to operator %; nothing was recorded', v_child, v_child_op, v_parent,
                            v_parent_op
                USING ERRCODE = 'AID07',
                      HINT = 'Re-pointing an agent to another operator is an out-of-band act.';
        END IF;
    END IF;
    v_child_op := public.epigraph_human_of(v_child, false);
    v_link_live := public.epigraph_human_of(v_child, true) IS NOT NULL;

    -- 5b (166). The parent's role attachments: every un-detached attachment
    -- of the parent that has not ended (live, or not yet started) is copied
    -- to the child over its window from now (or its own later start) to its
    -- own end, naming the row it came from: ONE ROW PER GAP the child's own
    -- un-detached rows for that role leave in that window, none where they
    -- cover it. So the child is attached for the whole of the parent's
    -- window (a short row of its own never ends its coverage early), a
    -- repeat registration finds nothing uncovered, and no copy overlaps a
    -- live row (the guard never aborts the registration). A parent row the
    -- child has ever inherited is not copied again (detached included: a
    -- detach is final, so a repeat registration naming the same parent never
    -- undoes an operator's detach). So a LEARNED.md edit or a model change
    -- does not detach an agent from its role. Each copy meets the table's
    -- guards and writes its own audit row. An attachment only ever refuses,
    -- so a copy never grants the child anything.
    -- A SHARED child (it already runs in another group folder: step 5's
    -- `shared_identity`) is copied ALIKE: an attachment only ever refuses,
    -- so skipping it would leave a linked, write-capable identity outside
    -- the role's restriction. The cost, accepted, is that the shared
    -- identity is dormant in every group it runs in while the role has no
    -- holder, so the audit row below FLAGS it (`role_attachments_shared =
    -- 'shared_identity'`) for the host to alert every group affected.
    -- 180: NEVER BACK ONTO ITS SOURCE. A parent row is not copied when the
    -- child is that row's own source: when its `inherited_from` chain
    -- (detached rows included: a detached source is exactly the case) reaches
    -- a row of the child. Copying would hand the earlier identity back the
    -- very attachment the operator may have detached from it. Withheld rows
    -- are counted in the audit row (`role_attachments_withheld`).
    -- 195: that is the only guard. A REVERT whose parent row does not come
    -- from the child (the host names the later identity as the earlier one's
    -- parent; "the parent succeeded the child" may be on record) is copied
    -- like any succession, so the reverted identity is held by the role's
    -- restriction exactly as its parent is. Whether the copy also GRANTS
    -- (179's attached mode) is the derivation's question: never to an
    -- identity the operator detached (the sticky rule there).
    IF v_parent IS NOT NULL THEN
        SELECT count(*) INTO v_withheld  -- 180
          FROM public.role_agents pr
         WHERE pr.agent_id = v_parent AND pr.detached_at IS NULL
           AND (pr.valid_to IS NULL OR pr.valid_to > now())
           AND NOT EXISTS (
                   SELECT 1 FROM public.role_agents c
                    WHERE c.agent_id = v_child AND c.inherited_from = pr.id)
           AND EXISTS (  -- 195: the chain guard alone
                   WITH RECURSIVE up (hop_id, hop_agent, hop_source) AS (
                       SELECT u.id, u.agent_id, u.inherited_from
                         FROM public.role_agents u WHERE u.id = pr.inherited_from
                       UNION
                       SELECT u.id, u.agent_id, u.inherited_from
                         FROM public.role_agents u JOIN up ON u.id = up.hop_source
                   )
                   SELECT 1 FROM up WHERE up.hop_agent = v_child);
        INSERT INTO public.role_agents (role, agent_id, valid_from, valid_to, reason,
                                        inherited_from)
        SELECT pr.role, v_child, lower(g.gap), upper(g.gap),
               'succession from ' || v_parent::text || ' in ' || p_group_folder, pr.id
          FROM public.role_agents pr
         CROSS JOIN LATERAL unnest(
                   tstzmultirange(tstzrange(GREATEST(now(), pr.valid_from), pr.valid_to))
                   - COALESCE((SELECT range_agg(tstzrange(c.valid_from, c.valid_to))
                                 FROM public.role_agents c
                                WHERE c.agent_id = v_child AND c.role = pr.role
                                  AND c.detached_at IS NULL),
                              '{}'::tstzmultirange)) AS g(gap)
         WHERE pr.agent_id = v_parent AND pr.detached_at IS NULL
           AND (pr.valid_to IS NULL OR pr.valid_to > now())
           AND NOT EXISTS (
                   SELECT 1 FROM public.role_agents c
                    WHERE c.agent_id = v_child AND c.inherited_from = pr.id)
           -- 180: never back onto its source (above); 195: the chain guard alone.
           AND NOT EXISTS (
                   WITH RECURSIVE up (hop_id, hop_agent, hop_source) AS (
                       SELECT u.id, u.agent_id, u.inherited_from
                         FROM public.role_agents u WHERE u.id = pr.inherited_from
                       UNION
                       SELECT u.id, u.agent_id, u.inherited_from
                         FROM public.role_agents u JOIN up ON u.id = up.hop_source
                   )
                   SELECT 1 FROM up WHERE up.hop_agent = v_child)
         ORDER BY pr.role, lower(g.gap);
        GET DIAGNOSTICS v_roles_new = ROW_COUNT;
        v_shared := v_roles_new > 0
                    AND EXISTS (SELECT 1 FROM public.agent_prompt_snapshots s
                                 WHERE s.agent_id = v_child
                                   AND s.group_folder <> p_group_folder);
    END IF;

    -- 6. The audit row, when something new was recorded.
    IF v_created OR v_succ_rows > 0 OR v_snap_new OR v_key_new OR v_inherited
       OR v_roles_new > 0 THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('agent.identity_registered', v_child, true,
                jsonb_build_object('parent_agent_id', v_parent,
                                   'group_folder', p_group_folder,
                                   'model', p_model,
                                   'prompt_hash', p_prompt_hash,
                                   'operator_id', v_child_op,
                                   'snapshot_id', v_snapshot,
                                   'agent_created', v_created,
                                   'succession_created', v_succ_rows > 0,
                                   'snapshot_created', v_snap_new,
                                   'signing_key_registered', v_key_new,
                                   'inherited', v_inherited,
                                   'link_live', v_link_live,
                                   'inherit_reason', v_reason,
                                   'role_attachments_copied', v_roles_new,
                                   'role_attachments_shared',
                                   CASE WHEN v_shared THEN 'shared_identity' END,
                                   'role_attachments_withheld', v_withheld,  -- 180
                                   'recorded_by', session_user));
    END IF;

    RETURN QUERY
    SELECT v_child, v_created, v_succ_rows > 0, v_snapshot, v_snap_new, v_key_new,
           v_child_op, v_inherited, v_link_live, v_reason;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_register_agent_identity(
    bytea, uuid, text, text, text, bytea, jsonb) FROM PUBLIC;

-- -------------------------------------------------------------------
-- The attach-time lineage follow (166's body); delta: the copies CHAIN
-- (section 2). Each successor's copy names the row of the identity it
-- succeeded, never the new attachment past it, so the derivation's chain
-- walk sees every identity in between (a detached one is a dead hop there,
-- and a later detach of one revokes what was copied through it). Same
-- windows, gaps, reason text and shared-successor flag as 166.
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_role_agents_follow_lineage()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    -- 195: the walk, one level of `agent_succession` at a time from
    -- NEW.agent_id (breadth first; each identity is reached once, at its
    -- shortest distance, so a revert's cycle ends the walk).
    v_window  tstzmultirange := tstzmultirange(tstzrange(NEW.valid_from, NEW.valid_to));
    v_seen    uuid[] := ARRAY[NEW.agent_id];
    v_level   uuid[] := ARRAY[NEW.agent_id];
    v_next    uuid[];
    -- 195: identities that hold a detached row for the role, or were reached
    -- through one (the predecessor rule below prefers them: fail closed).
    v_dead    uuid[] := '{}';
    v_agent   uuid;
    v_pred    uuid;
    v_gap     tstzmultirange;
    v_cover   tstzmultirange;
    v_piece   record;
    -- 195: the copies to write, in walk order (a copy's source row is always
    -- written before it, or already exists).
    c_id      uuid[] := '{}';
    c_agent   uuid[] := '{}';
    c_from    timestamptz[] := '{}';
    c_to      timestamptz[] := '{}';
    c_src     uuid[] := '{}';
BEGIN
    LOOP
        SELECT array_agg(DISTINCT s.child_agent_id ORDER BY s.child_agent_id) INTO v_next
          FROM public.agent_succession s
         WHERE s.parent_agent_id = ANY (v_level)
           AND s.child_agent_id <> ALL (v_seen);
        EXIT WHEN v_next IS NULL;
        FOREACH v_agent IN ARRAY v_next LOOP
            -- 195: the PREDECESSOR the copy chains through: a parent on the
            -- level above (already walked). With several, one that holds a
            -- detached row or was reached through one comes first (fail
            -- closed), then the lowest id. One `inherited_from` chain names
            -- one path: a successor with a second parent on the same level is
            -- judged through the first by this rule only.
            SELECT s.parent_agent_id INTO v_pred
              FROM public.agent_succession s
             WHERE s.child_agent_id = v_agent AND s.parent_agent_id = ANY (v_level)
             ORDER BY (s.parent_agent_id = ANY (v_dead)) DESC, s.parent_agent_id
             LIMIT 1;
            -- 166: one copy per GAP the successor's own un-detached rows leave
            -- in the window (none where they cover it), a detached successor
            -- included (its copy restricts).
            v_gap := v_window
                     - COALESCE((SELECT range_agg(tstzrange(c.valid_from, c.valid_to))
                                   FROM public.role_agents c
                                  WHERE c.agent_id = v_agent AND c.role = NEW.role
                                    AND c.detached_at IS NULL),
                                '{}'::tstzmultirange);
            -- 195: each gap is split by the predecessor's rows over the
            -- window, and each piece names the row covering it: NEW itself
            -- for the attached identity; otherwise the predecessor's own
            -- un-detached rows and the copies this walk writes for it, which
            -- together cover the whole window (it was walked, every gap of it
            -- filled).
            v_cover := '{}'::tstzmultirange;
            FOR v_piece IN
                WITH src (id, span) AS (
                    SELECT NEW.id, tstzrange(NEW.valid_from, NEW.valid_to)
                     WHERE v_pred = NEW.agent_id
                    UNION ALL
                    SELECT r.id, tstzrange(r.valid_from, r.valid_to)
                      FROM public.role_agents r
                     WHERE v_pred <> NEW.agent_id
                       AND r.agent_id = v_pred AND r.role = NEW.role
                       AND r.detached_at IS NULL
                    UNION ALL
                    SELECT p.id, tstzrange(p.vf, p.vt)
                      FROM unnest(c_id, c_agent, c_from, c_to) AS p(id, ag, vf, vt)
                     WHERE p.ag = v_pred
                )
                SELECT g.gap * s.span AS span, s.id AS src
                  FROM unnest(v_gap) AS g(gap)
                  JOIN src s ON g.gap && s.span
                 ORDER BY lower(g.gap * s.span)
            LOOP
                c_id    := c_id || gen_random_uuid();
                c_agent := c_agent || v_agent;
                c_from  := c_from || lower(v_piece.span);
                c_to    := c_to || upper(v_piece.span);
                c_src   := c_src || v_piece.src;
                v_cover := v_cover + tstzmultirange(v_piece.span);
            END LOOP;
            IF v_cover <> v_gap THEN
                -- Unreachable: the predecessor's rows cover the window. A copy
                -- is never written without its source row (nor left out).
                RAISE EXCEPTION '195: the lineage follow of attachment % found no row of % '
                                'covering % of %''s gap; nothing was attached',
                                NEW.id, v_pred, v_gap - v_cover, v_agent
                    USING ERRCODE = 'XX000';
            END IF;
            IF v_pred = ANY (v_dead)
               OR EXISTS (SELECT 1 FROM public.role_agents dd
                           WHERE dd.agent_id = v_agent AND dd.role = NEW.role
                             AND dd.detached_at IS NOT NULL) THEN
                v_dead := v_dead || v_agent;
            END IF;
        END LOOP;
        v_seen := v_seen || v_next;
        v_level := v_next;
    END LOOP;

    IF cardinality(c_id) = 0 THEN
        RETURN NULL;
    END IF;
    -- One statement: the copies, in walk order (each source row precedes the
    -- copies naming it, so the insert guard sees it), then one flag event per
    -- SHARED successor that received one, read from the copies actually
    -- written. The copies' own firings walk lineages this walk already
    -- covered and write (and flag) nothing. 195: 166's skip of a successor
    -- that "inherited this row before" is gone. A row inserted in this
    -- statement has no earlier copies, so the skip only ever fired for a hand
    -- INSERT that named an earlier row of the same statement, and it then
    -- left that successor's other gaps uncovered (unrestricted).
    WITH copied AS (
        INSERT INTO public.role_agents (id, role, agent_id, valid_from, valid_to, reason,
                                        inherited_from)
        SELECT u.id, NEW.role, u.agent_id, u.vf, u.vt,
               'lineage of ' || NEW.agent_id::text || ' (attachment ' || NEW.id::text || ')',
               u.src
          FROM unnest(c_id, c_agent, c_from, c_to, c_src)
               WITH ORDINALITY AS u(id, agent_id, vf, vt, src, ord)
         ORDER BY u.ord
        RETURNING role_agents.agent_id, role_agents.id
    )
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    SELECT 'platform.role_agent_copied_shared', c.agent_id, true,
           jsonb_build_object('attachment_id', NEW.id, 'role', NEW.role,
                              'from_agent', NEW.agent_id, 'reason', 'shared_identity',
                              'copies', jsonb_agg(c.id ORDER BY c.id))
      FROM copied c
     WHERE (SELECT count(DISTINCT s.group_folder) FROM public.agent_prompt_snapshots s
             WHERE s.agent_id = c.agent_id) > 1
     GROUP BY c.agent_id
     ORDER BY c.agent_id;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_agents_follow_lineage() FROM PUBLIC;
