-- 166_role_attached_agents.sql
-- Role-attached agents run only while a human holds the role.
--
-- ===================================================================
-- 1. WHY
--
-- Operator ruling: an agent attached to a role cannot run while no human is
-- attached to that role. A scheduled run that falls in such a gap is skipped
-- (the host's job, with an alert; nothing is queued), and a run in progress
-- when the holder's assignment ends may finish, but every write it makes
-- after the end is refused (this file's job).
--
-- Agents are NOT bound to roles for authority. An agent acts for the human it
-- is linked to (107/122), and that human holds a role through 123's
-- time-windowed `role_assignments`. "Attached to a role" means the role's own
-- agents: its curator and the fleet identities that run the role's schedules.
-- Until now that attachment existed only on the host. This file records it
-- and enforces the ruling at write time, as a second control behind the
-- host's skip.
--
-- WHAT THE DATABASE GUARANTEES, AND WHAT IT DOES NOT. The rule binds the
-- STAMPED principal and the claim's AUTHOR column. An application session
-- that writes as itself, stamped as the attached agent, is refused in a gap.
-- But a session that can choose its own principal can stamp a DIFFERENT
-- identity of the same human (the human itself, an unattached sibling agent,
-- or an ancestor identity registered before the attachment) as both writer
-- and author, and nothing here can tell it from that identity's own write.
-- So the database enforces the ruling only against a writer that does not
-- choose its own principal (the API, which stamps the authenticated
-- viewer). A container that holds the application DSN directly can stamp
-- itself as another principal; it is held by the host's skip, not by this
-- file. Section 3 says which writes the rule covers: every write an
-- application session makes.
--
-- `role_agents` CONFERS NOTHING. It only adds a refusal. An attachment never
-- grants an agent a group, a scope or a read; whatever the agent may do, it
-- may do only through its linked human, as before.
--
-- ===================================================================
-- 2. THE RECORD: `role_agents`
--
-- One row per (role, agent, window): `valid_from`, an optional `valid_to`,
-- who wrote it (`attached_by`, the writing login), why, and, for a row a
-- succession copied, the row it was copied from (`inherited_from`). A row is
-- LIVE at time t when it is not detached, `valid_from <= t` and
-- `t < valid_to` (or no `valid_to`).
--
-- Append-only, on every role (a superuser and the table owner included,
-- short of disabling triggers). The guards raise `ROL02`:
--   * on INSERT: a detach field set; a back-dated `valid_from` (more than a
--     minute in the past); provenance the writer supplied (`attached_by`
--     other than the writing login, `created_at` other than `now()`); a
--     HUMAN (a registered human operator, or `agent_type 'human'`) or a role
--     node as the agent (agents only); an un-detached row for the same
--     (role, agent) whose window overlaps; an `inherited_from` row of another
--     role;
--   * on UPDATE: anything but the one detach (`detached_at = now()`,
--     `detached_by` = the detaching login, a reason, every other column
--     unchanged), and any change to a detached row (a detach is final);
--   * DELETE and TRUNCATE are refused outright.
-- An attachment FOLLOWS THE LINEAGE forward: inserting one also attaches,
-- over the same window, every registered successor of the agent (161's
-- `agent_succession`, transitively), each naming the row in
-- `inherited_from`. A successor that already holds its own un-detached rows
-- for the role gets one row per GAP those rows leave in the window, so the
-- whole window is covered and no row the guard would refuse is written. A
-- SHARED successor (one that runs in more than one group folder) is attached
-- alike and flagged (section 5). An operator who attaches an identity read
-- from a stale list therefore still attaches the identity that runs now. A
-- detach does
-- not follow (a successor stays attached until it is detached itself: the
-- direction that only refuses).
-- Each attach and each detach writes one `security_events` row
-- (`platform.role_agent_attached` / `platform.role_agent_detached`), whatever
-- path wrote it. The `platform.` prefix is already reserved to a privileged
-- session or a maintenance-owned definer (123 section 4), so an application
-- session cannot forge one.
--
-- WHO WRITES IT: a maintenance session (`epigraph_attach_agent_to_role` /
-- `epigraph_detach_agent_from_role`, or a direct statement meeting the same
-- guards) and the identity registration (section 5), which runs as a
-- maintenance-owned definer on the attestor's connection. Row security admits
-- exactly those (`epigraph_bypass()` or `epigraph_definer_bypass()`). The
-- application role holds SELECT only and reads no row.
--
-- ===================================================================
-- 3. THE RULE (`ROL01`)
--
-- Every write an application session makes (an INSERT, UPDATE, DELETE or
-- TRUNCATE of any table it can write) is refused `ROL01` when the ACTING
-- agent has a live attachment, unless, for EVERY live attachment of that
-- agent, at `clock_timestamp()`:
--   (a) the role has a live human holder (`epigraph_live_role_assignment`), and
--   (b) the agent's live-linked human (`epigraph_human_of(agent, true)`) is
--       that holder.
-- The ACTING agents of a write: the stamped principal (the writer), always;
-- and, for a claim, the agent it is ATTRIBUTED to (the author column), on an
-- insert, a re-open and a re-attribution (the claims trigger, below) and on
-- every UPDATE or DELETE of the row (the author arm), whoever writes it. A
-- claim an attached agent authored is its output: after its holder's end no
-- application session changes what it says, retires it or deletes it, the
-- human and a session with no principal included. The author arm does not
-- check an UPDATE that changes only the DERIVED caches the database keeps on
-- the row from everyone's evidence and jobs (the DS belief cache and its
-- frame, classification, beta parameters, embeddings, theme, the matcher's
-- scan mark, `updated_at`): that is another principal's evidence landing,
-- not the agent speaking, and refusing it would stop every evidence
-- submission on the agent's claims for the length of the gap. Every other
-- column, one added later included, is what the author said.
-- (b) also refuses an agent still linked to the PREVIOUS holder after a
-- handover. A link is permanent (107 refuses a second operator for an agent),
-- so such an agent stays refused: the remedies are to grant the role back to
-- its human, or to detach it and attach an identity linked to the new holder.
--
-- `clock_timestamp()`, not `now()`: `now()` is the transaction's start, so a
-- long-running transaction opened inside the window would keep writing past
-- `valid_to`. The ruling is "every write after the end is refused".
-- READ COMMITTED only: a write whose acting agent COULD be attached (any
-- agent: not a human operator, not a human or role node) under REPEATABLE
-- READ or SERIALIZABLE is refused `ROL01`, attached or not, and even while
-- its human holds the role. An assignment ended by a handover is REVOKED
-- (123's `epigraph_end_role_assignment`), and an attachment is a new row:
-- both are visibility questions, and an older snapshot would still see the
-- assignment live, or no attachment at all. The test is decided before the
-- gate and on what no attach changes, because every read in the
-- transaction, the gate's included, uses that older snapshot. A human may
-- use any isolation level. (No application write path uses another level.)
--
-- WHERE: one shared check, `epigraph_require_role_holder(agent)`, reached
-- three ways.
--   * `epigraph_role_agent_write_check()`, a BEFORE INSERT OR UPDATE OR
--     DELETE OR TRUNCATE ... FOR EACH STATEMENT trigger
--     (`role_agent_write_check`) on every table the application role writes
--     (the list below), on the stamped principal. A statement trigger fires
--     once per statement, whatever rows it touches (none included).
--   * The same function as a BEFORE UPDATE OR DELETE row trigger on
--     `claims` (`claims_role_agent_author`), on the row's author (old and,
--     on a re-attribution, new).
--   * The operator-binding path, by re-stating 123's
--     `epigraph_require_writer_scope` (which the claims trigger calls on the
--     author when the writer is the author or no principal is stamped, and on
--     the writer otherwise) and `epigraph_require_attributable` (the author,
--     when the writer is someone else); 153's trigger body is not touched.
--     These reach the author of an insert, a re-open and a re-attribution.
-- THE ONE RELIEF on an author: a RETIRED identity (`epigraph_agent_is_retired`).
-- A restatement of a RETIRED predecessor (the supersede act's
-- inherited author) is relieved of the check on that author ONLY when the
-- author identity is itself retired (`epigraph_agent_is_retired`: a retired
-- operator link and no live one, so it can never run again and naming it is
-- its human's act). An inherited author that is a live attached agent is
-- checked like any other: otherwise a sibling of the same human, or the human,
-- could restate the agent's claim under its name in the gap. The writer of a
-- restatement is checked either way. The author arm grants the same relief:
-- a retired identity's claim may be updated by its human.
--
-- EXEMPT: a privileged session (`epigraph_bypass()`: the maintenance role or a
-- superuser, i.e. the custodial path, and the system jobs that run on it),
-- as it is from OPL02, whatever principal it stamps. KEYED ON ARMING like
-- OPL02 (nothing is checked on an unarmed database), and NOT relieved by the
-- valve, which relieves OPL01 only. An agent with no live attachment, and an
-- attached agent while its human holds the role, write exactly as before.
--
-- COVERAGE: COMPLETE for the application role. The ruling refuses EVERY
-- write a run makes after its holder's assignment ends, and every table the
-- application role can INSERT, UPDATE or DELETE carries the statement
-- trigger: 79 tables on a database migrated to this file, measured from the
-- catalog (table- and column-level grants after 118 and every later
-- migration), with NO exemption. That includes `claims` (every column,
-- `is_current` and a same-author retire included, and DELETE), `evidence`,
-- `edges`, `mass_functions`, memberships and groups, the derived belief and
-- cluster tables, the audit and ledger tables (`security_events`,
-- `provenance_log`, `privatization_audit`: an audit row written for an
-- attached agent in its gap belongs to an act this check refuses), and the
-- OAuth, refresh-token and key tables (a token or a key minted for an
-- attached agent in its gap is that agent running). The catalog ratchet in
-- `role_attached_agents.rs` (`every_table_the_app_role_writes_carries_the_
-- role_holder_write_check`) re-measures the set, so a table a later
-- migration hands the application role (077's default privileges do) fails
-- it until it carries the trigger or an exemption with a concrete harm.
-- A write the application role makes THROUGH a maintenance-owned definer
-- into one of these tables meets the trigger too (it reads the session's
-- principal, not the role). The tables only such definers write, and the
-- application role cannot, are not checked: `elevation_sessions`,
-- `elevation_tickets`, `elevated_access`, `pending_admin_acts`,
-- `person_authenticators` and `passkey_enrollments` are PERSON flows
-- (elevation, passkeys, admin acts), and a person is never attached (ROL02);
-- `revoked_access_tokens` takes a token revocation (any client, an agent
-- included, may revoke its own token), which only ever takes authority away.
-- THE REMAINING STATED LIMIT is section 1's: a container that holds the
-- application DSN can stamp itself as another principal (or as none, for a
-- table other than `claims`), and nothing here can tell that from the other
-- identity's own write. The host's skip holds it.
-- A write that changes what an attached agent's claim says (its
-- `truth_value` included, so a belief recompute that rewrites it), or
-- retires or deletes it, fails as a whole in that agent's gap (a multi-row
-- UPDATE included; a human's supersede of the claim too, because it retires
-- the predecessor); a custodial correction runs on the maintenance DSN.
-- DEPLOY: creating 80 triggers takes a SHARE ROW EXCLUSIVE lock on each
-- table under this file's 3 s `lock_timeout`; on a busy database a timeout
-- rolls the whole migration back, and it is re-run.
--
-- ===================================================================
-- 4. THE QUESTION THE HOST AND EPIGRAPH-MCP ASK
--
-- `epigraph_role_agent_may_run(agent)` -> (may_run, role, holder, reason),
-- reason one of `unattached`, `held`, `no_holder`, `not_holder`, answered at
-- `clock_timestamp()` by the same predicate as ROL01. EXECUTE-able by
-- `epigraph_app` (epigraph-mcp refuses to boot on `may_run = false`) and by
-- `epigraph_identity_attestor` (the host asks before starting a container or
-- a role-owned schedule). Neither reads the table; each asks about one agent
-- at a time. That is still ENUMERABLE: `agents` is world-readable, so an
-- application session can ask about every agent id and rebuild the roster
-- (the first failing, or first, role per agent) and whether each role has a
-- holder. DISCLOSURE, accepted on that basis: the app role needs the answer
-- to refuse its own boot. `holder` is returned only when it IS the agent's
-- own linked human (an `operator_links` fact the app role already reads,
-- 107), never the holder an agent of a previous holder is missing.
--
-- THE ATTESTOR'S GRANT, OUT OF BAND. The grant to
-- `epigraph_identity_attestor` below is made only when that role exists when
-- this file runs. Where operations create (or re-create) the attestor login
-- after it, as 161's section 2 describes for a database the migration cannot
-- create roles on, run this together with 161's recipe:
--   GRANT EXECUTE ON FUNCTION public.epigraph_role_agent_may_run(uuid)
--       TO epigraph_identity_attestor;
-- Without it the host's question is denied (42501).
--
-- ===================================================================
-- 5. SUCCESSION
--
-- 161's `epigraph_register_agent_identity` is re-stated with its body
-- unchanged except for one step (5b): when a parent is named, the parent's
-- live (or not yet started) attachments are copied to the child, each with
-- `inherited_from`: the parent row's window from the registration on, minus
-- what the child's own un-detached rows for that role already cover, one row
-- per gap (so the child is attached for ALL of the parent's window, a repeat
-- registration finds nothing uncovered, and the guard's overlap test never
-- aborts the registration). A parent row the child has inherited before,
-- detached included, is not copied again (a detach is final: a repeat
-- registration does not re-attach the child).
--
-- A SHARED identity (the child already runs in another group folder) is
-- copied ALIKE, although it inherits no LINK (161 step 5,
-- `shared_identity`). The two differ in direction: a link would let the
-- first group's parent decide every group's operator, which grants; an
-- attachment only ever refuses. Skipping it would leave a linked,
-- write-capable shared identity outside its parent's role restriction (the
-- succession escape this step exists to close). The accepted cost is
-- availability: while the role has no holder, the shared identity is dormant
-- in EVERY group that runs it, which is what "agents attached to a role
-- cannot run" means. So the registration's audit row FLAGS it
-- (`role_attachments_shared = 'shared_identity'`, beside
-- `role_attachments_copied`) and the lineage follow (section 2) writes one
-- `platform.role_agent_copied_shared` security event per shared successor it
-- attaches, for the host to alert every affected group. Neither is written
-- again by a repeat start, which copies nothing. 161's result columns are
-- unchanged (the host and the repository read them): the flag is in the
-- audit, and `inherit_reason` already says `shared_identity` for an unlinked
-- shared child.
--
-- ORDER: REGISTER, THEN ATTACH. 161 adopts a never-registered identity only
-- while it is FRESH (no reference into `agents` but its own personal group,
-- legacy key, audit rows and claims). An attachment is such a reference, so
-- attaching an identity before the host first registers it makes that
-- registration abort `AID09` (fail closed: the identity stays refused). An
-- operator link is one too, so this is not specific to `role_agents`.
--
-- ===================================================================
-- 6. UNDO
--
-- `docs/runbooks/166-undo.sql` restores 123's two check bodies and 161's
-- registration body, then drops what this file creates. Roll back first any
-- epigraph-mcp built against this file: it calls
-- `epigraph_role_agent_may_run` at boot and fails closed without it.

SET LOCAL lock_timeout = '3s';

-- The copies below compute uncovered windows as multiranges (PostgreSQL 14+).
DO $$ BEGIN
    IF current_setting('server_version_num')::integer < 140000 THEN
        RAISE EXCEPTION '166 needs PostgreSQL 14 or later (multiranges); this server is %',
                        current_setting('server_version');
    END IF;
END $$;

-- ===================================================================
-- THE RECORD (section 2)
-- ===================================================================
CREATE TABLE IF NOT EXISTS public.role_agents (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    role           text NOT NULL REFERENCES public.platform_roles(key) ON DELETE RESTRICT,
    agent_id       uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    valid_from     timestamptz NOT NULL DEFAULT now(),
    valid_to       timestamptz,
    -- The database login that wrote the row (a maintenance login, or the
    -- attestor's for a succession copy).
    attached_by    text NOT NULL DEFAULT session_user,
    reason         text NOT NULL CONSTRAINT role_agents_reason_present
                       CHECK (length(btrim(reason)) > 0),
    inherited_from uuid REFERENCES public.role_agents(id) ON DELETE RESTRICT,
    created_at     timestamptz NOT NULL DEFAULT now(),
    detached_at    timestamptz,
    detached_by    text,
    detach_reason  text,
    CONSTRAINT role_agents_window CHECK (valid_to IS NULL OR valid_to > valid_from),
    CONSTRAINT role_agents_detach_shape
        CHECK ((detached_at IS NULL) = (detached_by IS NULL)
               AND (detached_at IS NULL) = (detach_reason IS NULL))
);
REVOKE ALL ON public.role_agents FROM PUBLIC;
CREATE INDEX IF NOT EXISTS idx_role_agents_live
    ON public.role_agents (agent_id, role) WHERE detached_at IS NULL;

-- BEFORE INSERT: ROL02 (section 2).
CREATE OR REPLACE FUNCTION public.epigraph_role_agents_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    -- One attach (or copy) at a time, so two concurrent writers of the same
    -- (role, agent) see each other's row below.
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.role_agents'));
    IF NEW.detached_at IS NOT NULL OR NEW.detached_by IS NOT NULL
       OR NEW.detach_reason IS NOT NULL THEN
        RAISE EXCEPTION 'ROL02: an attachment is recorded live; end it with '
                        'epigraph_detach_agent_from_role'
            USING ERRCODE = 'ROL02';
    END IF;
    IF NEW.valid_from < now() - interval '1 minute' THEN
        RAISE EXCEPTION 'ROL02: an attachment is never back-dated (valid_from % is before now)',
                        NEW.valid_from
            USING ERRCODE = 'ROL02';
    END IF;
    IF NEW.attached_by IS DISTINCT FROM session_user::text
       OR NEW.created_at IS DISTINCT FROM now() THEN
        RAISE EXCEPTION 'ROL02: attached_by and created_at are recorded by the database (the '
                        'writing login, now()); an attach does not supply them'
            USING ERRCODE = 'ROL02';
    END IF;
    IF public.epigraph_is_human_operator(NEW.agent_id)
       OR EXISTS (SELECT 1 FROM public.agents a
                   WHERE a.id = NEW.agent_id AND a.agent_type IN ('human', 'role')) THEN
        RAISE EXCEPTION 'ROL02: % is a human or a role node; only an agent is attached to a role '
                        '(a human holds a role through role_assignments)', NEW.agent_id
            USING ERRCODE = 'ROL02';
    END IF;
    IF NEW.inherited_from IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM public.role_agents p
                        WHERE p.id = NEW.inherited_from AND p.role = NEW.role) THEN
        RAISE EXCEPTION 'ROL02: inherited_from % is not an attachment to role %',
                        NEW.inherited_from, NEW.role
            USING ERRCODE = 'ROL02';
    END IF;
    IF EXISTS (SELECT 1 FROM public.role_agents e
                WHERE e.role = NEW.role AND e.agent_id = NEW.agent_id
                  AND e.detached_at IS NULL
                  AND (e.valid_to IS NULL OR e.valid_to > NEW.valid_from)
                  AND (NEW.valid_to IS NULL OR NEW.valid_to > e.valid_from)) THEN
        RAISE EXCEPTION 'ROL02: agent % already has an attachment to role % in that window',
                        NEW.agent_id, NEW.role
            USING ERRCODE = 'ROL02',
                  HINT = 'Detach it first (epigraph_detach_agent_from_role).';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_agents_guard_insert() FROM PUBLIC;

-- BEFORE UPDATE: the one detach, nothing else; a detached row is final.
CREATE OR REPLACE FUNCTION public.epigraph_role_agents_guard_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF OLD.detached_at IS NOT NULL THEN
        RAISE EXCEPTION 'ROL02: attachment % is detached, and a detach is final', OLD.id
            USING ERRCODE = 'ROL02';
    END IF;
    IF NEW.detached_at IS NULL OR NEW.detached_at <> now()
       OR NEW.detached_by IS DISTINCT FROM session_user::text
       OR NEW.detach_reason IS NULL OR length(btrim(NEW.detach_reason)) = 0
       OR (NEW.id, NEW.role, NEW.agent_id, NEW.valid_from, NEW.valid_to, NEW.attached_by,
           NEW.reason, NEW.inherited_from, NEW.created_at)
          IS DISTINCT FROM
          (OLD.id, OLD.role, OLD.agent_id, OLD.valid_from, OLD.valid_to, OLD.attached_by,
           OLD.reason, OLD.inherited_from, OLD.created_at) THEN
        RAISE EXCEPTION 'ROL02: an attachment is only ever detached (detached_at = now(), '
                        'detached_by = the detaching login, and a detach_reason), nothing '
                        'else; nothing was changed'
            USING ERRCODE = 'ROL02',
                  HINT = 'Detach it with epigraph_detach_agent_from_role and attach a new one.';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_agents_guard_update() FROM PUBLIC;

-- DELETE and TRUNCATE: never (a row trigger never sees a TRUNCATE).
CREATE OR REPLACE FUNCTION public.epigraph_role_agents_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'ROL02: role_agents rows are append-only (migration 166); % refused', TG_OP
        USING ERRCODE = 'ROL02';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_agents_append_only() FROM PUBLIC;

-- AFTER INSERT / UPDATE: one audit row per attach and per detach.
CREATE OR REPLACE FUNCTION public.epigraph_role_agents_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_agent_attached', NEW.agent_id, true,
                jsonb_build_object('attachment_id', NEW.id, 'role', NEW.role,
                                   'agent', NEW.agent_id,
                                   'valid_from', NEW.valid_from, 'valid_to', NEW.valid_to,
                                   'attached_by', NEW.attached_by, 'reason', NEW.reason,
                                   'inherited_from', NEW.inherited_from));
    ELSIF OLD.detached_at IS NULL AND NEW.detached_at IS NOT NULL THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_agent_detached', NEW.agent_id, true,
                jsonb_build_object('attachment_id', NEW.id, 'role', NEW.role,
                                   'agent', NEW.agent_id,
                                   'detached_at', NEW.detached_at,
                                   'detached_by', NEW.detached_by,
                                   'detach_reason', NEW.detach_reason));
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_agents_audit() FROM PUBLIC;

-- AFTER INSERT: an attachment follows the identity's LINEAGE forward. An
-- identity changes whenever its prompt files or model do, so the identity an
-- operator attaches may already have registered successors (161's
-- `agent_succession`), one of which is the identity that runs now. Every
-- registered successor down the lineage (transitively) gets the same window,
-- naming this row in `inherited_from`: one row per gap its own un-detached
-- rows for the role leave in that window (none when they cover it), unless it
-- has inherited this row before. A SHARED successor (it runs in more than one
-- group folder: section 5) is attached alike and FLAGGED with one
-- `platform.role_agent_copied_shared` security event. One INSERT walks the
-- whole lineage, so the copies' own firings find their descendants already
-- attached and insert (and flag) nothing (no deep recursion, no repeated
-- flag). A copy only ever refuses, so it never grants a successor anything; a
-- succession registered LATER is covered by the registration's own copy
-- (section 5).
CREATE OR REPLACE FUNCTION public.epigraph_role_agents_follow_lineage()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    -- One statement: the copies, then one flag event per SHARED successor
    -- that received one, read from the copies actually written (so a copy's
    -- own firing, which writes nothing, flags nothing: one event per
    -- successor however deep it sits).
    WITH RECURSIVE lineage(agent_id) AS (
        SELECT s.child_agent_id FROM public.agent_succession s
         WHERE s.parent_agent_id = NEW.agent_id
        UNION
        SELECT s.child_agent_id FROM public.agent_succession s
          JOIN lineage l ON s.parent_agent_id = l.agent_id
    ),
    copied AS (
        INSERT INTO public.role_agents (role, agent_id, valid_from, valid_to, reason,
                                        inherited_from)
        SELECT NEW.role, l.agent_id, lower(g.gap), upper(g.gap),
               'lineage of ' || NEW.agent_id::text || ' (attachment ' || NEW.id::text || ')',
               NEW.id
          FROM lineage l
         CROSS JOIN LATERAL unnest(
                   tstzmultirange(tstzrange(NEW.valid_from, NEW.valid_to))
                   - COALESCE((SELECT range_agg(tstzrange(c.valid_from, c.valid_to))
                                 FROM public.role_agents c
                                WHERE c.agent_id = l.agent_id AND c.role = NEW.role
                                  AND c.detached_at IS NULL),
                              '{}'::tstzmultirange)) AS g(gap)
         WHERE l.agent_id <> NEW.agent_id
           AND NOT EXISTS (
                   SELECT 1 FROM public.role_agents c
                    WHERE c.agent_id = l.agent_id AND c.inherited_from = NEW.id)
         ORDER BY l.agent_id, lower(g.gap)
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

DROP TRIGGER IF EXISTS role_agents_guard_insert ON public.role_agents;
CREATE TRIGGER role_agents_guard_insert
    BEFORE INSERT ON public.role_agents
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_role_agents_guard_insert();
DROP TRIGGER IF EXISTS role_agents_guard_update ON public.role_agents;
CREATE TRIGGER role_agents_guard_update
    BEFORE UPDATE ON public.role_agents
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_role_agents_guard_update();
DROP TRIGGER IF EXISTS role_agents_no_delete ON public.role_agents;
CREATE TRIGGER role_agents_no_delete
    BEFORE DELETE ON public.role_agents
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_role_agents_append_only();
DROP TRIGGER IF EXISTS role_agents_no_truncate ON public.role_agents;
CREATE TRIGGER role_agents_no_truncate
    BEFORE TRUNCATE ON public.role_agents
    FOR EACH STATEMENT EXECUTE FUNCTION public.epigraph_role_agents_append_only();
DROP TRIGGER IF EXISTS role_agents_follow_lineage ON public.role_agents;
CREATE TRIGGER role_agents_follow_lineage
    AFTER INSERT ON public.role_agents
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_role_agents_follow_lineage();
DROP TRIGGER IF EXISTS role_agents_audit ON public.role_agents;
CREATE TRIGGER role_agents_audit
    AFTER INSERT OR UPDATE ON public.role_agents
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_role_agents_audit();

-- Row security: a maintenance session and a maintenance-owned definer frame
-- (the registration's succession copy, on the attestor's connection) read,
-- insert and detach; nobody deletes (no policy, and the trigger above).
ALTER TABLE public.role_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.role_agents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS role_agents_privileged_read ON public.role_agents;
CREATE POLICY role_agents_privileged_read ON public.role_agents
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS role_agents_privileged_insert ON public.role_agents;
CREATE POLICY role_agents_privileged_insert ON public.role_agents
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS role_agents_privileged_update ON public.role_agents;
CREATE POLICY role_agents_privileged_update ON public.role_agents
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));

-- The maintenance verbs. They add nothing to the table's own rules: the
-- INSERT and UPDATE meet the guards and the audit above.
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
REVOKE EXECUTE ON FUNCTION
    public.epigraph_attach_agent_to_role(text, uuid, timestamptz, timestamptz, text) FROM PUBLIC;

-- Detach every un-detached attachment of `p_agent` to `p_role`, now. Returns
-- how many were detached (0: nothing to detach; a detach is never repeated).
CREATE OR REPLACE FUNCTION public.epigraph_detach_agent_from_role(
    p_role text, p_agent uuid, p_reason text)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF p_role IS NULL OR p_agent IS NULL OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_detach_agent_from_role: the role, the agent and a reason are '
                        'required'
            USING ERRCODE = '22004';
    END IF;
    UPDATE public.role_agents
       SET detached_at = now(), detached_by = session_user, detach_reason = p_reason
     WHERE role = p_role AND agent_id = p_agent AND detached_at IS NULL;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END $$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_detach_agent_from_role(text, uuid, text) FROM PUBLIC;

-- ===================================================================
-- OWNERSHIP AND GRANTS for the record, guarded as every such block since 060
-- is. 077's default privileges hand the application role DML on a new table:
-- taken back here, leaving SELECT (row security shows it nothing).
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_role_agents_guard_insert() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_role_agents_guard_update() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_role_agents_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_role_agents_follow_lineage() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_attach_agent_to_role(text, uuid, timestamptz, '
                'timestamptz, text) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_detach_agent_from_role(text, uuid, text) '
                'OWNER TO epigraph_maintenance';
        -- SELECT also serves 161's AID09 freshness scan, which reads every
        -- foreign key into `agents` as the registration's owner and treats an
        -- unreadable column as "bound".
        EXECUTE 'GRANT SELECT, INSERT ON public.role_agents TO epigraph_maintenance';
        EXECUTE 'GRANT UPDATE (detached_at, detached_by, detach_reason) ON public.role_agents '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_attach_agent_to_role(text, uuid, '
                'timestamptz, timestamptz, text), '
                'public.epigraph_detach_agent_from_role(text, uuid, text) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.role_agents FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.role_agents TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_attach_agent_to_role(text, uuid, '
                'timestamptz, timestamptz, text), '
                'public.epigraph_detach_agent_from_role(text, uuid, text) FROM epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- THE RULE (section 3) AND THE QUESTION (section 4)
-- ===================================================================

-- The predicate, at `p_at`, for any agent. Internal: EXECUTE-able by the
-- maintenance role only; the application role and the attestor ask through
-- `epigraph_role_agent_may_run`, which pins the clock. Every LIVE attachment
-- must be held by the agent's own live-linked human; the first one that is
-- not (by role key) is the answer. `holder` is returned only when it is the
-- agent's own human (section 4's disclosure).
CREATE OR REPLACE FUNCTION public.epigraph_role_agent_gate(p_agent uuid, p_at timestamptz)
RETURNS TABLE (may_run boolean, role text, holder uuid, reason text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_human uuid;
    v_role  text;
    v_first text;
BEGIN
    -- FAIL CLOSED under a wrong owner. `role_agents` admits only a privileged
    -- session or a maintenance-owned definer frame; under any other owner this
    -- read sees no row and every agent would read as unattached (ROL01 never
    -- fires, epigraph-mcp boots in a gap). Inline, not through the bypass
    -- helpers, so the check needs no grant of its own. Skipped on a database
    -- without the maintenance role (060 only NOTICEs on managed Postgres),
    -- where row security is not FORCEd against a superuser owner.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance')
       AND NOT pg_has_role(current_user, 'epigraph_maintenance', 'MEMBER')
       AND NOT pg_has_role(session_user, 'epigraph_maintenance', 'MEMBER') THEN
        RAISE EXCEPTION 'ROL01: epigraph_role_agent_gate runs as %, which cannot read '
                        'role_agents; refusing rather than reading every agent as unattached',
                        current_user
            USING ERRCODE = 'ROL01',
                  HINT = 'Nothing was written. ALTER FUNCTION '
                         'public.epigraph_role_agent_gate(uuid, timestamptz) OWNER TO '
                         'epigraph_maintenance (tenancy_backfill verify reports it).';
    END IF;
    IF p_agent IS NULL OR p_at IS NULL THEN
        RETURN QUERY SELECT true, NULL::text, NULL::uuid, 'unattached'::text;
        RETURN;
    END IF;
    -- Most agents were never attached: answer without the human lookup. After
    -- the owner check above, so a misowned gate still fails closed.
    IF NOT EXISTS (SELECT 1 FROM public.role_agents ra
                    WHERE ra.agent_id = p_agent AND ra.detached_at IS NULL) THEN
        RETURN QUERY SELECT true, NULL::text, NULL::uuid, 'unattached'::text;
        RETURN;
    END IF;
    v_human := public.epigraph_human_of(p_agent, true);
    FOR v_role IN
        SELECT DISTINCT ra.role FROM public.role_agents ra
         WHERE ra.agent_id = p_agent AND ra.detached_at IS NULL
           AND ra.valid_from <= p_at AND (ra.valid_to IS NULL OR p_at < ra.valid_to)
         ORDER BY ra.role
    LOOP
        IF public.epigraph_live_role_assignment(v_human, v_role, p_at) IS NULL THEN
            RETURN QUERY
            SELECT false, v_role, NULL::uuid,
                   CASE WHEN EXISTS (
                            SELECT 1 FROM public.role_assignments x
                             WHERE x.role = v_role AND x.revoked_at IS NULL
                               AND public.epigraph_live_role_assignment(
                                       x.holder_person_id, v_role, p_at) IS NOT NULL)
                        THEN 'not_holder' ELSE 'no_holder' END;
            RETURN;
        END IF;
        v_first := COALESCE(v_first, v_role);
    END LOOP;
    IF v_first IS NULL THEN
        RETURN QUERY SELECT true, NULL::text, NULL::uuid, 'unattached'::text;
    ELSE
        RETURN QUERY SELECT true, v_first, v_human, 'held'::text;
    END IF;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_agent_gate(uuid, timestamptz) FROM PUBLIC;

-- Section 4: the host's and epigraph-mcp's question, now.
CREATE OR REPLACE FUNCTION public.epigraph_role_agent_may_run(p_agent uuid)
RETURNS TABLE (may_run boolean, role text, holder uuid, reason text)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT g.may_run, g.role, g.holder, g.reason
      FROM public.epigraph_role_agent_gate(p_agent, clock_timestamp()) g
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_agent_may_run(uuid) FROM PUBLIC;

-- Section 3: returns quietly, or raises ROL01 naming the role. The statement's
-- clock, never the transaction's start: a run that opened its transaction
-- inside the window writes nothing after `valid_to`. A privileged session is
-- exempt (the custodial path), as it is from OPL02.
CREATE OR REPLACE FUNCTION public.epigraph_require_role_holder(p_agent uuid)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_gate record;
BEGIN
    IF p_agent IS NULL OR public.epigraph_bypass() THEN
        RETURN;
    END IF;
    -- An agent that COULD be attached writes only on a FRESH snapshot, and
    -- this is decided BEFORE the gate, on something no attach can change.
    -- Under REPEATABLE READ or SERIALIZABLE every statement, and every read
    -- in this definer, uses the transaction's first snapshot: an assignment
    -- ended (revoked) after it would still read as live, and an attachment
    -- committed after it would not be seen at all (the gate would answer
    -- `unattached`), for as long as the transaction stays open (123's CUS06
    -- refuses a grant under REPEATABLE READ for the same reason). SERIALIZABLE
    -- does not save it: the revoke or the attach reads no row this write
    -- writes, so no conflict is detected. So the test is "attachable"
    -- (ROL02's: not a human operator, not a human or role node), not
    -- "attached". A human, which is never attached, may use any level.
    IF current_setting('transaction_isolation') <> 'read committed'
       AND NOT public.epigraph_is_human_operator(p_agent)
       AND NOT EXISTS (SELECT 1 FROM public.agents a
                        WHERE a.id = p_agent AND a.agent_type IN ('human', 'role')) THEN
        RAISE EXCEPTION 'ROL01: agent % could be attached to a role, and an agent writes only '
                        'under READ COMMITTED (this transaction is %): an older snapshot would '
                        'miss an attachment, or an assignment end, committed since', p_agent,
                        current_setting('transaction_isolation')
            USING ERRCODE = 'ROL01',
                  HINT = 'Nothing was written. Write under READ COMMITTED (the default).';
    END IF;
    SELECT g.* INTO v_gate FROM public.epigraph_role_agent_gate(p_agent, clock_timestamp()) g;
    IF v_gate.may_run THEN
        RETURN;
    END IF;
    RAISE EXCEPTION 'ROL01: agent % is attached to role %, and %; a role''s agents write only '
                    'while a human holds the role, and only for that holder', p_agent,
                    v_gate.role,
                    CASE v_gate.reason
                        WHEN 'no_holder' THEN 'no human holds that role now'
                        ELSE 'the human it is linked to does not hold that role now'
                    END
        USING ERRCODE = 'ROL01',
              HINT = 'Nothing was written. An operator grants the role to the agent''s linked '
                     'human, or detaches the agent from the role '
                     '(epigraph_detach_agent_from_role) and attaches an identity linked to the '
                     'current holder; a link never moves to another human.';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_require_role_holder(uuid) FROM PUBLIC;

-- Is `p_agent` a RETIRED identity: linked to a human only through a retired
-- link (`epigraph_human_of(p, false)` but not `epigraph_human_of(p, true)`)?
-- Such an identity can never run again (107: a link never moves, and a
-- retired link never writes), so a write that names it as the inherited
-- author of a restatement is its human's act, not the agent running. The one
-- relief from the author arms of ROL01; an unlinked or live-linked agent is
-- never retired.
CREATE OR REPLACE FUNCTION public.epigraph_agent_is_retired(p_agent uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT p_agent IS NOT NULL
       AND public.epigraph_human_of(p_agent, true) IS NULL
       AND public.epigraph_human_of(p_agent, false) IS NOT NULL
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_is_retired(uuid) FROM PUBLIC;

-- The two 123 checks the claims trigger calls, re-stated (signatures, owner
-- and grants unchanged: CREATE OR REPLACE keeps both) with the 166 lines. A
-- later migration that re-bodies either starts from these bodies.
-- 123's claims-path writer scope (122's, with 123's HINT); delta: the 166 line.
CREATE OR REPLACE FUNCTION public.epigraph_require_writer_scope(p_agent uuid, p_group uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_human uuid;
BEGIN
    IF NOT public.epigraph_operator_binding_armed() THEN
        RETURN;
    END IF;
    -- 166: ROL01, the agent the claims trigger checks here (the author, or
    -- the stamped writer when that is someone else).
    PERFORM public.epigraph_require_role_holder(p_agent);
    v_human := public.epigraph_human_of(p_agent, false);
    IF v_human IS NULL OR public.epigraph_operator_writes_group(v_human, p_group) THEN
        RETURN;
    END IF;
    IF public.epigraph_operator_scope_exempt() THEN
        RETURN;
    END IF;
    IF v_human = p_agent THEN
        RAISE EXCEPTION 'OPL02: human operator % holds no writer/admin membership in group %; '
                        'a human writes only where it writes', p_agent, p_group
            USING ERRCODE = 'OPL02',
                  HINT = 'Write into a group you write (your personal group is the default). '
                         'A custodial revision is made on the maintenance DSN with '
                         'epigraph-operator custodial-supersede.';
    END IF;
    RAISE EXCEPTION 'OPL02: agent % is linked to operator %, which holds no writer/admin '
                    'membership in group %; a linked agent writes only where its own operator '
                    'writes', p_agent, v_human, p_group
        USING ERRCODE = 'OPL02',
              HINT = 'Write into a group the operator writes (its personal group is the '
                     'default), or have the operator join the group first. No application '
                     'session crosses humans, a custodian''s included.';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_require_writer_scope(uuid, uuid) FROM PUBLIC;

-- 123's attribution check (122's, with 123's HINTs); delta: the 166 block.
CREATE OR REPLACE FUNCTION public.epigraph_require_attributable(
    p_author uuid, p_writer uuid, p_inherited boolean)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_author_human uuid;
    v_writer_human uuid;
BEGIN
    IF NOT public.epigraph_operator_binding_armed() THEN
        RETURN;
    END IF;
    -- 166: ROL01 on the AUTHOR a writer names. Relieved only for the
    -- inherited author of a retired predecessor's restatement when that
    -- author identity is itself RETIRED (it can never run again, so naming it
    -- is its human's act); a live attached author is checked like any other.
    -- The writer was checked by the writer scope.
    IF NOT (COALESCE(p_inherited, false) AND public.epigraph_agent_is_retired(p_author)) THEN
        PERFORM public.epigraph_require_role_holder(p_author);
    END IF;
    v_writer_human := public.epigraph_human_of(p_writer, true);
    v_author_human := public.epigraph_human_of(p_author, NOT COALESCE(p_inherited, false));
    IF v_author_human IS NULL THEN
        -- No human for this row's kind. A RETIRED identity still belongs to
        -- its human: a writer outside that human is refused below (OPL02,
        -- whatever the valve), before the binding check the valve relieves.
        v_author_human := public.epigraph_human_of(p_author, false);
        IF v_author_human IS NULL OR v_author_human = v_writer_human
           OR public.epigraph_operator_scope_exempt() THEN
            PERFORM public.epigraph_require_bound_author(p_author);
            RETURN;
        END IF;
    ELSIF v_writer_human = v_author_human THEN
        RETURN;
    ELSIF public.epigraph_operator_scope_exempt() THEN
        RETURN;
    END IF;
    IF v_writer_human IS NULL THEN
        RAISE EXCEPTION 'OPL02: the writing principal % belongs to no human operator, and a claim '
                        'it writes may not be attributed to %, which belongs to human operator %; '
                        'an unbound writer names no bound author', p_writer, p_author,
                        v_author_human
            USING ERRCODE = 'OPL02',
                  HINT = 'Author the claim as the writing agent itself. The valve relieves the '
                         'binding (OPL01) only; no application session crosses humans.';
    END IF;
    RAISE EXCEPTION 'OPL02: agent % writes a claim attributed to %, which belongs to human '
                    'operator %, not to the writer''s operator %; a claim may name only an '
                    'author of the writer''s own human', p_writer, p_author, v_author_human,
                    v_writer_human
        USING ERRCODE = 'OPL02',
              HINT = 'Author the claim as the writing agent itself. A custodial revision is '
                     'made on the maintenance DSN with epigraph-operator custodial-supersede.';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_require_attributable(uuid, uuid, boolean) FROM PUBLIC;

-- Section 3, EVERY WRITE: the one check every table the application role
-- writes runs, as a BEFORE ... FOR EACH STATEMENT trigger on INSERT, UPDATE,
-- DELETE and TRUNCATE (the acting agent is the stamped principal), and, on
-- `claims` only, as a BEFORE UPDATE OR DELETE row trigger (the AUTHOR of the
-- row, unless that identity is retired). Keyed on arming, a privileged
-- session exempt, the verdict `epigraph_require_role_holder`'s.
CREATE OR REPLACE FUNCTION public.epigraph_role_agent_write_check()
RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    -- The claim columns the database DERIVES from everyone's evidence and
    -- jobs, not from what the author said: the DS belief cache and its
    -- frame, the classification, the beta parameters, the embeddings, the
    -- theme, the matcher's scan mark, the generated text index and
    -- `updated_at`. Every other column (a column added later included) is
    -- what the author said.
    c_derived constant text[] := ARRAY[
        'belief', 'plausibility', 'mass_on_empty', 'pignistic_prob', 'mass_on_missing',
        'open_world_mass', 'belief_frame_id', 'classification', 'beta_alpha', 'beta_beta',
        'embedding', 'embedding_3072', 'theme_id', 'last_match_scan_at', 'content_tsv',
        'updated_at'];
BEGIN
    IF public.epigraph_operator_binding_armed() AND NOT public.epigraph_bypass() THEN
        IF TG_LEVEL = 'STATEMENT' THEN
            PERFORM public.epigraph_require_role_holder(public.epigraph_principal_id());
        ELSE
            -- `claims`: a claim an attached agent authored is its output, so
            -- no application session changes what it says, or deletes it, in
            -- the agent's gap, whoever is stamped (the claims trigger checks
            -- the author of an insert, a re-open and a re-attribution). An
            -- UPDATE of the derived caches alone is another principal's
            -- evidence landing, not the agent speaking, and is not checked on
            -- the author (the stamped principal was checked above). Nested,
            -- so the cheap gate answer comes first and the row comparison
            -- only runs for an attached author.
            -- Under any isolation but READ COMMITTED the gate's `unattached`
            -- may be a stale snapshot's, so the author is checked whatever
            -- it answers (`epigraph_require_role_holder` refuses an
            -- attachable author there).
            IF current_setting('transaction_isolation') <> 'read committed'
               OR (SELECT g.reason
                     FROM public.epigraph_role_agent_gate(OLD.agent_id, clock_timestamp()) g)
                  IS DISTINCT FROM 'unattached' THEN
                IF NOT public.epigraph_agent_is_retired(OLD.agent_id) THEN
                    IF TG_OP = 'DELETE'
                       OR (to_jsonb(NEW) - c_derived) IS DISTINCT FROM (to_jsonb(OLD) - c_derived)
                    THEN
                        PERFORM public.epigraph_require_role_holder(OLD.agent_id);
                    END IF;
                END IF;
            END IF;
            IF TG_OP = 'UPDATE' AND NEW.agent_id IS DISTINCT FROM OLD.agent_id
               AND NOT public.epigraph_agent_is_retired(NEW.agent_id) THEN
                PERFORM public.epigraph_require_role_holder(NEW.agent_id);
            END IF;
        END IF;
    END IF;
    IF TG_LEVEL = 'STATEMENT' THEN
        RETURN NULL;
    ELSIF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_agent_write_check() FROM PUBLIC;

-- Every public table the application role can INSERT, UPDATE or DELETE (at
-- table or column level) on a database migrated to this file, measured from
-- the catalog. `role_attached_agents.rs`
-- (`every_table_the_app_role_writes_carries_the_role_holder_write_check`)
-- re-measures it, so a table a later migration hands the application role
-- fails that test until it carries this trigger. Guarded per table, so a
-- database without one of them still migrates.
DO $$
DECLARE
    v_table text;
BEGIN
    FOREACH v_table IN ARRAY ARRAY[
        'activities', 'agent_keys', 'agent_spans', 'agent_state_history', 'agents', 'analyses',
        'analysis_methods', 'behavioral_executions', 'bp_messages', 'challenges',
        'claim_cluster_membership', 'claim_clusters', 'claim_encryption', 'claim_frames',
        'claim_neighborhood_membership', 'claim_signature_revocations', 'claim_themes',
        'claim_version_encryption', 'claim_versions', 'claims', 'cluster_centroids',
        'cluster_edges', 'cluster_labels', 'communities', 'community_members', 'contexts',
        'counterfactual_scenarios', 'ds_bayesian_divergence', 'ds_combined_beliefs',
        'edge_encryption', 'edges', 'edges_staging', 'entities', 'entity_mentions',
        'entity_types', 'events', 'evidence', 'evidence_encryption',
        'experiment_entity_mentions', 'experiment_results', 'experiment_triples', 'experiments',
        'factors', 'frames', 'gap_analyses', 'graph_cluster_runs', 'graph_clusters',
        'graph_neighborhoods', 'group_key_epochs', 'group_memberships', 'groups',
        'harvester_claim_provenance', 'harvester_fragments', 'jobs', 'learning_events',
        'mass_functions', 'match_candidates', 'method_capabilities', 'methods',
        'neighborhood_edges', 'oauth_authorization_codes', 'oauth_authorize_sessions',
        'oauth_clients', 'papers', 'pattern_templates', 'perspectives', 'privatization_audit',
        'provenance_log', 'reasoning_traces', 'recall_events', 'refresh_tokens', 'rls_canary',
        'security_events', 'tasks', 'trace_parents', 'triples', 'webhook_subscriptions',
        'workflow_executions', 'workflows'
    ] LOOP
        IF to_regclass('public.' || v_table) IS NOT NULL THEN
            EXECUTE format('DROP TRIGGER IF EXISTS role_agent_write_check ON public.%I',
                           v_table);
            EXECUTE format('CREATE TRIGGER role_agent_write_check '
                           'BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.%I '
                           'FOR EACH STATEMENT '
                           'EXECUTE FUNCTION public.epigraph_role_agent_write_check()',
                           v_table);
        END IF;
    END LOOP;
END $$;
DROP TRIGGER IF EXISTS claims_role_agent_author ON public.claims;
CREATE TRIGGER claims_role_agent_author
    BEFORE UPDATE OR DELETE ON public.claims
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_role_agent_write_check();

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_role_agent_gate(uuid, timestamptz) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_role_agent_may_run(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_require_role_holder(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_agent_is_retired(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_role_agent_write_check() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_role_agent_gate(uuid, timestamptz), '
                'public.epigraph_role_agent_may_run(uuid), '
                'public.epigraph_require_role_holder(uuid), '
                'public.epigraph_agent_is_retired(uuid) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        -- The question only. The check is reached through the writer checks,
        -- which are maintenance-owned definers, so their nested call is
        -- checked against the owner and the app role needs no EXECUTE on it.
        -- Never the gate, whose `p_at` would make it an any-time oracle.
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_role_agent_may_run(uuid) '
                'TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_role_agent_gate(uuid, timestamptz), '
                'public.epigraph_require_role_holder(uuid) FROM epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_identity_attestor') THEN
        -- The host asks before starting a role's container or schedule.
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_role_agent_may_run(uuid) '
                'TO epigraph_identity_attestor';
    END IF;
END $$;

-- ===================================================================
-- SUCCESSION (section 5): 161's registration, re-stated. Signature, owner and
-- ACL unchanged (CREATE OR REPLACE keeps both; the ACL stays the attestor's
-- alone). The body is 161's with exactly three deltas, each marked `166`:
-- the `v_roles_new` and `v_shared` variables, step 5b, and the audit row's
-- trigger and `role_attachments_copied` / `role_attachments_shared`
-- details. A later migration that re-bodies the
-- registration starts from this body.
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
        ELSIF NOT EXISTS (SELECT 1 FROM public.agents a
                           WHERE a.id = v_parent
                             AND (a.key_kind = 'derived' OR a.properties ? 'llm_model')
                             AND a.agent_type IS DISTINCT FROM 'human')
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
    IF v_parent IS NOT NULL THEN
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
                                   'recorded_by', session_user));
    END IF;

    RETURN QUERY
    SELECT v_child, v_created, v_succ_rows > 0, v_snapshot, v_snap_new, v_key_new,
           v_child_op, v_inherited, v_link_live, v_reason;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_register_agent_identity(
    bytea, uuid, text, text, text, bytea, jsonb) FROM PUBLIC;
