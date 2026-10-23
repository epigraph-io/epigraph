-- 161_agent_identity_lineage.sql
-- Host-attested agent identity registration, succession, link inheritance and
-- prompt history (agent identity lineage design D2, D3, D4; slice S1).
--
-- ===================================================================
-- 1. WHY
--
-- An EpiClaw agent's identity is a function of (model, prompt files). Editing
-- LEARNED.md or bumping the model mints a NEW agent, and that agent is not
-- linked to any operator, so it cannot write until someone links it by hand.
-- The host already knows which identity a group ran before; this migration lets
-- it SAY so ("X succeeds Y in group G, with these prompt files") and lets the
-- database act on it: X is linked to Y's operator only if Y is live-linked. The
-- container can never declare a parent.
--
-- It also records WHAT each identity ran: the IDENTITY, global CLAUDE, group
-- CLAUDE and LEARNED files, compressed and content-addressed, readable by the
-- agent's operator and by admins only.
--
-- ===================================================================
-- 2. THE TRUST BOUNDARY IS A DATABASE ROLE (D3)
--
-- `epigraph.principal_id` and the group lists are session settings that any
-- login can SET, and agent containers hold an application DSN. A check of
-- "the session principal is an attestor" inside a function is therefore
-- forgeable from a container. So registration is gated by the ROLE of the
-- connection:
--
--   * `epigraph_identity_attestor` is created here NOLOGIN, a member of nothing.
--     Operations gives it LOGIN and a password out of band; no migration ever
--     carries a password. Its only privilege is EXECUTE on
--     `epigraph_register_agent_identity`.
--   * The registration is a SECURITY DEFINER owned by `epigraph_maintenance`.
--     EXECUTE is revoked from PUBLIC, from `epigraph_app` and from its own
--     owner, and granted to the attestor alone. No API route registers.
--
-- Inside the definer `session_user` is the attestor, which is NOT a member of
-- `epigraph_maintenance`, so `epigraph_bypass()` is false there and every write
-- is admitted by `epigraph_definer_bypass()` (current_user = the owner), the
-- same arm every app-callable definer since 077 relies on.
--
-- ===================================================================
-- 3. THE TABLES (D3, D4)
--
--   * `agent_succession (child, parent, group_folder)`: many-to-many, because one
--     identity is shared by every group with the same model and files.
--     `agents.parent_agent_id` is set to the FIRST attested parent, for
--     display; this table is the record. Rows are never updated or deleted.
--   * `agent_prompt_blobs`: content-addressed by the BLAKE3 of the RAW bytes,
--     stored as a zstd frame. Immutable: no UPDATE or DELETE grant, no policy
--     for either, and a guard that refuses both even for a superuser
--     (content-addressing is only a guarantee if the content under a hash can
--     never change). The database cannot run BLAKE3 or zstd; the attestor's
--     client (`AgentIdentityRepository`) hashes and compresses, the definer
--     checks the shape (32-byte hash, zstd magic, size bounds), and the history
--     reader re-hashes after decompressing, so a wrong blob is an error on
--     read, never another file's text.
--   * `agent_prompt_snapshots`: one row per distinct (agent, group, model,
--     files, in_prompt, refused files); a repeat start bumps `last_seen` and
--     changes nothing else. `in_prompt` records which files actually reached
--     the prompt. `blob_refused` names a file the host refused to store
--     (a secret was found in it) and that file's column is NULL.
--
-- All three are FORCE ROW LEVEL SECURITY with policies that admit only a
-- maintenance session or a maintenance-owned definer frame, so an application
-- session reads no row (it keeps table SELECT only because
-- `rls_enforcement.rs` requires every relation to be reachable). They carry no
-- `visibility` / `owner_group_id` columns: they are control state, not tenanted
-- rows.
--
-- ===================================================================
-- 4. THE LINK BODY, SHARED (D3 step 5)
--
-- `epigraph_link_operator` (122's body) moves, unchanged, into
-- `epigraph_link_operator_body(agent, operator, edge_properties)`, a SECURITY
-- INVOKER function owned by the maintenance role and EXECUTE-able by it alone.
-- `epigraph_link_operator` becomes a one-line definer that calls it with the
-- edge properties it always wrote (`{"source": "epigraph_link_operator"}`), so
-- its behaviour, owner and ACL are what they were (`CREATE OR REPLACE` keeps
-- both). The registration calls the same body, so an inherited link is a link
-- in every respect (the same refusals, the writer membership, the OPERATED_BY
-- edge); only its edge properties name the registration.
--
-- ===================================================================
-- 5. REGISTRATION (D3 steps 1-6), ONE TRANSACTION, IDEMPOTENT
--
-- `epigraph_register_agent_identity(identity_pubkey, parent, model, prompt_hash,
-- group_folder, signing_pubkey, snapshot)` takes the operator-links advisory
-- lock first (107 section 10), then:
--   1. finds or creates the agent by its identity public key (`key_kind
--      'derived'`, `agent_type 'llm'`, properties llm_model / llm_prompt_hash /
--      source 'epiclaw'); an existing identity whose SNAPSHOTS record another
--      model or prompt hash is refused (22023: the key is a function of both).
--      The comparison reads the snapshots, which this function alone writes,
--      never `agents.properties`, which the application role may rewrite on
--      the agent's own row (118's column grant, 077's `agents_self_update`,
--      a principal any login can set): properties are display only, and the
--      registration re-asserts them when they differ;
--   2. stores the blobs and finds or creates the snapshot (D4);
--   3. records the succession and, if unset, `parent_agent_id`;
--   4. binds the signing key when the agent has no active one (a key already
--      bound as a signing or legacy key anywhere, including a key of this agent
--      that was rotated or revoked, or one equal to an identity key, is
--      refused 22023); the same key again is a no-op, and a DIFFERENT key
--      while one is active is refused AID08, never skipped in silence;
--   5. inherits the link: no link on the child and a LIVE-linked parent ->
--      the link body with the parent's operator. An unlinked or retired parent
--      links nothing (`inherited = false`, with a reason);
--   6. writes one `security_events` row `agent.identity_registered` naming the
--      child, parent, group, operator, snapshot and `session_user` -- only when
--      something new was recorded, so a repeat start writes nothing but
--      `last_seen`.
-- A parent equal to the child (only an unhashed file changed) records no
-- lineage. Refusals, each of which aborts the whole call:
--   * AID03: the parent is not an LLM agent (neither `key_kind 'derived'` nor
--     `llm_model` set), or is a human (a registered human operator or
--     `agent_type 'human'`: a keyless OAuth human is also `derived`);
--   * AID05: the identity already exists, has authored claims and was never
--     registered (no succession row and no snapshot): it is not EpiClaw's to
--     adopt. A prior snapshot counts as registration, so an agent first
--     registered in a new group (no parent) re-registers after it has written;
--   * AID07: the child is already linked to a different operator than the
--     live-linked parent's. Nothing changes; the host alerts.
--   * AID08: the child already has a different active signing key. Nothing
--     changes; revoking a bound key is a maintenance act (section 7a), after
--     which the host's new key is bound.
--
-- The event family `agent.identity_` is reserved for a privileged session or a
-- maintenance-owned definer (RESTRICTIVE policy, 148's shape), so an
-- application session cannot forge a registration record.
--
-- ===================================================================
-- 6. PROMPT HISTORY (D4)
--
-- `epigraph_agent_prompt_history(agent)`, a definer EXECUTE-able by the
-- application role. Allowed when the session principal is the agent's human
-- (`epigraph_human_of(agent, false)`: a retired link still reads its history),
-- or holds the admin role (129's switch: elevated when admin scopes are armed,
-- a live custodian otherwise), or the session is a maintenance session;
-- otherwise AID06. It returns one row per (lineage agent, snapshot): the agent
-- itself, its ancestors up `agent_succession` (negative depth) and its
-- descendants down it (positive depth). A lineage member the caller could not
-- read on its own appears by id with `readable = false` and no snapshot. Blobs
-- are returned as zstd bytes with their hash; the repository decompresses and
-- verifies.
--
-- Stated limit: the read gate rests on the session principal, which a holder
-- of an application DSN can set; that is the same exposure group-private rows
-- already have, and it closes with the same follow-on (no DSN in containers).
--
-- ===================================================================
-- 7. LEGACY KEYS (D2)
--
-- Every agent that exists when this runs gets one active `agent_keys` row,
-- `key_type 'identity-legacy'`, carrying its current public key, valid from
-- the agent's creation and open-ended (`valid_until` is set at cut-over), so
-- claims signed before signing keys exist stay bound to a key. An agent created
-- after this migration gets no such row from it.
--
-- ===================================================================
-- 7a. ATTESTED KEYS (D2: "Agents cannot self-register it")
--
-- A `signing` key is what S2's claim verification binds a signature to, and
-- an `identity-legacy` key keeps a pre-cut-over signature bound. Both are
-- attested state. 118 left `agent_keys` application-INSERTable with no row
-- security and its status definer callable by the application role with no
-- caller check, so a container holding the application DSN could plant a key
-- for any agent or rotate one away. Now:
--   * a BEFORE INSERT OR UPDATE guard refuses a row of either type (in any
--     spelling: the type is compared trimmed and lower-cased) unless the
--     session is privileged or the write comes from a maintenance-owned
--     definer frame (118's `epigraph_lockdown_privileged()`); other key types
--     are unchanged;
--   * `epigraph_agent_key_set_status` (118) refuses to move a key of either
--     type unless the SESSION is a maintenance (or superuser) session: inside
--     that definer the frame is always maintenance-owned, so the frame test
--     alone would admit every caller.
-- So the HTTP rotate and revoke routes, which run on the application role,
-- can no longer touch these keys: rotating or revoking a bound signing key is
-- a maintenance act, and the host then registers its new key.
--
-- ===================================================================
-- 8. UNDO
--
--   DROP FUNCTION public.epigraph_agent_prompt_history(uuid);
--   DROP FUNCTION public.epigraph_register_agent_identity(bytea, uuid, text, text, text, bytea, jsonb);
--   -- re-run 122's CREATE OR REPLACE FUNCTION public.epigraph_link_operator(uuid, uuid), then
--   DROP FUNCTION public.epigraph_link_operator_body(uuid, uuid, jsonb);
--   DROP POLICY security_events_agent_identity_privileged ON public.security_events;
--   DROP TABLE public.agent_succession, public.agent_prompt_snapshots, public.agent_prompt_blobs;
--   DROP FUNCTION public.epigraph_agent_lineage_append_only(), public.epigraph_agent_prompt_snapshots_guard();
--   DROP TRIGGER agent_keys_attested_guard ON public.agent_keys;
--   DROP FUNCTION public.epigraph_agent_keys_attested_guard();
--   -- re-run 118's CREATE OR REPLACE FUNCTION public.epigraph_agent_key_set_status(...), then
--   DELETE FROM public.agent_keys WHERE key_type = 'identity-legacy';
--   DROP ROLE epigraph_identity_attestor;   -- cluster-wide: only once no database uses it
-- Linked agents keep their links (operator_links rows are permanent by 107's rule).

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- THE ROLE. Cluster-scoped, so guarded exactly as 060 guards its three: a
-- parallel test database may create it first.
-- ===================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_identity_attestor') THEN
        BEGIN
            CREATE ROLE epigraph_identity_attestor NOLOGIN;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE NOTICE 'Cannot CREATE ROLE epigraph_identity_attestor: provision it out of '
                             'band (NOLOGIN, member of nothing) before the host registers identities.';
            WHEN duplicate_object THEN NULL;
            WHEN unique_violation THEN NULL;
        END;
    END IF;
END $$;

-- ===================================================================
-- THE TABLES
-- ===================================================================
CREATE TABLE IF NOT EXISTS public.agent_prompt_blobs (
    blob_hash  bytea PRIMARY KEY,
    codec      text NOT NULL,
    raw_size   integer NOT NULL,
    content    bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_prompt_blobs_hash_is_blake3 CHECK (octet_length(blob_hash) = 32),
    CONSTRAINT agent_prompt_blobs_codec CHECK (codec = 'zstd'),
    -- 8 MiB of prompt text per file is far past any real prompt file.
    CONSTRAINT agent_prompt_blobs_raw_size CHECK (raw_size BETWEEN 0 AND 8388608),
    -- A zstd frame starts with the magic number 0xFD2FB528 (little-endian), and
    -- an incompressible input grows by at most a small frame overhead.
    CONSTRAINT agent_prompt_blobs_is_zstd CHECK (
        substring(content FROM 1 FOR 4) = '\x28b52ffd'::bytea
        AND octet_length(content) <= 8388608 + 65536)
);

CREATE TABLE IF NOT EXISTS public.agent_prompt_snapshots (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id         uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    group_folder     text NOT NULL,
    model            text NOT NULL,
    prompt_hash      text NOT NULL,
    identity_md      bytea REFERENCES public.agent_prompt_blobs(blob_hash) ON DELETE RESTRICT,
    global_claude_md bytea REFERENCES public.agent_prompt_blobs(blob_hash) ON DELETE RESTRICT,
    group_claude_md  bytea REFERENCES public.agent_prompt_blobs(blob_hash) ON DELETE RESTRICT,
    learned_md       bytea REFERENCES public.agent_prompt_blobs(blob_hash) ON DELETE RESTRICT,
    in_prompt        jsonb NOT NULL,
    blob_refused     text[] NOT NULL DEFAULT '{}',
    runner_version   text,
    host_sha         text,
    first_seen       timestamptz NOT NULL DEFAULT now(),
    last_seen        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_prompt_snapshots_group_folder CHECK (
        group_folder <> '' AND length(group_folder) <= 255),
    CONSTRAINT agent_prompt_snapshots_model CHECK (btrim(model) <> '' AND length(model) <= 255),
    CONSTRAINT agent_prompt_snapshots_prompt_hash CHECK (prompt_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT agent_prompt_snapshots_in_prompt CHECK (jsonb_typeof(in_prompt) = 'object'),
    CONSTRAINT agent_prompt_snapshots_refused_names CHECK (
        blob_refused <@ ARRAY['identity_md', 'global_claude_md', 'group_claude_md',
                              'learned_md']::text[]),
    CONSTRAINT agent_prompt_snapshots_refused_has_no_blob CHECK (
        NOT ('identity_md' = ANY (blob_refused) AND identity_md IS NOT NULL)
        AND NOT ('global_claude_md' = ANY (blob_refused) AND global_claude_md IS NOT NULL)
        AND NOT ('group_claude_md' = ANY (blob_refused) AND group_claude_md IS NOT NULL)
        AND NOT ('learned_md' = ANY (blob_refused) AND learned_md IS NOT NULL)),
    CONSTRAINT agent_prompt_snapshots_meta CHECK (
        (runner_version IS NULL OR length(runner_version) <= 255)
        AND (host_sha IS NULL OR length(host_sha) <= 255)),
    CONSTRAINT agent_prompt_snapshots_seen_order CHECK (last_seen >= first_seen),
    CONSTRAINT agent_prompt_snapshots_one_per_state UNIQUE NULLS NOT DISTINCT
        (agent_id, group_folder, model, identity_md, global_claude_md, group_claude_md,
         learned_md, in_prompt, blob_refused)
);

CREATE TABLE IF NOT EXISTS public.agent_succession (
    child_agent_id  uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    parent_agent_id uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    group_folder    text NOT NULL,
    snapshot_id     uuid NOT NULL REFERENCES public.agent_prompt_snapshots(id) ON DELETE RESTRICT,
    attested_at     timestamptz NOT NULL DEFAULT now(),
    attested_by     text NOT NULL DEFAULT session_user,
    PRIMARY KEY (child_agent_id, parent_agent_id, group_folder),
    CONSTRAINT agent_succession_not_self CHECK (child_agent_id <> parent_agent_id),
    CONSTRAINT agent_succession_group_folder CHECK (
        group_folder <> '' AND length(group_folder) <= 255)
);
CREATE INDEX IF NOT EXISTS idx_agent_succession_parent
    ON public.agent_succession (parent_agent_id);

-- Append-only, for every role including a superuser and the table owner.
CREATE OR REPLACE FUNCTION public.epigraph_agent_lineage_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION '%: rows are append-only (migration 161); % refused', TG_TABLE_NAME, TG_OP
        USING ERRCODE = '55000';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_lineage_append_only() FROM PUBLIC;

DROP TRIGGER IF EXISTS agent_prompt_blobs_append_only ON public.agent_prompt_blobs;
CREATE TRIGGER agent_prompt_blobs_append_only
    BEFORE UPDATE OR DELETE ON public.agent_prompt_blobs
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_agent_lineage_append_only();
DROP TRIGGER IF EXISTS agent_succession_append_only ON public.agent_succession;
CREATE TRIGGER agent_succession_append_only
    BEFORE UPDATE OR DELETE ON public.agent_succession
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_agent_lineage_append_only();

-- A snapshot changes in one way only: `last_seen` moves forward.
CREATE OR REPLACE FUNCTION public.epigraph_agent_prompt_snapshots_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'agent_prompt_snapshots: rows are never deleted (migration 161)'
            USING ERRCODE = '55000';
    END IF;
    IF (NEW.id, NEW.agent_id, NEW.group_folder, NEW.model, NEW.prompt_hash, NEW.identity_md,
        NEW.global_claude_md, NEW.group_claude_md, NEW.learned_md, NEW.in_prompt,
        NEW.blob_refused, NEW.runner_version, NEW.host_sha, NEW.first_seen)
       IS DISTINCT FROM
       (OLD.id, OLD.agent_id, OLD.group_folder, OLD.model, OLD.prompt_hash, OLD.identity_md,
        OLD.global_claude_md, OLD.group_claude_md, OLD.learned_md, OLD.in_prompt,
        OLD.blob_refused, OLD.runner_version, OLD.host_sha, OLD.first_seen)
       OR NEW.last_seen < OLD.last_seen THEN
        RAISE EXCEPTION 'agent_prompt_snapshots: only last_seen may change, and only forward '
                        '(migration 161)'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_prompt_snapshots_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS agent_prompt_snapshots_guard ON public.agent_prompt_snapshots;
CREATE TRIGGER agent_prompt_snapshots_guard
    BEFORE UPDATE OR DELETE ON public.agent_prompt_snapshots
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_agent_prompt_snapshots_guard();

-- Row security: a maintenance session and a maintenance-owned definer frame
-- read and insert; the snapshot's `last_seen` is updated by the definer only;
-- nobody updates a blob or a succession row, and nobody deletes (no policy).
ALTER TABLE public.agent_prompt_blobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_prompt_blobs FORCE ROW LEVEL SECURITY;
ALTER TABLE public.agent_prompt_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_prompt_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE public.agent_succession ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_succession FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS agent_prompt_blobs_definer_read ON public.agent_prompt_blobs;
CREATE POLICY agent_prompt_blobs_definer_read ON public.agent_prompt_blobs
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS agent_prompt_blobs_definer_insert ON public.agent_prompt_blobs;
CREATE POLICY agent_prompt_blobs_definer_insert ON public.agent_prompt_blobs
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_definer_bypass()));

DROP POLICY IF EXISTS agent_prompt_snapshots_definer_read ON public.agent_prompt_snapshots;
CREATE POLICY agent_prompt_snapshots_definer_read ON public.agent_prompt_snapshots
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS agent_prompt_snapshots_definer_insert ON public.agent_prompt_snapshots;
CREATE POLICY agent_prompt_snapshots_definer_insert ON public.agent_prompt_snapshots
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS agent_prompt_snapshots_definer_update ON public.agent_prompt_snapshots;
CREATE POLICY agent_prompt_snapshots_definer_update ON public.agent_prompt_snapshots
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_definer_bypass()));

DROP POLICY IF EXISTS agent_succession_definer_read ON public.agent_succession;
CREATE POLICY agent_succession_definer_read ON public.agent_succession
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS agent_succession_definer_insert ON public.agent_succession;
CREATE POLICY agent_succession_definer_insert ON public.agent_succession
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_definer_bypass()));

REVOKE ALL ON public.agent_prompt_blobs, public.agent_prompt_snapshots,
              public.agent_succession FROM PUBLIC;

-- The registration's audit family, reserved (148's RESTRICTIVE shape).
-- length('agent.identity_') = 15.
DROP POLICY IF EXISTS security_events_agent_identity_privileged ON public.security_events;
CREATE POLICY security_events_agent_identity_privileged ON public.security_events
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        lower(left(btrim(event_type), 15)) <> 'agent.identity_'
        OR (((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
            AND created_at = now()));

-- ===================================================================
-- THE LINK BODY (section 4). 122's `epigraph_link_operator` body, byte for
-- byte, except that the OPERATED_BY edge's properties are the third argument.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_link_operator_body(
    p_agent uuid, p_operator uuid, p_edge_properties jsonb)
RETURNS TABLE (operator_group_id uuid,
               group_created boolean,
               membership_created boolean,
               membership_live boolean,
               edge_created boolean,
               link_live boolean,
               link_retired boolean)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = public, pg_temp AS $$
DECLARE
    v_group     uuid;
    v_other     uuid;
    v_group_existed boolean;
    v_link_rows integer := 0;
    v_mem_rows  integer := 0;
    v_edge_rows integer := 0;
BEGIN
    IF p_agent IS NULL OR p_operator IS NULL THEN
        RAISE EXCEPTION 'epigraph_link_operator: agent and operator are both required'
            USING ERRCODE = '22004';
    END IF;
    IF p_agent = p_operator THEN
        RAISE EXCEPTION 'epigraph_link_operator: agent % cannot be its own operator', p_agent
            USING ERRCODE = '22023';
    END IF;
    -- Serialise every link write (107 section 10). Taken before any check reads
    -- `operator_links`, so under READ COMMITTED each check below sees every
    -- link committed by the call this one waited for.
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    IF NOT EXISTS (SELECT 1 FROM public.agents WHERE id = p_agent) THEN
        RAISE EXCEPTION 'epigraph_link_operator: agent % does not exist', p_agent
            USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.agents WHERE id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_operator: operator % does not exist', p_operator
            USING ERRCODE = '22023';
    END IF;
    -- Single hop, enforced from BOTH ends (107 section 6).
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_operator: % is itself operated by another agent and '
                        'cannot be an operator', p_operator
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.operator_id = p_agent) THEN
        RAISE EXCEPTION 'epigraph_link_operator: % already operates other agents and cannot '
                        'itself be operated', p_agent
            USING ERRCODE = '55000';
    END IF;
    -- One operator per agent, ever.
    SELECT l.operator_id INTO v_other
      FROM public.operator_links l
     WHERE l.agent_id = p_agent AND l.operator_id <> p_operator;
    IF v_other IS NOT NULL THEN
        RAISE EXCEPTION 'epigraph_link_operator: agent % already has a link to operator %; '
                        'an agent is linked to one operator, and re-pointing it is an '
                        'out-of-band act', p_agent, v_other
            USING ERRCODE = '55000';
    END IF;
    -- A SHARED SIGNER is neither linkable nor an operator (107 section 9, 122
    -- section 9). Checked on a FIRST link only.
    IF NOT EXISTS (SELECT 1 FROM public.operator_links l
                    WHERE l.agent_id = p_agent AND l.operator_id = p_operator) THEN
        IF (SELECT count(DISTINCT e.target_id) FROM public.edges e
             WHERE e.source_id = p_agent AND e.relationship = 'OPERATED_BY') > 1 THEN
            RAISE EXCEPTION 'epigraph_link_operator: agent % carries OPERATED_BY auth-lineage edges to '
                            'more than one principal, the fingerprint of a shared HTTP '
                            'signer; refusing to link it', p_agent
                USING ERRCODE = '55000';
        END IF;
        IF NOT public.epigraph_is_human_operator(p_operator)
           AND (SELECT count(DISTINCT e.target_id) FROM public.edges e
             WHERE e.source_id = p_operator AND e.relationship = 'OPERATED_BY') > 1 THEN
            RAISE EXCEPTION 'epigraph_link_operator: operator % carries OPERATED_BY auth-lineage edges to '
                            'more than one principal, the fingerprint of a shared HTTP '
                            'signer; refusing it as an operator', p_operator
                USING ERRCODE = '55000';
        END IF;
    END IF;

    -- (a) The operator's personal group, through 105's definer and nothing
    -- else (RVK01 / RVK02 abort the call).
    v_group_existed := EXISTS (SELECT 1 FROM public.groups g
                                WHERE g.did_key = 'did:epigraph:personal:' || p_operator::text);
    v_group := public.epigraph_ensure_personal_group(p_operator);

    -- (b) The link record: recorded once.
    INSERT INTO public.operator_links (agent_id, operator_id, operator_group_id)
    VALUES (p_agent, p_operator, v_group)
    ON CONFLICT (agent_id) DO NOTHING;
    GET DIAGNOSTICS v_link_rows = ROW_COUNT;

    -- (c) The agent's writer membership: recorded once, and ONLY by the call
    -- that recorded the link row (107 section 3).
    IF v_link_rows > 0 THEN
        INSERT INTO public.group_memberships (group_id, agent_id, wrapped_key_share,
                                              epoch, role)
        SELECT v_group, p_agent, ''::bytea, 0, 'writer'
         WHERE NOT EXISTS (SELECT 1 FROM public.group_memberships m
                            WHERE m.group_id = v_group AND m.agent_id = p_agent)
           AND NOT EXISTS (SELECT 1 FROM public.operator_links l
                            WHERE l.agent_id = p_agent AND l.retired)
        ON CONFLICT DO NOTHING;
        GET DIAGNOSTICS v_mem_rows = ROW_COUNT;
    END IF;

    -- (d) The graph record, if no OPERATED_BY edge exists between the pair in
    -- any state. It grants nothing (107 section 4).
    INSERT INTO public.edges (source_id, source_type, target_id, target_type,
                              relationship, properties)
    SELECT p_agent, 'agent', p_operator, 'agent', 'OPERATED_BY', p_edge_properties
     WHERE NOT EXISTS (SELECT 1 FROM public.edges e
                        WHERE e.source_id = p_agent AND e.target_id = p_operator
                          AND e.relationship = 'OPERATED_BY');
    GET DIAGNOSTICS v_edge_rows = ROW_COUNT;

    RETURN QUERY
    SELECT v_group,
           NOT v_group_existed,
           v_mem_rows > 0,
           EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = v_group AND m.agent_id = p_agent
                      AND m.revoked_at IS NULL),
           v_edge_rows > 0,
           EXISTS (SELECT 1 FROM public.epigraph_operator_actor(p_agent) o
                    WHERE o.operator_id = p_operator),
           EXISTS (SELECT 1 FROM public.operator_links l
                    WHERE l.agent_id = p_agent AND l.retired);
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_link_operator_body(uuid, uuid, jsonb) FROM PUBLIC;

-- The maintenance entry point: the body, with the edge properties 107 and 122
-- always wrote. Owner and ACL are kept by CREATE OR REPLACE.
CREATE OR REPLACE FUNCTION public.epigraph_link_operator(p_agent uuid, p_operator uuid)
RETURNS TABLE (operator_group_id uuid,
               group_created boolean,
               membership_created boolean,
               membership_live boolean,
               edge_created boolean,
               link_live boolean,
               link_retired boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    RETURN QUERY
    SELECT b.operator_group_id, b.group_created, b.membership_created, b.membership_live,
           b.edge_created, b.link_live, b.link_retired
      FROM public.epigraph_link_operator_body(
               p_agent, p_operator,
               jsonb_build_object('source', 'epigraph_link_operator')) b;
END $$;

-- ===================================================================
-- ATTESTED KEYS (section 7a). The guard's trigger is created LAST, after the
-- legacy backfill, so the migration's own insert never depends on which role
-- runs it.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_agent_keys_attested_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF (lower(btrim(NEW.key_type)) IN ('signing', 'identity-legacy')
        OR (TG_OP = 'UPDATE' AND lower(btrim(OLD.key_type)) IN ('signing', 'identity-legacy')))
       AND NOT public.epigraph_lockdown_privileged() THEN
        RAISE EXCEPTION 'AK02: a % agent key is attested state, written by the identity '
                        'registration or a maintenance session only (migration 161)', NEW.key_type
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_keys_attested_guard() FROM PUBLIC;

-- 118's status definer, unchanged but for the attested-type gate. CREATE OR
-- REPLACE keeps its owner and ACL.
CREATE OR REPLACE FUNCTION public.epigraph_agent_key_set_status(
    p_key_id uuid, p_status text, p_revocation_reason text, p_revoked_by uuid)
RETURNS SETOF public.agent_keys
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_cur text;
        v_type text;
BEGIN
    SELECT k.status, k.key_type INTO v_cur, v_type
      FROM public.agent_keys k WHERE k.id = p_key_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF lower(btrim(v_type)) IN ('signing', 'identity-legacy')
       AND NOT (public.epigraph_bypass()
                OR COALESCE((SELECT r.rolsuper OR r.rolbypassrls
                               FROM pg_catalog.pg_roles r
                              WHERE r.rolname = session_user), false)) THEN
        RAISE EXCEPTION 'AK02: agent key % is a % key, attested state; only a maintenance '
                        'session changes its status (migration 161)', p_key_id, v_type
            USING ERRCODE = '42501';
    END IF;
    IF NOT ((p_status = 'rotated' AND v_cur = 'active')
            OR (p_status = 'revoked' AND v_cur IS DISTINCT FROM 'revoked')) THEN
        RAISE EXCEPTION 'AK01: agent key % cannot move from % to %', p_key_id, v_cur, p_status
            USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
        UPDATE public.agent_keys
           SET status = p_status,
               revocation_reason = COALESCE(p_revocation_reason, revocation_reason),
               revoked_by = COALESCE(p_revoked_by, revoked_by)
         WHERE id = p_key_id
        RETURNING *;
END $$;

-- ===================================================================
-- REGISTRATION (section 5)
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
    v_bound      bytea;
    v_rec_model  text;
    v_rec_hash   text;
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
        ELSIF v_child_op IS NULL THEN
            SELECT b.link_live INTO v_live
              FROM public.epigraph_link_operator_body(
                       v_child, v_parent_op,
                       jsonb_build_object('source', 'epigraph_register_agent_identity',
                                          'inherited_from', v_parent,
                                          'group_folder', p_group_folder)) b;
            v_inherited := COALESCE(v_live, false);
            IF NOT v_inherited THEN
                v_reason := 'link_not_live';
            END IF;
        ELSIF v_child_op = v_parent_op THEN
            v_reason := 'already_linked';
        ELSE
            RAISE EXCEPTION 'AID07: agent % is linked to operator %, but its parent % is live-linked '
                            'to operator %; nothing was recorded', v_child, v_child_op, v_parent,
                            v_parent_op
                USING ERRCODE = 'AID07',
                      HINT = 'Re-pointing an agent to another operator is an out-of-band act.';
        END IF;
    END IF;
    v_child_op := public.epigraph_human_of(v_child, false);

    -- 6. The audit row, when something new was recorded.
    IF v_created OR v_succ_rows > 0 OR v_snap_new OR v_key_new OR v_inherited THEN
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
                                   'inherit_reason', v_reason,
                                   'recorded_by', session_user));
    END IF;

    RETURN QUERY
    SELECT v_child, v_created, v_succ_rows > 0, v_snapshot, v_snap_new, v_key_new,
           v_child_op, v_inherited, v_reason;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_register_agent_identity(
    bytea, uuid, text, text, text, bytea, jsonb) FROM PUBLIC;

-- ===================================================================
-- PROMPT HISTORY (section 6)
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_agent_prompt_history(p_agent uuid)
RETURNS TABLE (agent_id uuid,
               relation text,
               depth integer,
               readable boolean,
               snapshot_id uuid,
               group_folder text,
               model text,
               prompt_hash text,
               in_prompt jsonb,
               blob_refused text[],
               runner_version text,
               host_sha text,
               first_seen timestamptz,
               last_seen timestamptz,
               identity_md_hash bytea,
               identity_md bytea,
               global_claude_md_hash bytea,
               global_claude_md bytea,
               group_claude_md_hash bytea,
               group_claude_md bytea,
               learned_md_hash bytea,
               learned_md bytea)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_admin     boolean;
BEGIN
    IF p_agent IS NULL THEN
        RAISE EXCEPTION 'epigraph_agent_prompt_history: an agent is required'
            USING ERRCODE = '22004';
    END IF;
    v_admin := public.epigraph_bypass()
               OR (v_principal IS NOT NULL
                   AND CASE WHEN public.epigraph_admin_scopes_armed()
                            THEN public.epigraph_is_elevated()
                            ELSE public.epigraph_is_instance_admin(v_principal)
                       END);
    IF NOT v_admin
       AND (v_principal IS NULL
            OR public.epigraph_human_of(p_agent, false) IS DISTINCT FROM v_principal) THEN
        RAISE EXCEPTION 'AID06: the prompt history of agent % is readable by its operator and by '
                        'admins only', p_agent
            USING ERRCODE = 'AID06';
    END IF;

    RETURN QUERY
    WITH RECURSIVE
    up (id, depth, path) AS (
        SELECT p_agent, 0, ARRAY[p_agent]
        UNION ALL
        SELECT s.parent_agent_id, up.depth - 1, up.path || s.parent_agent_id
          FROM up JOIN public.agent_succession s ON s.child_agent_id = up.id
         WHERE s.parent_agent_id <> ALL (up.path) AND up.depth > -64
    ),
    down (id, depth, path) AS (
        SELECT p_agent, 0, ARRAY[p_agent]
        UNION ALL
        SELECT s.child_agent_id, down.depth + 1, down.path || s.child_agent_id
          FROM down JOIN public.agent_succession s ON s.parent_agent_id = down.id
         WHERE s.child_agent_id <> ALL (down.path) AND down.depth < 64
    ),
    lineage AS (
        SELECT DISTINCT ON (l.id) l.id, l.depth
          FROM (SELECT u.id, u.depth FROM up u UNION ALL SELECT d.id, d.depth FROM down d) l
         ORDER BY l.id, abs(l.depth), l.depth
    ),
    gated AS (
        SELECT l.id, l.depth,
               COALESCE(l.id = p_agent OR v_admin
                        OR public.epigraph_human_of(l.id, false) = v_principal,
                        false) AS ok
          FROM lineage l
    )
    SELECT g.id,
           CASE WHEN g.depth = 0 THEN 'self'
                WHEN g.depth < 0 THEN 'ancestor'
                ELSE 'descendant' END,
           g.depth,
           g.ok,
           s.id, s.group_folder, s.model, s.prompt_hash, s.in_prompt, s.blob_refused,
           s.runner_version, s.host_sha, s.first_seen, s.last_seen,
           s.identity_md, bi.content,
           s.global_claude_md, bgl.content,
           s.group_claude_md, bgr.content,
           s.learned_md, bl.content
      FROM gated g
      LEFT JOIN public.agent_prompt_snapshots s ON g.ok AND s.agent_id = g.id
      LEFT JOIN public.agent_prompt_blobs bi  ON bi.blob_hash  = s.identity_md
      LEFT JOIN public.agent_prompt_blobs bgl ON bgl.blob_hash = s.global_claude_md
      LEFT JOIN public.agent_prompt_blobs bgr ON bgr.blob_hash = s.group_claude_md
      LEFT JOIN public.agent_prompt_blobs bl  ON bl.blob_hash  = s.learned_md
     ORDER BY g.depth, s.first_seen, s.id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_prompt_history(uuid) FROM PUBLIC;

-- ===================================================================
-- OWNERSHIP AND GRANTS, guarded as every such block since 060 is.
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_link_operator_body(uuid, uuid, jsonb) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_register_agent_identity('
                'bytea, uuid, text, text, text, bytea, jsonb) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_agent_prompt_history(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT ON public.agent_prompt_blobs, '
                'public.agent_prompt_snapshots, public.agent_succession TO epigraph_maintenance';
        EXECUTE 'GRANT UPDATE (last_seen) ON public.agent_prompt_snapshots TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agent_prompt_history(uuid) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        -- 077's ALTER DEFAULT PRIVILEGES handed the app role every table
        -- privilege at CREATE; keep SELECT only (no policy admits a row).
        EXECUTE 'REVOKE ALL ON public.agent_prompt_blobs, public.agent_prompt_snapshots, '
                'public.agent_succession FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.agent_prompt_blobs, public.agent_prompt_snapshots, '
                'public.agent_succession TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_link_operator_body(uuid, uuid, jsonb) '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_register_agent_identity('
                'bytea, uuid, text, text, text, bytea, jsonb) FROM epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agent_prompt_history(uuid) '
                'TO epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_identity_attestor') THEN
        EXECUTE 'GRANT USAGE ON SCHEMA public TO epigraph_identity_attestor';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_register_agent_identity('
                'bytea, uuid, text, text, text, bytea, jsonb) TO epigraph_identity_attestor';
    END IF;
    -- Last: the owner's own EXECUTE, so the ACL names the attestor alone. A
    -- maintenance session can still read and write these tables directly; what
    -- it cannot do is run the attestation as if it were the host.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance')
       AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_identity_attestor') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_register_agent_identity('
                'bytea, uuid, text, text, text, bytea, jsonb) FROM epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- LEGACY KEYS (section 7)
-- ===================================================================
INSERT INTO public.agent_keys (agent_id, public_key, key_type, status, valid_from)
SELECT a.id, a.public_key, 'identity-legacy', 'active', a.created_at
  FROM public.agents a
 WHERE NOT EXISTS (SELECT 1 FROM public.agent_keys k
                    WHERE k.agent_id = a.id AND k.key_type = 'identity-legacy');

-- The attested-key guard (section 7a), after the backfill above.
DROP TRIGGER IF EXISTS agent_keys_attested_guard ON public.agent_keys;
CREATE TRIGGER agent_keys_attested_guard
    BEFORE INSERT OR UPDATE ON public.agent_keys
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_agent_keys_attested_guard();
