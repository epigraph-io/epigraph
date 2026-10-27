-- ===================================================================
-- 180-undo.sql: take migration 180 (legacy fleet parents accepted by AID03,
-- and the after-the-fact succession record) back out, in ONE transaction, on
-- the migration (superuser) DSN.
--
-- READ FIRST. Once undone, AID03 refuses a legacy fleet parent again
-- (agent_type 'human' from the pre-161 create path), so the host registers
-- such a successor with no parent and it runs unlinked until an operator
-- links it by hand.
--
-- WHAT IT DOES
--   * Restores migration 166's body of `epigraph_register_agent_identity`,
--     byte for byte (CREATE OR REPLACE keeps its owner and ACL).
--   * Drops `epigraph_record_legacy_succession` and
--     `epigraph_is_legacy_fleet_parent`.
--
-- ORDER: newest first. Run this BEFORE `166-undo.sql`.
--
-- WHAT IT LEAVES: 180's `_sqlx_migrations` row, every `agent_succession` row
-- the record function wrote (the table is append-only) and their
-- `agent.identity_succession_recorded` audit rows (security_events is
-- immutable). Re-introducing the rule is a NEW migration, never a re-run of
-- 180. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

-- Precondition: the registration is 180's body (or already 166's: a second
-- run). Any other body means a LATER migration re-stated it, and restoring
-- 166's here would silently drop that migration's delta: undo it first.
DO $$
DECLARE
    v_found text;
BEGIN
    SELECT md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_register_agent_identity('
                                   'bytea, uuid, text, text, text, bytea, jsonb)');
    IF v_found IS NULL
       OR v_found NOT IN ('2fc3e7ee64fa3110c48aebc2432b2d95',   -- 180's
                          '9e195fdea9cf424aa5d6941c20f40651') THEN  -- 166's
        RAISE EXCEPTION '180-undo: the registration is neither 180''s nor 166''s body (md5 %); '
                        'a later migration re-stated it; undo that one first. Nothing was '
                        'changed', COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000';
    END IF;
END $$;

-- Migration 166's registration, verbatim.
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

DROP FUNCTION IF EXISTS public.epigraph_record_legacy_succession(uuid, uuid, text, text);
DROP FUNCTION IF EXISTS public.epigraph_is_legacy_fleet_parent(uuid);

COMMIT;
