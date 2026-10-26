-- 176: designed refusals an API or MCP caller can reach carry a refusal code
-- (backlog e2c22c7c, operator ruling R-25).
--
-- PR #686 made MCP internal errors fail closed: a database error reaches the
-- caller only when its MESSAGE opens with a schema refusal code
-- (`^[A-Z]{2,5}[0-9]{2}:`, e.g. `FA07: ...`); every other database text is
-- replaced with the generic internal-error reply and kept in the server log.
-- The refusals below are DESIGNED caller-facing text that an application
-- session reaches on a caller's write, but they named no code, so a caller
-- was told only "internal error". This migration gives each one a code.
--
-- WHAT CHANGES: each function is restated with CREATE OR REPLACE from its
-- LATEST definition (named above it), and only RAISE statements differ: a
-- code is prefixed to the message, the SQLSTATE (ERRCODE) is kept as it was,
-- so every caller that branches on the SQLSTATE answers as before. One
-- message also moves an interpolated value to DETAIL (AGK01: the system
-- agent's role). CREATE OR REPLACE keeps each function's owner, ACL,
-- SECURITY mode, volatility and search_path; the bodies are otherwise
-- byte-identical to their latest prior definition (pinned by
-- crates/epigraph-db/tests/caller_refusal_codes_restatement.rs, which compares
-- the catalog of a database at 175 with the same database after 176).
--
-- WHAT DOES NOT (R-25: only refusals a caller can reach are coded):
--   * maintenance-only, operator-CLI and admin-only refusals (functions the
--     application role cannot EXECUTE, triggers on tables it cannot write);
--   * refusals already coded by their SQLSTATE and mapped by a dedicated
--     DbError variant (RVK01/RVK02 in epigraph_ensure_personal_group);
--   * the deliberate copies of PostgreSQL's row-security text (FA04, FA06
--     in epigraph_foreign_aggregate_target, CR03 in
--     epigraph_resolve_challenge): they read as a policy refusal on purpose,
--     so a caller cannot tell a hidden row from a refused one;
--   * epigraph_claims_require_tenancy's predecessor and step-lineage arms
--     (they would tell a missing claim from a private one), and the three
--     *_require_tenancy bodies altogether while PR #511 restates them;
--   * refusals raised with SQLSTATE 23503 (foreign-key class), which both
--     surfaces classify by SQLSTATE before reading any message;
--   * guards whose argument every caller builds or pre-validates (the
--     22004 "is required" checks of the elevation and admin-act ceremony).
--
-- Codes introduced: AAR01-AAR12 (admin-act arguments), TEN01-TEN02 (row
-- ownership), GRM01-GRM06 (groups and their rosters), PRV01 (sealing),
-- AGK01 (a system agent's registered key). The HTTP layer maps exactly
-- these codes (epigraph_db::CALLER_REFUSAL_CODES) to a 4xx carrying the
-- message; the MCP layer already passes any coded message.

-- epigraph_admin_act_args: latest definition 130_pending_admin_acts.sql.
-- EXECUTE-able by epigraph_app; propose_admin_act (MCP and HTTP) relays its
-- 22023 text to the caller. Coded: AAR01, AAR02, AAR03, AAR04, AAR05, AAR06,
-- AAR07, AAR08, AAR09, AAR10, AAR11.

CREATE OR REPLACE FUNCTION public.epigraph_admin_act_args(p_kind text, p_args jsonb)
RETURNS jsonb
LANGUAGE plpgsql STABLE
SET search_path = public, pg_temp AS $$
DECLARE
    v_keys    text[];
    v_extra   text;
    v_truth   numeric;
    v_from    timestamptz;
    v_to      timestamptz;
BEGIN
    v_keys := CASE p_kind
                WHEN 'role.grant' THEN
                    ARRAY['role', 'holder', 'valid_from', 'valid_to', 'reason']
                WHEN 'role.end' THEN ARRAY['assignment', 'reason']
                WHEN 'claim.custodial_supersede' THEN
                    ARRAY['claim', 'content_sha256', 'truth', 'reason', 'allow_owned']
                WHEN 'passkey.register' THEN ARRAY['person', 'label', 'reason']
              END;
    IF v_keys IS NULL THEN
        RAISE EXCEPTION 'AAR01: epigraph_admin_act_args: % is not an admin act kind', p_kind
            USING ERRCODE = '22023';
    END IF;
    IF p_args IS NULL OR jsonb_typeof(p_args) <> 'object' THEN
        RAISE EXCEPTION 'AAR02: epigraph_admin_act_args: the args of % are a JSON object', p_kind
            USING ERRCODE = '22023';
    END IF;
    SELECT k INTO v_extra FROM jsonb_object_keys(p_args) AS k WHERE k <> ALL (v_keys) LIMIT 1;
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION 'AAR03: epigraph_admin_act_args: % takes no key %', p_kind, v_extra
            USING ERRCODE = '22023';
    END IF;
    -- Every kind carries a non-empty reason, as a string.
    IF jsonb_typeof(p_args->'reason') IS DISTINCT FROM 'string'
       OR length(btrim(p_args->>'reason')) = 0 THEN
        RAISE EXCEPTION 'AAR04: epigraph_admin_act_args: % needs a non-empty string reason', p_kind
            USING ERRCODE = '22023';
    END IF;
    BEGIN
        IF p_kind = 'role.grant' THEN
            IF jsonb_typeof(p_args->'role') IS DISTINCT FROM 'string'
               OR (p_args->>'role') !~ '^role:[a-z][a-z0-9-]*$'
               OR jsonb_typeof(p_args->'holder') IS DISTINCT FROM 'string'
               OR jsonb_typeof(COALESCE(p_args->'valid_from', 'null'))
                  NOT IN ('string', 'null')
               OR jsonb_typeof(COALESCE(p_args->'valid_to', 'null'))
                  NOT IN ('string', 'null') THEN
                RAISE EXCEPTION 'AAR05: role.grant: role (role:<key>), holder (uuid), valid_from and '
                                'valid_to (RFC 3339 or null)'
                    USING ERRCODE = '22023';
            END IF;
            v_from := (p_args->>'valid_from')::timestamptz;
            v_to := (p_args->>'valid_to')::timestamptz;
            IF NOT isfinite(COALESCE(v_from, now())) OR NOT isfinite(COALESCE(v_to, now())) THEN
                RAISE EXCEPTION 'AAR06: role.grant: valid_from and valid_to are finite times (null is '
                                '"from the execution" / "open-ended")'
                    USING ERRCODE = '22023';
            END IF;
            RETURN jsonb_build_object(
                'role', p_args->>'role',
                'holder', ((p_args->>'holder')::uuid)::text,
                'valid_from', public.epigraph_canonical_timestamp(v_from),
                'valid_to', public.epigraph_canonical_timestamp(v_to),
                'reason', p_args->>'reason');
        ELSIF p_kind = 'role.end' THEN
            IF jsonb_typeof(p_args->'assignment') IS DISTINCT FROM 'string' THEN
                RAISE EXCEPTION 'AAR07: role.end: assignment (uuid)'
                    USING ERRCODE = '22023';
            END IF;
            RETURN jsonb_build_object(
                'assignment', ((p_args->>'assignment')::uuid)::text,
                'reason', p_args->>'reason');
        ELSIF p_kind = 'claim.custodial_supersede' THEN
            IF jsonb_typeof(p_args->'claim') IS DISTINCT FROM 'string'
               OR jsonb_typeof(p_args->'content_sha256') IS DISTINCT FROM 'string'
               OR (p_args->>'content_sha256') !~ '^[0-9a-f]{64}$'
               OR jsonb_typeof(p_args->'truth') NOT IN ('string', 'number')
               OR jsonb_typeof(p_args->'allow_owned') IS DISTINCT FROM 'boolean' THEN
                RAISE EXCEPTION 'AAR08: claim.custodial_supersede: claim (uuid), content_sha256 (64 '
                                'lower-case hex), truth (a decimal in [0, 1]), allow_owned '
                                '(boolean)'
                    USING ERRCODE = '22023';
            END IF;
            v_truth := (p_args->>'truth')::numeric;
            IF v_truth < 0 OR v_truth > 1 OR v_truth <> round(v_truth, 6) THEN
                RAISE EXCEPTION 'AAR09: claim.custodial_supersede: truth % is not in [0, 1] with at '
                                'most six decimal places', p_args->>'truth'
                    USING ERRCODE = '22023';
            END IF;
            RETURN jsonb_build_object(
                'claim', ((p_args->>'claim')::uuid)::text,
                'content_sha256', p_args->>'content_sha256',
                'truth', round(v_truth, 6)::text,
                'reason', p_args->>'reason',
                'allow_owned', (p_args->>'allow_owned')::boolean);
        ELSE
            IF jsonb_typeof(p_args->'person') IS DISTINCT FROM 'string'
               OR jsonb_typeof(COALESCE(p_args->'label', 'null')) NOT IN ('string', 'null') THEN
                RAISE EXCEPTION 'AAR10: passkey.register: person (uuid), label (string or null)'
                    USING ERRCODE = '22023';
            END IF;
            -- `label` absent reads as null, like the times.
            RETURN jsonb_build_object(
                'person', ((p_args->>'person')::uuid)::text,
                'label', COALESCE(p_args->'label', 'null'::jsonb),
                'reason', p_args->>'reason');
        END IF;
    EXCEPTION
        WHEN invalid_text_representation OR invalid_datetime_format
             OR datetime_field_overflow OR numeric_value_out_of_range THEN
            RAISE EXCEPTION 'AAR11: epigraph_admin_act_args: a value of % does not parse: %',
                            p_kind, SQLERRM
                USING ERRCODE = '22023';
    END;
END $$;

-- epigraph_propose_admin_act: latest definition 130_pending_admin_acts.sql.
-- EXECUTE-able by epigraph_app; the MCP tool and the HTTP route relay its
-- 22023 text. Only the passkey.register refusal is the caller's; the reason
-- guard is pre-checked by both callers. Coded: AAR12.

CREATE OR REPLACE FUNCTION public.epigraph_propose_admin_act(
    p_kind text, p_args jsonb, p_reason text, p_jti text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_person     uuid := public.epigraph_principal_id();
    v_elevation  uuid;
    v_assignment uuid;
    v_args       jsonb;
    v_id         uuid;
BEGIN
    IF NOT public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'ELV07: an admin act is proposed only by an elevated session'
            USING ERRCODE = 'ELV07',
                  HINT = 'Elevate first (a passkey ceremony), then propose.';
    END IF;
    IF p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_propose_admin_act: a reason is required'
            USING ERRCODE = '22004';
    END IF;
    -- `epigraph_is_elevated()` has just checked the setting's shape.
    v_elevation := current_setting('epigraph.elevation_id', true)::uuid;
    SELECT s.assignment_id INTO v_assignment
      FROM public.elevation_sessions s WHERE s.id = v_elevation;
    v_args := public.epigraph_admin_act_args(p_kind, p_args);
    IF p_kind = 'passkey.register' AND (v_args->>'person')::uuid IS DISTINCT FROM v_person THEN
        RAISE EXCEPTION 'AAR12: epigraph_propose_admin_act: a passkey.register act registers the '
                        'proposer''s own later passkey'
            USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.pending_admin_acts (kind, args, args_digest, target_type, target_id,
                                           reason, proposed_by, elevation_id, assignment_id,
                                           jti, expires_at)
    VALUES (p_kind, v_args, public.epigraph_admin_act_digest(v_args),
            CASE p_kind WHEN 'role.end' THEN 'role_assignment'
                        WHEN 'claim.custodial_supersede' THEN 'claim'
                        ELSE 'agent' END,
            (v_args->>CASE p_kind WHEN 'role.grant' THEN 'holder'
                                  WHEN 'role.end' THEN 'assignment'
                                  WHEN 'claim.custodial_supersede' THEN 'claim'
                                  ELSE 'person' END)::uuid,
            p_reason, v_person, v_elevation, v_assignment, NULLIF(btrim(p_jti), ''),
            now() + interval '30 minutes')
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;

-- epigraph_owner_immutable_guard: latest definition
-- 115_owner_scoped_delete.sql. BEFORE UPDATE on rows epigraph_app may UPDATE.
-- Coded: TEN01.

CREATE OR REPLACE FUNCTION public.epigraph_owner_immutable_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_session_is_privileged_writer() THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'TEN01: epigraph tenancy: an UPDATE of % changes owner_group_id or '
                    'co_owner_group_id; only a maintenance session re-owns a row',
                    TG_TABLE_NAME
        USING ERRCODE = '42501';
END $$;

-- epigraph_writer_owner_guard: latest definition
-- 114_writer_owned_derived_rows.sql. BEFORE UPDATE on evidence,
-- mass_functions, reasoning_traces and challenges, which epigraph_app may
-- UPDATE. Coded: TEN02.

CREATE OR REPLACE FUNCTION public.epigraph_writer_owner_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_session_is_privileged_writer() THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'TEN02: epigraph tenancy: %.% changes owner_group_id or writer_owned, or the '
                    'claim_id or visibility of a writer-owned row; only a maintenance session '
                    're-owns a derived row or moves a writer-owned one', TG_TABLE_NAME, OLD.id
        USING ERRCODE = '42501';
END $$;

-- epigraph_group_memberships_identity_immutable: latest definition
-- 109_group_memberships_guards.sql. BEFORE UPDATE on group_memberships, which
-- epigraph_app may UPDATE. Coded: GRM01.

CREATE OR REPLACE FUNCTION public.epigraph_group_memberships_identity_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() OR public.epigraph_definer_bypass() THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'GRM01: group_memberships: a membership''s group_id and agent_id are its '
                    'identity and cannot be changed (migration 109 section 3); revoke the '
                    'row and insert a new one instead'
        USING ERRCODE = '42501';
END $$;

-- epigraph_group_memberships_no_retired_writer: latest definition
-- 109_group_memberships_guards.sql. BEFORE INSERT OR UPDATE on
-- group_memberships (the HTTP add-member write). Coded: GRM02.

CREATE OR REPLACE FUNCTION public.epigraph_group_memberships_no_retired_writer()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() OR public.epigraph_definer_bypass() THEN
        RETURN NEW;
    END IF;
    IF EXISTS (SELECT 1 FROM public.epigraph_operator_of_author(NEW.agent_id) o
                WHERE o.retired AND o.operator_group_id = NEW.group_id) THEN
        RAISE EXCEPTION 'GRM02: group_memberships: agent % has a RETIRED operator link to group %, '
                        'and a retired identity may hold no live writer or admin membership '
                        'there (migration 107 section 7)', NEW.agent_id, NEW.group_id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

-- epigraph_groups_identity_immutable: latest definition
-- 108_groups_identity_immutable.sql. BEFORE UPDATE on groups, which
-- epigraph_app may UPDATE. Coded: GRM03.

CREATE OR REPLACE FUNCTION public.epigraph_groups_identity_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() OR public.epigraph_definer_bypass() THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'GRM03: groups: created_by_agent_id, did_key and kind are immutable outside a '
                    'maintenance session (group %)', OLD.id
        USING ERRCODE = '42501';
END $$;

-- epigraph_groups_personal_identity_names_creator: latest definition
-- 108_groups_identity_immutable.sql. BEFORE INSERT on groups (the HTTP create-
-- group write). Coded: GRM04.

CREATE OR REPLACE FUNCTION public.epigraph_groups_personal_identity_names_creator()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() OR public.epigraph_definer_bypass() THEN
        RETURN NEW;
    END IF;
    IF NEW.kind IS DISTINCT FROM 'personal'
       OR NEW.did_key IS DISTINCT FROM
          'did:epigraph:personal:' || NEW.created_by_agent_id::text THEN
        RAISE EXCEPTION 'GRM04: groups: a personal group must be kind personal and carry '
                        'did:epigraph:personal:<its creator> (did_key %, kind %, creator %)',
                        NEW.did_key, NEW.kind, NEW.created_by_agent_id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

-- epigraph_team_group_roster_verbs_only: latest definition
-- 164_keyless_team_group_verbs.sql. BEFORE INSERT OR UPDATE on
-- group_memberships: an application write to a team group's roster. Coded:
-- GRM05.

CREATE OR REPLACE FUNCTION public.epigraph_team_group_roster_verbs_only()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() THEN
        RETURN NEW;
    END IF;
    -- NEW.group_id alone: 109 refuses moving a row to another group outside
    -- a maintenance session, and a maintenance session has returned above.
    IF EXISTS (SELECT 1 FROM public.groups g
                WHERE g.id = NEW.group_id AND g.did_key LIKE 'did:epigraph:group:%') THEN
        RAISE EXCEPTION 'GRM05: group_memberships: the roster of team group % is written only by the '
                        'team-group verbs (epigraph-operator group-member, on the maintenance '
                        'DSN); nothing was changed', NEW.group_id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

-- epigraph_team_group_row_verbs_only: latest definition
-- 164_keyless_team_group_verbs.sql. BEFORE INSERT / UPDATE on groups in the
-- team-group namespace. Coded: GRM06.

CREATE OR REPLACE FUNCTION public.epigraph_team_group_row_verbs_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'GRM06: groups: a keyless team group, or any group in the did:epigraph:group: '
                    'namespace, is created and changed only by the team-group verbs '
                    '(epigraph-operator create-group, on the maintenance DSN); nothing was '
                    'changed (did_key %, kind %, % key bytes)',
                    NEW.did_key, NEW.kind, octet_length(NEW.public_key)
        USING ERRCODE = '42501';
END $$;

-- epigraph_no_public_sealed: latest definition 081_privatization_guards.sql.
-- BEFORE INSERT OR UPDATE on claim_encryption (the HTTP claim create's sealing
-- write). Coded: PRV01.

CREATE OR REPLACE FUNCTION public.epigraph_no_public_sealed() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE v text;
BEGIN
    SELECT c.visibility INTO v FROM public.claims c WHERE c.id = NEW.claim_id;
    IF v = 'public' THEN
        RAISE EXCEPTION 'PRV01: privatization: refusing to seal claim % while it is '
                        'visibility=public. Restrict first, then seal.', NEW.claim_id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

-- epigraph_agents_refuse_registered_system_key: latest definition
-- 148_system_agent_registry.sql. BEFORE INSERT on agents (HTTP POST /agents,
-- the MCP document ingest's author agents). The role it names moves to DETAIL:
-- the caller's reply names no system identity. Coded: AGK01.

CREATE OR REPLACE FUNCTION public.epigraph_agents_refuse_registered_system_key()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_role text;
BEGIN
    SELECT s.role INTO v_role FROM public.system_agents s
     WHERE s.registered_public_key = NEW.public_key AND s.agent_id <> NEW.id;
    IF FOUND THEN
        RAISE EXCEPTION 'AGK01: agents: this public key was registered for a system agent '
                        '(migration 148); no other agent may hold it. Nothing was written'
            USING ERRCODE = '55000',
                  DETAIL = format('system agent role: %s', v_role);
    END IF;
    RETURN NEW;
END $$;
