-- 274: no non-superuser session marks a BBA retracted without a ledger grant
-- that names the row, the retractor and the reason the row then carries
-- (backlog 03d444a9).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- 184's retract guard has three arms. 251 closed two of them (the clear arm,
-- and 194's delete guard) by making each consume a grant of the append-only
-- ledger `mass_function_purge_grants`. 251's header recorded what it left:
--
--   * 184's MARK arm admits a privileged session (`epigraph_bypass()`), so a
--     maintenance login can still retract a live row with no audit row.
--
-- The mark arm fires on an UPDATE that sets or changes the retract columns
-- to a retracted state (`mass_functions_retract_guard`) and on an INSERT of
-- a row with any retract column set (`mass_functions_retract_insert_guard`).
-- It admitted `epigraph_bypass() OR epigraph_definer_bypass()`. A login
-- that inherits `epigraph_maintenance` passes the first, so it could
-- `UPDATE mass_functions SET retracted_at = now(), retracted_by = <anyone>,
-- retract_reason = <anything>` on any row: the row leaves every fold and
-- belief read, no `security_events` row is written, and the recorded
-- retractor is whoever the login chose.
--
-- ===================================================================
-- 1. WHAT IT DOES
-- ===================================================================
--
--   (1) THE LEDGER takes a third kind, `retract`
--       (`mass_function_purge_grants_kind_check`).
--   (2) `epigraph_mf_guard_grant` accepts that kind. `epigraph_mf_guard_consume`
--       consumes a `retract` grant only for a row whose `retracted_by` is the
--       grant's `granted_by` (which must be set), whose `retract_reason` is
--       the grant's `reason`, and whose `retracted_at` is the transaction's
--       `now()` (no backdating). Both stay owned by `epigraph_bba_guard_owner`,
--       SECURITY DEFINER on `pg_catalog, pg_temp`, naming no public object
--       but the ledger; their owner, ACL and path are unchanged (`CREATE OR
--       REPLACE` keeps them).
--   (3) THE MARK ARM of `epigraph_mass_function_retract_guard()` admits a
--       mark only by consuming a `retract` grant with `to_jsonb(NEW)` (the
--       row as it will be stored, retract columns included). Neither
--       `epigraph_bypass()` nor `epigraph_definer_bypass()` is read any
--       more. The one other admission is a SUPERUSER session (`session_user`
--       is a superuser): see (5).
--   (4) THE RETRACT DEFINER `epigraph_retract_mass_function` (184's body)
--       writes a `retract` grant through `epigraph_mf_guard_grant`, naming
--       its session principal and its trimmed reason, in its own statement
--       just before the UPDATE that sets the columns to exactly those. Every
--       other line is 184's; it stays maintenance-owned, on
--       `pg_catalog, public, pg_temp` (190's path).
--   (5) WHY A SUPERUSER IS STILL ADMITTED. A superuser may `ALTER TABLE ..
--       DISABLE TRIGGER` or drop the guard, so refusing it buys nothing
--       (251's header: "the migration login, superusers and the owner of
--       `mass_functions` can still do anything"). Test harnesses mark rows
--       directly on a superuser connection to set up a retracted row
--       independently of the definer, and keep doing so. The check reads
--       `session_user`, which neither a definer frame nor `SET ROLE` changes
--       and which `SET SESSION AUTHORIZATION` sets to the role it names, so a
--       maintenance login (NOSUPERUSER, as `docs/deploy.md` provisions it),
--       the maintenance role reached by `SET SESSION AUTHORIZATION`, and the
--       application role are all held to the grant.
--
-- The grant is consumed before the superuser check, so a definer call on a
-- superuser session still consumes, and records, its grant.
--
-- WHAT IS CLOSED: a mark that leaves no audit trail. Every mark by a
-- non-superuser session now leaves a ledger row no login can remove: the
-- kind, the row id, the session's own login (`grant_login`, which it cannot
-- choose), the retractor and reason the grant named, and the row as stored
-- (`consumed_row`); and the mark is stamped with the transaction's time.
--
-- WHAT IS NOT CLOSED (251's residual, now for the mark too; backlog
-- 03d444a9 stays open for it): a maintenance login can call
-- `epigraph_mf_guard_grant('retract', ..)` itself (the maintenance-owned
-- definer must be able to) and then mark the row with a direct UPDATE. The
-- retractor is then whatever that login named in its own grant, the mark
-- writes no `security_events` row, and the stored folds that included the
-- row (`ds_combined_beliefs`) are not cleared as the definer clears them.
-- Binding the mark to the definer itself does not fit here: the retractor
-- the definer records is `epigraph_principal_id()`, a setting any session
-- sets, and a role that alone could grant would still run the
-- maintenance-owned helpers the definer calls, which any maintenance login
-- may re-body (251 section 0). It needs the definer's privileged frame made
-- small enough to audit completely first, as 251 did for the ledger.
--
-- NOT CHANGED:
--   * The migration login, superusers and the owner of `mass_functions` (who
--     may disable the triggers) are outside what the guards defend.
--   * 114's dedup move and 184's other callers that move a retracted row
--     (claim, tenancy, tags) change no retract column, so the mark trigger
--     does not fire for them; no code path in this repository inserts a row
--     that arrives retracted (the dedup and K10 restores re-insert only rows
--     the guards let them delete, which are live).
--   * The definer writes its grant after its `already_retracted` return and
--     under its row lock, so its UPDATE always consumes it. A grant a
--     maintenance login writes and does not use stays unconsumed, bound to
--     its transaction like any other grant (and kept in the ledger).
--
-- ===================================================================
-- 2. PRIVILEGE, PRECONDITIONS AND REFUSALS
-- ===================================================================
--
-- It needs a SUPERUSER migration login: `CREATE OR REPLACE` of a function
-- owned by `epigraph_bba_guard_owner`, a role no login is a member of. A
-- login without that is refused 42501 with nothing changed.
--
-- PRECONDITIONS (55000, nothing changed unless all hold): `md5(prosrc)` and
-- `proconfig` of the four bodies it re-states are those of a database at 271:
--   epigraph_mass_function_retract_guard()          67fff432f24ba8c26be693c0c2d7f35b  {"search_path=pg_catalog, public, pg_temp"}
--   epigraph_mf_guard_grant(text, uuid[], text, uuid)
--                                                   7833508787fa01cffcf972d4c814a6a8  {"search_path=pg_catalog, pg_temp"}
--   epigraph_mf_guard_consume(text, uuid, jsonb)    a3a0ba7efcd8c45d9e2816ec0c8f1599  {"search_path=pg_catalog, pg_temp"}
--   epigraph_retract_mass_function(uuid, text, uuid, uuid)
--                                                   aca3e3d55092b3814cfebe8f062b1e37  {"search_path=pg_catalog, public, pg_temp"}
-- (251's three bodies, and 184's definer on 190's path.) And
-- `epigraph_bba_guard_owner_faults()` answers `{}` before and after.
-- Predeploy check: `SELECT p.oid::regprocedure, md5(p.prosrc), p.proconfig
-- FROM pg_proc p WHERE p.proname IN (...)`.
--
-- Locks: `ALTER TABLE` on the ledger (ACCESS EXCLUSIVE while its CHECK is
-- re-validated: one scan of the ledger), and `CREATE OR REPLACE` of the four
-- functions. `mass_functions` is not locked or scanned.
--
-- ===================================================================
-- 3. DEPLOY AND UNDO
-- ===================================================================
--
-- The HTTP route and MCP tool of the retraction call the definer with the
-- same signature and get the same answer; no binary changes. A tool or
-- script that marked rows retracted directly on the maintenance DSN is
-- refused after it (RT06, nothing written); none in this repository does.
--
-- UNDO: `docs/runbooks/274-undo.sql`. Undo 274 BEFORE 251 or 194 if either
-- is undone: 251's undo drops `epigraph_mf_guard_grant` and 194's drops the
-- ledger, both of which 274's retract definer writes through.
--
-- Slot 274 was assigned by the 2026-11-24 backlog triage. Checked before
-- claiming: no migration on main or on any origin branch carries a `274`,
-- and no in-flight migration touches these functions or the ledger.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 0. PRECONDITIONS
-- ===================================================================
DO $$
DECLARE
    v_bad text[] := '{}';
    v_faults text[];
    r record;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                    WHERE rolname = current_user AND rolsuper) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = pg_catalog.format(
                '274 refuses: %s is not a superuser, so it may not re-state the functions '
                'epigraph_bba_guard_owner owns; nothing was changed. Run epigraph-migrate on a '
                'superuser migration login.', current_user);
    END IF;
    FOR r IN
        SELECT e.sig, e.md5, e.cfg, p.prosrc IS NOT NULL AS present,
               pg_catalog.md5(p.prosrc) AS got_md5, p.proconfig AS got_cfg
          FROM (VALUES
                ('public.epigraph_mass_function_retract_guard()',
                 '67fff432f24ba8c26be693c0c2d7f35b',
                 ARRAY['search_path=pg_catalog, public, pg_temp']::text[]),
                ('public.epigraph_mf_guard_grant(text, uuid[], text, uuid)',
                 '7833508787fa01cffcf972d4c814a6a8',
                 ARRAY['search_path=pg_catalog, pg_temp']::text[]),
                ('public.epigraph_mf_guard_consume(text, uuid, jsonb)',
                 'a3a0ba7efcd8c45d9e2816ec0c8f1599',
                 ARRAY['search_path=pg_catalog, pg_temp']::text[]),
                ('public.epigraph_retract_mass_function(uuid, text, uuid, uuid)',
                 'aca3e3d55092b3814cfebe8f062b1e37',
                 ARRAY['search_path=pg_catalog, public, pg_temp']::text[])
               ) AS e(sig, md5, cfg)
          LEFT JOIN pg_catalog.pg_proc p
            ON p.oid = pg_catalog.to_regprocedure(e.sig)
    LOOP
        IF r.got_md5 IS DISTINCT FROM r.md5 OR r.got_cfg IS DISTINCT FROM r.cfg THEN
            v_bad := v_bad || pg_catalog.format('%s: md5 %s, proconfig %s', r.sig,
                                                COALESCE(r.got_md5, '(absent)'),
                                                COALESCE(r.got_cfg::text, '(none)'));
        END IF;
    END LOOP;
    IF pg_catalog.cardinality(v_bad) > 0 THEN
        RAISE EXCEPTION '274: these bodies are not the ones 274 re-states (a database at 271): '
                        '%; another migration re-bodied them, or 184/251 are not applied; '
                        'nothing was changed', v_bad
            USING ERRCODE = '55000',
                  HINT = 'Each body''s md5 and path must be the ones in 274''s header. Otherwise '
                         'apply a reconciling migration that re-states each body with every '
                         'delta instead of this one.';
    END IF;
    v_faults := public.epigraph_bba_guard_owner_faults();
    IF pg_catalog.cardinality(v_faults) > 0 THEN
        RAISE EXCEPTION '274 refuses: the retracted-BBA ledger or its owner is not isolated: %; '
                        'nothing was changed', v_faults
            USING ERRCODE = '55000',
                  HINT = 'Fix what epigraph_bba_guard_owner_faults() names (see 251), then re-run '
                         'epigraph-migrate.';
    END IF;
END $$;

-- ===================================================================
-- 1. THE LEDGER: a third kind
-- ===================================================================
ALTER TABLE public.mass_function_purge_grants
    DROP CONSTRAINT mass_function_purge_grants_kind_check,
    ADD CONSTRAINT mass_function_purge_grants_kind_check
        CHECK (kind IN ('purge', 'unretract', 'retract'));

COMMENT ON TABLE public.mass_function_purge_grants IS
    'Migrations 194, 251 and 274: the append-only ledger of grants that admit the delete (kind '
    'purge) or the un-retraction (kind unretract) of a retracted mass function, or the marking '
    'of one as retracted (kind retract, naming the retractor and the reason), in the transaction '
    'that wrote them (xact_id). Written only by epigraph_mf_guard_grant, consumed only by '
    'epigraph_mf_guard_consume (from the guards, with the row''s content), both owned by '
    'epigraph_bba_guard_owner, which alone holds a privilege on it. No row is deleted.';

-- ===================================================================
-- 2. THE OWNER'S FUNCTIONS (owner, ACL and path kept by CREATE OR REPLACE)
-- ===================================================================
-- 251's body; the delta is the third kind.
CREATE OR REPLACE FUNCTION public.epigraph_mf_guard_grant(
    p_kind text, p_ids uuid[], p_reason text, p_granted_by uuid)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_n pg_catalog.int4;
BEGIN
    IF p_kind IS NULL OR p_kind NOT IN ('purge', 'unretract', 'retract') THEN
        RAISE EXCEPTION 'a retracted-BBA grant is of kind purge, unretract or retract; nothing '
            'was written'
            USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.mass_function_purge_grants (mf_id, kind, granted_by, reason)
    SELECT DISTINCT u.id, p_kind, p_granted_by, p_reason
      FROM pg_catalog.unnest(p_ids) AS u(id)
     WHERE u.id IS NOT NULL;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    RETURN v_n;
END $$;
COMMENT ON FUNCTION public.epigraph_mf_guard_grant(text, uuid[], text, uuid) IS
    'Migrations 251 and 274: writes one ledger grant per id for this transaction, recording '
    'session_user. Runs as epigraph_bba_guard_owner and touches only the ledger.';

-- 251's body; the delta is the `274:` condition.
CREATE OR REPLACE FUNCTION public.epigraph_mf_guard_consume(p_kind text, p_id uuid, p_row jsonb)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_row IS NULL OR (p_row ->> 'id') IS DISTINCT FROM p_id::pg_catalog.text THEN
        RETURN false;
    END IF;
    UPDATE public.mass_function_purge_grants g
       SET consumed_at = pg_catalog.now(), consumed_login = session_user, consumed_row = p_row
     WHERE g.id = (SELECT pg_catalog.min(c.id) FROM public.mass_function_purge_grants c
                    WHERE c.xact_id = pg_catalog.pg_current_xact_id()
                      AND c.mf_id = p_id AND c.kind = p_kind
                      AND c.consumed_at IS NULL
                      -- 274: a retract grant admits only the row that names
                      -- the grant's retractor and reason, retracted at this
                      -- transaction's timestamp (never backdated).
                      AND (c.kind <> 'retract'
                           OR (c.granted_by IS NOT NULL
                               AND (p_row ->> 'retracted_by') = c.granted_by::pg_catalog.text
                               AND (p_row ->> 'retract_reason') = c.reason
                               AND ((p_row ->> 'retracted_at')::pg_catalog.timestamptz)
                                   = pg_catalog.now())));
    RETURN FOUND;
END $$;
COMMENT ON FUNCTION public.epigraph_mf_guard_consume(text, uuid, jsonb) IS
    'Migrations 251 and 274: consumes this transaction''s oldest unconsumed grant of the kind for '
    'the id (for kind retract, one naming the row''s retracted_by and retract_reason, for a row '
    'retracted at the transaction''s timestamp), recording '
    'the row and session_user; true when it did. The retracted-BBA guards'' only exception. Runs '
    'as epigraph_bba_guard_owner and touches only the ledger.';

-- ===================================================================
-- 3. THE GUARD
-- ===================================================================
-- 251's body; the delta is the `274:` lines of the mark arm.
CREATE OR REPLACE FUNCTION public.epigraph_mass_function_retract_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    -- No session or frame re-writes a retracted row's assessment.
    IF TG_ARGV[0] = 'rewrite' THEN
        RAISE EXCEPTION 'RT07: mass function % is retracted; a write to its key (claim, frame, '
            'source agent, perspective) is refused until it is un-retracted; nothing was written',
            OLD.id
            USING ERRCODE = '42501', DETAIL = OLD.id::text;
    END IF;
    -- Only 184's un-retract definer (section 2b) clears a retraction.
    IF TG_ARGV[0] = 'clear' THEN
        -- 251: consume the unretract grant that definer wrote, recording the
        -- row it admits.
        IF public.epigraph_mf_guard_consume('unretract', OLD.id, pg_catalog.to_jsonb(OLD)) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'RT06: a retracted mass function is made live again only through '
            'epigraph_unretract_mass_function (which records who, why and an audit row); '
            'nothing was written'
            USING ERRCODE = '42501';
    END IF;
    -- 274: consume the retract grant 184's definer wrote, which names this
    -- row's retractor and reason, recording the row as it will be stored.
    IF public.epigraph_mf_guard_consume('retract', NEW.id, pg_catalog.to_jsonb(NEW)) THEN
        RETURN NEW;
    END IF;
    -- 274: a superuser session may disable this trigger anyway.
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                WHERE r.rolname = session_user AND r.rolsuper) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'RT06: a mass function is retracted only through '
        'epigraph_retract_mass_function (which records the retractor and an audit row); '
        'nothing was written'
        USING ERRCODE = '42501';
END $$;

-- ===================================================================
-- 4. THE RETRACT DEFINER (maintenance-owned, as before)
-- ===================================================================
-- 184's body; the delta is the `274:` comment and the grant after it.
CREATE OR REPLACE FUNCTION public.epigraph_retract_mass_function(
    p_id uuid, p_reason text, p_admin_client uuid, p_admin_jti uuid)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE v_principal uuid := public.epigraph_principal_id();
        v_reason text := btrim(COALESCE(p_reason, ''));
        v_row public.mass_functions%ROWTYPE;
        v_arm text;
        v_at timestamptz;
        v_scoped bigint;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'RT01: retracting a mass function needs a session principal '
            '(epigraph.principal_id) to record as the retractor; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'RT05: an elevated session retracts no mass function; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF v_reason = '' OR length(v_reason) > 2000 THEN
        RAISE EXCEPTION 'RT04: a retraction needs a reason of 1 to 2000 characters; '
            'nothing was written'
            USING ERRCODE = '22023';
    END IF;

    -- Readability is in the WHERE: a caller that cannot read the row locks
    -- nothing and gets the answer a random id gets.
    SELECT mf.* INTO v_row
      FROM public.mass_functions mf
     WHERE mf.id = p_id
       AND (mf.visibility = 'public'
            OR mf.owner_group_id = ANY (public.epigraph_session_groups()))
       FOR UPDATE OF mf;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'RT02: mass function not found' USING ERRCODE = 'P0002';
    END IF;

    IF v_row.owner_group_id = ANY (COALESCE(public.epigraph_writable_groups(),
                                            ARRAY[]::uuid[])) THEN
        v_arm := 'owner';
    ELSIF p_admin_client IS NOT NULL AND EXISTS (
            SELECT 1 FROM public.oauth_clients c
             WHERE c.id = p_admin_client
               AND c.agent_id = v_principal
               AND c.status = 'active'
               AND 'claims:admin' = ANY (c.granted_scopes)) THEN
        v_arm := 'admin';
    ELSE
        RAISE EXCEPTION 'new row violates row-level security policy for table "mass_functions"'
            USING ERRCODE = '42501',
                  DETAIL = 'RT03: only a writer of the mass function''s owning group, or a '
                           'live claims:admin holder, retracts it; nothing was written';
    END IF;

    -- After the authority checks, so a caller that may not retract the row
    -- learns nothing of its state.
    IF v_row.retracted_at IS NOT NULL THEN
        RETURN jsonb_build_object(
            'status',           'already_retracted',
            'mass_function_id', v_row.id,
            'claim_id',         v_row.claim_id,
            'frame_id',         v_row.frame_id,
            'retracted_at',     v_row.retracted_at,
            'retracted_by',     v_row.retracted_by,
            'retract_reason',   v_row.retract_reason,
            'arm',              v_arm,
            'scoped_beliefs_cleared', 0);
    END IF;

    -- 274: the mark guard admits the UPDATE below only by consuming this
    -- grant, which the ledger's owner writes with this login, naming the
    -- retractor and reason the UPDATE sets.
    PERFORM public.epigraph_mf_guard_grant('retract', ARRAY[p_id], v_reason, v_principal);
    UPDATE public.mass_functions
       SET retracted_at = now(), retracted_by = v_principal, retract_reason = v_reason
     WHERE id = p_id
    RETURNING retracted_at INTO v_at;

    -- Only the stored folds that included this row: the global scope, its
    -- own perspective's, and each community counting that perspective (not
    -- a community's mass override, which folds no member row).
    DELETE FROM public.ds_combined_beliefs d
     WHERE d.claim_id = v_row.claim_id AND d.frame_id = v_row.frame_id
       AND (d.scope_type = 'global'
            OR (d.scope_type = 'perspective' AND d.scope_id = v_row.perspective_id)
            OR (d.scope_type = 'community'
                AND COALESCE(d.strategy_used, '') <> 'override'
                AND d.scope_id IN (SELECT cm.community_id
                                     FROM public.community_members cm
                                    WHERE cm.perspective_id = v_row.perspective_id)));
    GET DIAGNOSTICS v_scoped = ROW_COUNT;

    INSERT INTO public.security_events (event_type, agent_id, success, details, correlation_id)
    VALUES ('mass_functions.retract', v_principal, true,
            jsonb_build_object(
                'mass_function_id', v_row.id,
                'claim_id',         v_row.claim_id,
                'frame_id',         v_row.frame_id,
                'owner_group_id',   v_row.owner_group_id,
                'arm',              v_arm,
                'retractor_agent_id', v_principal,
                'admin_client_id',  CASE WHEN v_arm = 'admin' THEN p_admin_client END,
                'admin_token_jti',  CASE WHEN v_arm = 'admin' THEN p_admin_jti END,
                'reason',           v_reason,
                'before',           to_jsonb(v_row),
                'scoped_beliefs_cleared', v_scoped,
                'migration',        184),
            CASE WHEN v_arm = 'admin' THEN left(p_admin_jti::text, 64) END);

    RETURN jsonb_build_object(
        'status',           'retracted',
        'mass_function_id', v_row.id,
        'claim_id',         v_row.claim_id,
        'frame_id',         v_row.frame_id,
        'retracted_at',     v_at,
        'retracted_by',     v_principal,
        'retract_reason',   v_reason,
        'arm',              v_arm,
        'scoped_beliefs_cleared', v_scoped);
END $$;

-- ===================================================================
-- 5. POSTCONDITION
-- ===================================================================
DO $$
DECLARE
    v_faults text[] := public.epigraph_bba_guard_owner_faults();
BEGIN
    IF pg_catalog.cardinality(v_faults) > 0 THEN
        RAISE EXCEPTION '274 refuses: the retracted-BBA ledger or its owner is not isolated '
                        'after the re-statement: %; nothing was changed', v_faults
            USING ERRCODE = '55000';
    END IF;
END $$;
