-- 251: no session deletes or un-retracts a retracted BBA without a ledger row
-- that no login can remove; the only code that runs as the ledger's owner is
-- three small functions that touch nothing else (backlog 6bdac68f).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- Two guards on `mass_functions` keep a retracted BBA (migration 184) for
-- audit, and both had the same hole, which their own headers recorded:
--
--   * 194's delete guard admits the delete of a retracted row only when a row
--     of `mass_function_purge_grants` names it for the current transaction,
--     and only the purge definer was meant to write one. But the maintenance
--     role held INSERT on the table (its definers needed it), and every
--     maintenance login inherits that. Such a login could INSERT a grant
--     itself and then DELETE the retracted row: no audit row, no reason, the
--     row gone.
--   * 184's clear guard admits clearing the retract columns when the
--     statement runs as the maintenance role (`epigraph_definer_bypass()`)
--     AND the setting `epigraph.mf_unretract_id` names the row. A maintenance
--     login is the maintenance role and any session may set a setting, so
--     such a login could clear a retraction with no audit row.
--
-- Moving the two definers to a role no login can act as is not enough on its
-- own: whatever runs while such a definer runs, runs as that role. The
-- definers write `mass_functions`, `ds_combined_beliefs` and
-- `security_events`, whose row-security policies and triggers call
-- maintenance-owned functions. Any maintenance login may `ALTER FUNCTION` a
-- function its role owns (to SECURITY INVOKER, or to a path that searches the
-- session's temporary schema first for type names), and a type of its own in
-- `pg_temp` then runs its code inside the definer, as that role. An INVOKER
-- trigger whose path does not list `pg_temp` (184's guard) gave the same to
-- any session, the application's included. So the privileged frame must be
-- small enough to audit completely, not the whole definer.
--
-- ===================================================================
-- 1. WHAT IT DOES
-- ===================================================================
--
--   (1) THE LEDGER. `mass_function_purge_grants` becomes an append-only
--       ledger of grants: new columns `kind` ('purge' or 'unretract'),
--       `grant_login` (`session_user` of the granting session, which no
--       session can choose), `granted_at`, and the consumption
--       (`consumed_at`, `consumed_login`, `consumed_row`: the row's content
--       as the guard saw it). A surrogate identity key replaces the
--       (mf_id, xact_id) key, so a row can be granted twice in a transaction.
--       Rows are never deleted or rewritten except by the one consumption,
--       which only fills the three NULL consumption columns.
--   (2) THE OWNER. `epigraph_bba_guard_owner`: NOLOGIN, NOSUPERUSER,
--       NOBYPASSRLS, NOCREATEDB, NOCREATEROLE, NOREPLICATION, a member of no
--       role, granted to no role. It holds SELECT and INSERT on the ledger and
--       UPDATE of the three consumption columns, nothing else, and owns
--       exactly three SECURITY DEFINER functions, all on
--       `search_path = pg_catalog, pg_temp`, every name qualified, calling
--       only `pg_catalog`:
--         * `epigraph_mf_guard_grant(kind, ids, reason, granted_by)` writes
--           one grant per id (EXECUTE: the maintenance role);
--         * `epigraph_mf_guard_consume(kind, id, row)` consumes the oldest
--           unconsumed grant of the kind for the id in this transaction and
--           records the row, returning whether it did (EXECUTE: the
--           maintenance and application roles and a non-superuser owner of
--           `mass_functions`, the roles the guards run as);
--         * `epigraph_mf_purge_granted(uuid)` (194's helper; it now reads
--           only unconsumed purge grants).
--       The ledger has no trigger and no row security, its defaults and
--       checks call only `pg_catalog`, and so nothing else ever runs as the
--       owner.
--   (3) THE GUARDS. 194's delete guard admits the delete of a retracted row
--       only by consuming a purge grant with `to_jsonb(OLD)`; 184's clear
--       arm only by consuming an unretract grant the same way (the setting is
--       no longer read, and the guard's path now lists `pg_temp` last).
--   (4) THE DEFINERS stay maintenance-owned: the purge definer writes its
--       grants through (2) and keeps them (it deleted them before); the
--       un-retract definer writes an unretract grant through (2) instead of
--       setting the marker. Every other line of their bodies is unchanged.
--   (5) `REVOKE ALL` on the ledger from the maintenance role.
--   (6) `public.epigraph_bba_guard_owner_faults() RETURNS text[]` (SECURITY
--       INVOKER, runner-owned, EXECUTE to the maintenance role only): every
--       way the role or the ledger could be abused, `{}` when sound. Faults:
--       the role missing or holding any attribute above, a member of any
--       role; any non-superuser role that is a member of it (directly or
--       not; PostgreSQL 16's ADMIN-only grant counts: its holder can grant
--       itself the role), or that holds ADMIN OPTION on it; any non-superuser
--       CREATEROLE role; any non-superuser role other than the owner (and the
--       table owner's members) that can write the ledger, `pg_write_all_data`
--       included; the owner holding DELETE, TRUNCATE or table-wide UPDATE on
--       it; any object the owner owns beyond the three functions, or one of
--       them not owned by it, not SECURITY DEFINER or not on its path; any
--       trigger or row security on the ledger. The migration refuses (55000,
--       nothing changed) when it is not `{}` at the end.
--
-- WHAT A SESSION CAN STILL DO, AND WHY THAT IS THE CLAIM: a maintenance
-- login can call `epigraph_mf_guard_grant` itself (the maintenance-owned
-- definers do, so their role must be able to), then delete or un-retract the
-- row. It could already do both through the definers. Either way the ledger
-- now holds a row it cannot remove: the kind, the row id, its own login, the
-- reason, and the row's content consumed by the guard. "Without the audit
-- row" is what is closed.
--
-- NOT CHANGED, OUTSIDE WHAT THESE GUARDS DEFEND:
--   * 184's MARK arm admits a privileged session (`epigraph_bypass()`), so a
--     maintenance login can still retract a live row with no audit row.
--   * A purge grant the purge definer wrote for a live or absent id stays
--     unconsumed for the rest of that transaction; a later delete in the same
--     transaction of that row, once retracted, is admitted and consumes it
--     (recorded with the row's content).
--   * The migration login, superusers and the owner of `mass_functions` can
--     still do anything, including dropping these triggers.
--   * Maintenance-owned functions that run as the maintenance role inside
--     the maintenance-owned definers remain alterable by any maintenance
--     login, which gains nothing it does not already hold; this is now only
--     as strong as the maintenance role, which can no longer write the ledger.
--
-- ===================================================================
-- 2. PRIVILEGE, PRECONDITIONS AND REFUSALS
-- ===================================================================
--
-- No `epigraph_maintenance` role (a managed Postgres where 060 could only
-- NOTICE): the migration refuses (55000). The ledger's owner and grants need
-- it, and a silent skip would leave the hole open with 251 recorded.
--
-- Otherwise it needs a SUPERUSER migration login (`CREATE ROLE`, and `ALTER
-- FUNCTION ... OWNER TO` a role the runner is not a member of): a login
-- without that is refused 42501 with nothing changed, as 231 refuses.
--
-- PRECONDITIONS (55000, nothing changed unless all hold): `md5(prosrc)` and
-- `proconfig` of the five bodies it re-states are those of a database at 250,
-- except that the retract guard may also be on `pg_catalog, public, pg_temp`:
--   epigraph_mass_function_retract_guard()          be48455cec9bc897f0f13473129c52ff  {search_path=pg_catalog, public}
--                                                                                     or {"search_path=pg_catalog, public, pg_temp"}
--   mass_functions_retracted_delete_guard()         baf4285cd182aed1493a90a5eefef454  {search_path=pg_catalog, pg_temp}
--   epigraph_mf_purge_granted(uuid)                 2ac6c54699fcbb785e624a377997247b  {search_path=pg_catalog, pg_temp}
--   epigraph_purge_mass_functions(uuid[], text)     85e75b8d2da5a4a1a97496c7303d0c83  {search_path=pg_catalog, pg_temp}
--   epigraph_unretract_mass_function(uuid, text, uuid, uuid)
--                                                   3f0369e03257d9be2c1d62644c334c60  {"search_path=pg_catalog, public, pg_temp",epigraph.mf_unretract_id=}
-- Predeploy check: `SELECT p.oid::regprocedure, md5(p.prosrc), p.proconfig
-- FROM pg_proc p WHERE p.proname IN (...)`.
-- The retract guard's second path is the interim mitigation an operator may
-- apply before 251 deploys (backlog eff4aaf5: `ALTER FUNCTION
-- epigraph_mass_function_retract_guard() SET search_path = pg_catalog, public,
-- pg_temp`, `proconfig` only, so the md5 is the same either way), and the
-- path 251-undo.sql restores. 251 re-states the guard on that path anyway, so
-- either one leaves the same function. As 194 accepts 117's and 190's paths
-- for the cascade definer; every other body and path must match exactly.
--
-- An existing `epigraph_bba_guard_owner` is reused. A membership of
-- `epigraph_maintenance` it holds (an earlier draft of this change granted
-- one) is revoked; any other fault refuses the migration.
--
-- Locks: `ALTER TABLE` on the ledger (ACCESS EXCLUSIVE; the table holds at
-- most the grants of in-flight purges), and `CREATE OR REPLACE` of the five
-- functions. `mass_functions` is not locked or scanned.
--
-- ===================================================================
-- 3. DEPLOY AND UNDO
-- ===================================================================
--
-- The HTTP route and MCP tool of the un-retract, and the purge definer, call
-- the same functions with the same signatures. `epigraph-operator
-- delete-frames` counts the ledger's writes in its census (the purge now
-- inserts and consumes its grants instead of inserting and deleting them):
-- a binary built before 251 refuses its purge over 251 (rolled back,
-- nothing written), so install the `delete-frames` built with 251 with it.
-- A tool or script that wrote the ledger or cleared the retract columns
-- directly on the maintenance DSN is refused after it; none in this
-- repository does.
--
-- Audit after migrating: `SELECT public.epigraph_bba_guard_owner_faults()`
-- returns `{}` (`epigraph-tenancy-backfill verify` runs it).
--
-- UNDO: `docs/runbooks/251-undo.sql`.
--
-- Slot 251 was assigned by the 2026-11-22 backlog triage. Checked before
-- claiming: no migration on main or on any origin branch carries a `251`, and
-- no in-flight migration touches these functions or the ledger.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 0. PRECONDITIONS
-- ===================================================================
DO $$
DECLARE
    v_bad text[] := '{}';
    r record;
BEGIN
    FOR r IN
        SELECT e.sig, e.md5, e.cfg, e.alt_cfg, p.prosrc IS NOT NULL AS present,
               pg_catalog.md5(p.prosrc) AS got_md5, p.proconfig AS got_cfg
          FROM (VALUES
                ('public.epigraph_mass_function_retract_guard()',
                 'be48455cec9bc897f0f13473129c52ff',
                 ARRAY['search_path=pg_catalog, public']::text[],
                 ARRAY['search_path=pg_catalog, public, pg_temp']::text[]),
                ('public.mass_functions_retracted_delete_guard()',
                 'baf4285cd182aed1493a90a5eefef454',
                 ARRAY['search_path=pg_catalog, pg_temp']::text[],
                 NULL::text[]),
                ('public.epigraph_mf_purge_granted(uuid)',
                 '2ac6c54699fcbb785e624a377997247b',
                 ARRAY['search_path=pg_catalog, pg_temp']::text[],
                 NULL::text[]),
                ('public.epigraph_purge_mass_functions(uuid[], text)',
                 '85e75b8d2da5a4a1a97496c7303d0c83',
                 ARRAY['search_path=pg_catalog, pg_temp']::text[],
                 NULL::text[]),
                ('public.epigraph_unretract_mass_function(uuid, text, uuid, uuid)',
                 '3f0369e03257d9be2c1d62644c334c60',
                 ARRAY['search_path=pg_catalog, public, pg_temp',
                       'epigraph.mf_unretract_id=']::text[],
                 NULL::text[])
               ) AS e(sig, md5, cfg, alt_cfg)
          LEFT JOIN pg_catalog.pg_proc p
            ON p.oid = pg_catalog.to_regprocedure(e.sig)
    LOOP
        -- alt_cfg is the retract guard's second accepted path (NULL for the
        -- other four, which must match cfg exactly; an absent proconfig
        -- matches neither).
        IF r.got_md5 IS DISTINCT FROM r.md5
           OR (r.got_cfg IS DISTINCT FROM r.cfg
               AND (r.alt_cfg IS NULL OR r.got_cfg IS DISTINCT FROM r.alt_cfg)) THEN
            v_bad := v_bad || pg_catalog.format('%s: md5 %s, proconfig %s', r.sig,
                                                COALESCE(r.got_md5, '(absent)'),
                                                COALESCE(r.got_cfg::text, '(none)'));
        END IF;
    END LOOP;
    IF pg_catalog.cardinality(v_bad) > 0 THEN
        RAISE EXCEPTION '251: these bodies are not the ones 251 re-states (a database at 250): '
                        '%; another migration re-bodied them, or 184/190/194 are not applied; '
                        'nothing was changed', v_bad
            USING ERRCODE = '55000',
                  HINT = 'Each body''s md5 and path must be the ones in 251''s header (the '
                         'retract guard may be on pg_catalog, public or on pg_catalog, public, '
                         'pg_temp). Otherwise apply a reconciling migration that re-states each '
                         'body with every delta instead of this one.';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        RAISE EXCEPTION '251: role epigraph_maintenance does not exist; the ledger''s grants '
                        'and the definers'' owner need it; nothing was changed'
            USING ERRCODE = '55000',
                  HINT = 'Provision the tenancy roles (060) and re-apply 184, 194 and 251.';
    END IF;
END $$;

-- ===================================================================
-- 1. THE OWNER
-- ===================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_bba_guard_owner') THEN
        BEGIN
            CREATE ROLE epigraph_bba_guard_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB
                NOCREATEROLE NOREPLICATION NOINHERIT;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE EXCEPTION USING
                    ERRCODE = '42501',
                    MESSAGE = pg_catalog.format(
                        '251 refuses: %s may not CREATE ROLE epigraph_bba_guard_owner; nothing '
                        'was changed. Run epigraph-migrate on a superuser migration login.',
                        current_user);
            -- Lost a race with a parallel database of the same cluster (060's
            -- note: 42710 when it merely lost, 23505 when the two raced).
            WHEN duplicate_object THEN NULL;
            WHEN unique_violation THEN NULL;
        END;
    END IF;
    -- An earlier draft of this change made the role a member of the
    -- maintenance role; it must hold no role.
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                WHERE m.member = 'epigraph_bba_guard_owner'::pg_catalog.regrole
                  AND m.roleid = 'epigraph_maintenance'::pg_catalog.regrole) THEN
        BEGIN
            REVOKE epigraph_maintenance FROM epigraph_bba_guard_owner;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                MESSAGE = pg_catalog.format(
                    '251 refuses: %s may not revoke epigraph_maintenance from '
                    'epigraph_bba_guard_owner; nothing was changed. Run epigraph-migrate on a '
                    'superuser migration login.', current_user);
        END;
    END IF;
END $$;

-- ===================================================================
-- 2. THE LEDGER
-- ===================================================================
ALTER TABLE public.mass_function_purge_grants
    ADD COLUMN kind text NOT NULL DEFAULT 'purge'
        CONSTRAINT mass_function_purge_grants_kind_check CHECK (kind IN ('purge', 'unretract')),
    ADD COLUMN grant_login name NOT NULL DEFAULT session_user,
    ADD COLUMN granted_at timestamptz NOT NULL DEFAULT pg_catalog.now(),
    ADD COLUMN consumed_at timestamptz,
    ADD COLUMN consumed_login name,
    ADD COLUMN consumed_row jsonb,
    ADD COLUMN id bigint GENERATED ALWAYS AS IDENTITY,
    ADD CONSTRAINT mass_function_purge_grants_consumed_check
        CHECK ((consumed_at IS NULL) = (consumed_login IS NULL)
               AND (consumed_at IS NULL) = (consumed_row IS NULL));
ALTER TABLE public.mass_function_purge_grants ALTER COLUMN kind DROP DEFAULT;
ALTER TABLE public.mass_function_purge_grants
    DROP CONSTRAINT mass_function_purge_grants_pkey,
    ADD CONSTRAINT mass_function_purge_grants_pkey PRIMARY KEY (id);
CREATE INDEX mass_function_purge_grants_xact_idx
    ON public.mass_function_purge_grants (xact_id, mf_id, kind);

COMMENT ON TABLE public.mass_function_purge_grants IS
    'Migrations 194 and 251: the append-only ledger of grants that admit the delete (kind '
    'purge) or the un-retraction (kind unretract) of a retracted mass function in the '
    'transaction that wrote them (xact_id). Written only by epigraph_mf_guard_grant, consumed '
    'only by epigraph_mf_guard_consume (from the guards, with the row''s content), both owned '
    'by epigraph_bba_guard_owner, which alone holds a privilege on it. No row is deleted.';
COMMENT ON COLUMN public.mass_function_purge_grants.grant_login IS
    'Migration 251: session_user of the session that wrote the grant.';
COMMENT ON COLUMN public.mass_function_purge_grants.consumed_row IS
    'Migration 251: the mass_functions row (to_jsonb(OLD)) the guard admitted with this grant.';

REVOKE ALL ON public.mass_function_purge_grants FROM PUBLIC;
REVOKE ALL ON public.mass_function_purge_grants FROM epigraph_maintenance;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.mass_function_purge_grants FROM epigraph_app';
    END IF;
END $$;
GRANT USAGE ON SCHEMA public TO epigraph_bba_guard_owner;
GRANT SELECT, INSERT ON public.mass_function_purge_grants TO epigraph_bba_guard_owner;
GRANT UPDATE (consumed_at, consumed_login, consumed_row)
    ON public.mass_function_purge_grants TO epigraph_bba_guard_owner;

-- ===================================================================
-- 3. THE OWNER'S THREE FUNCTIONS
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_mf_guard_grant(
    p_kind text, p_ids uuid[], p_reason text, p_granted_by uuid)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_n pg_catalog.int4;
BEGIN
    IF p_kind IS NULL OR p_kind NOT IN ('purge', 'unretract') THEN
        RAISE EXCEPTION 'a retracted-BBA grant is of kind purge or unretract; nothing was written'
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
    'Migration 251: writes one ledger grant per id for this transaction, recording session_user. '
    'Runs as epigraph_bba_guard_owner and touches only the ledger.';

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
                      AND c.consumed_at IS NULL);
    RETURN FOUND;
END $$;
COMMENT ON FUNCTION public.epigraph_mf_guard_consume(text, uuid, jsonb) IS
    'Migration 251: consumes this transaction''s oldest unconsumed grant of the kind for the id, '
    'recording the row and session_user; true when it did. The retracted-BBA guards'' only '
    'exception. Runs as epigraph_bba_guard_owner and touches only the ledger.';

-- 194's helper: unconsumed purge grants only.
CREATE OR REPLACE FUNCTION public.epigraph_mf_purge_granted(p_id uuid)
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM public.mass_function_purge_grants g
                    WHERE g.mf_id = p_id
                      AND g.kind = 'purge'
                      AND g.consumed_at IS NULL
                      AND g.xact_id = pg_catalog.pg_current_xact_id());
END $$;
COMMENT ON FUNCTION public.epigraph_mf_purge_granted(uuid) IS
    'Migrations 194 and 251: true when an unconsumed purge grant names this mass_functions id '
    'for the current transaction.';

REVOKE EXECUTE ON FUNCTION public.epigraph_mf_guard_grant(text, uuid[], text, uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.epigraph_mf_guard_consume(text, uuid, jsonb) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) FROM PUBLIC;

-- ===================================================================
-- 4. THE GUARDS
-- ===================================================================
-- 194's body; the one delta is the `251:` line.
CREATE OR REPLACE FUNCTION public.mass_functions_retracted_delete_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- 251: consume a purge grant, recording the row it admits.
    IF public.epigraph_mf_guard_consume('purge', OLD.id, pg_catalog.to_jsonb(OLD)) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'SR09: a retracted mass function is deleted only through '
        'epigraph_purge_mass_functions, which records the row and the reason; a claim or frame '
        'delete that would cascade onto one is refused too (purge its retracted rows first); '
        'nothing was deleted'
        USING ERRCODE = '42501', DETAIL = OLD.id::text;
END $$;

-- 184's body; the deltas are the `251:` lines of the clear arm, two comment
-- lines reworded, and the path, which now lists `pg_temp` last.
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
    IF public.epigraph_bypass() OR public.epigraph_definer_bypass() THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'RT06: a mass function is retracted only through '
        'epigraph_retract_mass_function (which records the retractor and an audit row); '
        'nothing was written'
        USING ERRCODE = '42501';
END $$;

-- ===================================================================
-- 5. THE DEFINERS (maintenance-owned, as before)
-- ===================================================================
-- 194's body; the deltas are the two `251:` comments and what follows them.
CREATE OR REPLACE FUNCTION public.epigraph_purge_mass_functions(p_ids uuid[], p_reason text)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_reason text := pg_catalog.btrim(COALESCE(p_reason, ''));
    v_ids uuid[];
    v_rows jsonb;
    v_n integer;
BEGIN
    IF v_reason = '' OR pg_catalog.length(v_reason) > 2000 THEN
        RAISE EXCEPTION 'a purge of mass functions needs a reason of 1 to 2000 characters; '
            'nothing was deleted'
            USING ERRCODE = '22023';
    END IF;
    v_ids := ARRAY(SELECT DISTINCT u.id
                     FROM pg_catalog.unnest(COALESCE(p_ids, ARRAY[]::uuid[])) AS u(id)
                    WHERE u.id IS NOT NULL);
    IF pg_catalog.cardinality(v_ids) = 0 THEN
        RETURN 0;
    END IF;

    -- The grants first, in their own statement: the guard on the DELETE below
    -- reads them, and the parts of one statement share one snapshot, so a
    -- grant written by a sibling CTE would be invisible to it.
    -- 251: written by the ledger's owner, which records this login; the
    -- delete guard consumes each grant with the row it admits.
    PERFORM public.epigraph_mf_guard_grant('purge', v_ids, v_reason, v_principal);

    WITH gone AS (
        DELETE FROM public.mass_functions m
         WHERE m.id = ANY (v_ids)
        RETURNING m.*
    )
    SELECT pg_catalog.count(*)::integer,
           COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(g) ORDER BY g.id),
                    '[]'::jsonb)
      INTO v_n, v_rows
      FROM gone g;

    -- 251: the grants are kept; they are the ledger of this purge.

    IF v_n > 0 THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('mass_functions.purge', v_principal, true,
                pg_catalog.jsonb_build_object(
                    'reason',    v_reason,
                    'requested', pg_catalog.cardinality(v_ids),
                    'deleted',   v_n,
                    'rows',      v_rows,
                    'migration', 194));
    END IF;
    RETURN v_n;
END $$;

-- 184's body; the delta is the `251:` comment and the grant that replaces
-- the two `set_config` calls. The marker setting stays in `proconfig`
-- (inert: the clear guard no longer reads it).
CREATE OR REPLACE FUNCTION public.epigraph_unretract_mass_function(
    p_id uuid, p_reason text, p_admin_client uuid, p_admin_jti uuid)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
SET epigraph.mf_unretract_id = ''
AS $$
DECLARE v_principal uuid := public.epigraph_principal_id();
        v_reason text := btrim(COALESCE(p_reason, ''));
        v_row public.mass_functions%ROWTYPE;
        v_arm text;
        v_scoped bigint;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'RT01: un-retracting a mass function needs a session principal '
            '(epigraph.principal_id) to record; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'RT05: an elevated session un-retracts no mass function; '
            'nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF v_reason = '' OR length(v_reason) > 2000 THEN
        RAISE EXCEPTION 'RT04: an un-retraction needs a reason of 1 to 2000 characters; '
            'nothing was written'
            USING ERRCODE = '22023';
    END IF;

    -- Readability in the WHERE, as in section 2.
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
                           'live claims:admin holder, un-retracts it; nothing was written';
    END IF;

    -- After the authority checks, so a caller that may not un-retract the row
    -- learns nothing of its state.
    IF v_row.retracted_at IS NULL THEN
        RETURN jsonb_build_object(
            'status',           'not_retracted',
            'mass_function_id', v_row.id,
            'claim_id',         v_row.claim_id,
            'frame_id',         v_row.frame_id,
            'unretracted_by',   v_principal,
            'reason',           v_reason,
            'arm',              v_arm,
            'previously_retracted_at', NULL,
            'previously_retracted_by', NULL,
            'previous_retract_reason', NULL,
            'scoped_beliefs_cleared', 0);
    END IF;

    -- 251: the clear guard admits the UPDATE below only by consuming this
    -- grant, which the ledger's owner writes with this login.
    PERFORM public.epigraph_mf_guard_grant('unretract', ARRAY[p_id], v_reason, v_principal);
    UPDATE public.mass_functions
       SET retracted_at = NULL, retracted_by = NULL, retract_reason = NULL
     WHERE id = p_id;

    -- The stored folds that will include this row again: the same scopes a
    -- retraction clears.
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
    VALUES ('mass_functions.unretract', v_principal, true,
            jsonb_build_object(
                'mass_function_id', v_row.id,
                'claim_id',         v_row.claim_id,
                'frame_id',         v_row.frame_id,
                'owner_group_id',   v_row.owner_group_id,
                'arm',              v_arm,
                'unretractor_agent_id', v_principal,
                'admin_client_id',  CASE WHEN v_arm = 'admin' THEN p_admin_client END,
                'admin_token_jti',  CASE WHEN v_arm = 'admin' THEN p_admin_jti END,
                'reason',           v_reason,
                'before',           to_jsonb(v_row),
                'scoped_beliefs_cleared', v_scoped,
                'migration',        184),
            CASE WHEN v_arm = 'admin' THEN left(p_admin_jti::text, 64) END);

    RETURN jsonb_build_object(
        'status',           'unretracted',
        'mass_function_id', v_row.id,
        'claim_id',         v_row.claim_id,
        'frame_id',         v_row.frame_id,
        'unretracted_by',   v_principal,
        'reason',           v_reason,
        'arm',              v_arm,
        'previously_retracted_at', v_row.retracted_at,
        'previously_retracted_by', v_row.retracted_by,
        'previous_retract_reason', v_row.retract_reason,
        'scoped_beliefs_cleared', v_scoped);
END $$;

-- ===================================================================
-- 6. OWNERSHIP AND EXECUTE
-- ===================================================================
DO $$
DECLARE
    v_owner name;
    v_super boolean;
BEGIN
    BEGIN
        ALTER FUNCTION public.epigraph_mf_guard_grant(text, uuid[], text, uuid)
            OWNER TO epigraph_bba_guard_owner;
        ALTER FUNCTION public.epigraph_mf_guard_consume(text, uuid, jsonb)
            OWNER TO epigraph_bba_guard_owner;
        ALTER FUNCTION public.epigraph_mf_purge_granted(uuid) OWNER TO epigraph_bba_guard_owner;
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = pg_catalog.format(
                '251 refuses: %s may not give the ledger''s functions to '
                'epigraph_bba_guard_owner; nothing was changed. Run epigraph-migrate on a '
                'superuser migration login.', current_user);
    END;

    GRANT EXECUTE ON FUNCTION public.epigraph_mf_guard_grant(text, uuid[], text, uuid)
        TO epigraph_maintenance;
    GRANT EXECUTE ON FUNCTION public.epigraph_mf_guard_consume(text, uuid, jsonb)
        TO epigraph_maintenance;
    -- OWNER TO rewrote the maintenance role's own entry on 194's helper to the
    -- new owner; give it back.
    GRANT EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) TO epigraph_maintenance;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_mf_guard_consume(text, uuid, jsonb) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) TO epigraph_app';
    END IF;

    -- The guards run as the owner of `mass_functions` inside an FK cascade
    -- from `claims` or `frames` (194 section 3).
    SELECT r.rolname, r.rolsuper INTO v_owner, v_super
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
     WHERE c.oid = 'public.mass_functions'::pg_catalog.regclass;
    IF NOT v_super THEN
        EXECUTE pg_catalog.format(
            'GRANT EXECUTE ON FUNCTION public.epigraph_mf_guard_consume(text, uuid, jsonb) TO %I',
            v_owner);
        EXECUTE pg_catalog.format(
            'GRANT EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) TO %I', v_owner);
    END IF;
END $$;

-- ===================================================================
-- 7. THE FAULTS FUNCTION, AND THE CHECK
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_bba_guard_owner_faults()
RETURNS text[]
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_role pg_catalog.oid;
    v_table pg_catalog.regclass := pg_catalog.to_regclass('public.mass_function_purge_grants');
    v_table_owner pg_catalog.oid;
    v_fns pg_catalog.oid[];
    v_out pg_catalog.text[] := '{}';
    v_sig pg_catalog.text;
    v_fn pg_catalog.oid;
    v_fn_owner pg_catalog.oid;
    v_fn_secdef boolean;
    v_fn_config pg_catalog.text[];
BEGIN
    SELECT r.oid INTO v_role FROM pg_catalog.pg_roles r
     WHERE r.rolname = 'epigraph_bba_guard_owner';
    IF v_role IS NULL THEN
        RETURN ARRAY['epigraph_bba_guard_owner does not exist'];
    END IF;

    -- The role itself.
    SELECT pg_catalog.array_remove(ARRAY[
               CASE WHEN r.rolcanlogin THEN 'epigraph_bba_guard_owner can LOGIN' END,
               CASE WHEN r.rolsuper THEN 'epigraph_bba_guard_owner is SUPERUSER' END,
               CASE WHEN r.rolbypassrls THEN 'epigraph_bba_guard_owner is BYPASSRLS' END,
               CASE WHEN r.rolcreaterole THEN 'epigraph_bba_guard_owner is CREATEROLE' END,
               CASE WHEN r.rolcreatedb THEN 'epigraph_bba_guard_owner is CREATEDB' END,
               CASE WHEN r.rolreplication THEN 'epigraph_bba_guard_owner is REPLICATION' END],
           NULL)
      INTO v_out
      FROM pg_catalog.pg_roles r WHERE r.oid = v_role;
    v_out := v_out || ARRAY(
        SELECT 'epigraph_bba_guard_owner is a member of ' || r.rolname
          FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
         WHERE m.member = v_role
         ORDER BY 1);

    -- Who could become it. MEMBER counts every grant, an ADMIN-only one
    -- included: its holder can GRANT the role to itself with SET.
    v_out := v_out || ARRAY(
        SELECT r.rolname || ' is a member of epigraph_bba_guard_owner'
          FROM pg_catalog.pg_roles r
         WHERE r.oid <> v_role AND NOT r.rolsuper
           AND pg_catalog.pg_has_role(r.oid, v_role, 'MEMBER')
         ORDER BY 1);
    v_out := v_out || ARRAY(
        SELECT DISTINCT r.rolname || ' holds ADMIN OPTION on epigraph_bba_guard_owner'
          FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.member
         WHERE m.roleid = v_role AND m.admin_option AND NOT r.rolsuper
         ORDER BY 1);
    -- CREATEROLE: before PostgreSQL 16 it grants any non-superuser role,
    -- itself included; on 16 it administers the roles it creates.
    v_out := v_out || ARRAY(
        SELECT r.rolname || ' is a non-superuser CREATEROLE role'
          FROM pg_catalog.pg_roles r
         WHERE r.rolcreaterole AND NOT r.rolsuper
         ORDER BY 1);

    -- What it owns: exactly the three ledger functions, each a definer on the
    -- pinned path.
    v_fns := ARRAY[
        pg_catalog.to_regprocedure('public.epigraph_mf_guard_grant(text, uuid[], text, uuid)'),
        pg_catalog.to_regprocedure('public.epigraph_mf_guard_consume(text, uuid, jsonb)'),
        pg_catalog.to_regprocedure('public.epigraph_mf_purge_granted(uuid)')]::pg_catalog.oid[];
    FOREACH v_sig IN ARRAY ARRAY[
        'public.epigraph_mf_guard_grant(text, uuid[], text, uuid)',
        'public.epigraph_mf_guard_consume(text, uuid, jsonb)',
        'public.epigraph_mf_purge_granted(uuid)']
    LOOP
        v_fn := pg_catalog.to_regprocedure(v_sig);
        IF v_fn IS NULL THEN
            v_out := v_out || (v_sig || ' does not exist');
            CONTINUE;
        END IF;
        SELECT p.proowner, p.prosecdef, p.proconfig INTO v_fn_owner, v_fn_secdef, v_fn_config
          FROM pg_catalog.pg_proc p WHERE p.oid = v_fn;
        IF v_fn_owner <> v_role THEN
            v_out := v_out || (v_sig || ' is not owned by epigraph_bba_guard_owner');
        END IF;
        IF NOT v_fn_secdef
           OR v_fn_config IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']::pg_catalog.text[] THEN
            v_out := v_out || (v_sig || ' is not SECURITY DEFINER on search_path pg_catalog, pg_temp');
        END IF;
    END LOOP;
    v_out := v_out || ARRAY(
        SELECT 'epigraph_bba_guard_owner owns '
               || pg_catalog.pg_describe_object(d.classid, d.objid, d.objsubid)
          FROM pg_catalog.pg_shdepend d
         WHERE d.refclassid = 'pg_catalog.pg_authid'::pg_catalog.regclass
           AND d.refobjid = v_role AND d.deptype = 'o'
           AND d.dbid IN (0, (SELECT db.oid FROM pg_catalog.pg_database db
                               WHERE db.datname = pg_catalog.current_database()))
           AND NOT (d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
                    AND d.objid = ANY (v_fns))
         ORDER BY 1);

    -- The ledger: nothing runs on it, and only the owner writes it.
    IF v_table IS NULL THEN
        RETURN v_out || 'public.mass_function_purge_grants does not exist'::pg_catalog.text;
    END IF;
    SELECT c.relowner INTO v_table_owner FROM pg_catalog.pg_class c WHERE c.oid = v_table;
    v_out := v_out || ARRAY(
        SELECT 'trigger ' || t.tgname || ' on public.mass_function_purge_grants'
          FROM pg_catalog.pg_trigger t
         WHERE t.tgrelid = v_table AND NOT t.tgisinternal
         ORDER BY 1);
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c
                WHERE c.oid = v_table AND (c.relrowsecurity OR c.relforcerowsecurity)) THEN
        v_out := v_out || 'row security is enabled on public.mass_function_purge_grants'::pg_catalog.text;
    END IF;
    IF pg_catalog.has_table_privilege(v_role, v_table, 'UPDATE, DELETE, TRUNCATE') THEN
        v_out := v_out || 'epigraph_bba_guard_owner may UPDATE, DELETE or TRUNCATE public.mass_function_purge_grants'::pg_catalog.text;
    END IF;
    v_out := v_out || ARRAY(
        SELECT r.rolname || ' can write public.mass_function_purge_grants'
          FROM pg_catalog.pg_roles r
         WHERE r.oid <> v_role AND NOT r.rolsuper
           -- The predefined roles themselves (pg_write_all_data writes every
           -- table); a role granted one of them is reported.
           AND r.rolname !~ '^pg_'
           AND NOT pg_catalog.pg_has_role(r.oid, v_table_owner, 'USAGE')
           AND (pg_catalog.has_table_privilege(r.oid, v_table, 'INSERT, UPDATE, DELETE, TRUNCATE')
                OR pg_catalog.has_any_column_privilege(r.oid, v_table, 'INSERT, UPDATE'))
         ORDER BY 1);
    RETURN v_out;
END $$;
COMMENT ON FUNCTION public.epigraph_bba_guard_owner_faults() IS
    'Migration 251: every way epigraph_bba_guard_owner (the NOLOGIN owner of the retracted-BBA '
    'grant ledger) or the ledger could be abused; empty when sound. A non-empty answer means '
    'some role could write or rewrite the ledger outside its three functions.';
REVOKE EXECUTE ON FUNCTION public.epigraph_bba_guard_owner_faults() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.epigraph_bba_guard_owner_faults() TO epigraph_maintenance;

DO $$
DECLARE
    v_faults text[] := public.epigraph_bba_guard_owner_faults();
BEGIN
    IF pg_catalog.cardinality(v_faults) > 0 THEN
        RAISE EXCEPTION '251 refuses: the retracted-BBA ledger or its owner is not isolated: %; '
                        'nothing was changed', v_faults
            USING ERRCODE = '55000',
                  HINT = 'Only the ledger''s three functions may act as epigraph_bba_guard_owner '
                         'or write the ledger: remove the memberships, attributes or privileges '
                         'named, then re-run epigraph-migrate.';
    END IF;
END $$;
