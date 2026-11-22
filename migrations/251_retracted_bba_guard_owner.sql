-- 251: the retracted-BBA guards are owned by a NOLOGIN role that no login can
-- act as, so a maintenance login can no longer write a purge grant or clear a
-- retraction outside the audited definers (backlog 6bdac68f).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- Two guards on `mass_functions` keep a retracted BBA (migration 184) for
-- audit, and both had the same hole, which their own headers recorded as the
-- residual:
--
--   * 194's delete guard admits the delete of a retracted row only when a row
--     of `mass_function_purge_grants` names it for the current transaction,
--     and only the purge definer was meant to write one. But the grant table
--     granted INSERT to `epigraph_maintenance` (the definer's owner needed
--     it), and every maintenance login inherits that. Such a login could
--     INSERT a grant row itself and then DELETE the retracted row: no
--     `mass_functions.purge` audit row, no reason, the row gone.
--   * 184's un-retract guard admits clearing the retract columns only when
--     the statement runs as the maintenance role (`epigraph_definer_bypass()`,
--     true inside a maintenance-owned definer) AND the transaction-local
--     setting `epigraph.mf_unretract_id` names the row. A maintenance login
--     is the maintenance role (`current_user` is a member of it) and any
--     session may set a setting, so such a login could set both and UPDATE
--     the columns to NULL: the BBA folded again, no `mass_functions.unretract`
--     audit row.
--
-- Both definers were owned by `epigraph_maintenance`, so "what the definer
-- may do" and "what any maintenance login may do" were the same set.
--
-- ===================================================================
-- 1. WHAT IT DOES
-- ===================================================================
--
--   (1) Creates `epigraph_bba_guard_owner`: NOLOGIN, NOSUPERUSER,
--       NOBYPASSRLS, NOCREATEDB, NOCREATEROLE, NOREPLICATION, INHERIT, and a
--       member of `epigraph_maintenance` (with INHERIT). Membership runs ONE
--       way: the new role holds the maintenance role's privileges, so a body
--       it owns still passes `epigraph_definer_bypass()`, row security and
--       every grant the maintenance role has, but no maintenance login gains
--       anything the new role holds. Nothing is ever granted the new role.
--       Cluster-scoped, so created as 060 and 161 create theirs (a parallel
--       test database may create it first).
--   (2) `public.epigraph_bba_guard_owner_faults() RETURNS text[]` (SECURITY
--       INVOKER, owned by the migration runner, EXECUTE revoked from PUBLIC):
--       every way the role could be abused, empty when it is sound. A fault
--       is the role missing, any of the attributes above being wrong, the
--       role not inheriting `epigraph_maintenance` or being a member of any
--       other role, or any non-superuser role other than itself that can act
--       as it (PostgreSQL 16's SET or USAGE membership, directly or through
--       other roles). ADMIN alone does not let a role act as it, and a
--       non-superuser CREATEROLE runner holds exactly that on a role it
--       creates on PostgreSQL 16, so it is not counted (161's reasoning). The
--       migration refuses (55000, nothing changed) on any fault.
--   (3) Re-owns the three definers that write what the guards admit to the
--       new role: `epigraph_mf_purge_granted(uuid)` and
--       `epigraph_purge_mass_functions(uuid[], text)` (194) and
--       `epigraph_unretract_mass_function(uuid, text, uuid, uuid)` (184).
--       `ALTER ... OWNER TO` rewrites the old owner's own ACL entry to the new
--       owner, so the maintenance role's EXECUTE is re-granted after it; the
--       application role's entries are kept and re-stated. The FK-cascade
--       invoker grant of 194 section 3 (EXECUTE on the helper to a
--       non-superuser owner of `mass_functions`) is re-stated too. Bodies,
--       `search_path` and every other setting are unchanged.
--   (4) The grant table: `REVOKE ALL ... FROM epigraph_maintenance`, `GRANT
--       SELECT, INSERT, DELETE ... TO epigraph_bba_guard_owner` (exactly what
--       the two 194 definers do). The table stays owned by the migration
--       runner, which already owns `mass_functions` and its triggers, so
--       re-owning the table would take nothing from anyone who could not
--       already drop the guard.
--   (5) Re-bodies `public.epigraph_mass_function_retract_guard()` with ONE
--       delta, marked `251:` in the body: the clear arm admits a clear only
--       when `current_user = 'epigraph_bba_guard_owner'` (inside the
--       un-retract definer, which the new role owns) AND the setting names
--       the row. It was `epigraph_definer_bypass()`, which every maintenance
--       login satisfies. A name comparison, not `pg_has_role`: a superuser
--       session, or a role holding only USAGE on the new role, is not a frame
--       of the definer either, and a comparison raises nothing when the role
--       is absent. The `mark` and `rewrite` arms are 184's verbatim. The
--       header states 184's `SET search_path = pg_catalog, public`, because
--       `CREATE OR REPLACE` replaces `proconfig` with the one it states.
--
-- After 251 a maintenance login (a NOSUPERUSER login that is a member of
-- `epigraph_maintenance`) is refused 42501 inserting, updating or deleting a
-- purge grant, so its delete of a retracted row is refused SR09; and its clear
-- of the retract columns is refused RT06 whatever it sets. The purge and
-- un-retract definers work as before, for the callers they had.
--
-- NOT CHANGED, AND STILL OUTSIDE WHAT THE GUARDS DEFEND:
--   * 184's MARK arm admits a privileged session (`epigraph_bypass()`), so a
--     maintenance login can still SET the retract columns on a live row with
--     no audit row and any `retracted_by`. That retracts (excludes from every
--     fold) rather than destroying or reviving evidence; it is a separate item.
--   * A maintenance login owns the maintenance-owned SECURITY INVOKER trigger
--     functions that fire on `mass_functions` and `ds_combined_beliefs` while
--     the new role's definers write them (`epigraph_writer_owner_guard`,
--     `epigraph_attach_writer_owner`, `epigraph_owner_immutable_guard`), so it
--     may `ALTER FUNCTION` their settings. It cannot replace their bodies:
--     `CREATE OR REPLACE` needs CREATE on schema `public`, which no
--     maintenance login may hold (docs/deploy.md, step 5; `verify` fails while
--     one can).
--   * The migration login and every superuser can still do anything,
--     including dropping these triggers. They are not what these guards
--     defend against.
--
-- ===================================================================
-- 2. PRIVILEGE AND REFUSALS
-- ===================================================================
--
-- No `epigraph_maintenance` role (a managed Postgres where 060 could only
-- NOTICE): NOTICE, and only the re-body (5) applies. Without the maintenance
-- role no body passes the old clear arm either, so nothing changes in effect.
--
-- Otherwise the migration needs a SUPERUSER migration login: `CREATE ROLE`,
-- `GRANT epigraph_maintenance TO ...` (ADMIN on that role) and `ALTER
-- FUNCTION ... OWNER TO` a role the runner is not a member of. A login
-- without that privilege is refused 42501 here with nothing changed, as 231
-- refuses; a silent skip would leave the hole open with the migration
-- recorded as applied. An existing `epigraph_bba_guard_owner` with any fault
-- (2) is refused 55000, nothing changed.
--
-- PRECONDITION: the opening block refuses (55000, nothing changed) unless
-- `md5(prosrc)` of `epigraph_mass_function_retract_guard()` is 184's
-- (`be48455cec9bc897f0f13473129c52ff`) and its `proconfig` is 184's
-- `search_path=pg_catalog, public`. Predeploy check: `SELECT md5(prosrc),
-- proconfig FROM pg_proc WHERE oid =
-- to_regprocedure('public.epigraph_mass_function_retract_guard()')`.
--
-- Catalog-only: no table is rewritten or scanned. `CREATE OR REPLACE` of the
-- guard function and the `ALTER FUNCTION`s take no lock on `mass_functions`.
--
-- ===================================================================
-- 3. DEPLOY AND UNDO
-- ===================================================================
--
-- No binary change depends on it, and a binary of any age works over it: the
-- purge (`epigraph-operator delete-frames`) and the un-retract (the HTTP route
-- and the MCP tool) call the same definers with the same grants. A tool or
-- script that wrote `mass_function_purge_grants` or cleared the retract
-- columns directly on the maintenance DSN is refused after it; none in this
-- repository does.
--
-- Audit after migrating: `SELECT public.epigraph_bba_guard_owner_faults()`
-- returns `{}`.
--
-- UNDO: `docs/runbooks/251-undo.sql` (restores 184's guard body, re-owns the
-- three definers to `epigraph_maintenance` with their grants, gives the
-- maintenance role 194's SELECT, INSERT, DELETE on the grant table back,
-- drops the faults function; leaves the role, which another database of the
-- cluster may use; the runbook names the statement that drops it).
--
-- Slot 251 was assigned by the 2026-11-22 backlog triage. Checked before
-- claiming: no migration on main or on any origin branch carries a `251`, and
-- no in-flight migration touches these functions or the grant table.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 0. PRECONDITION
-- ===================================================================
DO $$
DECLARE
    v_md5 text;
    v_config text[];
BEGIN
    SELECT pg_catalog.md5(p.prosrc), p.proconfig INTO v_md5, v_config
      FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure('public.epigraph_mass_function_retract_guard()');
    IF v_md5 IS DISTINCT FROM 'be48455cec9bc897f0f13473129c52ff'
       OR v_config IS DISTINCT FROM ARRAY['search_path=pg_catalog, public']::text[] THEN
        RAISE EXCEPTION '251: public.epigraph_mass_function_retract_guard() is not the body 251 '
                        're-states (184''s, md5 be48455cec9bc897f0f13473129c52ff, search_path '
                        'pg_catalog, public); found md5 % with proconfig %. Another migration '
                        're-bodied it, or 184 is not applied; nothing was changed',
                        COALESCE(v_md5, '(absent)'), COALESCE(v_config::text, '(none)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the guard with every '
                         'delta instead of this one.';
    END IF;
END $$;

-- ===================================================================
-- 1. THE FAULTS FUNCTION
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_bba_guard_owner_faults()
RETURNS text[]
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_role oid;
    v_maint oid;
    v_out  text[] := '{}';
    -- PostgreSQL 16 split membership into SET / USAGE (INHERIT) / ADMIN. Only
    -- SET and USAGE let a role act as the owner; before 16, MEMBER is the
    -- right to SET ROLE (161's reasoning).
    v_set  text := CASE WHEN pg_catalog.current_setting('server_version_num')::integer >= 160000
                        THEN 'SET' ELSE 'MEMBER' END;
BEGIN
    SELECT r.oid INTO v_role FROM pg_catalog.pg_roles r
     WHERE r.rolname = 'epigraph_bba_guard_owner';
    IF v_role IS NULL THEN
        RETURN ARRAY['epigraph_bba_guard_owner does not exist'];
    END IF;
    SELECT r.oid INTO v_maint FROM pg_catalog.pg_roles r
     WHERE r.rolname = 'epigraph_maintenance';
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
    IF v_maint IS NULL OR NOT pg_catalog.pg_has_role(v_role, v_maint, 'USAGE') THEN
        v_out := v_out || 'epigraph_bba_guard_owner does not inherit epigraph_maintenance'::text;
    END IF;
    v_out := v_out || ARRAY(
        SELECT 'epigraph_bba_guard_owner is a member of ' || r.rolname
          FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
         WHERE m.member = v_role AND m.roleid IS DISTINCT FROM v_maint
         ORDER BY 1);
    v_out := v_out || ARRAY(
        SELECT r.rolname || ' can act as epigraph_bba_guard_owner'
          FROM pg_catalog.pg_roles r
         WHERE r.oid <> v_role AND NOT r.rolsuper
           AND (pg_catalog.pg_has_role(r.oid, v_role, 'USAGE')
                OR pg_catalog.pg_has_role(r.oid, v_role, v_set))
         ORDER BY 1);
    RETURN v_out;
END $$;
COMMENT ON FUNCTION public.epigraph_bba_guard_owner_faults() IS
    'Migration 251: every way epigraph_bba_guard_owner (the NOLOGIN owner of the retracted-BBA '
    'purge and un-retract definers) could be abused; empty when it is sound. A non-empty answer '
    'means some login can write a purge grant or clear a retraction outside the audited definers.';
REVOKE EXECUTE ON FUNCTION public.epigraph_bba_guard_owner_faults() FROM PUBLIC;

-- ===================================================================
-- 2. THE ROLE, THE RE-OWNS AND THE GRANT TABLE
-- ===================================================================
DO $$
DECLARE
    v_faults text[];
    v_owner name;
    v_super boolean;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        RAISE NOTICE '251: role epigraph_maintenance does not exist, so the purge and un-retract '
                     'definers have no maintenance owner to move off; nothing but the guard '
                     're-body applies. Provision the tenancy roles out of band and re-apply '
                     '184, 194 and 251.';
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_bba_guard_owner') THEN
        BEGIN
            CREATE ROLE epigraph_bba_guard_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB
                NOCREATEROLE NOREPLICATION INHERIT;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE EXCEPTION USING
                    ERRCODE = '42501',
                    MESSAGE = pg_catalog.format(
                        '251 refuses: %s may not CREATE ROLE epigraph_bba_guard_owner; nothing '
                        'was changed. Run epigraph-migrate on a superuser migration login '
                        '(docs/deploy.md, the migration 251 row of section 11).', current_user);
            -- Lost a race with a parallel database of the same cluster (060's
            -- note: 42710 when it merely lost, 23505 when the two raced).
            WHEN duplicate_object THEN NULL;
            WHEN unique_violation THEN NULL;
        END;
    END IF;

    IF NOT pg_catalog.pg_has_role('epigraph_bba_guard_owner', 'epigraph_maintenance', 'USAGE') THEN
        BEGIN
            GRANT epigraph_maintenance TO epigraph_bba_guard_owner;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE EXCEPTION USING
                    ERRCODE = '42501',
                    MESSAGE = pg_catalog.format(
                        '251 refuses: %s may not GRANT epigraph_maintenance TO '
                        'epigraph_bba_guard_owner; nothing was changed. Run epigraph-migrate on '
                        'a superuser migration login.', current_user);
            WHEN unique_violation THEN NULL;
        END;
    END IF;

    v_faults := public.epigraph_bba_guard_owner_faults();
    IF pg_catalog.cardinality(v_faults) > 0 THEN
        RAISE EXCEPTION '251 refuses: epigraph_bba_guard_owner is not isolated: %; nothing was '
                        'changed', v_faults
            USING ERRCODE = '55000',
                  HINT = 'Only the definers it owns may act as epigraph_bba_guard_owner: remove '
                         'the memberships or attributes named, then re-run epigraph-migrate.';
    END IF;

    BEGIN
        EXECUTE 'ALTER FUNCTION public.epigraph_mf_purge_granted(uuid) OWNER TO epigraph_bba_guard_owner';
        EXECUTE 'ALTER FUNCTION public.epigraph_purge_mass_functions(uuid[], text) OWNER TO epigraph_bba_guard_owner';
        EXECUTE 'ALTER FUNCTION public.epigraph_unretract_mass_function(uuid, text, uuid, uuid) OWNER TO epigraph_bba_guard_owner';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = pg_catalog.format(
                '251 refuses: %s may not re-own the retracted-BBA definers to '
                'epigraph_bba_guard_owner; nothing was changed. Run epigraph-migrate on a '
                'superuser migration login.', current_user);
    END;

    -- OWNER TO rewrote the maintenance role's own EXECUTE entry to the new
    -- owner; give it back. The application role's entries survive and are
    -- re-stated.
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) TO epigraph_maintenance';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_purge_mass_functions(uuid[], text) TO epigraph_maintenance';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_unretract_mass_function(uuid, text, uuid, uuid) TO epigraph_maintenance';
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_unretract_mass_function(uuid, text, uuid, uuid) TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_purge_mass_functions(uuid[], text) FROM epigraph_app';
    END IF;

    -- 194 section 3, re-stated: the delete guard runs as the owner of
    -- `mass_functions` inside an FK cascade from `claims` or `frames`.
    SELECT r.rolname, r.rolsuper INTO v_owner, v_super
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
     WHERE c.oid = 'public.mass_functions'::pg_catalog.regclass;
    IF NOT v_super THEN
        EXECUTE pg_catalog.format(
            'GRANT EXECUTE ON FUNCTION public.epigraph_mf_purge_granted(uuid) TO %I', v_owner);
    END IF;

    -- The grant table: only the new role writes it.
    EXECUTE 'REVOKE ALL ON public.mass_function_purge_grants FROM epigraph_maintenance';
    EXECUTE 'GRANT SELECT, INSERT, DELETE ON public.mass_function_purge_grants '
            'TO epigraph_bba_guard_owner';
END $$;

COMMENT ON TABLE public.mass_function_purge_grants IS
    'Migration 194 (H10): one row names one mass_functions id that the purge definer is about to '
    'delete in THIS transaction (xact_id). Written and cleared only by '
    'epigraph_purge_mass_functions; read only through epigraph_mf_purge_granted. Since 251 only '
    'epigraph_bba_guard_owner (the definers'' NOLOGIN owner) holds a privilege on it; neither the '
    'application role nor the maintenance role does.';

-- ===================================================================
-- 3. THE GUARD: ONLY THE UN-RETRACT DEFINER CLEARS
-- ===================================================================
-- 184's body; the one delta is the `251:` line of the clear arm (and two
-- comment lines reworded).
CREATE OR REPLACE FUNCTION public.epigraph_mass_function_retract_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public AS $$
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
        -- 251: the un-retract definer's owner, which no login can act as.
        IF current_user = 'epigraph_bba_guard_owner'::name
           AND current_setting('epigraph.mf_unretract_id', true) = OLD.id::text THEN
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
