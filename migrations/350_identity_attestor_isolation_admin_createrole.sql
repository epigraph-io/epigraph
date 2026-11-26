-- 350: the attestor isolation check names every role that can make itself
-- the attestor: an ADMIN OPTION holder, a member of any kind, and any
-- non-superuser CREATEROLE role (backlog cfaa5065).
--
-- ===================================================================
-- 1. WHY
--
-- 161 gates agent-identity registration on the ROLE of the connection:
-- `epigraph_register_agent_identity` is executable by
-- `epigraph_identity_attestor` alone, and `epigraph_identity_attestor_faults()`
-- names every way another role could act as it. The migration refuses to
-- apply on any fault, and an operator runs the function at any time (an empty
-- array is the pass).
--
-- 161's arm for other roles asked only whether a non-superuser can act as the
-- attestor NOW: `pg_has_role(r, attestor, 'USAGE') OR pg_has_role(r,
-- attestor, 'SET')` (MEMBER before PostgreSQL 16). Two kinds of role pass it
-- and can still become the attestor:
--
--   * an ADMIN OPTION holder. On PostgreSQL 16 a grant `WITH ADMIN TRUE,
--     INHERIT FALSE, SET FALSE` confers neither USAGE nor SET, so 161 did not
--     name it, but its holder can `GRANT epigraph_identity_attestor TO
--     itself` and then register any identity under any parent;
--   * a non-superuser CREATEROLE role. Before 16 it may grant itself any
--     non-superuser role, the attestor included. On 16 it administers every
--     role it created or holds ADMIN on, so it can make itself the attestor
--     only with ADMIN on it (named by the ADMIN arm); it is named anyway, as
--     251 and 257 name one, because one ALTER ROLE or grant away it is.
--
-- 161 left the ADMIN-only grant out on purpose: on 16 a non-superuser
-- CREATEROLE migration runner receives exactly that grant on a role it
-- creates, and 161 had to pass on such a runner. That case no longer reaches
-- this file. 251 (which applies before it) refuses a non-superuser migrating
-- login (42501) and refuses while ANY non-superuser CREATEROLE role exists
-- (`epigraph_bba_guard_owner_faults()`, no exemption), and 257 uses the same
-- three arms for `epigraph_operator_link_retirer`. A database that reaches 350
-- was migrated by a superuser, and every arm below already excludes
-- superusers, so no exemption is needed for the runner. An ADMIN-only grant a
-- 161-era non-superuser runner still holds is a real fault: that login can
-- make itself the attestor. Revoke it.
--
-- ===================================================================
-- 2. THE CHANGE
--
-- `epigraph_identity_attestor_faults()` is re-stated. It keeps 161's
-- signature, its SECURITY INVOKER mode, its owner and its ACL (CREATE OR
-- REPLACE keeps both; the REVOKE and GRANT are restated anyway). It moves to
-- 172's `pg_catalog, pg_temp` path, with every name qualified. It names:
--   * the role missing (unchanged);
--   * any elevated attribute of the role itself (unchanged; LOGIN is not a
--     fault: operations give the attestor LOGIN by design);
--   * any role the attestor is a member of (unchanged);
--   * NEW: any non-superuser role that is a MEMBER of the attestor, directly
--     or not, whatever its INHERIT / SET / ADMIN options (this replaces 161's
--     USAGE / SET arm and covers it);
--   * NEW: any non-superuser role holding ADMIN OPTION on the attestor, named
--     once however many grantors granted it;
--   * NEW: any non-superuser CREATEROLE role other than the attestor (whose
--     own CREATEROLE is reported as an attribute).
-- These are the three arms 251 and 257 apply to their own roles.
--
-- The migration then runs the check and refuses (55000, nothing changed) when
-- the attestor exists and is not isolated. A cluster where 161 could not
-- create the role is unchanged: the role is optional (deploy.md, section 9).
-- `epigraph-tenancy-backfill verify` runs the same function, so a grant made
-- after this file is reported.
--
-- PRECONDITION (55000, nothing changed): the function carries 161's body
-- (`md5(prosrc)` 31cac2063a345bfff500e75b4095c4fa, the value 271-undo also
-- pins) on 271's path. CREATE OR REPLACE replaces a body whole, so applying
-- this over another body would drop that body's arms silently.
--
-- PREDEPLOY MEASUREMENT (the migration refuses if any row comes back):
--   SELECT r.rolname, r.rolcreaterole,
--          pg_has_role(r.oid, 'epigraph_identity_attestor', 'MEMBER') AS member,
--          EXISTS (SELECT 1 FROM pg_auth_members m
--                   WHERE m.roleid = 'epigraph_identity_attestor'::regrole
--                     AND m.member = r.oid AND m.admin_option) AS admin_option
--     FROM pg_roles r
--    WHERE NOT r.rolsuper AND r.rolname <> 'epigraph_identity_attestor'
--      AND (r.rolcreaterole
--           OR pg_has_role(r.oid, 'epigraph_identity_attestor', 'MEMBER'));
--
-- Locks: CREATE OR REPLACE of one function, which no trigger and no other
-- function calls. No table is touched.
--
-- ===================================================================
-- 3. UNDO: docs/runbooks/350-undo.sql (restores 161's body on 271's path).
-- Slot 350 was assigned by the 2026-11-26 burndown triage.
-- **Applied to throwaway databases only, NOT to any deployed database.**

SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- Precondition: the function still carries 161's body on 271's path.
-- -------------------------------------------------------------------
DO $$
DECLARE
    v_md5    text;
    v_config text[];
BEGIN
    SELECT md5(p.prosrc), p.proconfig INTO v_md5, v_config
      FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure('public.epigraph_identity_attestor_faults()');
    IF v_md5 IS DISTINCT FROM '31cac2063a345bfff500e75b4095c4fa'
       OR v_config IS DISTINCT FROM ARRAY['search_path=pg_catalog, public, pg_temp'] THEN
        RAISE EXCEPTION '350: public.epigraph_identity_attestor_faults() is not the function 350 '
                        're-states (161''s body, md5 31cac2063a345bfff500e75b4095c4fa, on 271''s '
                        'path pg_catalog, public, pg_temp); found md5 % with %. Nothing was '
                        'changed', COALESCE(v_md5, '(absent)'), COALESCE(v_config::text, '(no path)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with every '
                         'delta instead of this one.';
    END IF;
END $$;

-- ===================================================================
-- THE CHECK
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_identity_attestor_faults()
RETURNS text[]
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_role pg_catalog.oid;
    v_out  pg_catalog.text[] := '{}';
BEGIN
    SELECT r.oid INTO v_role FROM pg_catalog.pg_roles r
     WHERE r.rolname = 'epigraph_identity_attestor';
    IF v_role IS NULL THEN
        RETURN ARRAY['epigraph_identity_attestor does not exist'];
    END IF;

    -- The role itself. LOGIN is not a fault: operations give it LOGIN.
    SELECT pg_catalog.array_remove(ARRAY[
               CASE WHEN r.rolsuper THEN 'epigraph_identity_attestor is SUPERUSER' END,
               CASE WHEN r.rolbypassrls THEN 'epigraph_identity_attestor is BYPASSRLS' END,
               CASE WHEN r.rolcreaterole THEN 'epigraph_identity_attestor is CREATEROLE' END,
               CASE WHEN r.rolcreatedb THEN 'epigraph_identity_attestor is CREATEDB' END,
               CASE WHEN r.rolreplication THEN 'epigraph_identity_attestor is REPLICATION' END],
           NULL)
      INTO v_out
      FROM pg_catalog.pg_roles r WHERE r.oid = v_role;
    v_out := v_out || ARRAY(
        SELECT 'epigraph_identity_attestor is a member of ' || r.rolname
          FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
         WHERE m.member = v_role
         ORDER BY 1);

    -- Who could become it. MEMBER counts every membership, direct or not,
    -- whatever its INHERIT / SET / ADMIN options: on PostgreSQL 16 an
    -- ADMIN-only grant confers neither USAGE nor SET, but its holder can
    -- GRANT the role to itself and then act as it.
    v_out := v_out || ARRAY(
        SELECT r.rolname || ' is a member of epigraph_identity_attestor'
          FROM pg_catalog.pg_roles r
         WHERE r.oid <> v_role AND NOT r.rolsuper
           AND pg_catalog.pg_has_role(r.oid, v_role, 'MEMBER')
         ORDER BY 1);
    -- An ADMIN OPTION row is named on its own (once, whatever the number of
    -- grantors: PostgreSQL 16 keeps one row per grantor).
    v_out := v_out || ARRAY(
        SELECT DISTINCT r.rolname || ' holds ADMIN OPTION on epigraph_identity_attestor'
          FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.member
         WHERE m.roleid = v_role AND m.admin_option AND NOT r.rolsuper
         ORDER BY 1);
    -- CREATEROLE: before PostgreSQL 16 it grants any non-superuser role,
    -- itself included; on 16 it administers the roles it creates or holds
    -- ADMIN on (the ADMIN arm above names that case). Named either way, as
    -- 251 names one. The attestor's own CREATEROLE is reported above.
    v_out := v_out || ARRAY(
        SELECT r.rolname || ' is a non-superuser CREATEROLE role'
          FROM pg_catalog.pg_roles r
         WHERE r.rolcreaterole AND NOT r.rolsuper AND r.oid <> v_role
         ORDER BY 1);
    RETURN v_out;
END $$;
COMMENT ON FUNCTION public.epigraph_identity_attestor_faults() IS
    'Migrations 161 and 350: every way epigraph_identity_attestor could be abused (an elevated '
    'attribute, a membership of its own, a non-superuser member of it in any form, an ADMIN '
    'OPTION holder, any non-superuser CREATEROLE role); empty when isolated.';
REVOKE EXECUTE ON FUNCTION public.epigraph_identity_attestor_faults() FROM PUBLIC;

DO $$
DECLARE
    v_faults text[];
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_identity_attestor_faults() '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_identity_attestor_faults() '
                'FROM epigraph_app';
    END IF;
    -- The attestor is optional (161 skips it without CREATEROLE): no role,
    -- nothing to check.
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                WHERE rolname = 'epigraph_identity_attestor') THEN
        v_faults := public.epigraph_identity_attestor_faults();
        IF pg_catalog.cardinality(v_faults) > 0 THEN
            RAISE EXCEPTION '350: epigraph_identity_attestor exists but is not isolated: %; '
                            'nothing was changed', v_faults
                USING ERRCODE = '55000',
                      HINT = 'Only the host may act as the attestor: revoke the memberships, '
                             'ADMIN OPTION grants and CREATEROLE attributes named, then re-run '
                             'epigraph-migrate.';
        END IF;
    END IF;
END $$;
