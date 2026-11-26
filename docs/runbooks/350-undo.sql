-- ===================================================================
-- 350-undo.sql: take migration 350 (the attestor isolation check names
-- ADMIN OPTION holders, members of any kind and non-superuser CREATEROLE
-- roles) back out, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST: no binary depends on 350, so nothing needs rolling back first.
-- Undoing it RE-OPENS what 350 closes: `epigraph_identity_attestor_faults()`
-- (and `epigraph-tenancy-backfill verify`, which runs it) no longer names a
-- non-superuser that holds ADMIN OPTION on `epigraph_identity_attestor`
-- without USAGE or SET, or a non-superuser CREATEROLE role. Either can grant
-- itself the attestor and register agent identities.
--
-- WHAT IT DOES: restores 161's body of the function byte for byte (md5 of
-- `prosrc` 31cac2063a345bfff500e75b4095c4fa, the value 271-undo pins) on the
-- path 271 gave it (`pg_catalog, public, pg_temp`), and drops 350's comment
-- (161 set none). CREATE OR REPLACE keeps the owner and the ACL; EXECUTE stays
-- the maintenance role's (161's grant), not PUBLIC's.
--
-- WHAT IT LEAVES: 350's `_sqlx_migrations` row; delete it as well if 350 is
-- to be re-applied by `epigraph-migrate`:
--   DELETE FROM _sqlx_migrations WHERE version = 350;
-- 350 re-applied refuses (55000) if a role it names was added meanwhile.
-- Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_identity_attestor_faults()
RETURNS text[]
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    v_role oid;
    v_out  text[] := '{}';
    -- PostgreSQL 16 split membership into SET / USAGE (INHERIT) / ADMIN. Only
    -- SET and USAGE let a role act as the attestor. ADMIN alone does not, and
    -- a non-superuser CREATEROLE runner holds exactly that on a role it creates
    -- on 16, so MEMBER would flag the deployment's own runner. Before 16,
    -- MEMBER is the right to SET ROLE.
    v_set  text := CASE WHEN current_setting('server_version_num')::integer >= 160000
                        THEN 'SET' ELSE 'MEMBER' END;
BEGIN
    SELECT r.oid INTO v_role FROM pg_roles r WHERE r.rolname = 'epigraph_identity_attestor';
    IF v_role IS NULL THEN
        RETURN ARRAY['epigraph_identity_attestor does not exist'];
    END IF;
    SELECT array_remove(ARRAY[
               CASE WHEN r.rolsuper THEN 'epigraph_identity_attestor is SUPERUSER' END,
               CASE WHEN r.rolbypassrls THEN 'epigraph_identity_attestor is BYPASSRLS' END,
               CASE WHEN r.rolcreaterole THEN 'epigraph_identity_attestor is CREATEROLE' END,
               CASE WHEN r.rolcreatedb THEN 'epigraph_identity_attestor is CREATEDB' END,
               CASE WHEN r.rolreplication THEN 'epigraph_identity_attestor is REPLICATION' END],
           NULL)
      INTO v_out
      FROM pg_roles r WHERE r.oid = v_role;
    v_out := v_out || ARRAY(
        SELECT 'epigraph_identity_attestor is a member of ' || r.rolname
          FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid
         WHERE m.member = v_role
         ORDER BY 1);
    v_out := v_out || ARRAY(
        SELECT r.rolname || ' can act as epigraph_identity_attestor'
          FROM pg_roles r
         WHERE r.oid <> v_role AND NOT r.rolsuper
           AND (pg_has_role(r.oid, v_role, 'USAGE') OR pg_has_role(r.oid, v_role, v_set))
         ORDER BY 1);
    RETURN v_out;
END $$;
COMMENT ON FUNCTION public.epigraph_identity_attestor_faults() IS NULL;
REVOKE EXECUTE ON FUNCTION public.epigraph_identity_attestor_faults() FROM PUBLIC;

COMMIT;
