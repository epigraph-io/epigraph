-- 231: the application role `epigraph_app` is NOLOGIN, whatever the cluster
-- held before (backlog bb200b7b).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- Migration 060 creates `epigraph_app`, `epigraph_maintenance` and
-- `epigraph_seed` NOLOGIN, but only `IF NOT EXISTS`, and it never alters a
-- role that is already there. On a cluster where `epigraph_app` existed before
-- 060 ran, or was given a login by hand afterwards (docs/deploy.md told
-- installers to do exactly that until this migration), the role keeps LOGIN.
-- CI never sees it: its Postgres is created empty on every run, so 060 always
-- takes the CREATE branch.
--
-- A logging-in `epigraph_app` means the role that row security is written
-- against is also a credential. Every holder of that one password is
-- indistinguishable in `pg_stat_activity` and in every `session_user` audit
-- column, and the role cannot be rotated without rotating every service at
-- once. Each service logs in as its own role that is a member of
-- `epigraph_app` instead (docs/deploy.md, section 2, step 4).
--
-- ===================================================================
-- 1. WHAT IT DOES
-- ===================================================================
--
-- Asserts the END STATE: after it, `epigraph_app` is NOLOGIN.
--
--   * no `epigraph_app` role (a managed Postgres where 060 could only
--     NOTICE): NOTICE, nothing changes;
--   * already NOLOGIN (every fresh install): nothing changes;
--   * LOGIN, and a session is logged in as `epigraph_app` right now: REFUSES
--     with SQLSTATE 55000, changing nothing. That session is a live consumer
--     of the login (typically the API), and NOLOGIN would refuse its next
--     connection, so the deploy stops here instead of taking the service
--     down. Move that service to its own login first (docs/deploy.md,
--     section 2, step 4), then re-run the migration;
--   * LOGIN and no such session: `ALTER ROLE epigraph_app NOLOGIN`.
--
-- The session check reads `pg_stat_activity.usename`, the role a backend
-- AUTHENTICATED as. A session that only switched to `epigraph_app` (a login
-- whose default is `SET role = 'epigraph_app'`, or a superuser's `SET SESSION
-- AUTHORIZATION epigraph_app`) is not counted: NOLOGIN does not affect it.
-- The check is cluster-wide, because roles are.
--
-- The role's password is left as it is, so the undo is one statement.
-- No table, column, function, trigger, policy, index or grant. No migration
-- grants a login (`schema_contract.rs::no_migration_grants_a_role_login`).
--
-- ===================================================================
-- 2. WHAT IT CANNOT SEE
-- ===================================================================
--
-- Only sessions that are open while it runs. A service that is STOPPED during
-- the migration, or a timer that connects once a day, and that still logs in
-- as `epigraph_app` passes this check and is refused at its next connect.
-- Before migrating, find every DSN that names `epigraph_app` as its user and
-- move it to a member login.
--
-- ===================================================================
-- 3. PRIVILEGE
-- ===================================================================
--
-- `ALTER ROLE ... NOLOGIN` needs a superuser, or CREATEROLE with ADMIN OPTION
-- on `epigraph_app`. A migration login without either fails this migration
-- (SQLSTATE 42501) while `epigraph_app` can log in; run the statement once as
-- a superuser, then re-run the migration, which then has nothing to do.
--
-- ===================================================================
-- 4. UNDO
-- ===================================================================
--
--   ALTER ROLE epigraph_app LOGIN;
--
-- as a superuser. It restores the old login with its old password. It is a
-- rollback of the credential split, not of the schema; nothing else to undo.

DO $$
DECLARE
    can_login boolean;
    live      bigint;
    apps      text;
BEGIN
    SELECT rolcanlogin INTO can_login FROM pg_roles WHERE rolname = 'epigraph_app';

    IF NOT FOUND THEN
        RAISE NOTICE '231: role epigraph_app does not exist; nothing to do. Provision it NOLOGIN out of band (docs/deploy.md, section 2, step 2).';
        RETURN;
    END IF;

    IF NOT can_login THEN
        RETURN;
    END IF;

    SELECT count(*),
           string_agg(DISTINCT coalesce(nullif(application_name, ''), '<none>'), ', ')
      INTO live, apps
      FROM pg_stat_activity
     WHERE usename = 'epigraph_app'
       AND pid <> pg_backend_pid();

    IF live > 0 THEN
        -- sqlx shows the MESSAGE only (not the HINT), so the MESSAGE carries
        -- the whole instruction an operator needs.
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = format(
                '231 refuses: %s session(s) are logged in as epigraph_app (application_name: %s), '
                'and NOLOGIN would refuse their next connection; nothing was changed. Move that '
                'service to its own login, a member of epigraph_app with SET role = epigraph_app '
                '(docs/deploy.md, section 2, step 4, and the migration 231 row of section 11), '
                'restart it, then re-run epigraph-migrate.',
                live, apps);
    END IF;

    BEGIN
        ALTER ROLE epigraph_app NOLOGIN;
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = format(
                '231 refuses: %s may not ALTER ROLE epigraph_app, which can still log in. Run '
                'ALTER ROLE epigraph_app NOLOGIN once as a superuser, after moving every service '
                'off that role (docs/deploy.md, the migration 231 row of section 11), then re-run '
                'epigraph-migrate.',
                current_user);
    END;

    IF (SELECT rolcanlogin FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = '231: epigraph_app can still log in after ALTER ROLE ... NOLOGIN.';
    END IF;
END $$;
