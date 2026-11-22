-- ===================================================================
-- 271-undo.sql: take migration 271 (every function that pins a
-- `search_path` lists `pg_temp` last; every trigger function pins one) back
-- out, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST: no binary depends on 271, so nothing needs rolling back first.
-- Undoing it RE-OPENS the defect 271 closes: the nine functions below whose
-- path omits `pg_temp` search the caller's temporary schema first again, and
-- 184's retract guard runs inside the application-executable un-retract
-- definer as the maintenance role (271's header).
--
-- WHAT IT DOES: for each of the 19 functions 271 changed on a database at
-- 235, restores the path it had at 235 (`ALTER ROUTINE .. SET search_path`
-- or `RESET search_path`), and only while:
--   * the function still has its 235 body (md5 of `prosrc`); a later
--     migration that re-stated the body set its own path, which stays; and
--   * its path is the one 271 set; any other path stays.
-- It changes no body, owner, ACL or other configuration entry. Every
-- statement it runs is built from the constants below, never from catalog
-- text (a function's owner controls its stored path).
--
-- WHAT IT LEAVES: 271's `_sqlx_migrations` row, and any function a migration
-- after 271 created. Re-introducing the change is a NEW migration, never a
-- re-run of 271. Idempotent: a second run finds nothing on 271's path.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    r record;
    v_md5 text;
    v_path text;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        -- (signature, md5(prosrc) at 235, path at 235 (NULL: unpinned), path 271 set)
        ('public.epigraph_agent_keys_attested_guard()',
         '865574a43103a4a38a60db8a13cb3434', 'pg_catalog, public', 'pg_catalog, public, pg_temp'),
        ('public.epigraph_agents_competence_guard()',
         'b4248f39a2df4bc005ed046e5240bd6f', 'pg_catalog, public', 'pg_catalog, public, pg_temp'),
        ('public.epigraph_claims_supersedes_guard()',
         '92424ddf5d3eb2465d0f64220d0f0aaf', 'pg_catalog, public', 'pg_catalog, public, pg_temp'),
        ('public.epigraph_edges_repoint_unsign()',
         'a7864a89d1eac4df8caa2e0881989a4f', 'pg_catalog, public', 'pg_catalog, public, pg_temp'),
        ('public.epigraph_edge_writer_scope(text, text)',
         '0b969be2cba076e02f352d0613a20260', 'pg_catalog', 'pg_catalog, pg_temp'),
        ('public.epigraph_identity_attestor_faults()',
         '31cac2063a345bfff500e75b4095c4fa', 'pg_catalog, public', 'pg_catalog, public, pg_temp'),
        ('public.epigraph_lockdown_privileged()',
         '755e598a600307553848af6ba5e9357c', 'pg_catalog, public', 'pg_catalog, public, pg_temp'),
        ('public.epigraph_mass_function_retract_guard()',
         'be48455cec9bc897f0f13473129c52ff', 'pg_catalog, public', 'pg_catalog, public, pg_temp'),
        ('public.epigraph_match_candidates_stale_guard()',
         '8e7fdda34382ca406e2bd60672e9328a', 'pg_catalog, public', 'pg_catalog, public, pg_temp'),
        ('public.cascade_delete_edges()',
         '87db9bc536eafd1ef8eb5a0696ceb3db', NULL, 'pg_catalog, public, pg_temp'),
        ('public.epigraph_audit_immutable()',
         '1a4ca97b124023370731d34b2e8eb499', NULL, 'pg_catalog, public, pg_temp'),
        ('public.epigraph_block_group_delete()',
         'f43bc48b25fbd27ed5c60c9cd9324340', NULL, 'pg_catalog, public, pg_temp'),
        ('public.epigraph_claims_block_widening()',
         '7d9079127fe7ad6c7195047421e87c0e', NULL, 'pg_catalog, public, pg_temp'),
        ('public.epigraph_no_public_sealed()',
         '706d3eda9209cccb7f6fe7134cc3d686', NULL, 'pg_catalog, public, pg_temp'),
        ('public.epigraph_privatization_approver_guard()',
         '28e19600a25ee2c4455d846bf6eb36c2', NULL, 'pg_catalog, public, pg_temp'),
        ('public.epigraph_privatization_plan_guard()',
         'b9cdfb9c07968e0da81db33cfcde0d48', NULL, 'pg_catalog, public, pg_temp'),
        ('public.raise_immutable_error()',
         'c22261519e8e5eda6eae6b22f45f8639', NULL, 'pg_catalog, public, pg_temp'),
        ('public.trigger_validate_edge_refs()',
         'a5191bde7e69610743949890fb4f7495', NULL, 'pg_catalog, public, pg_temp'),
        ('public.update_updated_at_column()',
         '06bcf30ac3d0a7f279a54cbf228a7bec', NULL, 'pg_catalog, public, pg_temp'))
        AS t(sig, md5_235, path_235, path_271)
    LOOP
        SELECT pg_catalog.md5(p.prosrc),
               (SELECT pg_catalog.substr(c, 13) FROM pg_catalog.unnest(p.proconfig) c
                 WHERE c LIKE 'search_path=%' LIMIT 1)
          INTO v_md5, v_path
          FROM pg_catalog.pg_proc p
         WHERE p.oid = pg_catalog.to_regprocedure(r.sig);
        IF v_md5 IS DISTINCT FROM r.md5_235 THEN
            RAISE NOTICE '271-undo: % is not its 235 body (md5 %); left on its path %',
                         r.sig, COALESCE(v_md5, '(absent)'), COALESCE(v_path, '(unpinned)');
            CONTINUE;
        END IF;
        IF v_path IS DISTINCT FROM r.path_271 THEN
            -- Already undone, or re-pathed by something other than 271.
            CONTINUE;
        END IF;
        IF r.path_235 IS NULL THEN
            EXECUTE pg_catalog.format('ALTER ROUTINE %s RESET search_path', r.sig);
        ELSE
            EXECUTE pg_catalog.format('ALTER ROUTINE %s SET search_path = %s',
                                      r.sig, r.path_235);
        END IF;
        RAISE NOTICE '271-undo: % search_path % -> %', r.sig, v_path,
                     COALESCE(r.path_235, '(unpinned)');
    END LOOP;
END $$;

COMMIT;
