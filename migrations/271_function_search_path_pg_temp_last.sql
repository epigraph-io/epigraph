-- 271: every function that pins a `search_path`, SECURITY INVOKER included,
-- lists `pg_temp` LAST, and every trigger function pins one (backlog
-- eff4aaf5).
--
-- EVIDENCE (measured on a database migrated to 235)
-- 190 moved every SECURITY DEFINER function's path to list `pg_temp` last. It
-- left nine SECURITY INVOKER functions that pin a path without `pg_temp`:
-- eight on `pg_catalog, public` and `epigraph_edge_writer_scope` on
-- `pg_catalog`. Six are triggers (on `mass_functions`, `edges`, `claims`,
-- `agents`, `agent_keys` and `match_candidates`), and
-- `epigraph_lockdown_privileged`, `epigraph_identity_attestor_faults` and
-- `epigraph_edge_writer_scope` are helpers. A path that does not list
-- `pg_temp` searches the session's temporary schema FIRST for relation and
-- type names. An INVOKER body runs as its caller, which inside a definer is
-- the definer's OWNER, and the path it pins replaces the definer's for the
-- body. So a write by a maintenance-owned definer that the application role
-- may execute fires an invoker trigger that resolves the CALLER's temporary
-- types and relations with the maintenance role's privileges, which lets the
-- caller's own code run with them. 184's retract guard
-- is one: the application-executable un-retract definer's UPDATE fires it,
-- and its clear arm resolves a type name.
-- `crates/epigraph-db/tests/function_search_path_pg_temp_ratchet.rs::
-- an_application_login_cannot_run_its_own_type_as_the_definer_owner`
-- reproduces that on a real NOSUPERUSER application login below this file.
--
-- Separately, ten INVOKER trigger functions pin no path at all. Inside a
-- definer they inherit the definer's path (pg_temp last), but a row trigger
-- that a foreign-key action fires can run as the REFERENCING table's owner on
-- the SESSION's path, which the session sets. Pinning each one closes that,
-- and makes a trigger's resolution independent of where it fires. They get
-- `pg_catalog, <their schema>, pg_temp`, the form 190 gave an unpinned
-- definer: their bodies name `public` objects unqualified and resolved them
-- through the session's `"$user", public` until now, so `public` stays on
-- the path (a body on `pg_catalog, pg_temp` would resolve an unqualified
-- public relation through pg_temp instead, the opposite of the intent).
--
-- CHANGE (proconfig only)
-- 1. A catalog sweep over every function and procedure outside the system
--    schemas and outside any extension:
--    a. a pinned path that does not list `pg_temp` gets `, pg_temp` appended
--       (`ALTER ROUTINE .. SET search_path`, which changes that one
--       configuration entry and neither the body nor any other entry);
--    b. an empty path (`search_path = ''`, which searches `pg_temp` first)
--       becomes `pg_catalog, pg_temp` (none exists at 235);
--    c. a trigger function (returns `trigger`, or is attached to a trigger)
--       in a language other than `c` / `internal` with no path gets
--       `pg_catalog, <its schema>, pg_temp`;
--    d. a path that lists `pg_temp` anywhere but last (including one that
--       also lists it last) is refused (55000, nothing changed), not guessed
--       at (none exists at 235). Items are compared as PostgreSQL reads
--       them: an unquoted item ASCII lower-cased, a quoted one with its
--       quotes stripped, so a stored `PG_TEMP` or `"pg_temp"` is `pg_temp`
--       (the same reading in the postcondition and in the ratchet);
--    e. a path it would rebuild whose items are not each a plain lower-case
--       identifier or exactly "$user" is refused (55000, nothing changed).
--       The stored text is whatever the function's owner set (`SET
--       search_path FROM CURRENT` stores a session value verbatim, and an
--       unquoted list item may hold any character but a comma or
--       whitespace), and the new path goes into a statement run as the
--       migrating role, so it is rebuilt from validated items with
--       `quote_ident` and the stored text never reaches EXECUTE.
--    The sweep reads the catalog, so it also covers a function a
--    lower-numbered migration created before this file is applied. Each
--    change is reported as a NOTICE.
-- 2. A postcondition refuses (55000) if any function still pins a path
--    without `pg_temp` listed once, last, or any trigger function is unpinned.
--
-- At 235 the sweep changes exactly these 19 functions (all in `public`), and
-- no body (`prosrc`), owner, ACL, volatility or security mode. Other
-- migrations' preconditions that md5 `prosrc` therefore still hold after it.
--   appended `, pg_temp` (was `pg_catalog, public` unless noted):
--     epigraph_agent_keys_attested_guard()      epigraph_agents_competence_guard()
--     epigraph_claims_supersedes_guard()        epigraph_edges_repoint_unsign()
--     epigraph_identity_attestor_faults()       epigraph_lockdown_privileged()
--     epigraph_mass_function_retract_guard()    epigraph_match_candidates_stale_guard()
--     epigraph_edge_writer_scope(text, text)    (was `pg_catalog`)
--   pinned `pg_catalog, public, pg_temp` (was unpinned):
--     cascade_delete_edges()                    epigraph_audit_immutable()
--     epigraph_block_group_delete()             epigraph_claims_block_widening()
--     epigraph_no_public_sealed()               epigraph_privatization_approver_guard()
--     epigraph_privatization_plan_guard()       raise_immutable_error()
--     trigger_validate_edge_refs()              update_updated_at_column()
--
-- NOT CHANGED HERE: `TEMP` on the database. The application role holds it
-- only through PUBLIC (PostgreSQL's default grant), so a revoke from
-- `epigraph_app` alone changes nothing. Removing it means `REVOKE TEMP ON
-- DATABASE .. FROM PUBLIC` and granting TEMP to the roles whose logins need
-- it (the maintenance role and the migrating role; member logins inherit
-- it). The API and MCP server create no temporary tables; only command-line
-- tools do, on maintenance connections. That is a deployment decision, left
-- to the operator. With every path listing `pg_temp` last, a temporary
-- object no longer shadows a name a body means.
--
-- ORDER: a migration numbered below 271 that is applied AFTER it (sqlx
-- applies a missing lower version) is not swept by it, so it must state
-- `pg_temp` last on every path it sets and pin every trigger function it
-- creates; `function_search_path_pg_temp_ratchet.rs` fails on one that does
-- not. A later `CREATE OR REPLACE` of any of these functions must restate its
-- path with `pg_temp` last (a replace replaces the path).
--
-- UNDO: `docs/runbooks/271-undo.sql` restores each of the 19 functions' path
-- as it was at 235, and only while its body is still the 235 body (md5 of
-- `prosrc`), so a later re-statement keeps its own path. It re-opens the
-- resolution order described above.
SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- 1. The sweep.
-- -------------------------------------------------------------------
DO $$
DECLARE
    r record;
    v_items text[];
    v_norm text[];
    v_n integer;
    v_bad text;
    v_new text;
BEGIN
    FOR r IN
        SELECT p.oid::pg_catalog.regprocedure AS sig, n.nspname,
               (SELECT pg_catalog.substr(c, 13) FROM pg_catalog.unnest(p.proconfig) c
                 WHERE c LIKE 'search_path=%' LIMIT 1) AS path,
               (p.prorettype = 'pg_catalog.trigger'::pg_catalog.regtype
                OR EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t
                            WHERE t.tgfoid = p.oid AND NOT t.tgisinternal))
               AND l.lanname NOT IN ('c', 'internal') AS is_trigger
          FROM pg_catalog.pg_proc p
          JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
          JOIN pg_catalog.pg_language l ON l.oid = p.prolang
         WHERE p.prokind IN ('f', 'p')
           AND n.nspname NOT IN ('pg_catalog', 'information_schema')
           AND n.nspname !~ '^pg_(toast|temp)'
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                            WHERE d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
                              AND d.objid = p.oid AND d.deptype = 'e')
         ORDER BY p.oid::pg_catalog.regprocedure::pg_catalog.text
    LOOP
        IF r.path IS NULL THEN
            IF NOT r.is_trigger THEN
                -- An unpinned non-trigger function runs on its caller's path,
                -- which inside a definer is the definer's.
                CONTINUE;
            END IF;
            v_new := pg_catalog.format('pg_catalog, %I, pg_temp', r.nspname);
        ELSIF pg_catalog.btrim(r.path, E' \t\n\r\f\x0B') IN ('', '""') THEN
            -- `SET search_path = ''`: only pg_catalog, and pg_temp FIRST.
            v_new := 'pg_catalog, pg_temp';
        ELSE
            v_items := ARRAY(SELECT pg_catalog.btrim(i, E' \t\n\r\f\x0B')
                               FROM pg_catalog.unnest(pg_catalog.string_to_array(r.path, ','))
                                    WITH ORDINALITY AS u(i, ord)
                              ORDER BY ord);
            v_n := pg_catalog.cardinality(v_items);
            -- Each item as PostgreSQL reads it: an unquoted name ASCII
            -- lower-cased, a quoted one with its quotes stripped. So a stored
            -- `PG_TEMP` or `"pg_temp"` IS pg_temp, and is compared as such.
            v_norm := ARRAY(SELECT CASE WHEN i ~ '^".*"$'
                                        THEN pg_catalog.replace(
                                                 pg_catalog.substr(i, 2, pg_catalog.length(i) - 2),
                                                 '""', '"')
                                        ELSE pg_catalog.translate(i, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
                                                                     'abcdefghijklmnopqrstuvwxyz')
                                   END
                              FROM pg_catalog.unnest(v_items) WITH ORDINALITY AS u(i, ord)
                             ORDER BY ord);
            -- Refuse first: a path listing pg_temp before its last item is
            -- searched in that order whatever follows, so appending cannot
            -- fix it.
            IF 'pg_temp' = ANY (v_norm[1:v_n - 1]) THEN
                RAISE EXCEPTION '271: % lists pg_temp before another schema '
                                '(search_path=%); nothing was changed', r.sig, r.path
                    USING ERRCODE = '55000',
                          HINT = 'Re-state it with pg_temp last, then apply 271.';
            END IF;
            IF v_norm[v_n] = 'pg_temp' THEN
                CONTINUE;
            END IF;
            -- The stored text is whatever the function's OWNER set (`ALTER
            -- FUNCTION .. SET search_path FROM CURRENT` stores a session value
            -- verbatim), and the new path is spliced into a statement this
            -- migration runs as the migrating role. So every item must be a
            -- plain lower-case identifier or exactly "$user", and the path is
            -- rebuilt from the validated items with quote_ident; the stored
            -- text itself never reaches EXECUTE.
            SELECT pg_catalog.string_agg(pg_catalog.quote_literal(i), ', ') INTO v_bad
              FROM pg_catalog.unnest(v_items) AS i
             WHERE i !~ '^[a-z_][a-z0-9_]*$' AND i <> '"$user"';
            IF v_bad IS NOT NULL THEN
                RAISE EXCEPTION '271: % pins a search_path whose items are not plain schema '
                                'names (%); nothing was changed', r.sig, v_bad
                    USING ERRCODE = '55000',
                          HINT = 'Inspect who set that path, re-state it with plain schema '
                                 'names and pg_temp last, then apply 271.';
            END IF;
            SELECT pg_catalog.string_agg(
                       CASE WHEN i = '"$user"' THEN i ELSE pg_catalog.quote_ident(i) END,
                       ', ' ORDER BY ord) || ', pg_temp'
              INTO v_new
              FROM pg_catalog.unnest(v_items) WITH ORDINALITY AS u(i, ord);
        END IF;
        RAISE NOTICE '271: % search_path % -> %', r.sig, COALESCE(r.path, '(unpinned)'), v_new;
        EXECUTE pg_catalog.format('ALTER ROUTINE %s SET search_path = %s', r.sig, v_new);
    END LOOP;
END $$;

-- -------------------------------------------------------------------
-- 2. Postcondition.
-- -------------------------------------------------------------------
DO $$
DECLARE
    v_bad text;
BEGIN
    SELECT pg_catalog.string_agg(p.oid::pg_catalog.regprocedure::pg_catalog.text, ', ')
      INTO v_bad
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      JOIN pg_catalog.pg_language l ON l.oid = p.prolang
     WHERE p.prokind IN ('f', 'p')
       AND n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND n.nspname !~ '^pg_(toast|temp)'
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                        WHERE d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
                          AND d.objid = p.oid AND d.deptype = 'e')
       AND (
            -- a pinned path without pg_temp listed once, last, each item
            -- read as the sweep reads it (unquoted: ASCII lower-cased;
            -- quoted: quotes stripped)
            EXISTS (SELECT 1
                      FROM pg_catalog.unnest(p.proconfig) c
                      CROSS JOIN LATERAL (
                          SELECT pg_catalog.array_agg(
                                     CASE WHEN b.t ~ '^".*"$'
                                          THEN pg_catalog.replace(
                                                   pg_catalog.substr(b.t, 2, pg_catalog.length(b.t) - 2),
                                                   '""', '"')
                                          ELSE pg_catalog.translate(b.t, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
                                                                         'abcdefghijklmnopqrstuvwxyz')
                                     END ORDER BY u.ord) AS norm
                            FROM pg_catalog.unnest(pg_catalog.string_to_array(pg_catalog.substr(c, 13), ','))
                                 WITH ORDINALITY AS u(i, ord)
                            CROSS JOIN LATERAL
                                 (SELECT pg_catalog.btrim(u.i, E' \t\n\r\f\x0B') AS t) b) s
                     WHERE c LIKE 'search_path=%'
                       AND (s.norm IS NULL
                            OR s.norm[pg_catalog.cardinality(s.norm)] IS DISTINCT FROM 'pg_temp'
                            OR 'pg_temp' = ANY (s.norm[1:pg_catalog.cardinality(s.norm) - 1])))
            -- an unpinned trigger function
            OR ((p.prorettype = 'pg_catalog.trigger'::pg_catalog.regtype
                 OR EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t
                             WHERE t.tgfoid = p.oid AND NOT t.tgisinternal))
                AND l.lanname NOT IN ('c', 'internal')
                AND NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(p.proconfig) c
                                 WHERE c LIKE 'search_path=%')));
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION '271: functions without pg_temp listed only last, or unpinned '
                        'trigger functions, remain: %', v_bad
            USING ERRCODE = '55000';
    END IF;
END $$;
