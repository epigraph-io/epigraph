-- ===================================================================
-- 271-precheck.sql: list every function migration 271 would REFUSE, before
-- migrating. Read-only; run it on any DSN that can read `pg_proc`.
--
-- 271's sweep refuses (55000, nothing changed, nothing recorded) a function
-- outside the system schemas and outside any extension when its pinned
-- `search_path`:
--   * lists `pg_temp` before another item (appending cannot fix that
--     order), or
--   * does not end in `pg_temp` and has an item that is not a plain
--     lower-case name or exactly "$user" (271 rebuilds such a path from its
--     items, and refuses one it cannot rebuild safely).
-- Items are read as PostgreSQL reads them: an unquoted item ASCII
-- lower-cased, a quoted one with its quotes stripped. Each setting is tested
-- on its own, so a function with several `proconfig` entries is not
-- mis-read.
--
-- Expect no row. For each row, find who set that path, re-state it with
-- plain schema names and `pg_temp` last, then migrate.
-- ===================================================================
SELECT p.oid::pg_catalog.regprocedure AS function,
       c AS setting,
       w.reason
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
  CROSS JOIN LATERAL pg_catalog.unnest(p.proconfig) AS c
  CROSS JOIN LATERAL (
      SELECT pg_catalog.array_agg(b.t ORDER BY u.ord) AS items,
             pg_catalog.array_agg(
                 CASE WHEN b.t ~ '^".*"$'
                      THEN pg_catalog.replace(
                               pg_catalog.substr(b.t, 2, pg_catalog.length(b.t) - 2), '""', '"')
                      ELSE pg_catalog.translate(b.t, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
                                                     'abcdefghijklmnopqrstuvwxyz')
                 END ORDER BY u.ord) AS norm
        FROM pg_catalog.unnest(pg_catalog.string_to_array(pg_catalog.substr(c, 13), ','))
             WITH ORDINALITY AS u(i, ord)
        CROSS JOIN LATERAL (SELECT pg_catalog.btrim(u.i, E' \t\n\r\f\x0B') AS t) b
  ) s
  CROSS JOIN LATERAL (SELECT CASE
      WHEN 'pg_temp' = ANY (s.norm[1:pg_catalog.cardinality(s.norm) - 1])
          THEN 'lists pg_temp before another schema'
      WHEN s.norm[pg_catalog.cardinality(s.norm)] = 'pg_temp'
          THEN NULL
      WHEN pg_catalog.btrim(pg_catalog.substr(c, 13), E' \t\n\r\f\x0B') IN ('', '""')
          THEN NULL
      WHEN EXISTS (SELECT 1 FROM pg_catalog.unnest(s.items) AS i
                    WHERE i !~ '^[a-z_][a-z0-9_]*$' AND i <> '"$user"')
          THEN 'an item is not a plain lower-case schema name or "$user"'
  END AS reason) w
 WHERE c LIKE 'search_path=%'
   AND w.reason IS NOT NULL
   AND p.prokind IN ('f', 'p')
   AND n.nspname NOT IN ('pg_catalog', 'information_schema')
   AND n.nspname !~ '^pg_(toast|temp)'
   AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                    WHERE d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
                      AND d.objid = p.oid AND d.deptype = 'e')
 ORDER BY p.oid::pg_catalog.regprocedure::pg_catalog.text;
