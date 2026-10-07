-- Migration 132: OPEN ELEVATION (elevation plan EL-14; review cp2 SEC-01,
-- cp3 SEC-01). This is the one migration of the elevation stack that opens
-- migration 125's recorder gate. Nothing else may replace
-- `epigraph_elevated_access_ready()`.
--
-- WHAT IT CHANGES: one function body. 125 shipped the gate answering `false`
-- and ANDed it into `epigraph_elevation_session_is_live`, so no session was
-- live on any database before this file; 127 installed the per-access
-- recorder and left the gate closed, because the opening waited on more than
-- the recorder (125's header, "OPENING IT WAITS ON MORE THAN THE RECORDER").
-- Each of those conditions is now met by an earlier migration or batch of the
-- stack:
--
--   (1) operator-hidden (pinned) evidence: settled by an INTERIM operator
--       ruling (an elevated session may read it, and every such read is
--       recorded where the row's owner reads it; 127's header);
--   (2) elevated writes: the API refuses every non-GET request from a token
--       carrying an elevation claim, except a named allowlist of read routes
--       and the one act-proposal route; the MCP transport refuses every
--       non-read tool and every federated tool to an elevated request;
--   (3) `recall_events` is in the recorder's id-bearing set, attributed by
--       its owner group (127).
--
-- THE NEW BODY IS A READINESS TEST, NOT A CONSTANT. The gate answers true
-- only while the recorder is installed: the `elevated_access` table and
-- `epigraph_record_elevated_access(text, jsonb, integer, uuid[])` both exist.
-- So taking 127 back out (its undo drops both) closes the gate by itself,
-- even if this file's own undo was skipped.
--
-- WHAT IT DOES NOT CHANGE: no table, no policy, no grant. `CREATE OR
-- REPLACE` keeps the function's owner (the maintenance role) and its ACL
-- (no EXECUTE for PUBLIC or the application role); 125's register pins both.
--
-- THE SECOND KEY IS UNCHANGED. A session is live only to a connection that
-- also DECLARES the recorder (`epigraph.access_recorder` = 'on'), which only
-- a recording build stamps (the API server, the MCP HTTP transport). A unit
-- left on a build without the recorder never elevates on this database.
--
-- WHAT STILL HAS TO HOLD BEFORE THE FIRST REAL ELEVATION (operations, not
-- schema; docs/deploy.md, "Opening elevation (migration 132)"): the offline
-- confirmation verifier passes; only request units hold the application
-- DSN; `epigraph-tenancy-backfill verify` passes and the maintenance DSN is
-- not the superuser; every request unit runs on the application role with
-- no role switch in its DSN. Applying this migration with no passkey
-- enrolled and no elevating assignment held still widens nothing: a session
-- needs both, and a passkey ceremony.
--
-- UNDO: `docs/runbooks/132-undo.sql` restores 125's `SELECT false` body (the
-- gate closes; every live session stops being live at its next statement).
-- Run it FIRST, before every other elevation undo.

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_elevated_access_ready()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT to_regclass('public.elevated_access') IS NOT NULL
       AND to_regprocedure(
               'public.epigraph_record_elevated_access(text, jsonb, integer, uuid[])'
           ) IS NOT NULL
$$;
