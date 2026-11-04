-- ===================================================================
-- edge-relationship-casefold-undo.sql: put back the spelling
-- `edge-relationship-casefold.sql` folded, byte for byte, from
-- `ops_backup.edges_relationship_casefold`. Backlog 3ce5e00c.
--
-- Run on the migration (superuser) DSN. Restores only rows that still carry
-- the folded spelling (a row edited since keeps its edit), then empties the
-- backup table so a later fold records afresh. Idempotent. It does not undo
-- migration 175, and it does not need to: 175's factor table and unique
-- index accept both spellings.
--
-- Drop the backup once the fold is accepted:
--   DROP TABLE ops_backup.edges_relationship_casefold; DROP SCHEMA ops_backup;
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

-- Fail closed on a DSN row-level security filters: `edges` is FORCE RLS, so
-- on any other role every statement below would silently see only the rows
-- that role may read, and the report would look complete.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles
                    WHERE rolname = current_user AND (rolsuper OR rolbypassrls)) THEN
        RAISE EXCEPTION 'casefold: run on the migration (superuser) DSN; % is subject to row-level security on edges', current_user
            USING ERRCODE = '42501';
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('ops_backup.edges_relationship_casefold') IS NULL THEN
        RAISE NOTICE 'casefold undo: no backup table, nothing to restore';
        RETURN;
    END IF;
    UPDATE public.edges e
       SET relationship = b.old_relationship
      FROM ops_backup.edges_relationship_casefold b
     WHERE e.id = b.edge_id
       AND e.relationship::text = lower(b.old_relationship::text);
    DELETE FROM ops_backup.edges_relationship_casefold;
END $$;

COMMIT;
