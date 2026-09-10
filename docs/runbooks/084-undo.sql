-- docs/runbooks/084-undo.sql
--
-- UNDO for migration 084_retire_ownership.sql.
--
-- ⚠ READ THIS FIRST: THIS SCRIPT DOES NOT BRING THE DATA BACK.
--
-- It recreates the EMPTY SHAPE of `public.ownership` and its quarantine view, so
-- that a binary or a script written against the old schema can start. It cannot
-- restore a single row, and a runbook that implied otherwise would be worse than
-- no runbook at all.
--
-- WHY A RUNBOOK AND NOT A .down.sql. `migrations/` contains ZERO `.down.sql`
-- files — `sqlx migrate revert` is not available in this tree. Plan §7 names
-- three one-way doors that must therefore ship a checked-in undo script;
-- 084's `DROP TABLE` is one of them. (The plan calls this file
-- `docs/runbooks/080-undo.sql` in §7, and `081-undo.sql` in §3.1's rename note
-- beside its self-declared-authoritative `| Shipped |` column reading 081.
-- Both are pre-shift; `migrations/README.md`'s +4 supersedes them at 084. See
-- README's "Why 060-085 became 060-090", and 084's own header.)
--
-- ===================================================================
-- WHAT IS RECOVERABLE, AND FROM WHERE
--
-- `public.tenancy_transcription_log` SURVIVES 084 and is the only surviving
-- record of what the dropped rows declared. It is keyed `node_id uuid PRIMARY
-- KEY`, last-write-wins, and it carries:
--
--   node_id          -> ownership.node_id
--   node_type        -> ownership.node_type
--   from_partition   -> ownership.partition_type AS AT TRANSCRIPTION TIME
--   to_visibility    } the tenancy the node was given; NOT columns of
--   to_group_id      } `ownership`, but they identify the owner group
--   transcribed_at   -> when the shim ran, NOT ownership.created_at
--
-- IRRECOVERABLE, from anywhere in this database:
--
--   * `ownership.owner_id` — the AGENT of record. `to_group_id` names the
--     group the node landed in, which for the `private` arm was that agent's
--     personal group and is therefore usually resolvable
--     (`groups.created_by_agent_id`), but for the `community` arm it is the
--     community's group and says nothing about who declared the row.
--   * `ownership.created_at` and `ownership.updated_at`. `transcribed_at` is
--     when the shim fired, which is a different event.
--   * `ownership.community_id` and `ownership.encryption_key_id`.
--   * EVERY ROW THAT WAS NEVER TRANSCRIBED. There should be none — 084's second
--     pre-flight refuses to run while a non-public row lacks a ledger entry —
--     but a `public` row needed no ledger entry and so left no trace at all.
--
-- ===================================================================
-- WHAT ELSE 084 DROPPED, AND WHAT THIS SCRIPT DOES ABOUT IT
--
--   * `ownership_pkey`, `idx_ownership_node_type`, `idx_ownership_owner`,
--     `idx_ownership_partition`, `idx_ownership_community` — recreated below.
--   * `ownership_node_type_check`, `ownership_partition_check` (001),
--     `ownership_owner_fk`, `ownership_community_fkey`,
--     `ownership_key_id_is_uuid`,
--     `ownership_community_needs_community_partition` (068) — recreated below.
--   * `ownership_updated_at` (001) — recreated below; its function
--     `update_updated_at_column()` is not owned by 084 and still exists.
--   * `ownership_transcribe` and `public.epigraph_ownership_transcribe()` (071)
--     — **NOT recreated here.** Re-apply `migrations/071_ownership_compat_shim.sql`
--     if you need the write-through shim back; it is `CREATE OR REPLACE
--     FUNCTION` + `DROP TRIGGER IF EXISTS` throughout and is safe to re-run.
--     Recreating the table WITHOUT the shim is deliberate and is the safer of
--     the two states: an `ownership` write then changes nothing, rather than
--     silently reclassifying a live node from a table the rest of the system no
--     longer reads.
--
-- ORDERING WITH 070-undo. `docs/runbooks/070-undo.sql` drops
-- `ownership_transcribe ON public.ownership`. Its `IF EXISTS` guards the
-- TRIGGER, not the table, so on a database at 084 it would raise 42P01; that
-- script has been given an explicit table-existence guard. Running THIS script
-- first also resolves it.
--
-- Usage:
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f docs/runbooks/084-undo.sql

BEGIN;
SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS public.ownership (
    node_id uuid NOT NULL,
    node_type character varying(50) NOT NULL,
    partition_type character varying(20) DEFAULT 'public'::character varying NOT NULL,
    owner_id uuid NOT NULL,
    encryption_key_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    community_id uuid,
    CONSTRAINT ownership_pkey PRIMARY KEY (node_id),
    CONSTRAINT ownership_node_type_check CHECK (((node_type)::text = ANY ((ARRAY['claim'::character varying, 'agent'::character varying, 'evidence'::character varying, 'perspective'::character varying, 'community'::character varying, 'context'::character varying, 'frame'::character varying])::text[]))),
    CONSTRAINT ownership_partition_check CHECK (((partition_type)::text = ANY ((ARRAY['public'::character varying, 'community'::character varying, 'private'::character varying])::text[])))
);

-- The three constraints migration 068 added, in its own guarded form.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conrelid = 'public.ownership'::regclass
                    AND conname  = 'ownership_owner_fk')
  THEN ALTER TABLE public.ownership ADD CONSTRAINT ownership_owner_fk
       FOREIGN KEY (owner_id) REFERENCES public.agents(id) ON DELETE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conrelid = 'public.ownership'::regclass
                    AND conname  = 'ownership_community_fkey')
  THEN ALTER TABLE public.ownership ADD CONSTRAINT ownership_community_fkey
       FOREIGN KEY (community_id) REFERENCES public.communities(id) ON DELETE SET NULL;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conrelid = 'public.ownership'::regclass
                    AND conname  = 'ownership_key_id_is_uuid')
  THEN ALTER TABLE public.ownership ADD CONSTRAINT ownership_key_id_is_uuid
       CHECK (encryption_key_id IS NULL
              OR encryption_key_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conrelid = 'public.ownership'::regclass
                    AND conname  = 'ownership_community_needs_community_partition')
  THEN ALTER TABLE public.ownership
         ADD CONSTRAINT ownership_community_needs_community_partition
         CHECK (community_id IS NULL OR partition_type::text = 'community'::text);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_ownership_node_type ON public.ownership (node_type);
CREATE INDEX IF NOT EXISTS idx_ownership_owner     ON public.ownership (owner_id);
CREATE INDEX IF NOT EXISTS idx_ownership_partition ON public.ownership (partition_type);
CREATE INDEX IF NOT EXISTS idx_ownership_community
    ON public.ownership (community_id) WHERE community_id IS NOT NULL;

DROP TRIGGER IF EXISTS ownership_updated_at ON public.ownership;
CREATE TRIGGER ownership_updated_at BEFORE UPDATE ON public.ownership
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- A VIEW, never a snapshot, and `security_invoker` is not optional: a view
-- without it executes as its OWNER and bypasses the invoker's policies under the
-- FORCEd RLS migration 079 installs.
CREATE OR REPLACE VIEW public.ownership_key_id_quarantine
    WITH (security_invoker = true) AS
    SELECT node_id, node_type, partition_type, owner_id, encryption_key_id
      FROM public.ownership
     WHERE encryption_key_id IS NOT NULL AND community_id IS NULL;

COMMIT;

-- Confirm the SHAPE is back. It will report zero rows, and that is the correct
-- and expected outcome: the data is not recoverable.
SELECT relname, relkind FROM pg_class
 WHERE relname IN ('ownership', 'ownership_key_id_quarantine')
 ORDER BY relname;
SELECT count(*) AS rows_restored FROM public.ownership;

-- What the ledger still knows about the rows that are gone.
SELECT count(*) AS transcribed_nodes_on_record FROM public.tenancy_transcription_log;
