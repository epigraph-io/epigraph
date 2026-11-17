-- ===================================================================
-- 230-undo.sql: take migration 230 (the `seed-derived` agents.key_kind) back
-- out, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST: ROLL THE BINARIES BACK BEFORE THIS RUNS. A 230 binary inserts
-- `seed-derived` agent rows (document-ingest and workflow-ingest author
-- nodes, provenance organization nodes, the unregistered workflow-ingest
-- system agent, `epigraph-operator link --agent-model`). A unit left serving
-- after this undo answers each such insert with a CHECK violation (23514).
--
-- SEED-DERIVED ROWS BLOCK IT. Re-narrowing `agents_key_kind_check`
-- re-validates every row, so it fails while any `seed-derived` row exists.
-- This script refuses up front instead, naming the count, and changes
-- nothing. Decide what those rows become first. Setting them back to
-- `ed25519` makes their publicly computable keys signature verifiers again;
-- that is the state below 230, and the reason 230 exists. List them:
--     SELECT id, display_name, created_at FROM public.agents
--      WHERE key_kind = 'seed-derived';
--
-- WHAT IT DOES: re-creates `agents_key_kind_check` with migration 061's two
-- values, in 061's spelling, restores 061's column comment, and restores
-- 161's `epigraph_backfill_legacy_agent_keys()` body (without 230's
-- seed-derived skip; owner and grants are kept by CREATE OR REPLACE). Tested by
-- `epigraph-db/tests/agents_key_kind_seed_derived.rs` (run twice, it returns
-- the constraint to its definition below 230; it refuses while a
-- seed-derived row exists).
--
-- WHAT IT LEAVES: 230's `_sqlx_migrations` row. Re-introducing the kind is a
-- NEW migration, never a re-run of 230. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM public.agents WHERE key_kind = 'seed-derived';
    IF n > 0 THEN
        RAISE EXCEPTION '230-undo: % agent row(s) have key_kind = ''seed-derived''; '
                        'resolve them before narrowing agents_key_kind_check', n;
    END IF;
END
$$;

-- Migration 061's definition, spelled as 061 spells it.
ALTER TABLE public.agents
    DROP CONSTRAINT IF EXISTS agents_key_kind_check,
    ADD CONSTRAINT agents_key_kind_check CHECK (key_kind IN ('ed25519','derived'));

-- Migration 161's backfill, verbatim.
CREATE OR REPLACE FUNCTION public.epigraph_backfill_legacy_agent_keys()
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    n integer;
BEGIN
    INSERT INTO public.agent_keys (agent_id, public_key, key_type, status, valid_from)
    SELECT a.id, a.public_key, 'identity-legacy', 'active', a.created_at
      FROM public.agents a
     WHERE NOT EXISTS (SELECT 1 FROM public.agent_keys k
                        WHERE k.agent_id = a.id AND k.key_type = 'identity-legacy')
       -- A host-registered identity's key never signs (D1): its signatures
       -- bind through its `signing` key, so it gets no legacy row.
       AND NOT EXISTS (SELECT 1 FROM public.agent_prompt_snapshots s
                        WHERE s.agent_id = a.id)
       -- A key already retired in agent_keys (rotated or revoked) never comes
       -- back as an ACTIVE legacy key: rotation leaves agents.public_key as it
       -- was, so this column alone would re-legitimise it for key binding.
       AND NOT EXISTS (SELECT 1 FROM public.agent_keys r
                        WHERE r.public_key = a.public_key AND r.status <> 'active');
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END $$;

COMMENT ON COLUMN public.agents.key_kind IS
  '''derived'' means public_key is blake3::derive_key("epigraph-oauth-client", '
  'client_uuid) -- a 32-byte placeholder satisfying the NOT NULL/length CHECK '
  'for a keyless OAuth principal. It is NOT a signature verifier: every '
  'signature path MUST filter key_kind = ''ed25519''. See '
  'crates/epigraph-api/src/routes/submit.rs and '
  'crates/epigraph-db/src/repos/agent.rs::ensure_for_client.';

COMMIT;
