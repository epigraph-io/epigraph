-- 061_agents_key_kind.sql
--
-- PR-02 of the multi-user tenancy series.
--
-- WHY THIS FILE EXISTS, AND WHY IT IS 061.
-- Plan §3.1 assigns NO migration to PR-02 and puts `agents.key_kind` inside
-- PR-04's tenancy-columns migration. That is a sequencing error. PR-02's §6.3
-- `ensure_for_client` materialises an `agents` row whose `public_key` is
-- blake3::derive_key("epigraph-oauth-client", client_uuid) -- a 32-byte
-- PLACEHOLDER that satisfies agents_public_key_length (migration 001) but is
-- NOT a signature verifier. Without this discriminator (a) PR-02's required
-- negative test cannot be written, and (b) PR-04's later `DEFAULT 'ed25519'`
-- would retroactively stamp every placeholder agent PR-02 created as a real
-- verifier. So PR-02 claims 061; PR-04's three migrations become 062/063/064
-- and the rest of the §3.1 chain shifts +1, ending at 081 -- inside the
-- 060-085 range reserved in migrations/README.md by PR-01.
-- Every statement below is IF NOT EXISTS / catalog-guarded AND shape-guarded,
-- so PR-04 may keep the identical statements in its own file, where they will
-- simply no-op.
SET LOCAL lock_timeout = '3s';

-- DRIFT GUARD (mirrors the one at the top of 060).
-- `ADD COLUMN IF NOT EXISTS` is silent about a column that already exists in a
-- DIFFERENT shape, and a SQL CHECK passes on NULL -- so a pre-existing nullable
-- or non-varchar `agents.key_kind` would survive this file untouched, and
-- `public_key_if_signer`'s `AND key_kind = 'ed25519'` would then exclude every
-- NULL row, silently disabling packet signing for those agents. Catalog-guarded
-- and shape-guarded are not the same thing. `schema_contract.rs` cannot catch
-- this: `#[sqlx::test]` only ever sees a fresh database.
DO $$
DECLARE
    v_type text;
    v_nullable text;
BEGIN
    SELECT data_type, is_nullable INTO v_type, v_nullable
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'agents' AND column_name = 'key_kind';

    IF FOUND AND v_type IS NOT NULL AND (v_type <> 'character varying' OR v_nullable <> 'NO') THEN
        RAISE EXCEPTION
            'agents.key_kind already exists in a shape 061 did not create '
            '(data_type=%, is_nullable=%; expected character varying / NO). '
            'Reconcile by hand: ALTER TABLE public.agents ALTER COLUMN key_kind '
            'TYPE character varying(16), ALTER COLUMN key_kind SET DEFAULT ''ed25519'', '
            'UPDATE public.agents SET key_kind = ''ed25519'' WHERE key_kind IS NULL, '
            'ALTER COLUMN key_kind SET NOT NULL -- then re-run this migration.',
            v_type, v_nullable;
    END IF;
END $$;

-- agents.public_key is `bytea NOT NULL CHECK (octet_length(public_key) = 32)`
-- (migration 001, agents_public_key_length) and carries a UNIQUE constraint
-- (agents_public_key_unique), so a keyless OAuth principal cannot exist
-- without a placeholder. key_kind records which of the two a row holds.
-- Metadata-only on PostgreSQL 11+: a NOT NULL column with a constant DEFAULT
-- does not rewrite the table.
ALTER TABLE public.agents
    ADD COLUMN IF NOT EXISTS key_kind character varying(16) NOT NULL DEFAULT 'ed25519';

-- Plan §3.0: constraints land NOT VALID, validated later under a guard. The
-- plan's own snippet forgets it here (it applies NOT VALID to the sibling
-- agents_profile_visibility_check two lines above). It matters: `agents` is on
-- the token-mint hot path -- `ensure_for_client` upserts it on every mint -- and
-- a validating ADD CONSTRAINT holds ACCESS EXCLUSIVE for a full seq scan.
-- `SET LOCAL lock_timeout` bounds lock ACQUISITION, not the scan.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agents_key_kind_check')
    THEN ALTER TABLE public.agents
             ADD CONSTRAINT agents_key_kind_check
             CHECK (key_kind IN ('ed25519','derived')) NOT VALID;
    END IF;
END $$;

-- VALIDATE takes only SHARE UPDATE EXCLUSIVE (concurrent reads and writes
-- continue) and is trivially satisfied: the column's constant DEFAULT is
-- 'ed25519', so every pre-existing row already conforms. Guarded so a re-run
-- against an already-validated constraint is a no-op.
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'agents_key_kind_check' AND NOT convalidated
    )
    THEN ALTER TABLE public.agents VALIDATE CONSTRAINT agents_key_kind_check;
    END IF;
END $$;

COMMENT ON COLUMN public.agents.key_kind IS
  '''derived'' means public_key is blake3::derive_key("epigraph-oauth-client", '
  'client_uuid) -- a 32-byte placeholder satisfying the NOT NULL/length CHECK '
  'for a keyless OAuth principal. It is NOT a signature verifier: every '
  'signature path MUST filter key_kind = ''ed25519''. See '
  'crates/epigraph-api/src/routes/submit.rs and '
  'crates/epigraph-db/src/repos/agent.rs::ensure_for_client.';
