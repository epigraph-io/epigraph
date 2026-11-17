-- 230: admit `seed-derived` as an `agents.key_kind` (backlog bfc2eff8).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- Several agent keys are `BLAKE3(seed)` used as the Ed25519 SECRET, where
-- the seed is public: `author:{name}` and `orcid:{id}` (`did_key_for_author`,
-- every ingested author node), the same name derivation of `org:{name}`
-- (affiliation nodes),
-- `author:workflow-ingest-system` (the legacy system-agent constant), and
-- `llm-agent:{model}:{prompt hash}` (the unkeyed LLM identity). Anyone who
-- knows the seed can recompute the private key, so such a key names an
-- agent and must never verify a signature.
--
-- Migration 061 gave `agents.key_kind` two values: `ed25519` (a real
-- verifier, the default) and `derived` (the keyless OAuth principal's
-- placeholder). `derived` cannot carry these rows: 077's `agents_provision`
-- refuses it to the application role, which creates author nodes (MCP
-- document ingest, `POST /api/v1/claims/:id/provenance`), and 161 / 180 /
-- 195 read `derived` as "an LLM agent" or "a keyless OAuth human". So this
-- adds a third value with exactly one meaning: the public key is derived
-- from a public seed and is not a verifier.
--
-- ===================================================================
-- 1. WHAT IT DOES
-- ===================================================================
--
-- Re-creates `agents_key_kind_check` with 061's two values plus
-- `seed-derived`, in one ALTER TABLE so the table is never without the
-- constraint. Every existing row passes (the new set contains the old one);
-- the re-validation scans `agents` under the ALTER's ACCESS EXCLUSIVE lock,
-- and `lock_timeout` makes a busy table fail the migration fast rather than
-- queue the token mint behind it. 12 characters, inside 061's varchar(16).
--
-- The rows themselves are marked AT INSERT by the application
-- (`AgentRepository::create_seed_derived_conn`). Existing rows are NOT
-- backfilled: PostgreSQL cannot compute BLAKE3, so it cannot tell which keys
-- are seed-derived, and 118 bars the application role from updating
-- `key_kind`. Marking them is an operator task on the maintenance role.
--
-- Every reader that filters `key_kind = 'ed25519'`
-- (`AgentRepository::public_key_if_signer`, `ensure_for_client`'s real-signer
-- adoption) already excludes the new value; 077's `agents_provision` admits
-- it to the application role (it refuses only `derived`).
--
-- One function changes: 161's re-runnable `epigraph_backfill_legacy_agent_keys()`
-- gives every agent without one an ACTIVE `identity-legacy` row in
-- `agent_keys`, an ATTESTED key that `verify_claim` binds signatures to. Run
-- after 230 (the cut-over, `tenancy_backfill`), it would attest every
-- seed-derived key, the opposite of this migration. It now skips
-- `key_kind = 'seed-derived'`; everything else is 161's definition verbatim
-- (same signature, SECURITY DEFINER, search_path, owner and grants, which
-- CREATE OR REPLACE keeps). Rows it already wrote are not touched: retiring
-- them is the operator's rotation step. No table, column, trigger, policy,
-- index or grant changes.
--
-- ===================================================================
-- 2. UNDO
-- ===================================================================
--
-- `docs/runbooks/230-undo.sql`. It refuses while any `seed-derived` row
-- exists (re-narrowing the CHECK would fail on them anyway); roll every
-- binary that writes the kind back first. It restores 161's backfill body.

SET LOCAL lock_timeout = '3s';

ALTER TABLE public.agents
    DROP CONSTRAINT IF EXISTS agents_key_kind_check,
    ADD CONSTRAINT agents_key_kind_check
        CHECK (key_kind IN ('ed25519', 'derived', 'seed-derived'));

-- 161's backfill, plus the one predicate marked below.
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
                        WHERE r.public_key = a.public_key AND r.status <> 'active')
       -- 230: a key derived from a public seed is computable by anyone; it is
       -- never attested as a signing key.
       AND a.key_kind <> 'seed-derived';
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END $$;

COMMENT ON COLUMN public.agents.key_kind IS
  '''ed25519'': public_key is a real Ed25519 verifier (the default). '
  '''derived'': public_key is blake3::derive_key("epigraph-oauth-client", '
  'client_uuid), a 32-byte placeholder for a keyless OAuth principal (061). '
  '''seed-derived'': public_key is the Ed25519 key of BLAKE3(<public seed>) '
  '(author name/ORCID, org, legacy system constant, unkeyed LLM identity), '
  'whose private half anyone can compute (230). Neither of the last two is a '
  'signature verifier: every signature path MUST filter key_kind = ''ed25519''. '
  'See crates/epigraph-db/src/repos/agent.rs::public_key_if_signer.';
