-- 061_claims_canonical_hash.sql
--
-- `claims.canonical_hash` — a SECOND digest of a claim's text, computed over a
-- CANONICALIZED hash input (NFC, zero-width controls stripped, whitespace runs
-- collapsed). Used for the dedup LOOKUP only. Backlog e09986c2.
--
-- THE DEFECT THIS ADDRESSES
--
-- `claims.content_hash` is BLAKE3 over the raw UTF-8 bytes of `content`, and
-- `ClaimRepository::create_or_get` keys find-or-insert on
-- `(content_hash, agent_id)`. A digest of BYTES is not a digest of
-- TEXT-AS-PERCEIVED, so a resubmission that differs only in normalization form
-- (NFD `café` vs NFC `café`), in invisible characters (U+200B,
-- U+FEFF), or in whitespace runs misses the lookup and lands a SECOND row for
-- the SAME agent. Reproduced against a live database: the byte-identical
-- control dedups; all three cosmetic-variant cases do not.
--
-- WHY A NEW COLUMN INSTEAD OF REDEFINING content_hash
--
-- `content_hash` is load-bearing in nine places that must not move:
-- `uq_claims_content_hash_agent` (migration 013); the client-supplied
-- `content_hash` override on `POST /api/v1/claims`; the digest MCP signs;
-- `claim_signature_revocations.previous_content_hash`; `consolidate`'s
-- idempotency probe; `dedup_sweep`'s exact-vs-near classification; and the
-- `content_hash_prefix` matching blocker. Re-defining the digest would
-- invalidate every stored signature and every audit row. This column is
-- additive: `content_hash` keeps its value byte-for-byte.
--
-- DELIBERATELY NULLABLE, WITH NO UNIQUE CONSTRAINT
--
-- Nullable because BLAKE3 has no PostgreSQL function, so no `DEFAULT` and no
-- `UPDATE ... SET canonical_hash = <expr>` can fill legacy rows here; they are
-- filled by the `backfill_canonical_hash` CLI, and read as "not yet computed"
-- until it runs. Until then a cosmetic variant of a legacy row still misses the
-- lookup — strictly today's behaviour, never worse.
--
-- NOT UNIQUE because a UNIQUE `(canonical_hash, agent_id)` would hard-FAIL
-- writes that succeed today: cosmetic duplicate PAIRS already exist in the
-- table, so the index could not even be built before they are resolved, and
-- once built it would turn a survivable double-insert into an error. Dedup
-- here is a lookup that finds an equivalent row, not a constraint that rejects
-- one. `uq_claims_content_hash_agent` remains the only unique constraint on
-- `claims`, which is what lets `create_or_get`'s `DuplicateKey` race branch go
-- on matching the error without inspecting the constraint name.

ALTER TABLE claims ADD COLUMN IF NOT EXISTS canonical_hash BYTEA;

-- Reject a wrong-width digest at the boundary. `content_hash` has no such
-- guard (it predates this discipline and some legacy rows carry sha256 test
-- fixtures), but a column introduced today should not inherit that laxity.
ALTER TABLE claims DROP CONSTRAINT IF EXISTS claims_canonical_hash_length;
ALTER TABLE claims ADD CONSTRAINT claims_canonical_hash_length
    CHECK (canonical_hash IS NULL OR octet_length(canonical_hash) = 32);

-- Column order matches the lookup in `find_by_canonical_hash_and_agent`
-- (`WHERE canonical_hash = $1 AND agent_id = $2`). Partial on NOT NULL: the
-- unbackfilled rows are never a lookup target, and excluding them keeps the
-- index proportional to the backfilled set rather than to the table.
CREATE INDEX IF NOT EXISTS idx_claims_canonical_hash_agent
    ON claims (canonical_hash, agent_id)
    WHERE canonical_hash IS NOT NULL;

COMMENT ON COLUMN claims.canonical_hash IS
'BLAKE3 over the CANONICALIZED text of `content` (NFC, zero-width controls '
'stripped, whitespace runs collapsed to one ASCII space, trimmed) — see '
'epigraph_crypto::canonicalize_for_hash. Lookup-only: it is the fallback key '
'for ClaimRepository::create_or_get so that two submissions which render '
'identically dedup to one row. `content` itself is stored EXACTLY as '
'submitted; this column never rewrites it. NULL means "not yet computed" '
'(legacy row awaiting the backfill_canonical_hash CLI, or a writer outside '
'ClaimRepository), never "no canonical form". Deliberately not UNIQUE — '
'uq_claims_content_hash_agent on content_hash is still the only unique '
'constraint on this table. Backlog e09986c2.';
