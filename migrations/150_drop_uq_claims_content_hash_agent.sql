-- Migration 150: drop 013's uq_claims_content_hash_agent, so every database
-- has the shape the long-lived one already has.
--
-- DECISION (backlog 00f1a517, drain U044, option C; migrations/README.md,
-- "Known schema drift: `uq_claims_content_hash_agent` (013)"). Migration 013
-- added `UNIQUE (content_hash, agent_id)` on `claims`. The long-lived
-- `epigraph` database records 013 as applied but has no such constraint
-- (test fixtures dropped it there; audited 2026-08-08), and it cannot be
-- restored: ~95k blocking groups, most of them supersession history that a
-- full UNIQUE would force us to delete. Every freshly-migrated database (CI,
-- `#[sqlx::test]`) still had it, so green CI proved dedup behaviour that
-- production does not have.
--
-- WHAT REPLACES IT. The dedup contract is enforced in the application:
-- `ClaimRepository::create_or_get_signed` and POST /claims
-- (`if_not_exists=false`) take a transaction-scoped advisory lock on
-- `(content_hash, agent_id)` (`ClaimRepository::lock_content_hash_agent`)
-- before their find, so two concurrent first creates serialize instead of
-- both inserting. Pinned by `epigraph-db/tests/claim_repo_helpers.rs`
-- (`the_dedup_race_is_serialized_*`) and
-- `epigraph-api/tests/post_claims_dedup_409.rs`.
--
-- FUTURE TARGET (not this file): a partial unique index
-- `(content_hash, agent_id) WHERE is_current`, after the live duplicate groups
-- are reconciled with `mark_duplicate`. The `DuplicateKey` catch arms in the
-- repository stay for it.
--
-- ON PRODUCTION this is a no-op (`IF EXISTS`, the constraint is absent) and
-- cannot fail on data. ALTER TABLE still takes ACCESS EXCLUSIVE on `claims`
-- for the instant it runs, so `lock_timeout = '3s'` like 111-121 and 144-149:
-- on a timeout, re-run in a quiet window.
--
-- UNDO (only on a database with no duplicate (content_hash, agent_id) rows;
-- `scripts/audit_claims_content_hash_agent.py` counts them, read-only):
--   ALTER TABLE claims ADD CONSTRAINT uq_claims_content_hash_agent
--       UNIQUE (content_hash, agent_id);

SET LOCAL lock_timeout = '3s';

ALTER TABLE claims DROP CONSTRAINT IF EXISTS uq_claims_content_hash_agent;
