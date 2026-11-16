-- 229: admit `dataset` as a stored evidence type (backlog c8beb101).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- `EvidenceType::Dataset` (epigraph-core) is evidence that commits to a
-- multi-file dataset by the digest of its manifest: root_uri, manifest_uri or
-- manifest_blob_id, manifest_hash with its hash_algorithm, file_count and
-- total_bytes. Its fields live in `evidence.properties`, the serialised
-- `EvidenceType`, exactly as every other variant's do; the
-- `evidence.evidence_type` column carries its stored name, `dataset`
-- (`EvidenceType::stored_type`). Migration 001's `evidence_type_valid` CHECK
-- admits seven names and not this one, so every dataset row is refused with
-- 23514 until this runs.
--
-- ===================================================================
-- 1. WHAT IT DOES
-- ===================================================================
--
-- Re-creates `evidence_type_valid` with 001's seven values plus `dataset`,
-- in one ALTER TABLE so the table is never without the constraint. The list
-- is `epigraph_core::STORED_EVIDENCE_TYPES`; the test
-- `epigraph-db/tests/evidence_type_dataset.rs` compares the two, so a later
-- widening that forgets the Rust copy (or the reverse) fails.
--
-- The constraint is re-validated against existing rows. Every existing row
-- passes, since the new set contains the old one; the scan holds the ALTER's
-- ACCESS EXCLUSIVE lock on `evidence` for its duration. `lock_timeout` makes
-- a busy table fail the migration fast rather than queue every evidence
-- write behind it.
--
-- No table, column, function, trigger, policy, index or grant. No tenancy
-- surface: `evidence` keeps its tier-A columns and policies unchanged.
--
-- ===================================================================
-- 2. UNDO
-- ===================================================================
--
-- `docs/runbooks/229-undo.sql`. It refuses while any `dataset` row exists
-- (re-narrowing the CHECK would fail on them anyway); roll every binary that
-- writes dataset evidence back first, and decide what happens to those rows.

SET LOCAL lock_timeout = '5s';

ALTER TABLE public.evidence
    DROP CONSTRAINT IF EXISTS evidence_type_valid,
    ADD CONSTRAINT evidence_type_valid CHECK (
        (evidence_type)::text = ANY (ARRAY[
            'document'::text,
            'observation'::text,
            'testimony'::text,
            'computation'::text,
            'reference'::text,
            'figure'::text,
            'conversational'::text,
            'dataset'::text
        ])
    );
