-- Migration 031: Provenance constraints (G18)
--
-- Prevent duplicate evidence content per claim.
-- Without this constraint, the same PDF/document hash can be submitted
-- multiple times for the same claim, inflating belief through redundancy
-- rather than genuine independent evidence.

ALTER TABLE evidence
  ADD CONSTRAINT evidence_content_hash_claim_unique
  UNIQUE (content_hash, claim_id);
