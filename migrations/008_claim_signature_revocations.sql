-- Migration 098: audit log for revoked claim signatures
--
-- Evidence: There is no way to express "this claim's signature is no longer
--   trustworthy" without re-signing. Re-signing drifted content would forge
--   the original author's consent; deleting the row loses provenance. The
--   claims_signature_requires_signer CHECK (migration 073) forces either
--   (signature NULL AND signer_id NULL) or both NOT NULL, so "zero the bytes
--   but keep signer_id" is not a legal state.
--
-- Reasoning: Revocation must (a) null both signature and signer_id on the
--   claim row to satisfy the 073 constraint, AND (b) preserve the original
--   (signature, signer_id, content_hash) somewhere so forensic audit is
--   still possible. A separate table keeps the claims table semantically
--   clean ("current signature state") while this table answers "what did
--   the signature chain look like before each revocation?". The optional
--   superseded_by column links a revocation to a supersession when the
--   workflow is revoke-as-part-of-supersede; otherwise NULL for standalone
--   integrity-drift revocations.
--
-- FK policy: claim_id is ON DELETE CASCADE. Rationale: revocation rows are
--   *about* a specific claim — an orphan revocation row referring to a
--   deleted claim is meaningless. If the claim is deleted deliberately
--   (rare — most integrity drift resolves via supersede, not delete), the
--   revocation history is no longer load-bearing. RESTRICT was rejected
--   because it would retroactively block every existing delete_claim call
--   path on any revoked claim, which is surprising behavior.

CREATE TABLE claim_signature_revocations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_id UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    previous_signature BYTEA NOT NULL,
    previous_signer_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    previous_content_hash BYTEA NOT NULL,
    revoked_by UUID NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT NOT NULL,
    superseded_by UUID REFERENCES claims(id) ON DELETE SET NULL,
    CONSTRAINT revocations_previous_sig_length
        CHECK (octet_length(previous_signature) = 64),
    CONSTRAINT revocations_previous_hash_length
        CHECK (octet_length(previous_content_hash) = 32),
    CONSTRAINT revocations_reason_nonempty
        CHECK (length(trim(reason)) > 0)
);

CREATE INDEX idx_claim_sig_revocations_claim
    ON claim_signature_revocations(claim_id);

CREATE INDEX idx_claim_sig_revocations_revoker
    ON claim_signature_revocations(revoked_by);

CREATE INDEX idx_claim_sig_revocations_revoked_at
    ON claim_signature_revocations(revoked_at DESC);
