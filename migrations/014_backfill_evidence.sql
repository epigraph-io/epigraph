-- Backfill synthetic Testimonial evidence for orphan claims (no evidence records).
--
-- Root cause: the claim/trace/evidence insert sequence was not wrapped in a
-- transaction, so if insert_evidence failed after insert_claim succeeded, the
-- claim persisted without evidence. This migration creates placeholder evidence
-- so these claims participate correctly in recompute_from_evidence().
--
-- The 'backfilled' property flag marks these as synthetic for auditability.

INSERT INTO evidence (id, content_hash, evidence_type, claim_id, signature, signer_id, properties, created_at)
SELECT
    gen_random_uuid(),
    c.content_hash,
    'testimony',
    c.id,
    decode(repeat('00', 64), 'hex'),  -- 64-byte zero placeholder (Ed25519 length)
    c.agent_id,
    jsonb_build_object('supports', true, 'relevance', 0.5, 'backfilled', true),
    c.created_at
FROM claims c
LEFT JOIN evidence e ON e.claim_id = c.id
WHERE e.id IS NULL;
