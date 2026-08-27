-- Migration 071: Merkle manifests — a signed commitment over a SET of graph
-- rows (backlog 6e2364b8-a7e0-4d51-8834-ab4707ee4fbb).
--
-- NUMBERING -- the design called for 070, but 070_blobs.sql landed first on this
-- same branch (and 060..069 are deliberately left clear for a concurrently
-- developed sibling branch that is also adding migrations). 071 is the first
-- free number above both.
--
-- EVIDENCE
-- claims.signature / edges.signature prove each row's authorship but say nothing
-- about the completeness or the boundary of a SET. An exporter can drop
-- inconvenient rows from a subgraph export and every surviving row still
-- verifies individually. A consumer receiving a subgraph today must simply trust
-- the exporting instance to have selected honestly.
--
-- REASONING (the blocker the backlog item named)
-- A manifest that commits to WHOLE rows breaks on ordinary maintenance. `labels`
-- are patched by update_labels / patch_claim / resolve_backlog_item; claims are
-- superseded (is_current, supersedes, embedding); theme_id is reassigned by
-- theme_cluster; every Dempster-Shafer recompute rewrites truth_value / belief /
-- plausibility / classification; updated_at moves on all of it. So each leaf
-- commits ONLY to the write-once subset of its row:
--
--     claim leaf  <- (id, content_hash, agent_id, created_at)
--     edge  leaf  <- (id, relationship, created_at)
--
-- Every one of those columns was verified to have no production UPDATE path. The
-- single `UPDATE claims SET content_hash` in the tree
-- (epigraph-api/src/routes/claims.rs) runs inside the creating transaction under
-- `if was_created`, so it cannot rewrite an already-visible row.
--
-- Edge ENDPOINTS are deliberately excluded: source_id / target_id are rewritten
-- by dedup re-sourcing (ClaimRepository::mark_duplicate_with_repair,
-- mark_duplicate, consolidate_claims) and by the retraction cascade, so
-- committing to them would break every manifest that ever touched a deduped
-- edge. edges.content_hash is excluded because no write path populates it (the
-- column is NULL for every row).
--
-- Leaves are ordered canonically (kind tag, then row id bytes) and folded into
-- an RFC-6962-shaped BLAKE3 tree: leaf = BLAKE3(0x00 || preimage),
-- node = BLAKE3(0x01 || left || right), split at the largest power of two
-- strictly below n. The distinct domain tags stop an interior digest from being
-- replayed as a leaf; the RFC-6962 split (rather than Bitcoin's
-- duplicate-last-node promotion) avoids the CVE-2012-2459 collision shape.

CREATE TABLE IF NOT EXISTS manifests (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    algo               TEXT NOT NULL DEFAULT 'blake3-merkle-v1',
    root               BYTEA NOT NULL,
    entry_count        INTEGER NOT NULL,
    subject            JSONB NOT NULL DEFAULT '{}'::jsonb,
    signed_header      BYTEA NOT NULL,
    signature          BYTEA NOT NULL,
    signer_id          UUID REFERENCES agents(id) ON DELETE SET NULL,
    signer_public_key  BYTEA NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT manifests_root_length
        CHECK (octet_length(root) = 32),
    CONSTRAINT manifests_signature_length
        CHECK (octet_length(signature) = 64),
    CONSTRAINT manifests_signer_key_length
        CHECK (octet_length(signer_public_key) = 32),
    CONSTRAINT manifests_entry_count_positive
        CHECK (entry_count > 0),
    CONSTRAINT manifests_algo_known
        CHECK (algo = 'blake3-merkle-v1'),
    CONSTRAINT manifests_subject_is_object
        CHECK (jsonb_typeof(subject) = 'object'),
    CONSTRAINT manifests_signed_header_nonempty
        CHECK (octet_length(signed_header) > 0)
);

CREATE INDEX IF NOT EXISTS idx_manifests_signer_time
    ON manifests (signer_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_manifests_root
    ON manifests (root);

-- Answers "which manifests were taken over this root claim / this export kind?"
CREATE INDEX IF NOT EXISTS idx_manifests_subject
    ON manifests USING GIN (subject jsonb_path_ops);

COMMENT ON TABLE manifests IS
    'Signed Merkle commitment over a set of graph rows (backlog 6e2364b8). Each '
    'leaf covers only the write-once subset of its row, so the root survives '
    'label patches, supersession, theme reassignment and belief recomputes.';

COMMENT ON COLUMN manifests.root IS
    'BLAKE3 Merkle root, RFC-6962 shape: leaf = BLAKE3(0x00||preimage), '
    'node = BLAKE3(0x01||left||right), split at the largest power of two < n.';

COMMENT ON COLUMN manifests.signed_header IS
    'The EXACT canonical-JSON bytes that were Ed25519-signed: {algo, manifest_id, '
    'root, entry_count, created_at, signer_agent_id, signer_did, subject}. Stored '
    'verbatim so verification never depends on re-deriving the serialization. '
    'verify_manifest MUST cross-check the parsed header against the id / root / '
    'entry_count / created_at / signer_id columns before reporting the signature '
    'valid — otherwise a rewritten column could ride on a valid signature over '
    'different bytes.';

COMMENT ON COLUMN manifests.signer_public_key IS
    'Ed25519 public key snapshotted at signing time; this — not agents.public_key '
    '— is the verification authority, so a later key rotation cannot silently '
    'invalidate historical manifests. signer_id is ON DELETE SET NULL (lineage '
    'only): RESTRICT would break AgentRepository::delete.';

COMMENT ON COLUMN manifests.subject IS
    'What this manifest is ABOUT, e.g. {"kind":"provenance_export",'
    '"root_claim_id":"<uuid>","max_depth":10}. Inside the signed header, so a '
    'narrow export cannot be re-labelled as a broad one.';

CREATE TABLE IF NOT EXISTS manifest_entries (
    manifest_id  UUID NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
    position     INTEGER NOT NULL,
    row_kind     TEXT NOT NULL,
    row_id       UUID NOT NULL,
    leaf_hash    BYTEA NOT NULL,

    PRIMARY KEY (manifest_id, position),
    CONSTRAINT manifest_entries_leaf_length
        CHECK (octet_length(leaf_hash) = 32),
    CONSTRAINT manifest_entries_kind_known
        CHECK (row_kind IN ('claim', 'edge')),
    CONSTRAINT manifest_entries_position_nonneg
        CHECK (position >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_manifest_entries_row
    ON manifest_entries (manifest_id, row_kind, row_id);

-- Answers "which manifests commit to this claim / this edge?"
CREATE INDEX IF NOT EXISTS idx_manifest_entries_row
    ON manifest_entries (row_kind, row_id);

COMMENT ON TABLE manifest_entries IS
    'One Merkle leaf per committed row, in canonical order (kind tag, then row '
    'id bytes) so the same set always folds to the same root regardless of the '
    'order the exporter enumerated it in.';

COMMENT ON COLUMN manifest_entries.row_id IS
    'DELIBERATELY NOT A FOREIGN KEY. (1) It is polymorphic across claims and '
    'edges, so one FK is impossible. (2) Decisive: an ON DELETE CASCADE from '
    'claims would erase this row when the claim is deleted, destroying the '
    'evidence of the very omission the manifest exists to detect. A dangling '
    'row_id MUST survive so verify_manifest can report the entry as `missing`.';

COMMENT ON COLUMN manifest_entries.leaf_hash IS
    'BLAKE3(0x00 || b"epigraph.manifest.v1" || kind_tag || row_id(16) || '
    'created_at_micros_be(8) || payload), payload = content_hash(32)||agent_id(16) '
    'for claims, BLAKE3(relationship)(32) for edges. Fixed width per kind, so no '
    'length prefixes and no cross-field ambiguity.';
