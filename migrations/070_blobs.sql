-- Migration 070: content-addressed blob storage for the EpiGraph kernel.
--
-- EVIDENCE
-- The kernel has no place to put raw bytes. episcience carries a working
-- content-addressed blob store (migrations/5005_create_blobs.sql,
-- episcience-db/src/repos/blob.rs) whose only kernel-hostile piece is its
-- `sample_id` FK — a domain concept the kernel does not have. Instrument files,
-- gel images and raw measurement data are evidence for claims and belong in
-- the kernel next to the claims that cite them.
--
-- DECISION
-- Bytes live on the filesystem at
--     EPIGRAPH_BLOB_DIR/{hex[0:2]}/{hex[2:4]}/{hex}.blob
-- keyed by the BLAKE3-256 digest of the content (epigraph_crypto::ContentHasher).
-- This table holds only the metadata row. Duplicate uploads of identical bytes
-- reuse the same file.
--
-- SUBJECT BINDING -- there is deliberately NO subject column here: no claim_id,
-- no polymorphic (subject_type, subject_id). Per
-- docs/architecture/noun-claims-and-verb-edges.md a blob is a NOUN (its identity
-- IS its content hash) and "claim C was derived from blob B" is a RELATIONSHIP,
-- which belongs in `edges`. A nullable claim_id would also impose 0..1 where the
-- real cardinality is many-to-many, and a (subject_type, subject_id) pair would
-- be a second, drifting copy of exactly what `edges` + `validate_edge_reference`
-- already implement -- the defect migration 054 was written to kill.
--
-- The single entity_types row at the bottom of this file is what makes
-- edges.{source,target}_type = 'blob' insertable:
--   * migration 055 replaced the static edges_entity_types_valid CHECK with
--     FKs to entity_types(type_name), so the row satisfies the FK; and
--   * validate_edge_reference's registry-driven ELSE arm existence-checks
--     'blob' against public.blobs dynamically.
-- No CHECK rewrite, no plpgsql rewrite, no Rust change in routes/edges.rs.
--
-- NUMBERING -- 060..069 are intentionally skipped to avoid colliding with a
-- concurrently-developed branch that is also adding migrations. The next public
-- migration after this one is 071+.

CREATE TABLE IF NOT EXISTS blobs (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    filename     text NOT NULL,
    mime_type    varchar(255) NOT NULL,
    size_bytes   bigint NOT NULL,
    content_hash bytea NOT NULL,
    uploader_id  uuid NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    labels       text[] NOT NULL DEFAULT '{}',
    properties   jsonb NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT blobs_content_hash_length CHECK (octet_length(content_hash) = 32),
    CONSTRAINT blobs_size_positive       CHECK (size_bytes > 0),
    CONSTRAINT blobs_filename_not_empty  CHECK (length(trim(filename)) > 0),
    -- filename is echoed into a Content-Disposition response header and must
    -- never carry a quote, backslash, path separator, or control character.
    -- (Also enforced in Rust -- epigraph_core::blob::sanitize_filename -- so
    -- the rule survives a session with standard_conforming_strings=off.)
    CONSTRAINT blobs_filename_safe       CHECK (filename !~ '[[:cntrl:]"\\/]')
);

COMMENT ON TABLE blobs IS
    'Metadata for content-addressed blobs. Bytes live on the filesystem at '
    'EPIGRAPH_BLOB_DIR/{hex[0:2]}/{hex[2:4]}/{hex}.blob. Subject association is '
    'an edges row (claim -[derived_from]-> blob), never a column here. '
    'Multi-replica deployments MUST mount a shared volume: a replica with a '
    'different EPIGRAPH_BLOB_DIR cannot read rows another replica wrote.';

-- Canonical key, mirroring the claims (content_hash, agent_id) invariant from
-- docs/architecture/noun-claims-and-verb-edges.md: one row per (content,
-- uploader). Re-uploading identical bytes returns the existing row
-- (was_created = false); a DIFFERENT uploader gets their own row over the SAME
-- on-disk file -- provenance preserved, storage deduplicated.
CREATE UNIQUE INDEX IF NOT EXISTS uq_blobs_content_hash_uploader
    ON blobs (content_hash, uploader_id);

-- No separate content_hash index: the unique index above has content_hash as
-- its leading column and already serves `WHERE content_hash = $1`.
CREATE INDEX IF NOT EXISTS idx_blobs_uploader ON blobs (uploader_id);
CREATE INDEX IF NOT EXISTS idx_blobs_labels   ON blobs USING GIN (labels);
CREATE INDEX IF NOT EXISTS idx_blobs_created  ON blobs (created_at DESC);

-- Standard for every edge-addressable entity table (migrations 001, 023, 024):
-- deleting the row removes its edges instead of leaving them dangling. No
-- delete path ships with this migration; the trigger is installed so a future
-- one is correct by construction.
DROP TRIGGER IF EXISTS blobs_cascade_edges ON blobs;
CREATE TRIGGER blobs_cascade_edges
    BEFORE DELETE ON blobs
    FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('blob');

-- Register 'blob' as a CORE (API-immutable, hijack-guarded) entity type.
-- is_optional = false: the kernel owns `blobs`, so an absent table must fail
-- loud rather than silently resolve to "does not exist".
INSERT INTO entity_types
    (type_name, schema_name, table_name, id_column, is_optional, is_core)
VALUES
    ('blob', 'public', 'blobs', 'id', false, true)
ON CONFLICT (type_name) DO NOTHING;
