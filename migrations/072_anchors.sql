-- Migration 072: external anchoring of sealed manifest roots
-- (backlog 94e62824).
--
-- NUMBERING -- 070_blobs.sql and 071_manifests.sql landed first on this same
-- branch, and 060..069 are deliberately left clear for a concurrently developed
-- sibling branch that is also adding migrations. 072 is the first free number
-- above both.
--
-- EVIDENCE
-- provenance_log is tamper-EVIDENT but self-hosted: whoever controls this
-- Postgres controls the log, and countersignatures live in the same database.
-- `anchors` records a commitment to a Merkle root held by a party OTHER than
-- the operator, so a later verifier can detect after-the-fact edits without
-- trusting us.
--
-- What is anchored is a MANIFEST root (migration 071), not a raw provenance_log
-- row: the manifest root is already a redactable Merkle commitment over row
-- digests that survives label churn, it has natural boundaries (one export
-- run), and anchoring it transitively anchors every row it commits to.
-- Anchoring provenance_log rows directly would require inventing a windowing
-- scheme with no natural edges, and would re-anchor on every write.
--
-- (root_type, root_id) is POLYMORPHIC and carries NO foreign key, matching
-- provenance_log's (record_type, record_id). That keeps this migration
-- independent of the manifest table's ordering and reserves
-- root_type = 'checkpoint' for a future tree over many manifest roots.
--
-- commitment_bytes is the EXACT payload handed to the backend: deterministic
-- CBOR (RFC 8949 4.2.1), see crates/epigraph-interfaces/src/anchor.rs.
-- Verification re-decodes these bytes and never trusts root_hash on its own,
-- so an operator who edits root_hash alone is caught.

CREATE TABLE IF NOT EXISTS anchors (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    root_type           VARCHAR(32) NOT NULL,
    root_id             UUID        NOT NULL,
    root_hash           BYTEA       NOT NULL,
    commitment_version  SMALLINT    NOT NULL DEFAULT 1,
    commitment_hash     BYTEA       NOT NULL,
    commitment_bytes    BYTEA       NOT NULL,
    backend             VARCHAR(32) NOT NULL,
    network             VARCHAR(32) NOT NULL,
    status              VARCHAR(16) NOT NULL DEFAULT 'pending',
    tx_id               TEXT,
    block_height        BIGINT,
    block_time          TIMESTAMPTZ,
    sealed_at           TIMESTAMPTZ NOT NULL,
    submitted_at        TIMESTAMPTZ,
    confirmed_at        TIMESTAMPTZ,
    failure_reason      TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT anchors_status_valid
        CHECK (status IN ('pending', 'submitted', 'confirmed', 'failed')),
    CONSTRAINT anchors_root_hash_len
        CHECK (octet_length(root_hash) = 32),
    CONSTRAINT anchors_commitment_hash_len
        CHECK (octet_length(commitment_hash) = 32),
    CONSTRAINT anchors_commitment_not_empty
        CHECK (octet_length(commitment_bytes) > 0),
    CONSTRAINT anchors_confirmed_has_tx
        CHECK (status <> 'confirmed' OR (tx_id IS NOT NULL AND block_height IS NOT NULL))
);

-- One LIVE anchor per (root, backend, network). Failed attempts are excluded so
-- a retry after NotConfigured / a transport failure is allowed, while a
-- SUCCESSFUL anchor can never be silently duplicated -- two live commitments
-- would let an operator present whichever one suits them at verify time.
CREATE UNIQUE INDEX IF NOT EXISTS uq_anchors_live_root
    ON anchors (root_type, root_id, backend, network)
    WHERE status <> 'failed';

CREATE INDEX IF NOT EXISTS idx_anchors_root ON anchors (root_type, root_id);
CREATE INDEX IF NOT EXISTS idx_anchors_open ON anchors (status, created_at)
    WHERE status IN ('pending', 'submitted');
CREATE INDEX IF NOT EXISTS idx_anchors_tx ON anchors (backend, network, tx_id);

-- The mock "chain". Written ONLY by MockAnchorBackend, append-only, so that
-- verification reads the published commitment back from a store OTHER than the
-- anchors row it is checking. This proves the MECHANISM end to end.
-- It does NOT provide the trust property: it lives in the same Postgres, so the
-- operator remains in the trust base until a real backend is configured. Every
-- verification report says so in its `trust_basis` field.
CREATE TABLE IF NOT EXISTS anchor_mock_chain (
    tx_id           TEXT PRIMARY KEY,
    metadata_label  BIGINT      NOT NULL,
    metadata_cbor   BYTEA       NOT NULL,
    block_height    BIGINT      NOT NULL UNIQUE,
    block_time      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT anchor_mock_chain_metadata_not_empty
        CHECK (octet_length(metadata_cbor) > 0)
);

CREATE SEQUENCE IF NOT EXISTS anchor_mock_chain_height_seq AS BIGINT START 1;

-- Generic append-only guard. raise_immutable_error() (migration 001) is NOT
-- reused: its message is hardcoded to 'provenance_log'.
CREATE OR REPLACE FUNCTION public.raise_append_only_error() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: UPDATE and DELETE are prohibited', TG_TABLE_NAME;
END;
$$;

DROP TRIGGER IF EXISTS anchor_mock_chain_append_only ON anchor_mock_chain;
CREATE TRIGGER anchor_mock_chain_append_only
    BEFORE DELETE OR UPDATE ON anchor_mock_chain
    FOR EACH ROW EXECUTE FUNCTION public.raise_append_only_error();

-- `anchors` needs UPDATE for pending -> submitted -> confirmed, so the blanket
-- append-only trigger is wrong here. Guard exactly the commitment-bearing
-- columns instead: an operator must not be able to repoint an existing anchor
-- at a different root while keeping its transaction id.
CREATE OR REPLACE FUNCTION public.anchors_guard_commitment_columns() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.root_type          IS DISTINCT FROM OLD.root_type
    OR NEW.root_id            IS DISTINCT FROM OLD.root_id
    OR NEW.root_hash          IS DISTINCT FROM OLD.root_hash
    OR NEW.commitment_version IS DISTINCT FROM OLD.commitment_version
    OR NEW.commitment_hash    IS DISTINCT FROM OLD.commitment_hash
    OR NEW.commitment_bytes   IS DISTINCT FROM OLD.commitment_bytes
    OR NEW.backend            IS DISTINCT FROM OLD.backend
    OR NEW.network            IS DISTINCT FROM OLD.network
    OR NEW.sealed_at          IS DISTINCT FROM OLD.sealed_at
    OR NEW.created_at         IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'anchors: commitment columns are immutable (root_type, root_id, root_hash, commitment_version, commitment_hash, commitment_bytes, backend, network, sealed_at, created_at)';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS anchors_commitment_immutable ON anchors;
CREATE TRIGGER anchors_commitment_immutable
    BEFORE UPDATE ON anchors
    FOR EACH ROW EXECUTE FUNCTION public.anchors_guard_commitment_columns();

DROP TRIGGER IF EXISTS anchors_no_delete ON anchors;
CREATE TRIGGER anchors_no_delete
    BEFORE DELETE ON anchors
    FOR EACH ROW EXECUTE FUNCTION public.raise_append_only_error();

COMMENT ON TABLE anchors IS
    'Third-party commitments to Merkle roots (backlog 94e62824). One live row per (root_type, root_id, backend, network).';
COMMENT ON COLUMN anchors.commitment_bytes IS
    'Deterministic CBOR payload exactly as published. Verification re-decodes this; it never trusts root_hash alone.';
COMMENT ON COLUMN anchors.sealed_at IS
    'Seal time CLAIMED by the manifest. anchor_mock_chain.block_time (or the real chain block) is the PROVEN upper bound; sealed_at > block_time means a backdated seal.';
COMMENT ON TABLE anchor_mock_chain IS
    'MockAnchorBackend ledger. Append-only. Same Postgres as anchors, so it proves the mechanism, NOT the trust property.';
