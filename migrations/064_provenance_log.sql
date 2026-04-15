-- Immutable provenance audit log with PROV-O mapping.
--
-- Evidence: docs/superpowers/specs/2026-03-20-oauth2-authz-design.md §6

CREATE OR REPLACE FUNCTION raise_immutable_error() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'provenance_log is append-only: UPDATE and DELETE are prohibited';
END;
$$ LANGUAGE plpgsql;

CREATE TABLE provenance_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    record_type VARCHAR(50) NOT NULL,
    record_id UUID NOT NULL,
    action VARCHAR(20) NOT NULL,
    submitted_by UUID NOT NULL REFERENCES oauth_clients(id),
    principal_id UUID NOT NULL REFERENCES oauth_clients(id),
    authorization_chain UUID[] NOT NULL,
    authorization_type VARCHAR(30) NOT NULL CHECK (authorization_type IN (
        'auto_policy', 'mod_approved', 'council_approved', 'escalated'
    )),
    content_hash BYTEA NOT NULL,
    provenance_sig BYTEA NOT NULL,
    token_jti UUID NOT NULL,
    scopes_used TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER provenance_log_immutable
    BEFORE UPDATE OR DELETE ON provenance_log
    FOR EACH ROW EXECUTE FUNCTION raise_immutable_error();

CREATE INDEX idx_provenance_log_record ON provenance_log(record_type, record_id);
CREATE INDEX idx_provenance_log_submitted_by ON provenance_log(submitted_by);
CREATE INDEX idx_provenance_log_principal ON provenance_log(principal_id);
CREATE INDEX idx_provenance_log_created ON provenance_log(created_at);

-- Add FK from authorization_votes to provenance_log
ALTER TABLE authorization_votes
    ADD CONSTRAINT fk_authorization_votes_provenance
    FOREIGN KEY (provenance_log_id) REFERENCES provenance_log(id);
