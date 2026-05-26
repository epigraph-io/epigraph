ALTER TABLE claims ADD COLUMN last_match_scan_at TIMESTAMPTZ;
CREATE INDEX idx_claims_last_match_scan ON claims(last_match_scan_at)
    WHERE last_match_scan_at IS NOT NULL;
