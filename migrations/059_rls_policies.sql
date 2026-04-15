-- Row-Level Security policies for privacy tier enforcement
--
-- Evidence: Design spec §2 — RLS policies
-- Reasoning: Defense-in-depth — even raw SQL queries respect privacy tiers
--
-- SAFE DEFAULT: When app.group_id is NOT set (empty string), the policies
-- treat the session as a public viewer — all rows are visible EXCEPT
-- fully_private ones.

CREATE OR REPLACE FUNCTION epigraph_current_group_id() RETURNS uuid AS $$
DECLARE
    raw text;
BEGIN
    raw := current_setting('app.group_id', true);
    IF raw IS NULL OR raw = '' THEN
        RETURN NULL;
    END IF;
    RETURN raw::uuid;
EXCEPTION WHEN invalid_text_representation THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

ALTER TABLE claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE edges ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION epigraph_is_visible_to_group(
    p_entity_id uuid,
    p_table text
) RETURNS boolean AS $$
DECLARE
    gid uuid := epigraph_current_group_id();
    found boolean;
BEGIN
    IF p_table = 'claim' THEN
        SELECT EXISTS(
            SELECT 1 FROM claim_encryption ce
            WHERE ce.claim_id = p_entity_id
              AND ce.privacy_tier = 'fully_private'
              AND (gid IS NULL OR ce.group_id != gid)
        ) INTO found;
    ELSIF p_table = 'evidence' THEN
        SELECT EXISTS(
            SELECT 1 FROM evidence_encryption ee
            WHERE ee.evidence_id = p_entity_id
              AND ee.privacy_tier = 'fully_private'
              AND (gid IS NULL OR ee.group_id != gid)
        ) INTO found;
    ELSE
        found := false;
    END IF;
    RETURN NOT found;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE POLICY claims_privacy ON claims
  FOR ALL
  USING (epigraph_is_visible_to_group(claims.id, 'claim'));

CREATE POLICY evidence_privacy ON evidence
  FOR ALL
  USING (epigraph_is_visible_to_group(evidence.id, 'evidence'));

CREATE POLICY edges_privacy ON edges
  FOR ALL
  USING (
    epigraph_is_visible_to_group(edges.source_id, 'claim')
    AND epigraph_is_visible_to_group(edges.source_id, 'evidence')
    AND epigraph_is_visible_to_group(edges.target_id, 'claim')
    AND epigraph_is_visible_to_group(edges.target_id, 'evidence')
  );
