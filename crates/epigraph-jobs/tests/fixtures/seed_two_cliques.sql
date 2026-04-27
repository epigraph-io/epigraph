-- Six claims in two disjoint epistemic cliques.
-- Assumes 001 + 002 migrations are applied.
--
-- Schema reality (verified against migrations/001_initial_schema.sql, 2026-04-27):
--   claims  NOT NULL: id, content, content_hash (32 bytes), agent_id
--   agents  NOT NULL: id, public_key (32 bytes)
--   edges   NOT NULL: source_id, target_id, source_type, target_type, relationship
-- The seed therefore creates a test agent first, then claims, then edges.

-- The validate_edge_reference trigger references tables (propaganda_techniques,
-- coalitions, agent_spans, entities, tasks, events, etc.) not created by
-- 001+002 alone. Disable user triggers on edges for this seed; the
-- integration test validates clustering logic, not FK trigger correctness.
ALTER TABLE edges DISABLE TRIGGER USER;

INSERT INTO agents (id, public_key, display_name, agent_type)
VALUES (
  '00000000-0000-0000-0000-0000000000aa',
  decode(repeat('00', 32), 'hex'),
  'cluster-graph-test-agent',
  'system'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO claims (id, content, content_hash, agent_id, pignistic_prob)
VALUES
  ('00000000-0000-0000-0000-000000000001', 'a1', decode(repeat('01', 32), 'hex'), '00000000-0000-0000-0000-0000000000aa', 0.7),
  ('00000000-0000-0000-0000-000000000002', 'a2', decode(repeat('02', 32), 'hex'), '00000000-0000-0000-0000-0000000000aa', 0.7),
  ('00000000-0000-0000-0000-000000000003', 'a3', decode(repeat('03', 32), 'hex'), '00000000-0000-0000-0000-0000000000aa', 0.7),
  ('00000000-0000-0000-0000-000000000004', 'b1', decode(repeat('04', 32), 'hex'), '00000000-0000-0000-0000-0000000000aa', 0.3),
  ('00000000-0000-0000-0000-000000000005', 'b2', decode(repeat('05', 32), 'hex'), '00000000-0000-0000-0000-0000000000aa', 0.3),
  ('00000000-0000-0000-0000-000000000006', 'b3', decode(repeat('06', 32), 'hex'), '00000000-0000-0000-0000-0000000000aa', 0.3);

INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) VALUES
  ('00000000-0000-0000-0000-000000000001', 'claim', '00000000-0000-0000-0000-000000000002', 'claim', 'SUPPORTS'),
  ('00000000-0000-0000-0000-000000000001', 'claim', '00000000-0000-0000-0000-000000000003', 'claim', 'SUPPORTS'),
  ('00000000-0000-0000-0000-000000000002', 'claim', '00000000-0000-0000-0000-000000000003', 'claim', 'SUPPORTS'),
  ('00000000-0000-0000-0000-000000000004', 'claim', '00000000-0000-0000-0000-000000000005', 'claim', 'CONTRADICTS'),
  ('00000000-0000-0000-0000-000000000004', 'claim', '00000000-0000-0000-0000-000000000006', 'claim', 'SUPPORTS'),
  ('00000000-0000-0000-0000-000000000005', 'claim', '00000000-0000-0000-0000-000000000006', 'claim', 'SUPPORTS'),
  -- a governance edge that must be excluded:
  ('00000000-0000-0000-0000-000000000001', 'claim', '00000000-0000-0000-0000-000000000004', 'claim', 'OCCUPIES');
