-- Six claims in two disjoint epistemic cliques, plus one governance edge
-- between the cliques that clustering must ignore.
--
-- Runs on a database migrated to head. The caller gives it a fresh one
-- (`#[sqlx::test]`), which is why the ids are fixed and nothing is cleaned up.
--
-- Tenancy (migrations 062-074):
--   claims  declare (visibility, owner_group_id) themselves. Migration 074's
--           `claims_require_tenancy` refuses an undeclared claim (23502)
--           unless the connection is a member of `epigraph_seed`;
--           ('public', seed group) is what that escape hatch would stamp.
--   edges   name no tenancy column. The BEFORE ROW trigger `edges_tenancy`
--           derives both from the endpoints, as it does for
--           `EdgeRepository::create`. Do NOT disable user triggers on `edges`
--           to seed: with that trigger off `owner_group_id` stays NULL and
--           the insert fails its NOT NULL (backlog bd439a7f).

INSERT INTO agents (id, public_key, display_name, agent_type)
VALUES (
  '00000000-0000-0000-0000-0000000000aa',
  decode(repeat('00', 32), 'hex'),
  'cluster-graph-test-agent',
  'system'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO claims (id, content, content_hash, agent_id, pignistic_prob, visibility, owner_group_id)
VALUES
  ('00000000-0000-0000-0000-000000000001', 'a1', decode(repeat('01', 32), 'hex'), '00000000-0000-0000-0000-0000000000aa', 0.7, 'public', '00000000-0000-0000-0000-00000000dead'),
  ('00000000-0000-0000-0000-000000000002', 'a2', decode(repeat('02', 32), 'hex'), '00000000-0000-0000-0000-0000000000aa', 0.7, 'public', '00000000-0000-0000-0000-00000000dead'),
  ('00000000-0000-0000-0000-000000000003', 'a3', decode(repeat('03', 32), 'hex'), '00000000-0000-0000-0000-0000000000aa', 0.7, 'public', '00000000-0000-0000-0000-00000000dead'),
  ('00000000-0000-0000-0000-000000000004', 'b1', decode(repeat('04', 32), 'hex'), '00000000-0000-0000-0000-0000000000aa', 0.3, 'public', '00000000-0000-0000-0000-00000000dead'),
  ('00000000-0000-0000-0000-000000000005', 'b2', decode(repeat('05', 32), 'hex'), '00000000-0000-0000-0000-0000000000aa', 0.3, 'public', '00000000-0000-0000-0000-00000000dead'),
  ('00000000-0000-0000-0000-000000000006', 'b3', decode(repeat('06', 32), 'hex'), '00000000-0000-0000-0000-0000000000aa', 0.3, 'public', '00000000-0000-0000-0000-00000000dead');

INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) VALUES
  ('00000000-0000-0000-0000-000000000001', 'claim', '00000000-0000-0000-0000-000000000002', 'claim', 'SUPPORTS'),
  ('00000000-0000-0000-0000-000000000001', 'claim', '00000000-0000-0000-0000-000000000003', 'claim', 'SUPPORTS'),
  ('00000000-0000-0000-0000-000000000002', 'claim', '00000000-0000-0000-0000-000000000003', 'claim', 'SUPPORTS'),
  ('00000000-0000-0000-0000-000000000004', 'claim', '00000000-0000-0000-0000-000000000005', 'claim', 'CONTRADICTS'),
  ('00000000-0000-0000-0000-000000000004', 'claim', '00000000-0000-0000-0000-000000000006', 'claim', 'SUPPORTS'),
  ('00000000-0000-0000-0000-000000000005', 'claim', '00000000-0000-0000-0000-000000000006', 'claim', 'SUPPORTS'),
  -- a governance edge that must be excluded:
  ('00000000-0000-0000-0000-000000000001', 'claim', '00000000-0000-0000-0000-000000000004', 'claim', 'OCCUPIES');
