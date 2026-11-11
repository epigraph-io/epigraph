-- A production-shaped legacy corpus for `backfill-ingest-markers` at scale
-- (tests/operator_backfill_ingest_markers_scale.rs). Every name and id is
-- invented: ids are md5-derived from fixed strings, so the test can name the
-- signers without reading them back.
--
-- The shape, at scale 1 (`SET fx.scale = '<s>'` before running scales every
-- count; papers are sampled across the full size distribution):
--
-- * 1,400 papers, each with 1 to 7 authors (`agent -authored-> paper`,
--   ~5,600 edges from ~4,640 agents; one HEAVY agent authored 49 mid-sized
--   papers and asserts every claim of them, ~18k agent assertions);
-- * `paper -asserts-> claim`: per paper 35 * (700 / rank)^0.9 capped at 6,780
--   (~135k edges, median ~35, p99 ~1.2k); every 67th claim of a paper is
--   shared with up to ~33 papers of its rank block (claims asserted by
--   papers of different principals, some by one heavy author);
-- * `agent -asserts-> claim` closing a legacy chain (an author of the paper
--   asserts 60% of its claims), ~2% of them workflow attributions, plus ~28k
--   agent assertions closing no chain (~345k agent assertions in all);
-- * signers by paper: 40% one ingest signer, 15% a second, 5% a third, 10% an
--   attestation identity, 30% unsigned; every 97th paper has a second
--   author signed by another ingest signer (a conflicting paper); ~3% of
--   edges retracted;
-- * claims filed by the paper's ingest signer carry its extraction trace of
--   the paper (provable creation records);
-- * ~750k unrelated edges (claim -> claim, trace -> claim, paper -> paper,
--   agent -> claim), ~1.25M edges in all.
--
-- The edge indexes are a production deployment's: the btree indexes on
-- (relationship), (source_type, relationship, target_type),
-- (source_id, target_id), (created_at) and the labels GIN index are dropped,
-- and a jsonb_path_ops GIN index on properties is added. Then ANALYZE, as
-- autovacuum would have left the tables.
--
-- Rows are written with triggers off (session_replication_role = replica),
-- with their tenancy columns filled in as the triggers would: public, the
-- world group. Every endpoint the backfill touches (authored, asserts) is a
-- real agents / papers / claims row, because the backfill's own UPDATEs and
-- record INSERTs run with the triggers on.

SET session_replication_role = replica;
SET synchronous_commit = off;

DROP INDEX IF EXISTS idx_edges_typed_relationship;
DROP INDEX IF EXISTS idx_edges_relationship;
DROP INDEX IF EXISTS idx_edges_source_target;
DROP INDEX IF EXISTS idx_edges_created_at;
DROP INDEX IF EXISTS idx_edges_labels;
CREATE INDEX IF NOT EXISTS idx_edges_properties_path ON edges USING gin (properties jsonb_path_ops);

CREATE TEMP TABLE fx_conf AS
SELECT s,
       (SELECT g.id FROM groups g WHERE g.kind = 'world' LIMIT 1) AS world,
       now() - interval '30 days' AS t0,
       greatest(2, round(6000 * s))::int AS n_agents,
       greatest(1, round(4640 * s))::int AS n_authors,
       greatest(1, round(1400 * s))::int AS n_papers
  FROM (SELECT COALESCE(NULLIF(current_setting('fx.scale', true), '')::numeric, 1) AS s) x;

-- Agents 0 .. n_agents (0 is the heavy author); signers 1..3 ingest,
-- 4 attestation, 5 a claim filer.
INSERT INTO agents (id, public_key, agent_type)
SELECT md5('bf-agent-' || i)::uuid,
       decode(md5('bf-pk-' || i) || md5('bf-pk2-' || i), 'hex'), 'human'
  FROM fx_conf, generate_series(0, n_agents) i;
INSERT INTO agents (id, public_key, agent_type, display_name)
SELECT md5('bf-signer-' || i)::uuid,
       decode(md5('bf-spk-' || i) || md5('bf-spk2-' || i), 'hex'), 'system',
       'scale-signer-' || i
  FROM generate_series(1, 5) i;

CREATE TEMP TABLE fx_paper AS
SELECT r, rr, md5('bf-paper-' || rr)::uuid AS id,
       least(6780, greatest(1, floor(35 * power(700.0 / rr, 0.9))))::int AS n,
       1 + (rr % 7) AS n_auth,
       CASE WHEN rr % 20 < 8 THEN 1 WHEN rr % 20 < 11 THEN 2 WHEN rr % 20 < 12 THEN 3
            WHEN rr % 20 < 14 THEN 4 ELSE 0 END AS signer,
       rr % 97 = 5 AS conflicted
  FROM fx_conf, generate_series(1, n_papers) r,
       LATERAL (SELECT ceil(r / s)::int AS rr) k;
INSERT INTO papers (id, doi, title)
SELECT id, '10.9999/scale-' || rr, 'Scale paper ' || rr FROM fx_paper;

CREATE TEMP TABLE fx_auth AS
SELECT p.rr, p.id AS paper, j,
       CASE WHEN p.rr BETWEEN 30 AND 78 AND j = 0 THEN 0
            ELSE 1 + ((p.rr * 7 + j * 1013) % c.n_authors) END AS a,
       CASE WHEN p.conflicted AND j = 1 AND p.signer IN (1, 3) THEN 2
            WHEN p.conflicted AND j = 1 AND p.signer = 2 THEN 1
            ELSE p.signer END AS sg
  FROM fx_conf c, fx_paper p, generate_series(0, p.n_auth - 1) j;

CREATE TEMP TABLE fx_pa AS
SELECT p.rr, p.id AS paper, i, p.signer,
       CASE WHEN i % 67 = 0
            THEN md5('bf-pop-' || (i / 67) || '-' || (p.rr % 3) || '-' || (p.rr / 100))::uuid
            ELSE md5('bf-claim-' || p.rr || '-' || i)::uuid END AS claim,
       i % 67 = 0 AS shared
  FROM fx_paper p, generate_series(1, p.n) i;

-- Claims: filed by the paper's ingest signer (else the filer), created
-- with the paper's assertion.
CREATE TEMP TABLE fx_claim AS
SELECT DISTINCT ON (x.claim) x.claim AS id, x.rr, x.shared,
       CASE WHEN x.signer BETWEEN 1 AND 3 THEN x.signer ELSE 5 END AS filer,
       c.t0 + x.rr * interval '1 minute' + x.i * interval '1 millisecond' AS at
  FROM fx_conf c, fx_pa x ORDER BY x.claim, x.rr, x.i;
ALTER TABLE fx_claim ADD COLUMN n bigserial;
INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current,
                    visibility, owner_group_id, created_at, updated_at)
SELECT f.id, 'scale claim ' || f.n, decode(md5('bf-ch-' || f.id) || md5('bf-ch2-' || f.id), 'hex'),
       0.5, md5('bf-signer-' || f.filer)::uuid, true, 'public', c.world, f.at, f.at
  FROM fx_conf c, fx_claim f;
-- The ingest's extraction trace, on the claims an ingest signer filed.
INSERT INTO reasoning_traces (id, claim_id, reasoning_type, explanation, created_at,
                              owner_group_id, visibility)
SELECT md5('bf-trace-' || f.id)::uuid, f.id, 'deductive',
       'Extracted from ''Scale paper ' || f.rr || ''' (DOI: 10.9999/scale-' || f.rr
         || '); level 3 (atom)',
       f.at + interval '2 seconds', c.world, 'public'
  FROM fx_conf c, fx_claim f WHERE f.filer <> 5 AND NOT f.shared;
UPDATE claims c SET trace_id = md5('bf-trace-' || c.id)::uuid
  FROM fx_claim f WHERE f.id = c.id AND f.filer <> 5 AND NOT f.shared;

-- authored
INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties,
                   created_at, valid_to, signature, signer_id, content_hash,
                   owner_group_id, visibility)
SELECT md5('bf-agent-' || a.a)::uuid, 'agent', a.paper, 'paper', 'authored',
       jsonb_build_object('position', a.j, 'role', 'author'),
       ts, CASE WHEN (a.rr + a.j) % 33 = 0 THEN ts + interval '1 hour' END,
       CASE WHEN a.sg > 0 THEN decode(repeat(md5('bf-sig-' || a.sg), 4), 'hex') END,
       CASE WHEN a.sg > 0 THEN md5('bf-signer-' || a.sg)::uuid END,
       CASE WHEN a.sg > 0 THEN decode(md5('bf-h-' || a.rr) || md5('bf-h2-' || a.j), 'hex') END,
       c.world, 'public'
  FROM fx_conf c, fx_auth a,
       LATERAL (SELECT c.t0 + a.rr * interval '1 minute' + a.j * interval '1 millisecond' AS ts) t;

-- paper asserts
INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties,
                   created_at, valid_to, signature, signer_id, content_hash,
                   owner_group_id, visibility)
SELECT x.paper, 'paper', x.claim, 'claim', 'asserts', '{}'::jsonb,
       ts, CASE WHEN (x.rr + x.i) % 33 = 0 THEN ts + interval '1 hour' END,
       CASE WHEN x.signer > 0 THEN decode(repeat(md5('bf-sig-' || x.signer), 4), 'hex') END,
       CASE WHEN x.signer > 0 THEN md5('bf-signer-' || x.signer)::uuid END,
       CASE WHEN x.signer > 0 THEN decode(md5('bf-h-' || x.rr) || md5('bf-h3-' || x.i), 'hex') END,
       c.world, 'public'
  FROM fx_conf c, fx_pa x,
       LATERAL (SELECT c.t0 + x.rr * interval '1 minute' + interval '10 seconds'
                       + x.i * interval '1 millisecond' AS ts) t;

-- agent asserts closing a chain: one per (agent, claim), through the
-- agent's first paper asserting it.
INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties,
                   created_at, valid_to, signature, signer_id, content_hash,
                   owner_group_id, visibility)
SELECT md5('bf-agent-' || y.a)::uuid, 'agent', y.claim, 'claim', 'asserts',
       CASE WHEN (y.rr + y.i + y.j) % 50 = 0
            THEN '{"source": "workflow_attribution", "role": "author"}'::jsonb
            ELSE '{}'::jsonb END,
       ts, CASE WHEN (y.rr + y.i + y.j) % 31 = 0 THEN ts + interval '1 hour' END,
       CASE WHEN y.signer > 0 THEN decode(repeat(md5('bf-sig-' || y.signer), 4), 'hex') END,
       CASE WHEN y.signer > 0 THEN md5('bf-signer-' || y.signer)::uuid END,
       CASE WHEN y.signer > 0 THEN decode(md5('bf-h4-' || y.a) || md5('bf-h5-' || y.claim), 'hex') END,
       c.world, 'public'
  FROM fx_conf c,
       (SELECT DISTINCT ON (a.a, x.claim) a.a, x.claim, x.rr, x.i, a.j, x.signer
          FROM fx_pa x JOIN fx_auth a ON a.rr = x.rr
         WHERE a.a = 0 OR (x.rr * 13 + x.i * 7 + a.j * 3) % 10 < 6
         ORDER BY a.a, x.claim, x.rr, x.i) y,
       LATERAL (SELECT c.t0 + y.rr * interval '1 minute' + interval '20 seconds'
                       + y.i * interval '1 millisecond' + y.j * interval '1 microsecond' AS ts) t;

-- agent asserts closing no chain
INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties,
                   created_at, owner_group_id, visibility)
SELECT md5('bf-agent-' || (1 + (k * 37) % c.n_agents))::uuid, 'agent', f.id, 'claim', 'asserts',
       '{}'::jsonb, c.t0 + k * interval '10 milliseconds', c.world, 'public'
  FROM fx_conf c CROSS JOIN LATERAL generate_series(1, round(28000 * c.s)::int) k
  JOIN fx_claim f ON f.n = 1 + (k * 7919) % (SELECT count(*) FROM fx_claim);

-- unrelated edges
INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties,
                   created_at, owner_group_id, visibility)
SELECT s.id, 'claim', t.id, 'claim',
       CASE WHEN k % 10 < 7 THEN 'supports' ELSE 'derived_from' END,
       CASE WHEN k % 5 = 0 THEN jsonb_build_object('weight', (k % 100) / 100.0) ELSE '{}'::jsonb END,
       c.t0 + k * interval '1 millisecond', c.world, 'public'
  FROM fx_conf c CROSS JOIN LATERAL generate_series(1, round(600000 * c.s)::int) k
  JOIN fx_claim s ON s.n = 1 + (k * 7) % (SELECT count(*) FROM fx_claim)
  JOIN fx_claim t ON t.n = 1 + (k * 13 + 5) % (SELECT count(*) FROM fx_claim)
 WHERE s.id <> t.id;
INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties,
                   created_at, owner_group_id, visibility)
SELECT md5('bf-other-trace-' || k)::uuid, 'trace', f.id, 'claim', 'explains', '{}'::jsonb,
       c.t0 + k * interval '1 millisecond', c.world, 'public'
  FROM fx_conf c CROSS JOIN LATERAL generate_series(1, round(100000 * c.s)::int) k
  JOIN fx_claim f ON f.n = 1 + (k * 11) % (SELECT count(*) FROM fx_claim);
INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties,
                   created_at, owner_group_id, visibility)
SELECT md5('bf-agent-' || (1 + (k * 53) % c.n_agents))::uuid, 'agent', f.id, 'claim', 'endorses',
       '{}'::jsonb, c.t0 + k * interval '1 millisecond', c.world, 'public'
  FROM fx_conf c CROSS JOIN LATERAL generate_series(1, round(50000 * c.s)::int) k
  JOIN fx_claim f ON f.n = 1 + (k * 17) % (SELECT count(*) FROM fx_claim);
INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties,
                   created_at, owner_group_id, visibility)
SELECT p.id, 'paper', q.id, 'paper', 'cites', '{}'::jsonb,
       c.t0 + k * interval '1 millisecond', c.world, 'public'
  FROM fx_conf c CROSS JOIN LATERAL generate_series(1, round(1900 * c.s)::int) k
  JOIN fx_paper p ON p.r = 1 + (k * 3) % c.n_papers
  JOIN fx_paper q ON q.r = 1 + (k * 5 + 1) % c.n_papers
 WHERE p.id <> q.id;

RESET session_replication_role;
RESET synchronous_commit;
DROP TABLE fx_conf, fx_paper, fx_auth, fx_pa, fx_claim;
ANALYZE agents;
ANALYZE papers;
ANALYZE claims;
ANALYZE reasoning_traces;
ANALYZE edges;
