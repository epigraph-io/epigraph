-- 042_alternative_of_edge_type.sql
--
-- Symmetric uniqueness for alternative_of edges (the application-level
-- allow-list in routes/edges.rs admits the relationship; here we enforce
-- the symmetry contract at the schema level).
--
-- Plus a view materializing the transitive-closure equivalence class. CDST
-- BP reads this view to group supporters of a target into alternative
-- sets before max-Pl combining (see crates/epigraph-engine/src/cdst_bp.rs).

CREATE UNIQUE INDEX IF NOT EXISTS edges_alternative_of_symmetric_uniq
  ON edges (LEAST(source_id, target_id), GREATEST(source_id, target_id))
  WHERE relationship = 'alternative_of';

CREATE OR REPLACE VIEW alternative_set AS
WITH RECURSIVE pairs AS (
  SELECT source_id AS a, target_id AS b
    FROM edges WHERE relationship = 'alternative_of'
  UNION
  SELECT target_id, source_id
    FROM edges WHERE relationship = 'alternative_of'
), closure AS (
  SELECT a, b FROM pairs
  UNION
  SELECT c.a, p.b FROM closure c JOIN pairs p ON c.b = p.a
)
SELECT a AS claim_id,
       array_agg(DISTINCT b ORDER BY b) AS alt_members
  FROM closure
 GROUP BY a;

COMMENT ON VIEW alternative_set IS
'Equivalence class under the symmetric closure of alternative_of. Each row '
'maps a claim_id to the sorted list of claims it is mutually-exclusive with '
'(itself excluded). Drives max-Pl combine in CDST BP.';
