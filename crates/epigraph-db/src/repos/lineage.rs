//! Lineage repository for recursive CTE-based claim provenance queries
//!
//! This module provides efficient traversal of claim lineage using PostgreSQL
//! recursive CTEs. It returns claims, evidence, and reasoning traces in
//! topological order (ancestors before descendants).
//!
//! # Evidence
//! - IMPLEMENTATION_PLAN.md specifies claim provenance tracking
//! - Recursive CTE pattern required for arbitrary depth traversal
//!
//! # Reasoning
//! - PostgreSQL WITH RECURSIVE provides efficient graph traversal
//! - Topological order ensures ancestors always precede descendants
//! - Diamond dependencies require proper deduplication via DISTINCT ON

use crate::errors::DbError;
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::instrument;
use uuid::Uuid;

// ============================================================================
// Public Data Structures
// ============================================================================

/// Result of a Lowest Common Ancestor query
#[derive(Debug, Clone)]
pub struct LcaResult {
    pub ancestor_id: Uuid,
    pub depth_from_a: i32,
    pub depth_from_b: i32,
    pub total_depth: i32,
}

/// Represents a node in the lineage result
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LineageNode {
    pub claim_id: Uuid,
    pub depth: i32,
    pub path: Vec<Uuid>,
}

/// Full lineage result including claims, evidence, and traces
#[derive(Debug, Clone, Default)]
pub struct LineageResult {
    /// Claims in the lineage, keyed by claim_id
    pub claims: HashMap<Uuid, LineageClaim>,
    /// Evidence items, keyed by evidence_id
    pub evidence: HashMap<Uuid, LineageEvidence>,
    /// Reasoning traces, keyed by trace_id
    pub traces: HashMap<Uuid, LineageTrace>,
    /// Nodes in topological order (ancestors first)
    pub topological_order: Vec<Uuid>,
    /// Whether a cycle was detected
    pub cycle_detected: bool,
    /// Maximum depth reached
    pub max_depth_reached: i32,
}

/// Claim data in lineage result
#[derive(Debug, Clone)]
pub struct LineageClaim {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub depth: i32,
    pub parent_ids: Vec<Uuid>,
    pub evidence_ids: Vec<Uuid>,
    pub trace_id: Option<Uuid>,
}

/// Evidence data in lineage result
#[derive(Debug, Clone)]
pub struct LineageEvidence {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub evidence_type: String,
    pub content_hash: Vec<u8>,
}

/// Trace data in lineage result
#[derive(Debug, Clone)]
pub struct LineageTrace {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub reasoning_type: String,
    pub confidence: f64,
    pub parent_trace_ids: Vec<Uuid>,
}

// ============================================================================
// Row types for database queries (internal)
// ============================================================================

/// Row returned from lineage CTE query
#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)] // Fields populated by sqlx::FromRow, used via struct destructuring
struct LineageRow {
    id: Uuid,
    content: String,
    truth_value: f64,
    trace_id: Option<Uuid>,
    depth: i32,
    path: Vec<Uuid>,
    cycle_detected: bool,
}

/// Row for edge queries
#[derive(Debug, Clone, sqlx::FromRow)]
struct EdgeQueryRow {
    source_id: Uuid,
    target_id: Uuid,
}

/// Row for evidence queries
#[derive(Debug, Clone, sqlx::FromRow)]
struct EvidenceQueryRow {
    id: Uuid,
    claim_id: Uuid,
    evidence_type: String,
    content_hash: Vec<u8>,
}

/// Row for trace queries
#[derive(Debug, Clone, sqlx::FromRow)]
struct TraceQueryRow {
    id: Uuid,
    claim_id: Uuid,
    reasoning_type: String,
    confidence: f64,
}

/// Row for trace parent queries
#[derive(Debug, Clone, sqlx::FromRow)]
struct TraceParentRow {
    trace_id: Uuid,
    parent_id: Uuid,
}

// ============================================================================
// Repository Implementation
// ============================================================================

/// Repository for claim lineage queries using recursive CTEs
///
/// This repository provides efficient graph traversal for claim provenance,
/// returning all ancestors, evidence, and reasoning traces in topological order.
///
/// # Example
///
/// ```rust,no_run
/// use epigraph_db::{LineageRepository, create_pool};
/// use uuid::Uuid;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let pool = create_pool("postgres://...").await?;
///     let claim_id = Uuid::new_v4();
///
///     // Get lineage with max depth of 10
///     let lineage = LineageRepository::get_lineage(&pool, claim_id, Some(10)).await?;
///
///     // Process claims in topological order (ancestors first)
///     for claim_id in &lineage.topological_order {
///         let claim = lineage.claims.get(claim_id).unwrap();
///         println!("Claim at depth {}: {}", claim.depth, claim.content);
///     }
///
///     Ok(())
/// }
/// ```
pub struct LineageRepository;

impl LineageRepository {
    /// Query lineage for a claim using recursive CTE
    ///
    /// Returns all ancestor claims, their evidence, and reasoning traces
    /// in topological order (ancestors before descendants).
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `claim_id` - The claim to trace lineage from
    /// * `max_depth` - Maximum depth to traverse (None for default of 100)
    ///
    /// # Returns
    /// * `LineageResult` containing all claims, evidence, and traces in the lineage
    ///
    /// # SQL Pattern
    /// Uses PostgreSQL recursive CTE with cycle detection and deduplication:
    /// ```sql
    /// WITH RECURSIVE lineage AS (
    ///     SELECT id, 0 as depth, ARRAY[id] as path
    ///     FROM claims WHERE id = $1
    ///     UNION ALL
    ///     SELECT c.id, l.depth + 1, l.path || c.id
    ///     FROM claims c
    ///     JOIN edges e ON e.source_id = c.id AND e.source_type = 'claim'
    ///     JOIN lineage l ON e.target_id = l.id AND e.target_type = 'claim'
    ///     WHERE l.depth < $2 AND NOT c.id = ANY(l.path)
    /// )
    /// SELECT DISTINCT ON (id) * FROM lineage ORDER BY id, depth;
    /// ```
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database query fails.
    #[instrument(skip(pool))]
    pub async fn get_lineage(
        pool: &PgPool,
        claim_id: Uuid,
        max_depth: Option<i32>,
    ) -> Result<LineageResult, DbError> {
        let max_depth = max_depth.unwrap_or(100);

        // Query claim lineage with recursive CTE
        let lineage_rows: Vec<LineageRow> = sqlx::query_as(
            r#"
            WITH RECURSIVE lineage AS (
                -- Base case: start with the target claim
                SELECT
                    c.id,
                    c.content,
                    c.truth_value,
                    c.trace_id,
                    0 as depth,
                    ARRAY[c.id] as path,
                    false as cycle_detected
                FROM claims c
                WHERE c.id = $1

                UNION ALL

                -- Recursive case: find parent claims via edges
                SELECT
                    c.id,
                    c.content,
                    c.truth_value,
                    c.trace_id,
                    l.depth + 1,
                    l.path || c.id,
                    c.id = ANY(l.path) as cycle_detected
                FROM claims c
                JOIN edges e ON e.source_id = c.id AND e.source_type = 'claim'
                JOIN lineage l ON e.target_id = l.id AND e.target_type = 'claim'
                WHERE l.depth < $2
                  AND NOT c.id = ANY(l.path)
            )
            SELECT DISTINCT ON (id)
                id,
                content,
                truth_value,
                trace_id,
                depth,
                path,
                cycle_detected
            FROM lineage
            ORDER BY id, depth
            "#,
        )
        .bind(claim_id)
        .bind(max_depth)
        .fetch_all(pool)
        .await?;

        // Check for cycles
        let cycle_detected = lineage_rows.iter().any(|r| r.cycle_detected);
        let max_depth_reached = lineage_rows.iter().map(|r| r.depth).max().unwrap_or(0);

        // Collect claim IDs for subsequent queries
        let claim_ids: Vec<Uuid> = lineage_rows.iter().map(|r| r.id).collect();

        if claim_ids.is_empty() {
            return Ok(LineageResult::default());
        }

        // Query edges to build parent relationships
        let edges: Vec<EdgeQueryRow> = sqlx::query_as(
            r#"
            SELECT source_id, target_id
            FROM edges
            WHERE source_type = 'claim'
              AND target_type = 'claim'
              AND source_id = ANY($1)
              AND target_id = ANY($1)
            "#,
        )
        .bind(&claim_ids)
        .fetch_all(pool)
        .await?;

        // Build parent map
        let mut parent_map: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for edge in &edges {
            parent_map
                .entry(edge.target_id)
                .or_default()
                .push(edge.source_id);
        }

        // Query all evidence for claims in lineage
        let evidence_rows: Vec<EvidenceQueryRow> = sqlx::query_as(
            r#"
            SELECT id, claim_id, evidence_type, content_hash
            FROM evidence
            WHERE claim_id = ANY($1)
            "#,
        )
        .bind(&claim_ids)
        .fetch_all(pool)
        .await?;

        // Build evidence map
        let mut evidence_map: HashMap<Uuid, LineageEvidence> = HashMap::new();
        let mut claim_evidence_map: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for row in evidence_rows {
            let evidence = LineageEvidence {
                id: row.id,
                claim_id: row.claim_id,
                evidence_type: row.evidence_type,
                content_hash: row.content_hash,
            };
            evidence_map.insert(row.id, evidence);
            claim_evidence_map
                .entry(row.claim_id)
                .or_default()
                .push(row.id);
        }

        // Query all reasoning traces for claims in lineage
        let trace_ids: Vec<Uuid> = lineage_rows.iter().filter_map(|r| r.trace_id).collect();

        let trace_rows: Vec<TraceQueryRow> = sqlx::query_as(
            r#"
            SELECT id, claim_id, reasoning_type, confidence
            FROM reasoning_traces
            WHERE claim_id = ANY($1)
            "#,
        )
        .bind(&claim_ids)
        .fetch_all(pool)
        .await?;

        // Query trace parents for DAG structure
        let trace_parent_rows: Vec<TraceParentRow> = if !trace_ids.is_empty() {
            sqlx::query_as(
                r#"
                SELECT trace_id, parent_id
                FROM trace_parents
                WHERE trace_id = ANY($1)
                "#,
            )
            .bind(&trace_ids)
            .fetch_all(pool)
            .await?
        } else {
            Vec::new()
        };

        // Build trace parent map
        let mut trace_parent_map: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for row in trace_parent_rows {
            trace_parent_map
                .entry(row.trace_id)
                .or_default()
                .push(row.parent_id);
        }

        // Build trace map
        let mut trace_map: HashMap<Uuid, LineageTrace> = HashMap::new();
        for row in trace_rows {
            let trace = LineageTrace {
                id: row.id,
                claim_id: row.claim_id,
                reasoning_type: row.reasoning_type,
                confidence: row.confidence,
                parent_trace_ids: trace_parent_map.get(&row.id).cloned().unwrap_or_default(),
            };
            trace_map.insert(row.id, trace);
        }

        // Build claims map
        let mut claims_map: HashMap<Uuid, LineageClaim> = HashMap::new();
        for row in &lineage_rows {
            let claim = LineageClaim {
                id: row.id,
                content: row.content.clone(),
                truth_value: row.truth_value,
                depth: row.depth,
                parent_ids: parent_map.get(&row.id).cloned().unwrap_or_default(),
                evidence_ids: claim_evidence_map.get(&row.id).cloned().unwrap_or_default(),
                trace_id: row.trace_id,
            };
            claims_map.insert(row.id, claim);
        }

        // Build topological order (sorted by depth descending, so ancestors come first)
        let mut topological_order: Vec<(Uuid, i32)> =
            lineage_rows.iter().map(|r| (r.id, r.depth)).collect();
        topological_order.sort_by_key(|b| std::cmp::Reverse(b.1)); // Descending depth
        let topological_order: Vec<Uuid> =
            topological_order.into_iter().map(|(id, _)| id).collect();

        Ok(LineageResult {
            claims: claims_map,
            evidence: evidence_map,
            traces: trace_map,
            topological_order,
            cycle_detected,
            max_depth_reached,
        })
    }

    /// Detect cycles in the lineage graph
    ///
    /// Returns true if a cycle is detected, false otherwise.
    /// Uses recursive CTE with path tracking to detect back edges.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `claim_id` - The claim to check for cycles from
    ///
    /// # Returns
    /// * `true` if a cycle is detected, `false` otherwise
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn detect_cycles(pool: &PgPool, claim_id: Uuid) -> Result<bool, DbError> {
        #[derive(sqlx::FromRow)]
        struct CycleResult {
            has_cycle: Option<bool>,
        }

        let result: CycleResult = sqlx::query_as(
            r#"
            WITH RECURSIVE lineage AS (
                SELECT id, ARRAY[id] as path, false as has_cycle
                FROM claims WHERE id = $1

                UNION ALL

                SELECT c.id, l.path || c.id, c.id = ANY(l.path)
                FROM claims c
                JOIN edges e ON e.source_id = c.id AND e.source_type = 'claim'
                JOIN lineage l ON e.target_id = l.id AND e.target_type = 'claim'
                WHERE NOT l.has_cycle
                  AND array_length(l.path, 1) < 1000
            )
            SELECT bool_or(has_cycle) as has_cycle FROM lineage
            "#,
        )
        .bind(claim_id)
        .fetch_one(pool)
        .await?;

        Ok(result.has_cycle.unwrap_or(false))
    }

    /// Get the depth of a claim's lineage
    ///
    /// Returns the maximum depth of ancestors from the given claim.
    /// Useful for quick checks without fetching full lineage data.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `claim_id` - The claim to check depth for
    ///
    /// # Returns
    /// * Maximum depth of ancestors (0 if claim has no parents)
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_depth(pool: &PgPool, claim_id: Uuid) -> Result<i32, DbError> {
        #[derive(sqlx::FromRow)]
        struct DepthResult {
            max_depth: Option<i32>,
        }

        let result: DepthResult = sqlx::query_as(
            r#"
            WITH RECURSIVE lineage AS (
                SELECT id, 0 as depth, ARRAY[id] as path
                FROM claims WHERE id = $1

                UNION ALL

                SELECT c.id, l.depth + 1, l.path || c.id
                FROM claims c
                JOIN edges e ON e.source_id = c.id AND e.source_type = 'claim'
                JOIN lineage l ON e.target_id = l.id AND e.target_type = 'claim'
                WHERE NOT c.id = ANY(l.path)
                  AND l.depth < 1000
            )
            SELECT MAX(depth) as max_depth FROM lineage
            "#,
        )
        .bind(claim_id)
        .fetch_one(pool)
        .await?;

        Ok(result.max_depth.unwrap_or(0))
    }

    /// Get ancestor claim IDs only (without full data)
    ///
    /// Returns just the UUIDs of all ancestor claims, useful for
    /// quick membership checks without fetching full claim data.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `claim_id` - The claim to get ancestors for
    /// * `max_depth` - Maximum depth to traverse
    ///
    /// # Returns
    /// * Vector of ancestor claim UUIDs in topological order
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_ancestor_ids(
        pool: &PgPool,
        claim_id: Uuid,
        max_depth: Option<i32>,
    ) -> Result<Vec<Uuid>, DbError> {
        let max_depth = max_depth.unwrap_or(100);

        #[derive(sqlx::FromRow)]
        struct IdDepthRow {
            id: Uuid,
            depth: i32,
        }

        let rows: Vec<IdDepthRow> = sqlx::query_as(
            r#"
            WITH RECURSIVE lineage AS (
                SELECT id, 0 as depth, ARRAY[id] as path
                FROM claims WHERE id = $1

                UNION ALL

                SELECT c.id, l.depth + 1, l.path || c.id
                FROM claims c
                JOIN edges e ON e.source_id = c.id AND e.source_type = 'claim'
                JOIN lineage l ON e.target_id = l.id AND e.target_type = 'claim'
                WHERE l.depth < $2
                  AND NOT c.id = ANY(l.path)
            )
            SELECT DISTINCT ON (id) id, depth
            FROM lineage
            ORDER BY id, depth
            "#,
        )
        .bind(claim_id)
        .bind(max_depth)
        .fetch_all(pool)
        .await?;

        // Sort by depth descending (ancestors first)
        let mut sorted: Vec<(Uuid, i32)> = rows.iter().map(|r| (r.id, r.depth)).collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.1));

        Ok(sorted.into_iter().map(|(id, _)| id).collect())
    }

    /// Query descendant lineage for a claim using recursive CTE
    ///
    /// Returns all descendant claims (claims that depend on this claim),
    /// their evidence, and reasoning traces in topological order.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `claim_id` - The claim to trace descendants from
    /// * `max_depth` - Maximum depth to traverse (None for default of 100)
    ///
    /// # Returns
    /// * `LineageResult` containing all claims, evidence, and traces in the descendant lineage
    ///
    /// # SQL Pattern
    /// Uses PostgreSQL recursive CTE traversing edges in the opposite direction:
    /// ```sql
    /// WITH RECURSIVE descendants AS (
    ///     SELECT id, 0 as depth, ARRAY[id] as path
    ///     FROM claims WHERE id = $1
    ///     UNION ALL
    ///     SELECT c.id, d.depth + 1, d.path || c.id
    ///     FROM claims c
    ///     JOIN edges e ON e.target_id = c.id AND e.target_type = 'claim'
    ///     JOIN descendants d ON e.source_id = d.id AND e.source_type = 'claim'
    ///     WHERE d.depth < $2 AND NOT c.id = ANY(d.path)
    /// )
    /// SELECT DISTINCT ON (id) * FROM descendants ORDER BY id, depth;
    /// ```
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database query fails.
    #[instrument(skip(pool))]
    pub async fn get_descendants(
        pool: &PgPool,
        claim_id: Uuid,
        max_depth: Option<i32>,
    ) -> Result<LineageResult, DbError> {
        let max_depth = max_depth.unwrap_or(100);

        // Query descendant claims with recursive CTE (reverse direction)
        let lineage_rows: Vec<LineageRow> = sqlx::query_as(
            r#"
            WITH RECURSIVE descendants AS (
                -- Base case: start with the source claim
                SELECT
                    c.id,
                    c.content,
                    c.truth_value,
                    c.trace_id,
                    0 as depth,
                    ARRAY[c.id] as path,
                    false as cycle_detected
                FROM claims c
                WHERE c.id = $1

                UNION ALL

                -- Recursive case: find child claims via edges (reverse direction)
                SELECT
                    c.id,
                    c.content,
                    c.truth_value,
                    c.trace_id,
                    d.depth + 1,
                    d.path || c.id,
                    c.id = ANY(d.path) as cycle_detected
                FROM claims c
                JOIN edges e ON e.target_id = c.id AND e.target_type = 'claim'
                JOIN descendants d ON e.source_id = d.id AND e.source_type = 'claim'
                WHERE d.depth < $2
                  AND NOT c.id = ANY(d.path)
            )
            SELECT DISTINCT ON (id)
                id,
                content,
                truth_value,
                trace_id,
                depth,
                path,
                cycle_detected
            FROM descendants
            ORDER BY id, depth
            "#,
        )
        .bind(claim_id)
        .bind(max_depth)
        .fetch_all(pool)
        .await?;

        // Check for cycles
        let cycle_detected = lineage_rows.iter().any(|r| r.cycle_detected);
        let max_depth_reached = lineage_rows.iter().map(|r| r.depth).max().unwrap_or(0);

        // Collect claim IDs for subsequent queries
        let claim_ids: Vec<Uuid> = lineage_rows.iter().map(|r| r.id).collect();

        if claim_ids.is_empty() {
            return Ok(LineageResult::default());
        }

        // Query edges to build parent relationships (for descendants, parents are in reverse)
        let edges: Vec<EdgeQueryRow> = sqlx::query_as(
            r#"
            SELECT source_id, target_id
            FROM edges
            WHERE source_type = 'claim'
              AND target_type = 'claim'
              AND source_id = ANY($1)
              AND target_id = ANY($1)
            "#,
        )
        .bind(&claim_ids)
        .fetch_all(pool)
        .await?;

        // Build parent map (source supports target)
        let mut parent_map: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for edge in &edges {
            parent_map
                .entry(edge.target_id)
                .or_default()
                .push(edge.source_id);
        }

        // Query all evidence for claims in lineage
        let evidence_rows: Vec<EvidenceQueryRow> = sqlx::query_as(
            r#"
            SELECT id, claim_id, evidence_type, content_hash
            FROM evidence
            WHERE claim_id = ANY($1)
            "#,
        )
        .bind(&claim_ids)
        .fetch_all(pool)
        .await?;

        // Build evidence map
        let mut evidence_map: HashMap<Uuid, LineageEvidence> = HashMap::new();
        let mut claim_evidence_map: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for row in evidence_rows {
            let evidence = LineageEvidence {
                id: row.id,
                claim_id: row.claim_id,
                evidence_type: row.evidence_type,
                content_hash: row.content_hash,
            };
            evidence_map.insert(row.id, evidence);
            claim_evidence_map
                .entry(row.claim_id)
                .or_default()
                .push(row.id);
        }

        // Query all reasoning traces for claims in lineage
        let trace_ids: Vec<Uuid> = lineage_rows.iter().filter_map(|r| r.trace_id).collect();

        let trace_rows: Vec<TraceQueryRow> = sqlx::query_as(
            r#"
            SELECT id, claim_id, reasoning_type, confidence
            FROM reasoning_traces
            WHERE claim_id = ANY($1)
            "#,
        )
        .bind(&claim_ids)
        .fetch_all(pool)
        .await?;

        // Query trace parents for DAG structure
        let trace_parent_rows: Vec<TraceParentRow> = if !trace_ids.is_empty() {
            sqlx::query_as(
                r#"
                SELECT trace_id, parent_id
                FROM trace_parents
                WHERE trace_id = ANY($1)
                "#,
            )
            .bind(&trace_ids)
            .fetch_all(pool)
            .await?
        } else {
            Vec::new()
        };

        // Build trace parent map
        let mut trace_parent_map: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for row in trace_parent_rows {
            trace_parent_map
                .entry(row.trace_id)
                .or_default()
                .push(row.parent_id);
        }

        // Build trace map
        let mut trace_map: HashMap<Uuid, LineageTrace> = HashMap::new();
        for row in trace_rows {
            let trace = LineageTrace {
                id: row.id,
                claim_id: row.claim_id,
                reasoning_type: row.reasoning_type,
                confidence: row.confidence,
                parent_trace_ids: trace_parent_map.get(&row.id).cloned().unwrap_or_default(),
            };
            trace_map.insert(row.id, trace);
        }

        // Build claims map
        let mut claims_map: HashMap<Uuid, LineageClaim> = HashMap::new();
        for row in &lineage_rows {
            let claim = LineageClaim {
                id: row.id,
                content: row.content.clone(),
                truth_value: row.truth_value,
                depth: row.depth,
                parent_ids: parent_map.get(&row.id).cloned().unwrap_or_default(),
                evidence_ids: claim_evidence_map.get(&row.id).cloned().unwrap_or_default(),
                trace_id: row.trace_id,
            };
            claims_map.insert(row.id, claim);
        }

        // Build topological order (sorted by depth ascending for descendants)
        let mut topological_order: Vec<(Uuid, i32)> =
            lineage_rows.iter().map(|r| (r.id, r.depth)).collect();
        topological_order.sort_by_key(|a| a.1); // Ascending depth for descendants
        let topological_order: Vec<Uuid> =
            topological_order.into_iter().map(|(id, _)| id).collect();

        Ok(LineageResult {
            claims: claims_map,
            evidence: evidence_map,
            traces: trace_map,
            topological_order,
            cycle_detected,
            max_depth_reached,
        })
    }

    /// Get descendant claim IDs only (without full data)
    ///
    /// Returns just the UUIDs of all descendant claims, useful for
    /// quick membership checks without fetching full claim data.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `claim_id` - The claim to get descendants for
    /// * `max_depth` - Maximum depth to traverse
    ///
    /// # Returns
    /// * Vector of descendant claim UUIDs
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_descendant_ids(
        pool: &PgPool,
        claim_id: Uuid,
        max_depth: Option<i32>,
    ) -> Result<Vec<Uuid>, DbError> {
        let max_depth = max_depth.unwrap_or(100);

        #[derive(sqlx::FromRow)]
        struct IdDepthRow {
            id: Uuid,
            depth: i32,
        }

        let rows: Vec<IdDepthRow> = sqlx::query_as(
            r#"
            WITH RECURSIVE descendants AS (
                SELECT id, 0 as depth, ARRAY[id] as path
                FROM claims WHERE id = $1

                UNION ALL

                SELECT c.id, d.depth + 1, d.path || c.id
                FROM claims c
                JOIN edges e ON e.target_id = c.id AND e.target_type = 'claim'
                JOIN descendants d ON e.source_id = d.id AND e.source_type = 'claim'
                WHERE d.depth < $2
                  AND NOT c.id = ANY(d.path)
            )
            SELECT DISTINCT ON (id) id, depth
            FROM descendants
            ORDER BY id, depth
            "#,
        )
        .bind(claim_id)
        .bind(max_depth)
        .fetch_all(pool)
        .await?;

        // Sort by depth ascending (root first)
        let mut sorted: Vec<(Uuid, i32)> = rows.iter().map(|r| (r.id, r.depth)).collect();
        sorted.sort_by_key(|a| a.1);

        Ok(sorted.into_iter().map(|(id, _)| id).collect())
    }

    /// Find the Lowest Common Ancestor of two claims in the provenance DAG.
    ///
    /// Uses two recursive CTEs to compute ancestor sets, then finds the
    /// shared ancestor with minimum total depth.
    ///
    /// Returns None if the claims have no common ancestor.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `claim_a` - First claim UUID
    /// * `claim_b` - Second claim UUID
    /// * `max_depth` - Maximum depth to traverse (None for default of 100)
    ///
    /// # Returns
    /// * `Some(LcaResult)` with the closest common ancestor, or `None` if none exists
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_lca(
        pool: &PgPool,
        claim_a: Uuid,
        claim_b: Uuid,
        max_depth: Option<i32>,
    ) -> Result<Option<LcaResult>, DbError> {
        let max_depth = max_depth.unwrap_or(100);

        #[derive(sqlx::FromRow)]
        struct LcaRow {
            ancestor_id: Uuid,
            depth_a: i32,
            depth_b: i32,
            total_depth: i32,
        }

        let row: Option<LcaRow> = sqlx::query_as(
            r#"
            WITH RECURSIVE ancestors_a AS (
                -- Ancestor set for claim A
                SELECT id, 0 as depth, ARRAY[id] as path
                FROM claims WHERE id = $1

                UNION ALL

                SELECT c.id, a.depth + 1, a.path || c.id
                FROM claims c
                JOIN edges e ON e.source_id = c.id AND e.source_type = 'claim'
                JOIN ancestors_a a ON e.target_id = a.id AND e.target_type = 'claim'
                WHERE a.depth < $3
                  AND NOT c.id = ANY(a.path)
            ),
            ancestors_b AS (
                -- Ancestor set for claim B
                SELECT id, 0 as depth, ARRAY[id] as path
                FROM claims WHERE id = $2

                UNION ALL

                SELECT c.id, b.depth + 1, b.path || c.id
                FROM claims c
                JOIN edges e ON e.source_id = c.id AND e.source_type = 'claim'
                JOIN ancestors_b b ON e.target_id = b.id AND e.target_type = 'claim'
                WHERE b.depth < $3
                  AND NOT c.id = ANY(b.path)
            )
            SELECT
                a.id AS ancestor_id,
                a.depth AS depth_a,
                b.depth AS depth_b,
                (a.depth + b.depth) AS total_depth
            FROM (SELECT DISTINCT ON (id) id, depth FROM ancestors_a ORDER BY id, depth) a
            INNER JOIN (SELECT DISTINCT ON (id) id, depth FROM ancestors_b ORDER BY id, depth) b
                ON a.id = b.id
            ORDER BY total_depth ASC
            LIMIT 1
            "#,
        )
        .bind(claim_a)
        .bind(claim_b)
        .bind(max_depth)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| LcaResult {
            ancestor_id: r.ancestor_id,
            depth_from_a: r.depth_a,
            depth_from_b: r.depth_b,
            total_depth: r.total_depth,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test agent in the database and return its UUID.
    async fn create_test_agent(pool: &PgPool) -> Uuid {
        let agent_id = Uuid::new_v4();
        let mut pk = [0u8; 32];
        pk[..16].copy_from_slice(agent_id.as_bytes());
        sqlx::query(
            "INSERT INTO agents (id, display_name, public_key) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
        )
        .bind(agent_id)
        .bind(format!("lca-test-{}", &agent_id.to_string()[..8]))
        .bind(&pk[..])
        .execute(pool)
        .await
        .unwrap();
        agent_id
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_lineage_repository_exists(_pool: sqlx::PgPool) {
        // Verifies the repository compiles correctly; full integration tests are in tests/lineage_tests.rs
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_lca_shared_parent(pool: sqlx::PgPool) {
        // Setup: parent_claim <-- child_a, parent_claim <-- child_b
        // Expected: LCA of child_a and child_b is parent_claim at depth (1, 1)
        let test_agent = create_test_agent(&pool).await;

        let parent_id = Uuid::new_v4();
        let child_a = Uuid::new_v4();
        let child_b = Uuid::new_v4();

        // Insert claims
        sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
            .bind(parent_id)
            .bind("Parent claim")
            .bind(test_agent)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
            .bind(child_a)
            .bind("Child A")
            .bind(test_agent)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
            .bind(child_b)
            .bind("Child B")
            .bind(test_agent)
            .execute(&pool)
            .await
            .unwrap();

        // Insert edges: parent -> child_a, parent -> child_b
        sqlx::query("INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) VALUES ($1, $2, 'claim', $3, 'claim', 'supports')")
            .bind(Uuid::new_v4())
            .bind(parent_id)
            .bind(child_a)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) VALUES ($1, $2, 'claim', $3, 'claim', 'supports')")
            .bind(Uuid::new_v4())
            .bind(parent_id)
            .bind(child_b)
            .execute(&pool)
            .await
            .unwrap();

        let result = LineageRepository::get_lca(&pool, child_a, child_b, None)
            .await
            .unwrap();

        assert!(result.is_some(), "Expected a common ancestor");
        let lca = result.unwrap();
        assert_eq!(lca.ancestor_id, parent_id);
        assert_eq!(lca.depth_from_a, 1);
        assert_eq!(lca.depth_from_b, 1);
        assert_eq!(lca.total_depth, 2);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_lca_no_common_ancestor(pool: sqlx::PgPool) {
        // Setup: two unrelated claims with no shared ancestry
        // Expected: get_lca returns None
        let test_agent = create_test_agent(&pool).await;

        let claim_a = Uuid::new_v4();
        let claim_b = Uuid::new_v4();

        sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
            .bind(claim_a)
            .bind("Isolated claim A")
            .bind(test_agent)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
            .bind(claim_b)
            .bind("Isolated claim B")
            .bind(test_agent)
            .execute(&pool)
            .await
            .unwrap();

        let result = LineageRepository::get_lca(&pool, claim_a, claim_b, None)
            .await
            .unwrap();

        assert!(
            result.is_none(),
            "Expected no common ancestor for unrelated claims"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_lca_diamond(pool: sqlx::PgPool) {
        // Setup: diamond graph
        //     root
        //    /    \
        //  mid_a  mid_b
        //    \    /
        //     leaf
        // Expected: LCA of leaf via mid_a and leaf via mid_b converges at root,
        // but we query LCA(mid_a, mid_b) which should be root at depth (1, 1)
        let test_agent = create_test_agent(&pool).await;

        let root = Uuid::new_v4();
        let mid_a = Uuid::new_v4();
        let mid_b = Uuid::new_v4();

        // Insert claims
        for (id, content) in [(root, "Root claim"), (mid_a, "Mid A"), (mid_b, "Mid B")] {
            sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
                .bind(id)
                .bind(content)
                .bind(test_agent)
                .execute(&pool)
                .await
                .unwrap();
        }

        // Edges: root -> mid_a, root -> mid_b
        for target in [mid_a, mid_b] {
            sqlx::query("INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) VALUES ($1, $2, 'claim', $3, 'claim', 'supports')")
                .bind(Uuid::new_v4())
                .bind(root)
                .bind(target)
                .execute(&pool)
                .await
                .unwrap();
        }

        let result = LineageRepository::get_lca(&pool, mid_a, mid_b, None)
            .await
            .unwrap();

        assert!(result.is_some(), "Expected root as LCA in diamond");
        let lca = result.unwrap();
        assert_eq!(lca.ancestor_id, root);
        assert_eq!(lca.total_depth, 2); // depth 1 from each
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_lca_self_ancestor(pool: sqlx::PgPool) {
        // Setup: A -> B (A is ancestor/parent of B)
        // Expected: LCA(A, B) is A, with depth_from_a=0, depth_from_b=1
        let test_agent = create_test_agent(&pool).await;

        let ancestor = Uuid::new_v4();
        let descendant = Uuid::new_v4();

        sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
            .bind(ancestor)
            .bind("Ancestor claim")
            .bind(test_agent)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
            .bind(descendant)
            .bind("Descendant claim")
            .bind(test_agent)
            .execute(&pool)
            .await
            .unwrap();

        // Edge: ancestor -> descendant
        sqlx::query("INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) VALUES ($1, $2, 'claim', $3, 'claim', 'supports')")
            .bind(Uuid::new_v4())
            .bind(ancestor)
            .bind(descendant)
            .execute(&pool)
            .await
            .unwrap();

        let result = LineageRepository::get_lca(&pool, ancestor, descendant, None)
            .await
            .unwrap();

        assert!(result.is_some(), "Expected ancestor as LCA");
        let lca = result.unwrap();
        assert_eq!(lca.ancestor_id, ancestor);
        assert_eq!(lca.depth_from_a, 0);
        assert_eq!(lca.depth_from_b, 1);
        assert_eq!(lca.total_depth, 1);
    }
}
