//! Reasoning trace repository for database operations

use crate::errors::DbError;
use epigraph_core::{AgentId, ClaimId, Methodology, ReasoningTrace, TraceId, TraceInput};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// Repository for ReasoningTrace operations
pub struct ReasoningTraceRepository;

/// Row struct for trace queries that JOIN with claims to get agent_id.
///
/// This struct is used with `sqlx::query_as` to avoid requiring database
/// access at compile time while still preserving type safety at runtime.
#[derive(sqlx::FromRow)]
struct TraceWithAgentRow {
    id: Uuid,
    #[allow(dead_code)]
    claim_id: Uuid,
    reasoning_type: String,
    confidence: f64,
    explanation: String,
    properties: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
    agent_id: Uuid,
}

/// One reasoning trace as a provenance step: the identity, the **raw**
/// `reasoning_type` string as stored, and the confidence.
///
/// `reasoning_type` is deliberately NOT parsed into [`Methodology`]. See
/// [`ReasoningTraceRepository::provenance_step_by_id`] for why.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TraceProvenanceStep {
    /// `reasoning_traces.id`.
    pub id: Uuid,
    /// `reasoning_traces.reasoning_type`, exactly as stored.
    pub reasoning_type: String,
    /// `reasoning_traces.confidence`.
    pub confidence: f64,
}

/// Build ReasoningTrace from database row data.
///
/// This helper function handles the crypto fields that may not exist in
/// the database yet (public_key, content_hash). It uses placeholder values
/// until the database schema is migrated.
#[allow(clippy::too_many_arguments)]
fn trace_from_row(
    id: Uuid,
    agent_id: AgentId,
    methodology: Methodology,
    inputs: Vec<TraceInput>,
    confidence: f64,
    explanation: String,
    signature: Option<[u8; 64]>,
    created_at: chrono::DateTime<chrono::Utc>,
) -> ReasoningTrace {
    // Placeholder crypto fields - will be populated when DB schema includes them
    let public_key = [0u8; 32];
    let content_hash = [0u8; 32];

    ReasoningTrace::with_id(
        TraceId::from_uuid(id),
        agent_id,
        public_key,
        content_hash,
        methodology,
        inputs,
        confidence,
        explanation,
        signature,
        created_at,
    )
}

impl ReasoningTraceRepository {
    /// Create a new reasoning trace in the database
    ///
    /// Note: This stores the trace metadata but does NOT store the inputs
    /// in trace_parents. Use `add_parent` to link traces together.
    ///
    /// # The executor is generic, and that is what makes this table writable
    ///
    /// `reasoning_traces` is one of the tables migration 077 gives a STRICT
    /// `WITH CHECK` (`owner_group_id = ANY(epigraph_writable_groups())`) and 079
    /// FORCEs. An unstamped application connection has an empty writable set, so
    /// the INSERT is refused with `42501` — pinned by
    /// `epigraph-db/tests/rls_enforcement.rs::an_unstamped_app_connection_cannot_write_a_claim_derived_row`.
    /// The only connection that CAN write it is one stamped by
    /// `ScopedPool::begin_as`, and that hands back a transaction, not a pool. A
    /// `&PgPool` parameter therefore made this function unreachable from the one
    /// connection shape that works, which is why the executor is generic rather
    /// than a pool: `&PgPool` and `&mut PgConnection` both satisfy
    /// [`sqlx::PgExecutor`], so every existing pool-taking caller compiles
    /// unchanged while a transaction can now join.
    ///
    /// Mirrors the read side of this repository, which has been
    /// `<'e, E: PgExecutor<'e>>` since PR-09.
    ///
    /// # Arguments
    /// * `executor` - A pool, connection, or transaction handle
    /// * `trace` - The reasoning trace to create
    /// * `claim_id` - The ID of the claim this trace is associated with
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, trace))]
    pub async fn create<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        trace: &ReasoningTrace,
        claim_id: ClaimId,
    ) -> Result<ReasoningTrace, DbError> {
        Self::create_with_reasoning_type(
            executor,
            trace,
            claim_id,
            Self::reasoning_type_for(trace.methodology),
            None,
        )
        .await
    }

    /// The `reasoning_type` vocabulary `reasoning_traces.reasoning_type_valid`
    /// admits. Mirrors that CHECK as of migration 121, which added
    /// `observational`. A value outside it would be refused by Postgres;
    /// [`Self::create_with_reasoning_type`] refuses it first, in Rust.
    pub const REASONING_TYPES: [&str; 6] = [
        "deductive",
        "inductive",
        "abductive",
        "analogical",
        "statistical",
        "observational",
    ];

    /// `Ok` iff `reasoning_type` is in [`Self::REASONING_TYPES`].
    fn check_reasoning_type(reasoning_type: &str) -> Result<(), DbError> {
        if Self::REASONING_TYPES.contains(&reasoning_type) {
            Ok(())
        } else {
            Err(DbError::InvalidData {
                reason: format!(
                    "reasoning_type {reasoning_type:?} is not one of {:?}",
                    Self::REASONING_TYPES
                ),
            })
        }
    }

    /// [`Self::create`] with the stored `reasoning_type` chosen by the caller
    /// instead of derived from `trace.methodology`.
    ///
    /// # Why this exists
    ///
    /// [`Methodology`] is a trust-modifier bucket, coarser than what a caller
    /// says it did: `direct_observation` and `statistical_analysis` share
    /// [`Methodology::Instrumental`], which [`Self::reasoning_type_for`] stores
    /// as `statistical`. A caller that still holds the submitted methodology
    /// string (the MCP `submit_claim` path) can store the faithful value, e.g.
    /// `observational`, through this function (backlog e207bb6d). Changing the
    /// enum-level arm instead would relabel every statistical ingest.
    ///
    /// `submitted_methodology`, when `Some`, is recorded verbatim at
    /// `properties.submitted_methodology`, so the submitted word survives
    /// even where the 6-value CHECK forces a coarse `reasoning_type`. It is
    /// whatever string the caller passes here: a caller that filled in a
    /// default (the MCP batch and backlog-resolution paths do) records that
    /// default, not an absence.
    ///
    /// # Errors
    /// `DbError::InvalidData` if `reasoning_type` is not in
    /// [`Self::REASONING_TYPES`] (nothing is written); `DbError::QueryFailed`
    /// if the INSERT fails.
    #[instrument(skip(executor, trace))]
    pub async fn create_with_reasoning_type<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        trace: &ReasoningTrace,
        claim_id: ClaimId,
        reasoning_type: &str,
        submitted_methodology: Option<&str>,
    ) -> Result<ReasoningTrace, DbError> {
        Self::check_reasoning_type(reasoning_type)?;

        let id: Uuid = trace.id.into();
        let agent_id: Uuid = trace.agent_id.into();
        let claim_uuid: Uuid = claim_id.into();

        let mut properties_json = serde_json::json!({
            "inputs": trace.inputs,
        });
        if let Some(submitted) = submitted_methodology {
            properties_json["submitted_methodology"] = serde_json::json!(submitted);
        }

        let confidence = trace.confidence;
        let explanation = &trace.explanation;
        let created_at = trace.created_at;

        let row = sqlx::query!(
            r#"
            INSERT INTO reasoning_traces (
                id, claim_id, reasoning_type, confidence, explanation, properties, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, claim_id, reasoning_type, confidence, explanation, properties, created_at
            "#,
            id,
            claim_uuid,
            reasoning_type,
            confidence,
            explanation,
            properties_json,
            created_at
        )
        .fetch_one(executor)
        .await?;

        let methodology = Self::db_string_to_methodology(&row.reasoning_type)?;

        // Extract inputs from properties (properties is NOT NULL DEFAULT '{}')
        let inputs: Vec<TraceInput> = serde_json::from_value(
            row.properties
                .get("inputs")
                .cloned()
                .unwrap_or(serde_json::json!([])),
        )?;

        Ok(trace_from_row(
            row.id,
            AgentId::from_uuid(agent_id),
            methodology,
            inputs,
            row.confidence,
            row.explanation,
            None, // signature not stored yet
            row.created_at,
        ))
    }

    /// The three columns a provenance step renders — `id`, the **raw**
    /// `reasoning_type` string and `confidence` — read through a `Viewer`.
    ///
    /// # Why this is not [`Self::get_by_id`]
    ///
    /// `get_by_id` parses `reasoning_type` into [`Methodology`] via
    /// [`Self::db_string_to_methodology`], and that mapping is deliberately
    /// lossy in the direction this caller cannot absorb: `"statistical"` and
    /// `"analogical"` both resolve to a different spelling on the way back out.
    /// The provenance step label is a response field, so reusing `get_by_id`
    /// would change a public API response as a side effect of adding a filter.
    /// It also `INNER JOIN`s `claims` for an `agent_id` this caller does not
    /// project, and returns `explanation`, which it must not.
    ///
    /// So: the same visibility mechanism, over the projection the caller
    /// actually needs. One marker, one bind — `reasoning_traces` is the only
    /// relation here. The caller has already read the owning claim through the
    /// same viewer, so there is no second alias to mark.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn provenance_step_by_id<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        id: TraceId,
    ) -> Result<Option<TraceProvenanceStep>, DbError> {
        let uuid: Uuid = id.into();
        let sql = viewer.splice(
            r#"
            SELECT rt.id, rt.reasoning_type, rt.confidence
            FROM reasoning_traces rt
            WHERE rt.id = $1
              /* {VISIBILITY:rt} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, TraceProvenanceStep>(&sql).bind(uuid);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(executor).await?)
    }

    /// Get a reasoning trace by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_by_id<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        id: TraceId,
    ) -> Result<Option<ReasoningTrace>, DbError> {
        let uuid: Uuid = id.into();

        // JOIN with claims table to get the correct agent_id
        // This preserves provenance tracking - the agent who made the claim
        // is the agent associated with the reasoning trace
        //
        // BOTH aliases are marked. `reasoning_traces` carries its own tenancy
        // columns (062) and `explanation` is free prose about the claim, so
        // filtering only the joined `claims` row would still be wrong the other
        // way round: a trace private to another group hanging off a public
        // claim.
        let sql = viewer.splice(
            r#"
            SELECT rt.id, rt.claim_id, rt.reasoning_type, rt.confidence,
                   rt.explanation, rt.properties, rt.created_at,
                   c.agent_id
            FROM reasoning_traces rt
            INNER JOIN claims c ON rt.claim_id = c.id
            WHERE rt.id = $1
              /* {VISIBILITY:rt} */ /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, TraceWithAgentRow>(&sql).bind(uuid);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row: Option<TraceWithAgentRow> = q.fetch_optional(executor).await?;

        match row {
            Some(row) => {
                let methodology = Self::db_string_to_methodology(&row.reasoning_type)?;

                // Extract inputs from properties (properties is NOT NULL DEFAULT '{}')
                let inputs: Vec<TraceInput> = serde_json::from_value(
                    row.properties
                        .get("inputs")
                        .cloned()
                        .unwrap_or(serde_json::json!([])),
                )?;

                // Get agent_id from the joined claims table - preserves provenance
                let agent_id = AgentId::from_uuid(row.agent_id);

                Ok(Some(trace_from_row(
                    row.id,
                    agent_id,
                    methodology,
                    inputs,
                    row.confidence,
                    row.explanation,
                    None,
                    row.created_at,
                )))
            }
            None => Ok(None),
        }
    }

    /// Get all reasoning traces for a claim
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_by_claim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: ClaimId,
    ) -> Result<Vec<ReasoningTrace>, DbError> {
        let uuid: Uuid = claim_id.into();

        // JOIN with claims table to get the correct agent_id
        let sql = viewer.splice(
            r#"
            SELECT rt.id, rt.claim_id, rt.reasoning_type, rt.confidence,
                   rt.explanation, rt.properties, rt.created_at,
                   c.agent_id
            FROM reasoning_traces rt
            INNER JOIN claims c ON rt.claim_id = c.id
            WHERE rt.claim_id = $1
              /* {VISIBILITY:rt} */ /* {VISIBILITY:c} */
            ORDER BY rt.created_at DESC
            "#,
            2,
        );
        let mut qy = sqlx::query_as::<_, TraceWithAgentRow>(&sql).bind(uuid);
        if let Some(g) = viewer.group_bind() {
            qy = qy.bind(g);
        }
        let rows: Vec<TraceWithAgentRow> = qy.fetch_all(executor).await?;

        let mut traces = Vec::with_capacity(rows.len());

        for row in rows {
            let methodology = Self::db_string_to_methodology(&row.reasoning_type)?;

            let inputs: Vec<TraceInput> = serde_json::from_value(
                row.properties
                    .get("inputs")
                    .cloned()
                    .unwrap_or(serde_json::json!([])),
            )?;

            // Get agent_id from the joined claims table - preserves provenance
            let agent_id = AgentId::from_uuid(row.agent_id);

            traces.push(trace_from_row(
                row.id,
                agent_id,
                methodology,
                inputs,
                row.confidence,
                row.explanation,
                None,
                row.created_at,
            ));
        }

        Ok(traces)
    }

    /// Add a parent trace relationship
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn add_parent(
        pool: &PgPool,
        trace_id: TraceId,
        parent_id: TraceId,
    ) -> Result<(), DbError> {
        let trace_uuid: Uuid = trace_id.into();
        let parent_uuid: Uuid = parent_id.into();

        sqlx::query!(
            r#"
            INSERT INTO trace_parents (trace_id, parent_id)
            VALUES ($1, $2)
            ON CONFLICT (trace_id, parent_id) DO NOTHING
            "#,
            trace_uuid,
            parent_uuid
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get parent traces
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_parents<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        trace_id: TraceId,
    ) -> Result<Vec<ReasoningTrace>, DbError> {
        let uuid: Uuid = trace_id.into();

        // JOIN with claims table to get the correct agent_id for each parent trace
        let sql = viewer.splice(
            r#"
            SELECT rt.id, rt.claim_id, rt.reasoning_type, rt.confidence,
                   rt.explanation, rt.properties, rt.created_at,
                   c.agent_id
            FROM reasoning_traces rt
            INNER JOIN trace_parents tp ON rt.id = tp.parent_id
            INNER JOIN claims c ON rt.claim_id = c.id
            WHERE tp.trace_id = $1
              /* {VISIBILITY:rt} */ /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut qy = sqlx::query_as::<_, TraceWithAgentRow>(&sql).bind(uuid);
        if let Some(g) = viewer.group_bind() {
            qy = qy.bind(g);
        }
        let rows: Vec<TraceWithAgentRow> = qy.fetch_all(executor).await?;

        let mut traces = Vec::with_capacity(rows.len());

        for row in rows {
            let methodology = Self::db_string_to_methodology(&row.reasoning_type)?;

            let inputs: Vec<TraceInput> = serde_json::from_value(
                row.properties
                    .get("inputs")
                    .cloned()
                    .unwrap_or(serde_json::json!([])),
            )?;

            // Get agent_id from the joined claims table - preserves provenance
            let agent_id = AgentId::from_uuid(row.agent_id);

            traces.push(trace_from_row(
                row.id,
                agent_id,
                methodology,
                inputs,
                row.confidence,
                row.explanation,
                None,
                row.created_at,
            ));
        }

        Ok(traces)
    }

    /// Get child traces
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_children<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        trace_id: TraceId,
    ) -> Result<Vec<ReasoningTrace>, DbError> {
        let uuid: Uuid = trace_id.into();

        // JOIN with claims table to get the correct agent_id for each child trace
        let sql = viewer.splice(
            r#"
            SELECT rt.id, rt.claim_id, rt.reasoning_type, rt.confidence,
                   rt.explanation, rt.properties, rt.created_at,
                   c.agent_id
            FROM reasoning_traces rt
            INNER JOIN trace_parents tp ON rt.id = tp.trace_id
            INNER JOIN claims c ON rt.claim_id = c.id
            WHERE tp.parent_id = $1
              /* {VISIBILITY:rt} */ /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut qy = sqlx::query_as::<_, TraceWithAgentRow>(&sql).bind(uuid);
        if let Some(g) = viewer.group_bind() {
            qy = qy.bind(g);
        }
        let rows: Vec<TraceWithAgentRow> = qy.fetch_all(executor).await?;

        let mut traces = Vec::with_capacity(rows.len());

        for row in rows {
            let methodology = Self::db_string_to_methodology(&row.reasoning_type)?;

            let inputs: Vec<TraceInput> = serde_json::from_value(
                row.properties
                    .get("inputs")
                    .cloned()
                    .unwrap_or(serde_json::json!([])),
            )?;

            // Get agent_id from the joined claims table - preserves provenance
            let agent_id = AgentId::from_uuid(row.agent_id);

            traces.push(trace_from_row(
                row.id,
                agent_id,
                methodology,
                inputs,
                row.confidence,
                row.explanation,
                None,
                row.created_at,
            ));
        }

        Ok(traces)
    }

    /// The one [`Methodology`] -> `reasoning_type` mapping, for writers that
    /// hold only the enum (ingestion, `memorize`, the HTTP routes).
    ///
    /// Several variants share a stored value because the CHECK admits only
    /// [`Self::REASONING_TYPES`]; in particular `Instrumental` stays
    /// `statistical`, because ingestion lands planned `"statistical"` there. A
    /// writer that knows the submitted methodology string should use
    /// [`Self::create_with_reasoning_type`] instead.
    ///
    /// # Known asymmetry (inert)
    ///
    /// It is not inverted by [`Self::db_string_to_methodology`]: `observational`
    /// reads back as `Instrumental`, `Instrumental` writes as `statistical`, and
    /// `statistical` reads back as `BayesianInference`. No code path rewrites a
    /// trace through the enum (there is no `UPDATE reasoning_traces` outside a
    /// test), so the asymmetry cannot relabel a stored row today.
    pub fn reasoning_type_for(methodology: Methodology) -> &'static str {
        match methodology {
            Methodology::Deductive => "deductive",
            Methodology::Inductive => "inductive",
            Methodology::Abductive => "abductive",
            Methodology::Instrumental => "statistical",
            Methodology::Extraction => "statistical",
            Methodology::BayesianInference => "statistical",
            Methodology::VisualInspection => "statistical",
            Methodology::FormalProof => "deductive",
            Methodology::Heuristic => "abductive",
        }
    }

    /// Convert database string to Methodology enum
    fn db_string_to_methodology(s: &str) -> Result<Methodology, DbError> {
        match s {
            "deductive" => Ok(Methodology::Deductive),
            "inductive" => Ok(Methodology::Inductive),
            "abductive" => Ok(Methodology::Abductive),
            "analogical" => Ok(Methodology::Abductive), // Map to closest
            "statistical" => Ok(Methodology::BayesianInference),
            "observational" => Ok(Methodology::Instrumental),
            _ => Err(DbError::InvalidData {
                reason: format!("Unknown reasoning type: {}", s),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_with_reasoning_type_rejects_a_value_outside_the_check() {
        for bad in [
            "vibes",
            "",
            "Observational",
            "direct_observation",
            "extraction",
        ] {
            match ReasoningTraceRepository::check_reasoning_type(bad) {
                Err(DbError::InvalidData { reason }) => assert!(
                    reason.contains(bad),
                    "the refusal must name the rejected value {bad:?}: {reason}"
                ),
                other => panic!("{bad:?} must be refused as InvalidData, got {other:?}"),
            }
        }
        for ok in ReasoningTraceRepository::REASONING_TYPES {
            assert!(
                ReasoningTraceRepository::check_reasoning_type(ok).is_ok(),
                "{ok:?} is admitted by the CHECK and must be accepted"
            );
        }
    }

    /// Drift guard: `REASONING_TYPES` must equal the value list of the LATEST
    /// migration that (re)creates `reasoning_type_valid`. A future migration
    /// that widens the CHECK without updating the constant fails here instead
    /// of as a Rust-side refusal of a value Postgres would admit.
    #[test]
    fn reasoning_types_mirror_the_latest_reasoning_type_valid_migration() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .expect("read migrations/")
            .map(|e| e.expect("dir entry").path())
            .filter(|p| p.extension().is_some_and(|x| x == "sql"))
            .collect();
        files.sort();
        // Anchor on the constraint DDL in SQL text only: a header comment that
        // discusses the constraint (121's does) must not be parsed as it.
        const ANCHOR: &str = "ADD CONSTRAINT reasoning_type_valid CHECK";
        let without_comments = |sql: String| -> String {
            sql.lines()
                .filter(|l| !l.trim_start().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let (path, sql) = files
            .iter()
            .rev()
            .map(|p| {
                let sql = std::fs::read_to_string(p).expect("read migration");
                (p, without_comments(sql))
            })
            .find(|(_, sql)| sql.contains(ANCHOR))
            .expect("some migration adds reasoning_type_valid");
        let start = sql.find(ANCHOR).expect("anchor present");
        let body = &sql[start..];
        let body = &body[..body.find(';').expect("statement terminator")];
        let mut in_check: Vec<&str> = body.split('\'').skip(1).step_by(2).collect();
        in_check.sort_unstable();
        let mut ours = ReasoningTraceRepository::REASONING_TYPES.to_vec();
        ours.sort_unstable();
        assert!(
            in_check.contains(&"observational"),
            "parsed nothing sensible out of {}: {in_check:?}",
            path.display()
        );
        assert_eq!(
            ours,
            in_check,
            "REASONING_TYPES drifted from {}",
            path.display()
        );
    }

    /// Every arm of the enum-level mapping, written out independently (these
    /// are the arms of the pre-refactor private `methodology_to_db_string`,
    /// which ingestion, `memorize`, the HTTP routes and the packet submit
    /// route all persist through), and each one admitted by the CHECK.
    #[test]
    fn every_enum_mapping_is_admitted_by_the_check() {
        let expected = [
            (Methodology::Deductive, "deductive"),
            (Methodology::FormalProof, "deductive"),
            (Methodology::Inductive, "inductive"),
            (Methodology::Abductive, "abductive"),
            (Methodology::Heuristic, "abductive"),
            // The hard constraint of backlog e207bb6d's fix: the enum-level
            // Instrumental arm stays `statistical`, because ingestion lands a
            // planned "statistical" step on Instrumental.
            (Methodology::Instrumental, "statistical"),
            (Methodology::Extraction, "statistical"),
            (Methodology::BayesianInference, "statistical"),
            (Methodology::VisualInspection, "statistical"),
        ];
        for (m, want) in expected {
            let stored = ReasoningTraceRepository::reasoning_type_for(m);
            assert_eq!(stored, want, "{m:?} must be stored as {want:?}");
            assert!(
                ReasoningTraceRepository::REASONING_TYPES.contains(&stored),
                "{m:?} maps to {stored:?}, which reasoning_type_valid refuses"
            );
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_trace_crud(_pool: sqlx::PgPool) {
        // Placeholder: full CRUD coverage is in tests/trace_tests.rs
    }

    /// Test: Verify that traces return correct agent_id from claims table
    ///
    /// **Evidence**: Security vulnerability - placeholder AgentId::new() breaks provenance
    /// **Reasoning**: Agent ID must be fetched via JOIN with claims table
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_trace_returns_correct_agent_id_not_placeholder(pool: sqlx::PgPool) {
        // Create a specific agent with unique public key derived from agent ID
        let known_agent_id = Uuid::new_v4();
        let mut public_key = [0u8; 32];
        public_key[..16].copy_from_slice(&known_agent_id.as_bytes()[..16]);
        public_key[16..].copy_from_slice(&known_agent_id.as_bytes()[..16]);
        sqlx::query(
            r#"
            INSERT INTO agents (id, public_key, display_name)
            VALUES ($1, $2, $3)
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(known_agent_id)
        .bind(&public_key[..])
        .bind("Test Agent for Trace Provenance")
        .execute(&pool)
        .await
        .expect("Failed to create test agent");

        // Create a claim with that agent
        let claim_id = Uuid::new_v4();
        let content = "Test claim for trace provenance";
        let content_hash = blake3::hash(content.as_bytes());
        sqlx::query(
            r#"
            INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(claim_id)
        .bind(content)
        .bind(content_hash.as_bytes().as_slice())
        .bind(0.75f64)
        .bind(known_agent_id)
        .execute(&pool)
        .await
        .expect("Failed to create test claim");

        // Create a trace for that claim using the repository
        let trace = ReasoningTrace::new(
            AgentId::from_uuid(known_agent_id),
            public_key,
            Methodology::Deductive,
            vec![],
            0.9,
            "Test trace for provenance verification".to_string(),
        );

        let created_trace =
            ReasoningTraceRepository::create(&pool, &trace, ClaimId::from_uuid(claim_id))
                .await
                .expect("Failed to create trace");

        // CRITICAL: Verify the created trace has the correct agent_id
        let created_agent_uuid: Uuid = created_trace.agent_id.into();
        assert_eq!(
            created_agent_uuid, known_agent_id,
            "Created trace must have the original agent ID, not a placeholder"
        );

        // Now fetch the trace by ID and verify agent_id is correct
        let fetched_trace = ReasoningTraceRepository::get_by_id(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            created_trace.id,
        )
        .await
        .expect("Failed to fetch trace")
        .expect("Trace should exist");

        let fetched_agent_uuid: Uuid = fetched_trace.agent_id.into();
        assert_eq!(
            fetched_agent_uuid, known_agent_id,
            "Fetched trace must have the correct agent ID from claims table, not a random placeholder"
        );

        // Verify by fetching via get_by_claim
        let traces_for_claim = ReasoningTraceRepository::get_by_claim(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            ClaimId::from_uuid(claim_id),
        )
        .await
        .expect("Failed to fetch traces by claim");

        assert_eq!(traces_for_claim.len(), 1);
        let trace_from_claim: Uuid = traces_for_claim[0].agent_id.into();
        assert_eq!(
            trace_from_claim, known_agent_id,
            "Trace fetched by claim must have correct agent ID"
        );
    }

    /// `reasoning_type = 'observational'` is storable and reads back as Instrumental.
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_observational_reasoning_type_round_trips(pool: sqlx::PgPool) {
        let agent_id = Uuid::new_v4();
        let mut public_key = [0u8; 32];
        public_key[..16].copy_from_slice(&agent_id.as_bytes()[..16]);
        sqlx::query("INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, $3)")
            .bind(agent_id)
            .bind(&public_key[..])
            .bind("Observational Agent")
            .execute(&pool)
            .await
            .expect("Failed to create agent");

        let claim_id = Uuid::new_v4();
        let content_hash = blake3::hash(b"observational claim");
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(claim_id)
        .bind("observational claim")
        .bind(content_hash.as_bytes().as_slice())
        .bind(0.5f64)
        .bind(agent_id)
        .execute(&pool)
        .await
        .expect("Failed to create claim");

        let trace_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO reasoning_traces (id, claim_id, reasoning_type, confidence, explanation) \
             VALUES ($1, $2, 'observational', 0.7, 'saw it')",
        )
        .bind(trace_id)
        .bind(claim_id)
        .execute(&pool)
        .await
        .expect("observational must satisfy reasoning_type_valid");

        let viewer = crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]);
        let by_id =
            ReasoningTraceRepository::get_by_id(&pool, &viewer, TraceId::from_uuid(trace_id))
                .await
                .expect("get_by_id must not error on observational")
                .expect("trace exists");
        assert_eq!(by_id.methodology, Methodology::Instrumental);

        let by_claim =
            ReasoningTraceRepository::get_by_claim(&pool, &viewer, ClaimId::from_uuid(claim_id))
                .await
                .expect("get_by_claim must not error on observational");
        assert_eq!(by_claim.len(), 1);
        assert_eq!(by_claim[0].methodology, Methodology::Instrumental);
    }

    /// Test: Verify that get_parents and get_children return correct agent IDs
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_trace_parents_children_have_correct_agent_ids(pool: sqlx::PgPool) {
        // Create two agents with unique public keys
        let agent1_id = Uuid::new_v4();
        let agent2_id = Uuid::new_v4();
        let mut public_key1 = [0u8; 32];
        let mut public_key2 = [0u8; 32];
        // Use agent IDs to create unique public keys
        public_key1[..16].copy_from_slice(&agent1_id.as_bytes()[..16]);
        public_key2[..16].copy_from_slice(&agent2_id.as_bytes()[..16]);

        for (agent_id, public_key, name) in [
            (agent1_id, &public_key1[..], "Agent 1"),
            (agent2_id, &public_key2[..], "Agent 2"),
        ] {
            sqlx::query(
                r#"
                INSERT INTO agents (id, public_key, display_name)
                VALUES ($1, $2, $3)
                ON CONFLICT (id) DO NOTHING
                "#,
            )
            .bind(agent_id)
            .bind(public_key)
            .bind(name)
            .execute(&pool)
            .await
            .expect("Failed to create agent");
        }

        // Create two claims with different agents
        let claim1_id = Uuid::new_v4();
        let claim2_id = Uuid::new_v4();
        let content_hash = blake3::hash(b"test");

        for (claim_id, agent_id, content) in [
            (claim1_id, agent1_id, "Claim by agent 1"),
            (claim2_id, agent2_id, "Claim by agent 2"),
        ] {
            sqlx::query(
                r#"
                INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
                VALUES ($1, $2, $3, $4, $5)
                "#,
            )
            .bind(claim_id)
            .bind(content)
            .bind(content_hash.as_bytes().as_slice())
            .bind(0.5f64)
            .bind(agent_id)
            .execute(&pool)
            .await
            .expect("Failed to create claim");
        }

        // Create parent trace (for claim1 by agent1)
        let parent_trace = ReasoningTrace::new(
            AgentId::from_uuid(agent1_id),
            public_key1,
            Methodology::Deductive,
            vec![],
            0.8,
            "Parent trace".to_string(),
        );
        let parent =
            ReasoningTraceRepository::create(&pool, &parent_trace, ClaimId::from_uuid(claim1_id))
                .await
                .expect("Failed to create parent trace");

        // Create child trace (for claim2 by agent2)
        let child_trace = ReasoningTrace::new(
            AgentId::from_uuid(agent2_id),
            public_key2,
            Methodology::Inductive,
            vec![],
            0.7,
            "Child trace".to_string(),
        );
        let child =
            ReasoningTraceRepository::create(&pool, &child_trace, ClaimId::from_uuid(claim2_id))
                .await
                .expect("Failed to create child trace");

        // Link parent-child
        ReasoningTraceRepository::add_parent(&pool, child.id, parent.id)
            .await
            .expect("Failed to add parent");

        // Verify get_parents returns correct agent_id for parent
        let parents = ReasoningTraceRepository::get_parents(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            child.id,
        )
        .await
        .expect("Failed to get parents");
        assert_eq!(parents.len(), 1);
        let parent_agent: Uuid = parents[0].agent_id.into();
        assert_eq!(
            parent_agent, agent1_id,
            "Parent trace must have agent1's ID, not a placeholder"
        );

        // Verify get_children returns correct agent_id for child
        let children = ReasoningTraceRepository::get_children(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            parent.id,
        )
        .await
        .expect("Failed to get children");
        assert_eq!(children.len(), 1);
        let child_agent: Uuid = children[0].agent_id.into();
        assert_eq!(
            child_agent, agent2_id,
            "Child trace must have agent2's ID, not a placeholder"
        );
    }
}
