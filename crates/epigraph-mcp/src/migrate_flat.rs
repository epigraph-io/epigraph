//! Helpers for the `migrate-flat-workflows` bin (#34).
//!
//! Re-ingests existing flat-JSON workflows (claims labeled `'workflow'`) into
//! the new hierarchical `workflows` table introduced in migration 020.
//! Idempotent: rows already labeled `'legacy_flat'` are skipped.

use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::{Phase, Step, WorkflowExtraction, WorkflowSource};

#[derive(Debug, Deserialize)]
pub struct FlatContent {
    pub goal: String,
    #[serde(default)]
    pub steps: Vec<String>,
    #[serde(default)]
    pub prerequisites: Vec<String>,
    #[serde(default)]
    pub expected_outcome: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct FlatRow {
    pub id: Uuid,
    pub content: String,
    pub properties: serde_json::Value,
}

/// Slugify a free-text goal into a canonical_name.
/// Lowercase + alnum + hyphen-collapsed.
#[must_use]
pub fn slugify(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Fetch flat-JSON workflows that haven't been migrated yet.
///
/// Filters claims by:
/// - `'workflow'` label present (legacy flat-JSON marker)
/// - `'legacy_flat'` label NOT present (already-migrated marker)
///
/// Orders by `properties.generation` then `created_at` ASC so parents are
/// processed before their variants.
pub async fn fetch_unmigrated(
    pool: &PgPool,
    limit: Option<i64>,
    only_id: Option<Uuid>,
) -> Result<Vec<FlatRow>, sqlx::Error> {
    let lim = limit.unwrap_or(i64::MAX);
    if let Some(id) = only_id {
        sqlx::query_as::<_, FlatRow>(
            "SELECT id, content, properties FROM claims \
             WHERE id = $1 AND 'workflow' = ANY(labels) AND NOT 'legacy_flat' = ANY(labels)",
        )
        .bind(id)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, FlatRow>(
            "SELECT id, content, properties FROM claims \
             WHERE 'workflow' = ANY(labels) AND NOT 'legacy_flat' = ANY(labels) \
             ORDER BY (properties->>'generation')::int NULLS FIRST, created_at ASC \
             LIMIT $1",
        )
        .bind(lim)
        .fetch_all(pool)
        .await
    }
}

/// Build a `WorkflowExtraction` from parsed flat-JSON content.
///
/// Single-Body-phase mapping per the spec: each old `steps[i]` becomes one
/// `Step` whose `compound` is the step text. `operations` is left empty
/// intentionally — populating it with the same text as `compound` would
/// cause a `(content_hash, agent_id)` unique-constraint collision at ingest
/// time because the compound claim and operation atom share the same hash
/// but get different deterministic UUIDs. Richer operation hierarchies are
/// tracked as #36.
#[must_use]
pub fn build_extraction(
    parsed: &FlatContent,
    canonical_name: String,
    generation: u32,
    parent_canonical_name: Option<String>,
) -> WorkflowExtraction {
    let phases = if parsed.steps.is_empty() {
        vec![]
    } else {
        vec![Phase {
            title: "Body".to_string(),
            // Use the title as summary instead of the goal to avoid a
            // (content_hash, canonical_name) collision with the thesis claim,
            // which would generate the same compound_claim_id and create a
            // self-loop edge (source_id == target_id, same claim type).
            summary: "Body".to_string(),
            steps: parsed
                .steps
                .iter()
                .map(|step_text| Step {
                    compound: step_text.clone(),
                    rationale: String::new(),
                    operations: vec![],
                    generality: vec![],
                    confidence: 0.8,
                })
                .collect(),
        }]
    };

    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name,
            goal: parsed.goal.clone(),
            generation,
            parent_canonical_name,
            authors: vec![],
            expected_outcome: parsed.expected_outcome.clone(),
            tags: parsed.tags.clone(),
            metadata: serde_json::json!({
                "prerequisites": parsed.prerequisites,
            }),
        },
        thesis: Some(parsed.goal.clone()),
        thesis_derivation: ThesisDerivation::default(),
        phases,
        relationships: vec![],
    }
}

/// After a successful migration of a flat-JSON workflow, append the
/// `'legacy_flat'` label to the old claim and emit a `workflow → claim`
/// `supersedes` edge. Atomic via a single transaction.
pub async fn mark_legacy_and_supersede(
    pool: &PgPool,
    old_claim_id: Uuid,
    new_workflow_id: Uuid,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE claims SET labels = array_append(labels, 'legacy_flat') \
         WHERE id = $1 AND NOT 'legacy_flat' = ANY(labels)",
    )
    .bind(old_claim_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES ($1, 'workflow', $2, 'claim', 'supersedes', '{}'::jsonb) \
         ON CONFLICT DO NOTHING",
    )
    .bind(new_workflow_id)
    .bind(old_claim_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
