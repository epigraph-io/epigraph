//! A step a hierarchical workflow's deprecation retired is REVIVED when a later
//! generation or `add_step` reuses its exact text (backlog 1767f2ae).
//!
//! A step claim's id is `compound_claim_id(hash(text), canonical_name)`, with
//! no generation in the seed. `deprecate_workflow` retires the level 0-2
//! claims no live workflow still executes (`is_current = false`, truth 0.05,
//! both vectors nulled). The executor's dedup-by-id then skipped the existing
//! row and `add_step` inserted with `ON CONFLICT (id) DO NOTHING`, so a new
//! live generation executed a claim that was not current and had no vector:
//! invisible to semantic workflow search, and read as retired.
//!
//! The deprecation now marks what it retires, and the executor and `add_step`
//! revive a marked claim they reuse: current again, its truth value back, and
//! embedded by the caller. An `evolve_step` supersede (also `is_current =
//! false`, on purpose) carries no marker and has a successor, and stays
//! retired.
//!
//! Every assertion reads PERSISTED state. The embedder is a deterministic
//! generator (`McpEmbedder::with_generator`) behind the production store path
//! (`with_scoped_pool`), so "embedded" means a vector was stored on the row.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{first_text, seed_caller};
use epigraph_crypto::AgentSigner;
use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::tools;
use epigraph_mcp::tools::evolve_step::EvolveStepParams;
use epigraph_mcp::tools::step_ops::AddStepParams;
use epigraph_mcp::types::{
    DeprecateWorkflowParams, ImproveWorkflowHierarchyParams, IngestWorkflowParams,
};
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

const KEEP: &str = "revival: gather the inputs";
const DROP: &str = "revival: publish the report";

async fn server(pool: &PgPool) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(pool).await;
    let embedder = McpEmbedder::new(pool.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|text: &str| {
            let mut v = vec![0.0_f32; 1536];
            v[text.len() % 1536] = 1.0;
            Ok(v)
        }));
    EpiGraphMcpFull::new(
        pool.clone(),
        AgentSigner::from_bytes(&[0x3Du8; 32]).expect("signer"),
        embedder,
        false,
    )
    .with_scoped_pool(scoped)
}

fn extraction(canonical: &str, steps: &[&str]) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: format!("revival workflow {canonical}"),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: None,
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Body".to_string(),
            summary: format!("revival phase for {canonical}"),
            steps: steps
                .iter()
                .map(|s| Step {
                    compound: (*s).to_string(),
                    rationale: "because".to_string(),
                    operations: vec![],
                    generality: vec![1],
                    confidence: 0.7,
                    evidence_type: None,
                })
                .collect(),
        }],
        relationships: vec![],
    }
}

struct World {
    pool: PgPool,
    server: EpiGraphMcpFull,
    token: epigraph_auth::AuthContext,
    viewer: epigraph_db::visibility::Viewer,
    canonical: String,
}

impl World {
    async fn new(pool: PgPool, label: &str) -> Self {
        let server = server(&pool).await;
        let (_agent, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
        Self {
            pool,
            server,
            token,
            viewer,
            canonical: format!("{label}-{}", Uuid::new_v4()),
        }
    }

    async fn ingest(&self, steps: &[&str]) -> Uuid {
        tools::workflow_ingest::ingest_workflow(
            &self.server,
            &self.viewer,
            IngestWorkflowParams {
                extraction: extraction(&self.canonical, steps),
                tenancy: Some(common::public_tenancy_for(&self.viewer)),
                embed: None,
            },
            Some(&self.token),
        )
        .await
        .expect("ingest");
        self.row(0).await
    }

    async fn improve(&self, steps: &[&str], generation: i32) -> Uuid {
        let mut refined = extraction(&self.canonical, steps);
        refined.phases[0].summary = format!("revival phase {generation}");
        tools::workflow_ingest::improve_workflow_hierarchy(
            &self.server,
            &self.viewer,
            ImproveWorkflowHierarchyParams {
                parent_canonical_name: self.canonical.clone(),
                extraction: refined,
            },
            Some(&self.token),
        )
        .await
        .expect("improve");
        self.row(generation).await
    }

    async fn deprecate(&self, wf: Uuid) -> serde_json::Value {
        first_text(
            &tools::workflows::deprecate_workflow(
                &self.server,
                &self.viewer,
                DeprecateWorkflowParams {
                    workflow_id: wf.to_string(),
                    reason: "obsolete".into(),
                    cascade: Some(false),
                },
                Some(&self.token),
            )
            .await
            .expect("deprecate"),
        )
    }

    async fn row(&self, generation: i32) -> Uuid {
        sqlx::query_scalar("SELECT id FROM workflows WHERE canonical_name = $1 AND generation = $2")
            .bind(&self.canonical)
            .bind(generation)
            .fetch_one(&self.pool)
            .await
            .expect("workflows row")
    }

    /// The claim `wf` executes whose content is `text`.
    async fn step(&self, wf: Uuid, text: &str) -> Uuid {
        sqlx::query_scalar(
            "SELECT c.id FROM edges e JOIN claims c ON c.id = e.target_id \
             WHERE e.source_id = $1 AND e.relationship = 'executes' AND c.content = $2",
        )
        .bind(wf)
        .bind(text)
        .fetch_one(&self.pool)
        .await
        .unwrap_or_else(|e| panic!("step {text:?} of {wf}: {e}"))
    }

    /// `(is_current, truth_value, embedding IS NOT NULL, marked)`.
    async fn state(&self, claim: Uuid) -> (bool, f64, bool, bool) {
        sqlx::query_as(
            "SELECT is_current, truth_value, embedding IS NOT NULL, \
                    COALESCE(properties ? 'workflow_deprecation_retired', false) \
             FROM claims WHERE id = $1",
        )
        .bind(claim)
        .fetch_one(&self.pool)
        .await
        .expect("claim state")
    }
}

/// `improve_workflow_hierarchy` after a deprecation: the new generation reuses
/// the retired step rows and revives them.
#[sqlx::test(migrations = "../../migrations")]
async fn a_new_generation_revives_the_steps_a_deprecation_retired(pool: PgPool) {
    let w = World::new(pool, "revive-generation").await;
    let gen0 = w.ingest(&[KEEP, DROP]).await;
    let keep = w.step(gen0, KEEP).await;
    let before = w.state(keep).await;
    assert!(
        before.0 && before.2,
        "PRECONDITION: the ingested step is current and embedded: {before:?}"
    );

    let out = w.deprecate(gen0).await;
    assert!(
        out["retired_claim_ids"]
            .as_array()
            .expect("retired ids")
            .iter()
            .any(|id| id.as_str() == Some(&keep.to_string())),
        "PRECONDITION: the deprecation retired the step: {out}"
    );
    assert_eq!(
        w.state(keep).await,
        (false, 0.05, false, true),
        "PRECONDITION: retired, unembedded and marked"
    );

    let gen1 = w.improve(&[KEEP, DROP], 1).await;
    assert_eq!(
        w.step(gen1, KEEP).await,
        keep,
        "PRECONDITION: the new generation reuses the retired row"
    );
    assert_eq!(
        w.state(keep).await,
        (true, before.1, true, false),
        "the reused step is current, has its truth value back, is embedded and unmarked"
    );
}

/// `add_step` of a retired step's text onto the live head revives it.
#[sqlx::test(migrations = "../../migrations")]
async fn add_step_revives_a_step_a_deprecation_retired(pool: PgPool) {
    let w = World::new(pool, "revive-add-step").await;
    let gen0 = w.ingest(&[KEEP, DROP]).await;
    let dropped = w.step(gen0, DROP).await;
    let before = w.state(dropped).await;
    let gen1 = w.improve(&[KEEP], 1).await;

    // Generation 1 does not execute DROP, so deprecating generation 0 retires
    // it (and keeps KEEP, which generation 1 still runs).
    w.deprecate(gen0).await;
    assert_eq!(
        w.state(dropped).await,
        (false, 0.05, false, true),
        "PRECONDITION: retired, unembedded and marked"
    );

    let added = first_text(
        &tools::step_ops::add_step(
            &w.server,
            &w.viewer,
            AddStepParams {
                canonical_name: w.canonical.clone(),
                step_text: DROP.to_string(),
                position: None,
            },
            Some(&w.token),
        )
        .await
        .expect("add_step"),
    );
    assert_eq!(added["workflow_id"], serde_json::json!(gen1), "{added}");
    assert_eq!(
        added["step_claim_id"],
        serde_json::json!(dropped),
        "PRECONDITION: add_step reuses the retired row"
    );
    let lineage: Option<Uuid> =
        sqlx::query_scalar("SELECT step_lineage_id FROM claims WHERE id = $1")
            .bind(dropped)
            .fetch_one(&w.pool)
            .await
            .expect("lineage");
    assert_eq!(
        added["step_lineage_id"],
        serde_json::json!(lineage.expect("a step has a lineage")),
        "add_step reports the reused step's own lineage, not a fresh one"
    );
    assert_eq!(
        w.state(dropped).await,
        (true, before.1, true, false),
        "the reused step is current, has its truth value back, is embedded and unmarked"
    );
}

/// An `evolve_step` supersede is not a deprecation's retirement: a new
/// generation that goes back to the superseded text reuses that row and must
/// leave it retired (its lineage head is the successor).
#[sqlx::test(migrations = "../../migrations")]
async fn a_superseded_step_is_not_revived(pool: PgPool) {
    let w = World::new(pool, "no-revive-supersede").await;
    let gen0 = w.ingest(&[KEEP, DROP]).await;
    let keep = w.step(gen0, KEEP).await;
    tools::evolve_step::evolve_step(
        &w.server,
        &w.viewer,
        EvolveStepParams {
            parent_id: keep.to_string(),
            canonical_name: None,
            step_index: None,
            step_lineage_id: String::new(),
            content: "revival: gather the inputs, deduplicated".to_string(),
            edge_type: "supersedes".to_string(),
            rationale: Some("refined".to_string()),
            level: Some(2),
        },
        Some(&w.token),
    )
    .await
    .expect("evolve_step");
    let superseded = w.state(keep).await;
    assert!(
        !superseded.0 && !superseded.3,
        "PRECONDITION: superseded, not current and unmarked: {superseded:?}"
    );

    let gen1 = w.improve(&[KEEP, DROP], 1).await;
    assert_eq!(
        w.step(gen1, KEEP).await,
        keep,
        "PRECONDITION: the new generation reuses the superseded row"
    );
    assert_eq!(
        w.state(keep).await,
        superseded,
        "a superseded step stays exactly as the supersede left it"
    );
}
