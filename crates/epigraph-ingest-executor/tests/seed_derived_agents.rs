//! The agents the workflow-ingest executor creates for PUBLIC seeds are stored
//! `key_kind = 'seed-derived'` (backlog bfc2eff8, migration 230), and no
//! signature verifier accepts their keys:
//!
//! * a workflow's author node, `did_key_for_author(None, name)`: the key of
//!   `BLAKE3("author:{name}")`;
//! * on an unregistered, unarmed database, the legacy `workflow-ingest-system`
//!   agent, `did_key_for_author(None, "workflow-ingest-system")`.
//!
//! Anyone who knows the name holds either private key. Before 230 both rows
//! took the column default `ed25519`, so `AgentRepository::public_key_if_signer`
//! handed the key to the packet-signature verifier.

use epigraph_db::AgentRepository;
use epigraph_ingest::common::schema::{AuthorEntry, ThesisDerivation};
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use sqlx::PgPool;
use uuid::Uuid;

fn workflow_by(author: &str) -> WorkflowExtraction {
    let author: AuthorEntry =
        serde_json::from_value(serde_json::json!({ "name": author })).expect("author entry");
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: "seed-derived-agents-test".to_string(),
            goal: "Store the agents of public seeds as identifiers, never verifiers".to_string(),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![author],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: Some("A seed-derived key names an agent and verifies nothing".to_string()),
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Phase 1".to_string(),
            summary: "Ingest a workflow with one author".to_string(),
            steps: vec![Step {
                compound: "Run the executor".to_string(),
                rationale: "It creates the author and system agents".to_string(),
                operations: vec!["Call execute_workflow_ingest_plan".to_string()],
                generality: vec![2],
                confidence: 0.9,
                evidence_type: None,
            }],
        }],
        relationships: vec![],
    }
}

async fn kind_and_verifier(pool: &PgPool, key: &[u8; 32]) -> (String, Option<Vec<u8>>) {
    let (id, kind): (Uuid, String) =
        sqlx::query_as("SELECT id, key_kind::text FROM agents WHERE public_key = $1")
            .bind(key.as_slice())
            .fetch_one(pool)
            .await
            .expect("the executor created the agent");
    let mut conn = pool.acquire().await.expect("acquire");
    let verifier = AgentRepository::public_key_if_signer(&mut conn, id)
        .await
        .expect("public_key_if_signer");
    (kind, verifier)
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_author_and_legacy_system_agents_are_seed_derived(pool: PgPool) {
    let name = "Perpetua Lindqvist-Oyelaran";
    let extraction = workflow_by(name);
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);
    let result = epigraph_ingest_executor::execute_workflow_ingest_plan(
        &mut pool.acquire().await.expect("acquire"),
        None,
        &plan,
        &extraction,
    )
    .await
    .expect("ingest");
    assert!(result.claims_ingested > 0, "calibration: the ingest wrote");

    for (what, key) in [
        (
            "the author node",
            epigraph_crypto::did_key::did_key_for_author(None, name).1,
        ),
        (
            "the legacy workflow-ingest-system agent",
            epigraph_crypto::did_key::did_key_for_author(None, "workflow-ingest-system").1,
        ),
    ] {
        let (kind, verifier) = kind_and_verifier(&pool, &key).await;
        assert_eq!(
            kind, "seed-derived",
            "{what}: its key is derived from a public name and must not be stored as a verifier"
        );
        assert_eq!(
            verifier, None,
            "{what}: public_key_if_signer must refuse it"
        );
    }
}
