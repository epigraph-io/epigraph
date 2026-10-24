//! `hypothesis promote <id>` MOVES the latest `hypothesis_assessment` BBA onto
//! `research_validity` (backlog 846b808e).
//!
//! The CLI is the promotion path that actually writes on a cleanly-migrated
//! schema (it runs on the maintenance connection; the HTTP route's unstamped
//! write is refused at the copy). Before this file it ran `copy_to_frame` and
//! never retired the source, so both binary frames held the same evidence and
//! `MassFunctionRepository::get_for_claim_binary_frames` (the reader the
//! `ds_auto` fold uses) returned it twice. An evidence-less row like the
//! `error_derived` BBA seeded here has no source key and was folded twice as
//! independent evidence.
//!
//! The real binary runs via `CARGO_BIN_EXE_hypothesis` against the
//! `#[sqlx::test]` database, with BOTH DSN variables set explicitly (see
//! `backfill_idempotence.rs` for why an inherited `MAINTENANCE_DATABASE_URL`
//! would point it elsewhere).

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_hypothesis");

async fn binary_frame(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['true','false']::text[]) \
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {name} frame: {e}"))
}

/// The promotion gate's inputs: a complete experiment whose result an analysis
/// with an explicit scope `analyzes`, and that analysis `provides_evidence` to
/// the hypothesis (the shape `routes/experiment_loop.rs::analyze` writes).
async fn seed_completed_analysis(pool: &PgPool, agent: Uuid, hypothesis: Uuid) {
    let experiment: Uuid = sqlx::query_scalar(
        "INSERT INTO experiments (hypothesis_id, created_by, status) \
         VALUES ($1, $2, 'complete') RETURNING id",
    )
    .bind(hypothesis)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed experiment");
    let result: Uuid = sqlx::query_scalar(
        "INSERT INTO experiment_results (experiment_id, data_source, raw_measurements, measurement_count) \
         VALUES ($1, 'instrument', '[]'::jsonb, 0) RETURNING id",
    )
    .bind(experiment)
    .fetch_one(pool)
    .await
    .expect("seed result");
    let analysis: Uuid = sqlx::query_scalar(
        "INSERT INTO analyses (analysis_type, method_description, inference_path, agent_id, properties) \
         VALUES ('automated', 'error-derived', 'novel', $1, $2) RETURNING id",
    )
    .bind(agent)
    .bind(serde_json::json!({"scope_limitations": [{"type": "small_sample_size"}]}))
    .fetch_one(pool)
    .await
    .expect("seed analysis");
    for (target, target_type, relationship) in [
        (result, "experiment_result", "analyzes"),
        (hypothesis, "claim", "provides_evidence"),
    ] {
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
             VALUES ($1, 'analysis', $2, $3, $4, '{}')",
        )
        .bind(analysis)
        .bind(target)
        .bind(target_type)
        .bind(relationship)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("seed {relationship} edge: {e}"));
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn cli_promote_leaves_the_evidence_on_one_binary_frame(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "846b808e-cli").await;
    let claim = fixture::seed_public_claim(&pool, agent, "846b808e cli promoted hypothesis").await;
    let hyp_frame = binary_frame(&pool, "hypothesis_assessment").await;
    let rv_frame = binary_frame(&pool, "research_validity").await;
    seed_completed_analysis(&pool, agent, claim).await;
    // Untyped and evidence-less, like the `error_derived` BBA `analyze` writes;
    // Bel(supported) 0.8 clears the 0.6 promotion gate.
    let masses = serde_json::json!({"0": 0.8, "0,1": 0.2});
    let source = epigraph_db::MassFunctionRepository::store_with_perspective(
        &pool,
        claim,
        hyp_frame,
        Some(agent),
        None,
        &masses,
        None,
        Some("error_derived"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("seed the hypothesis_assessment BBA");

    let url = fixture::database_url_for(&pool).await;
    let out = Command::new(BIN)
        .args(["promote", &claim.to_string()])
        .env("DATABASE_URL", &url)
        .env("MAINTENANCE_DATABASE_URL", &url)
        .env("RUST_LOG", "warn")
        .output()
        .expect("spawn hypothesis");
    assert!(
        out.status.success(),
        "hypothesis promote exited {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let status: Option<String> =
        sqlx::query_scalar("SELECT properties->>'hypothesis_status' FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read status");
    assert_eq!(
        status.as_deref(),
        Some("promoted"),
        "CALIBRATION: the promotion ran"
    );

    let viewer = fixture::public_viewer(&pool).await;
    let folded: Vec<epigraph_db::MassFunctionRow> =
        epigraph_db::MassFunctionRepository::get_for_claim_binary_frames(&pool, &viewer, claim)
            .await
            .expect("binary-frame BBAs")
            .into_iter()
            .filter(|row| row.source_agent_id == Some(agent))
            .collect();
    assert_eq!(
        folded.len(),
        1,
        "the promoted evidence must be read ONCE across binary frames, got {:?}",
        folded
            .iter()
            .map(|r| (r.id, r.frame_id))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        folded[0].frame_id, rv_frame,
        "it lives on research_validity"
    );
    assert_eq!(folded[0].masses, masses, "with the source's masses");
    assert_ne!(folded[0].id, source, "the source row itself is retired");
}

/// `hypothesis status` on a promoted hypothesis reads the frame its evidence
/// was moved to, `research_validity` (backlog 090221d9): reading
/// `hypothesis_assessment` printed zero belief, or, as here, the masses of a
/// BBA another agent filed there after the promotion.
#[sqlx::test(migrations = "../../migrations")]
async fn cli_status_of_a_promoted_hypothesis_reads_research_validity(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "090221d9-cli").await;
    let (later, _) = fixture::seed_agent_with_group(&pool, "090221d9-cli-later").await;
    let claim = fixture::seed_public_claim(&pool, agent, "090221d9 cli promoted hypothesis").await;
    let hyp_frame = binary_frame(&pool, "hypothesis_assessment").await;
    binary_frame(&pool, "research_validity").await;
    seed_completed_analysis(&pool, agent, claim).await;
    let store = |who: Uuid, masses: serde_json::Value| {
        let pool = pool.clone();
        async move {
            epigraph_db::MassFunctionRepository::store_with_perspective(
                &pool,
                claim,
                hyp_frame,
                Some(who),
                None,
                &masses,
                None,
                Some("error_derived"),
                None,
                None,
                "unknown",
                None,
            )
            .await
            .expect("seed a hypothesis_assessment BBA")
        }
    };
    store(agent, serde_json::json!({"0": 0.8, "0,1": 0.2})).await;

    let url = fixture::database_url_for(&pool).await;
    let run = |args: [&str; 2]| {
        let out = Command::new(BIN)
            .args(args)
            .env("DATABASE_URL", &url)
            .env("MAINTENANCE_DATABASE_URL", &url)
            .env("RUST_LOG", "warn")
            .output()
            .expect("spawn hypothesis");
        assert!(
            out.status.success(),
            "hypothesis {args:?} exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let id = claim.to_string();
    run(["promote", &id]);
    store(later, serde_json::json!({"1": 0.9, "0,1": 0.1})).await;

    let printed = run(["status", &id]);
    assert!(
        printed.contains("Status: promoted"),
        "CALIBRATION: {printed}"
    );
    assert!(
        printed.contains("Supported:   0.8000") && printed.contains("Unsupported: 0.0000"),
        "a promoted hypothesis's status prints the evidence it was promoted on:\n{printed}"
    );
}
