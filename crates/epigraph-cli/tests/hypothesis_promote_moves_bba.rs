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

/// `experiment analyze` on a PROMOTED hypothesis files its error-derived BBA on
/// `research_validity`, the frame the promoted hypothesis's readers (`hypothesis
/// status`, the HTTP status) read (operator ruling R-8: writers follow the
/// readers). Filed on `hypothesis_assessment`, the new analysis is invisible to
/// every reader of the promoted hypothesis.
#[sqlx::test(migrations = "../../migrations")]
async fn cli_analyze_after_promotion_files_on_research_validity(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "r8-cli").await;
    let (later, _) = fixture::seed_agent_with_group(&pool, "r8-cli-later").await;
    let claim = fixture::seed_public_claim(&pool, agent, "r8 cli hypothesis analyzed later").await;
    let hyp_frame = binary_frame(&pool, "hypothesis_assessment").await;
    let rv_frame = binary_frame(&pool, "research_validity").await;
    seed_completed_analysis(&pool, agent, claim).await;
    epigraph_db::MassFunctionRepository::store_with_perspective(
        &pool,
        claim,
        hyp_frame,
        Some(agent),
        None,
        &serde_json::json!({"0": 0.8, "0,1": 0.2}),
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
    let run = |bin: &str, args: &[&str]| {
        let out = Command::new(bin)
            .args(args)
            .env("DATABASE_URL", &url)
            .env("MAINTENANCE_DATABASE_URL", &url)
            .env("RUST_LOG", "warn")
            .output()
            .expect("spawn the binary");
        assert!(
            out.status.success(),
            "{bin} {args:?} exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let id = claim.to_string();
    run(BIN, &["promote", &id]);
    let on = |frame: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (Option<Uuid>, Option<String>, serde_json::Value)>(
                "SELECT source_agent_id, combination_method, masses FROM mass_functions \
                  WHERE claim_id = $1 AND frame_id = $2 ORDER BY created_at, id",
            )
            .bind(claim)
            .bind(frame)
            .fetch_all(&pool)
            .await
            .expect("read BBAs")
        }
    };
    assert!(
        on(hyp_frame).await.is_empty(),
        "CALIBRATION: the promotion left nothing on hypothesis_assessment"
    );

    // A later experiment's result, analyzed through the real binary.
    let experiment: Uuid = sqlx::query_scalar(
        "INSERT INTO experiments (hypothesis_id, created_by, status) \
         VALUES ($1, $2, 'running') RETURNING id",
    )
    .bind(claim)
    .bind(later)
    .fetch_one(&pool)
    .await
    .expect("seed experiment");
    let result: Uuid = sqlx::query_scalar(
        "INSERT INTO experiment_results (experiment_id, data_source, raw_measurements, measurement_count) \
         VALUES ($1, 'instrument', $2, 2) RETURNING id",
    )
    .bind(experiment)
    .bind(serde_json::json!([
        {"value": 1.2, "random_error": 0.05, "systematic_error": 0.02},
        {"value": 1.1, "random_error": 0.05, "systematic_error": 0.02}
    ]))
    .fetch_one(&pool)
    .await
    .expect("seed result");
    run(
        env!("CARGO_BIN_EXE_experiment"),
        &[
            "analyze",
            &result.to_string(),
            "--direction",
            "refutes",
            "--agent-id",
            &later.to_string(),
            "--scope",
            "small_sample_size",
        ],
    );

    assert!(
        on(hyp_frame).await.is_empty(),
        "evidence analyzed after the promotion must not land on hypothesis_assessment"
    );
    let rv = on(rv_frame).await;
    let filed: Vec<_> = rv.iter().filter(|(a, _, _)| *a == Some(later)).collect();
    assert_eq!(
        filed.len(),
        1,
        "the later analysis is on research_validity: {rv:?}"
    );
    assert_eq!(filed[0].1.as_deref(), Some("error_derived"));
    assert!(
        filed[0]
            .2
            .get("1")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0)
            > 0.0,
        "with the refuting masses: {:?}",
        filed[0].2
    );
    assert!(
        rv.iter().any(|(a, _, _)| *a == Some(agent)),
        "beside the promoted evidence: {rv:?}"
    );
}

/// Every BBA on (claim, frame), oldest first, as `(id, masses)`.
async fn frame_rows(pool: &PgPool, claim: Uuid, frame: Uuid) -> Vec<(Uuid, serde_json::Value)> {
    sqlx::query_as(
        "SELECT id, masses FROM mass_functions WHERE claim_id = $1 AND frame_id = $2 \
         ORDER BY created_at ASC, id ASC",
    )
    .bind(claim)
    .bind(frame)
    .fetch_all(pool)
    .await
    .expect("read BBA rows")
}

/// A promotable hypothesis: a completed analysis with an explicit scope and a
/// `hypothesis_assessment` BBA whose Bel(supported) 0.8 clears the gate.
async fn promotable(pool: &PgPool, tag: &str) -> (Uuid, Uuid, Uuid, Uuid) {
    let (agent, _group) = fixture::seed_agent_with_group(pool, tag).await;
    let claim = fixture::seed_public_claim(pool, agent, &format!("{tag} hypothesis")).await;
    let hyp_frame = binary_frame(pool, "hypothesis_assessment").await;
    let rv_frame = binary_frame(pool, "research_validity").await;
    seed_completed_analysis(pool, agent, claim).await;
    store_assessment(
        pool,
        claim,
        hyp_frame,
        agent,
        serde_json::json!({"0": 0.8, "0,1": 0.2}),
    )
    .await;
    (agent, claim, hyp_frame, rv_frame)
}

async fn store_assessment(
    pool: &PgPool,
    claim: Uuid,
    hyp_frame: Uuid,
    agent: Uuid,
    masses: serde_json::Value,
) -> Uuid {
    epigraph_db::MassFunctionRepository::store_with_perspective(
        pool,
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
    .expect("seed a hypothesis_assessment BBA")
}

fn promote_cmd(url: &str, claim: Uuid) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.args(["promote", &claim.to_string()])
        .env("DATABASE_URL", url)
        .env("MAINTENANCE_DATABASE_URL", url)
        .env("RUST_LOG", "warn");
    cmd
}

/// Backlog 03b1508f (1): `hypothesis promote` refuses an already-promoted
/// hypothesis, as `POST /hypothesis/:id/promote` does (409) since #687. At
/// origin/main the CLI re-ran the gate on `hypothesis_assessment` only, so a
/// BBA filed there after the promotion (here a ready-making one) passed it,
/// and the CLI promoted again and moved that BBA onto `research_validity`.
#[sqlx::test(migrations = "../../migrations")]
async fn cli_refuses_to_promote_an_already_promoted_hypothesis(pool: PgPool) {
    let (agent, claim, hyp_frame, rv_frame) = promotable(&pool, "03b1508f-cli-twice").await;
    let url = fixture::database_url_for(&pool).await;
    let first = promote_cmd(&url, claim).output().expect("spawn hypothesis");
    assert!(
        first.status.success(),
        "CALIBRATION: the first promotion runs: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let promoted = frame_rows(&pool, claim, rv_frame).await;
    assert_eq!(promoted.len(), 1, "CALIBRATION: one promoted row");

    let later = store_assessment(
        &pool,
        claim,
        hyp_frame,
        agent,
        serde_json::json!({"0": 0.95, "0,1": 0.05}),
    )
    .await;
    let again = promote_cmd(&url, claim).output().expect("spawn hypothesis");
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(
        !again.status.success(),
        "a second promotion must be refused, got exit {:?}: {}",
        again.status.code(),
        String::from_utf8_lossy(&again.stdout)
    );
    assert!(stderr.contains("already promoted"), "{stderr}");
    assert_eq!(
        frame_rows(&pool, claim, rv_frame).await,
        promoted,
        "the refused promotion leaves research_validity as the first one left it"
    );
    assert!(
        frame_rows(&pool, claim, hyp_frame)
            .await
            .iter()
            .any(|(id, _)| *id == later),
        "the refused promotion leaves the later hypothesis_assessment BBA in place"
    );
}
