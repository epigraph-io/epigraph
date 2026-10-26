//! `submit_ds_evidence` naming `hypothesis_assessment` for a PROMOTED
//! hypothesis files the BBA on `research_validity` (operator ruling R-8:
//! evidence submitted against a hypothesis after its promotion goes to the
//! frame its readers read, on every transport that writes hypothesis evidence).
//! The REST twin is `epigraph-api/tests/promoted_hypothesis_evidence_frame.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x7bu8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let scoped = fixture::scoped_pool(&pool).await;
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

async fn ensure_frame(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['supported','unsupported']::text[]) \
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {name} frame: {e}"))
}

async fn hypothesis(pool: &PgPool, status: &str) -> Uuid {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let content = format!("r8 mcp {status} hypothesis {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, labels, \
                             properties)
         VALUES ($1, sha256($1::bytea), 0.5, $2, true, ARRAY['hypothesis'], $3) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(serde_json::json!({ "hypothesis_status": status }))
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn frames_with_bbas(pool: &PgPool, claim: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT frame_id FROM mass_functions WHERE claim_id = $1 ORDER BY created_at, id",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read BBAs")
}

async fn submit(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim: Uuid,
    frame: Uuid,
) -> serde_json::Value {
    first_text(
        &tools::ds::submit_ds_evidence(
            server,
            viewer,
            serde_json::from_value(serde_json::json!({
                "claim_id": claim.to_string(),
                "frame_id": frame.to_string(),
                "hypothesis_index": 0,
                "masses": {"1": 0.7, "0,1": 0.3},
            }))
            .unwrap(),
            None,
        )
        .await
        .expect("accepted"),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn evidence_named_on_hypothesis_assessment_for_a_promoted_hypothesis_lands_on_research_validity(
    pool: PgPool,
) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let hyp_frame = ensure_frame(&pool, "hypothesis_assessment").await;
    let rv_frame = ensure_frame(&pool, "research_validity").await;
    let promoted = hypothesis(&pool, "promoted").await;
    let active = hypothesis(&pool, "active").await;

    // CALIBRATION: an unpromoted hypothesis's evidence goes where it was named.
    submit(&server, &viewer, active, hyp_frame).await;
    assert_eq!(frames_with_bbas(&pool, active).await, vec![hyp_frame]);

    let out = submit(&server, &viewer, promoted, hyp_frame).await;
    assert_eq!(
        frames_with_bbas(&pool, promoted).await,
        vec![rv_frame],
        "a promoted hypothesis's evidence is filed on research_validity, where its readers \
         look: {out}"
    );
    let warned = out["warnings"].as_array().is_some_and(|w| {
        w.iter().any(|s| {
            s.as_str()
                .is_some_and(|s| s.contains("research_validity") && s.contains("promoted"))
        })
    });
    assert!(warned, "the response says where the evidence went: {out}");
}

/// The redirect refuses a `research_validity` frame whose hypothesis count
/// differs from the named frame's (the caller's masses would not address it):
/// a CALLER error (invalid params, as the REST twin's 400), with the reason
/// and nothing written, not an internal error.
#[sqlx::test(migrations = "../../migrations")]
async fn a_redirect_onto_a_mismatched_research_validity_frame_is_a_caller_error(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let hyp_frame = ensure_frame(&pool, "hypothesis_assessment").await;
    sqlx::query(
        "INSERT INTO frames (name, hypotheses) VALUES ('research_validity', \
                ARRAY['valid','invalid','undetermined']::text[]) \
         ON CONFLICT (name) DO UPDATE SET hypotheses = EXCLUDED.hypotheses",
    )
    .execute(&pool)
    .await
    .expect("a three-hypothesis research_validity frame");
    let promoted = hypothesis(&pool, "promoted").await;

    let err = tools::ds::submit_ds_evidence(
        &server,
        &viewer,
        serde_json::from_value(serde_json::json!({
            "claim_id": promoted.to_string(),
            "frame_id": hyp_frame.to_string(),
            "hypothesis_index": 0,
            "masses": {"1": 0.7, "0,1": 0.3},
        }))
        .unwrap(),
        None,
    )
    .await
    .expect_err("the masses cannot address the target frame");
    assert_eq!(
        err.code,
        rmcp::model::ErrorCode::INVALID_PARAMS,
        "a caller error, not an internal one: {err:?}"
    );
    assert!(
        err.message.contains("research_validity") && err.message.contains("nothing was written"),
        "{}",
        err.message
    );
    assert!(
        frames_with_bbas(&pool, promoted).await.is_empty(),
        "nothing written"
    );
    let bound: i64 = sqlx::query_scalar("SELECT count(*) FROM claim_frames WHERE claim_id = $1")
        .bind(promoted)
        .fetch_one(&pool)
        .await
        .expect("claim_frames");
    assert_eq!(bound, 0, "no frame binding either");
}

/// A redirected write's frame-scoped checks are made against the frame the BBA
/// is FILED on: `research_validity` here carries an `evidence_type_weights`
/// override for a custom evidence type that `hypothesis_assessment` does not.
/// The BBA is combined at that override's weight, so the response must not
/// warn that the type falls to the 0.5 unknown-type reliability.
#[sqlx::test(migrations = "../../migrations")]
async fn a_redirected_write_checks_its_evidence_type_against_the_frame_it_is_filed_on(
    pool: PgPool,
) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let hyp_frame = ensure_frame(&pool, "hypothesis_assessment").await;
    let rv_frame = ensure_frame(&pool, "research_validity").await;
    sqlx::query(
        "UPDATE frames SET properties = COALESCE(properties, '{}'::jsonb) \
              || '{\"evidence_type_weights\": {\"r8_bench_assay\": 0.8}}'::jsonb \
          WHERE id = $1",
    )
    .bind(rv_frame)
    .execute(&pool)
    .await
    .expect("research_validity's override");
    let promoted = hypothesis(&pool, "promoted").await;

    let out = first_text(
        &tools::ds::submit_ds_evidence(
            &server,
            &viewer,
            serde_json::from_value(serde_json::json!({
                "claim_id": promoted.to_string(),
                "frame_id": hyp_frame.to_string(),
                "hypothesis_index": 0,
                "masses": {"1": 0.7, "0,1": 0.3},
                "evidence_type": "r8_bench_assay",
            }))
            .unwrap(),
            None,
        )
        .await
        .expect("accepted"),
    );
    assert_eq!(
        frames_with_bbas(&pool, promoted).await,
        vec![rv_frame],
        "CALIBRATION: redirected: {out}"
    );
    assert!(
        out.get("unknown_keys")
            .is_none_or(|k| k == &serde_json::json!([])),
        "the filed-on frame's override resolves the type: {out}"
    );
    let vocab_warning = out["warnings"].as_array().is_some_and(|w| {
        w.iter().any(|s| {
            s.as_str()
                .is_some_and(|s| s.contains("not in the calibration vocabulary"))
        })
    });
    assert!(!vocab_warning, "no unknown-type warning: {out}");
}

async fn update_with_evidence(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim: Uuid,
) -> serde_json::Value {
    first_text(
        &tools::claims::update_with_evidence(
            server,
            viewer,
            epigraph_mcp::types::UpdateWithEvidenceParams {
                canonical_name: None,
                step_index: None,
                claim_id: claim.to_string(),
                evidence_type: "empirical".into(),
                evidence_data: format!("r17 bench result {}", Uuid::new_v4()),
                source_url: None,
                supports: true,
                strength: 0.8,
                labels: Vec::new(),
            },
            None,
        )
        .await
        .expect("update_with_evidence accepted"),
    )
}

/// The frames holding the BBA of an evidence row (`mass_functions.evidence_id`).
async fn frames_of_evidence_bbas(pool: &PgPool, claim: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT f.name FROM mass_functions mf JOIN frames f ON f.id = mf.frame_id \
          WHERE mf.claim_id = $1 AND mf.evidence_id IS NOT NULL ORDER BY mf.created_at, mf.id",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read evidence BBAs")
}

/// Operator ruling R-17 (backlog 0e013aa8): R-8 covers MCP
/// `update_with_evidence`. Its BBA used to go on `binary_truth` whatever the
/// claim, and no reader of a PROMOTED hypothesis reads that frame: the status
/// reads the latest `research_validity` BBA. So the evidence never reached the
/// displayed belief. It is now filed on `research_validity` for a promoted
/// hypothesis, INSTEAD of `binary_truth`. The cache fold reads every
/// two-hypothesis frame, so filing it on both would count it twice there, the
/// double read the promotion's move (846b808e) removed.
#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_on_a_promoted_hypothesis_lands_on_research_validity(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    ensure_frame(&pool, "hypothesis_assessment").await;
    let rv_frame = ensure_frame(&pool, "research_validity").await;
    let promoted = hypothesis(&pool, "promoted").await;
    let active = hypothesis(&pool, "active").await;

    // CALIBRATION: an unpromoted claim's evidence goes on binary_truth.
    update_with_evidence(&server, &viewer, active).await;
    assert_eq!(
        frames_of_evidence_bbas(&pool, active).await,
        vec!["binary_truth".to_string()]
    );

    let out = update_with_evidence(&server, &viewer, promoted).await;
    assert_eq!(
        frames_of_evidence_bbas(&pool, promoted).await,
        vec!["research_validity".to_string()],
        "a promoted hypothesis's evidence is filed on research_validity, once: {out}"
    );
    // The promoted status reader reads the latest research_validity row.
    let latest = epigraph_db::MassFunctionRepository::get_for_claim_frame(
        &pool, &viewer, promoted, rv_frame,
    )
    .await
    .expect("research_validity rows")
    .pop()
    .expect("a research_validity row");
    assert!(
        latest.evidence_id.is_some()
            && latest.masses.get("0").and_then(serde_json::Value::as_f64) > Some(0.0),
        "the status reader's row is this supporting evidence: {latest:?}"
    );
    assert!(
        out["pignistic_prob"].as_f64() > Some(0.5),
        "the claim's cached belief still folds the evidence: {out}"
    );
}

/// R-17 on the path most production calls take: a NON-OWNER (migration 114)
/// attaching evidence to a promoted hypothesis that the memberless world group
/// owns, with every connection of the server on the application role (a
/// superuser pool bypasses RLS and would make this arm vacuous). The evidence
/// BBA is the writer's and lands on `research_validity` only; the claim-owned
/// frame binding the promotion made is kept, and the claim row is not written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_owners_update_on_a_promoted_world_hypothesis_lands_on_research_validity(
    pool: PgPool,
) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(&pool)
            .await
            .expect("read epigraph_app");
    assert!(!bypassrls, "CALIBRATION: epigraph_app does not bypass RLS");
    let url = fixture::database_url_for(&pool).await;
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &url,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let server = build_scoped_test_server(plain, scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("viewer");

    sqlx::query(
        "INSERT INTO frames (name, hypotheses) VALUES ('binary_truth', ARRAY['TRUE','FALSE']::text[]) \
         ON CONFLICT (name) DO NOTHING",
    )
    .execute(&pool)
    .await
    .expect("binary_truth");
    ensure_frame(&pool, "hypothesis_assessment").await;
    let rv_frame = ensure_frame(&pool, "research_validity").await;
    let claim = seed_claim(&pool, "r17 world hypothesis someone else wrote", 0.5).await;
    sqlx::query(
        "UPDATE claims SET labels = ARRAY['hypothesis'], \
                properties = COALESCE(properties, '{}'::jsonb) \
                             || '{\"hypothesis_status\": \"promoted\"}'::jsonb \
          WHERE id = $1",
    )
    .bind(claim)
    .execute(&pool)
    .await
    .expect("a promoted hypothesis");
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0)",
    )
    .bind(claim)
    .bind(rv_frame)
    .execute(&pool)
    .await
    .expect("the promotion's research_validity binding");
    let owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("owner");
    assert!(
        !viewer.writable_groups().contains(&owner),
        "CALIBRATION: the caller cannot write the claim's group"
    );
    let truth_before: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("truth");

    let out = update_with_evidence(&server, &viewer, claim).await;
    assert_eq!(out["evidence_owner"], "writer", "CALIBRATION: {out}");
    assert_eq!(out["truth_written"], false, "{out}");
    assert_eq!(
        frames_of_evidence_bbas(&pool, claim).await,
        vec!["research_validity".to_string()],
        "a non-owner's evidence on a promoted hypothesis is filed on research_validity: {out}"
    );
    let bound: Vec<(Uuid, Option<i32>)> = sqlx::query_as(
        "SELECT frame_id, hypothesis_index FROM claim_frames \
          WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(claim)
    .bind(rv_frame)
    .fetch_all(&pool)
    .await
    .expect("binding");
    assert_eq!(bound, vec![(rv_frame, Some(0))], "the binding is kept");
    let truth_after: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("truth");
    assert_eq!(truth_after, truth_before, "the claim row is not written");
}
