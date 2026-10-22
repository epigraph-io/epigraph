//! Every MCP path that writes a BBA must store the CANONICAL evidence type it
//! actually knows in `mass_functions.evidence_type` (backlog bc06ec6f).
//!
//! The canonical keys are the `[evidence_type_weights]` keys of
//! `calibration.toml`; the DB-vocabulary tags an evidence row carries
//! (`observation`, `testimony`, `reference`, `document`, `computation`) resolve
//! to them through `[evidence_type_aliases]`. A writer that knows a type only
//! from its OWN evidence row resolves that row's tag through the alias map. A
//! writer that does not know the type stores NULL; nothing here guesses.
//!
//! Each test goes through the real tool, then reads the stored row back.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::tools;
use epigraph_mcp::tools::ds_auto::{auto_wire_ds_batch, auto_wire_ds_update, BatchDsEntry};
use epigraph_mcp::types::{
    MemorizeParams, ReportWorkflowOutcomeParams, StepExecution, SubmitClaimParams,
    SubmitDsEvidenceParams, UpdateWithEvidenceParams,
};
use sqlx::PgPool;
use uuid::Uuid;

/// The `evidence_type` of every `auto_wire` BBA stored for `claim_id`.
async fn auto_wire_types(pool: &PgPool, claim_id: Uuid) -> Vec<Option<String>> {
    sqlx::query_scalar(
        "SELECT evidence_type FROM mass_functions \
         WHERE claim_id = $1 AND combination_method = 'auto_wire' ORDER BY created_at",
    )
    .bind(claim_id)
    .fetch_all(pool)
    .await
    .expect("read auto_wire BBAs")
}

async fn claim_id_by_content(pool: &PgPool, content: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("claim row")
}

/// `memorize` writes its own evidence row as `EvidenceType::Testimony`
/// (DB tag `testimony`) in the same transaction as the BBA. That row is the
/// caller's own evidence, so the BBA carries its alias-resolved canonical type,
/// `testimonial`. It used to store NULL.
#[sqlx::test(migrations = "../../migrations")]
async fn memorize_types_its_bba_from_its_own_testimony_evidence(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let content = format!("bc06ec6f memorize typing {}", Uuid::new_v4());

    tools::memory::memorize(
        &server,
        &viewer,
        MemorizeParams {
            content: content.clone(),
            confidence: Some(0.7),
            tags: None,
            novelty_threshold: None,
        },
        None,
    )
    .await
    .expect("memorize");

    let claim_id = claim_id_by_content(&pool, &content).await;
    // Non-vacuity: the evidence row the type comes from is the one memorize wrote.
    let ev_types: Vec<String> =
        sqlx::query_scalar("SELECT evidence_type FROM evidence WHERE claim_id = $1")
            .bind(claim_id)
            .fetch_all(&pool)
            .await
            .expect("evidence rows");
    assert_eq!(
        ev_types,
        vec!["testimony".to_string()],
        "memorize's own evidence row"
    );
    assert_eq!(
        auto_wire_types(&pool, claim_id).await,
        vec![Some("testimonial".to_string())],
        "memorize's BBA must carry the canonical type of its own evidence row"
    );
}

/// `submit_claim` accepts its `evidence_type` case-insensitively
/// (`parse_evidence_type`), so the stored tag must be the canonical lowercase
/// key, not the caller's spelling. It used to store the raw string.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_stores_the_canonical_key_not_the_callers_spelling(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let content = format!("bc06ec6f submit_claim typing {}", Uuid::new_v4());

    tools::claims::submit_claim(
        &server,
        &viewer,
        SubmitClaimParams {
            content: content.clone(),
            evidence_data: "a measured value".to_string(),
            evidence_type: "Empirical".to_string(),
            methodology: "bayesian".to_string(),
            confidence: 0.7,
            source_url: None,
            reasoning: None,
            labels: vec![],
            novelty_threshold: None,
        },
        None,
    )
    .await
    .expect("submit_claim");

    let claim_id = claim_id_by_content(&pool, &content).await;
    assert_eq!(
        auto_wire_types(&pool, claim_id).await,
        vec![Some("empirical".to_string())]
    );
}

/// `update_with_evidence`: same contract as `submit_claim`.
#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_stores_the_canonical_key(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let claim_id = seed_claim(&pool, &format!("bc06ec6f uwe {}", Uuid::new_v4()), 0.5).await;

    tools::claims::update_with_evidence(
        &server,
        &viewer,
        UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim_id.to_string(),
            evidence_type: "Logical".to_string(),
            evidence_data: "a derivation".to_string(),
            source_url: None,
            supports: true,
            strength: 0.8,
            labels: vec![],
        },
        None,
    )
    .await
    .expect("update_with_evidence");

    assert_eq!(
        auto_wire_types(&pool, claim_id).await,
        vec![Some("logical".to_string())]
    );
}

/// `report_workflow_outcome` (legacy claim-backed workflow) writes its own
/// evidence row as `EvidenceType::Observation` and used to copy the raw DB tag
/// `observation` onto the BBA. The BBA must carry the canonical key
/// `empirical` that tag resolves to.
#[sqlx::test(migrations = "../../migrations")]
async fn report_workflow_outcome_stores_the_canonical_key_of_its_observation(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let claim_id = seed_workflow_claim(&pool, "bc06ec6f workflow outcome", &["s1"]).await;

    tools::workflows::report_workflow_outcome(
        &server,
        &viewer,
        ReportWorkflowOutcomeParams {
            workflow_id: claim_id.to_string(),
            success: true,
            execution_log: vec![StepExecution {
                step_index: 0,
                planned: "s1".to_string(),
                actual: "s1".to_string(),
                deviated: false,
                deviation_reason: None,
            }],
            outcome_details: "ran".to_string(),
            quality: Some(0.8),
            goal_text: None,
        },
        None,
    )
    .await
    .expect("report_workflow_outcome");

    let ev_types: Vec<String> =
        sqlx::query_scalar("SELECT evidence_type FROM evidence WHERE claim_id = $1")
            .bind(claim_id)
            .fetch_all(&pool)
            .await
            .expect("evidence rows");
    assert_eq!(
        ev_types,
        vec!["observation".to_string()],
        "its own evidence row"
    );
    assert_eq!(
        auto_wire_types(&pool, claim_id).await,
        vec![Some("empirical".to_string())]
    );
}

fn ds_params(
    claim_id: Uuid,
    frame_id: Uuid,
    evidence_type: Option<&str>,
) -> SubmitDsEvidenceParams {
    SubmitDsEvidenceParams {
        claim_id: claim_id.to_string(),
        frame_id: frame_id.to_string(),
        hypothesis_index: 0,
        masses: serde_json::json!({"0": 0.8, "~": 0.2}),
        reliability: None,
        combination_method: None,
        gamma: None,
        perspective_id: None,
        evidence_type: evidence_type.map(str::to_string),
        locality_tag: None,
    }
}

async fn ds_stored_type(pool: &PgPool, claim_id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT evidence_type FROM mass_functions WHERE claim_id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("exactly one BBA")
}

/// `submit_ds_evidence` with a DB-vocabulary alias stores the canonical key;
/// with an unknown key it keeps the caller's key (lowercased: every reader
/// lowercases), because per-frame overrides may key on it deliberately; with
/// no type it stores NULL (its masses were pre-discounted by `reliability`, so
/// typing them would discount twice).
#[sqlx::test(migrations = "../../migrations")]
async fn submit_ds_evidence_resolves_aliases_and_never_invents_a_type(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let frame_id = epigraph_mcp::tools::ds_auto::ensure_binary_frame(
        &mut pool.acquire().await.expect("acquire"),
        &viewer,
    )
    .await
    .expect("binary frame");

    let aliased = seed_claim(&pool, &format!("bc06ec6f ds alias {}", Uuid::new_v4()), 0.5).await;
    tools::ds::submit_ds_evidence(
        &server,
        &viewer,
        ds_params(aliased, frame_id, Some("Testimony")),
        None,
    )
    .await
    .expect("submit_ds_evidence alias");
    assert_eq!(
        ds_stored_type(&pool, aliased).await.as_deref(),
        Some("testimonial")
    );

    let unknown = seed_claim(
        &pool,
        &format!("bc06ec6f ds unknown {}", Uuid::new_v4()),
        0.5,
    )
    .await;
    tools::ds::submit_ds_evidence(
        &server,
        &viewer,
        ds_params(unknown, frame_id, Some("Western_Clinical")),
        None,
    )
    .await
    .expect("submit_ds_evidence unknown key");
    assert_eq!(
        ds_stored_type(&pool, unknown).await.as_deref(),
        Some("western_clinical")
    );

    let untyped = seed_claim(&pool, &format!("bc06ec6f ds none {}", Uuid::new_v4()), 0.5).await;
    tools::ds::submit_ds_evidence(&server, &viewer, ds_params(untyped, frame_id, None), None)
        .await
        .expect("submit_ds_evidence untyped");
    assert_eq!(ds_stored_type(&pool, untyped).await, None);
}

/// `auto_wire_ds_update` as `backfill_factors` calls it: the type comes from a
/// linked evidence row's DB tag (`reference`), which must be stored as the
/// canonical key it resolves to (`logical`), not copied raw.
#[sqlx::test(migrations = "../../migrations")]
async fn auto_wire_ds_update_resolves_a_linked_evidence_tag(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim(&pool, &format!("bc06ec6f update {}", Uuid::new_v4()), 0.5).await;
    let agent = seed_agent(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");

    auto_wire_ds_update(
        &mut conn,
        &viewer,
        claim_id,
        agent,
        1.0,
        0.85,
        true,
        Some("reference"),
        None,
        false, // seed_truth_prior: backfill_factors does not seed (ds_auto doc)
    )
    .await
    .expect("auto_wire_ds_update");

    assert_eq!(
        auto_wire_types(&pool, claim_id).await,
        vec![Some("logical".to_string())]
    );
}

/// The ingest batch path (`auto_wire_ds_batch`) canonicalizes too; an entry
/// with no type stays NULL.
#[sqlx::test(migrations = "../../migrations")]
async fn auto_wire_ds_batch_canonicalizes_and_keeps_none(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let typed = seed_claim(
        &pool,
        &format!("bc06ec6f batch typed {}", Uuid::new_v4()),
        0.5,
    )
    .await;
    let untyped = seed_claim(
        &pool,
        &format!("bc06ec6f batch none {}", Uuid::new_v4()),
        0.5,
    )
    .await;
    let agent = seed_agent(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");

    let entries = vec![
        BatchDsEntry {
            claim_id: typed,
            confidence: 0.8,
            weight: 0.9,
            evidence_type: Some("Computation".to_string()),
            axis: None,
        },
        BatchDsEntry {
            claim_id: untyped,
            confidence: 0.8,
            weight: 0.9,
            evidence_type: None,
            axis: None,
        },
    ];
    let (_frame, wired) = auto_wire_ds_batch(&mut conn, &viewer, &entries, agent)
        .await
        .expect("auto_wire_ds_batch");
    assert_eq!(wired, 2, "both entries wired");

    assert_eq!(
        auto_wire_types(&pool, typed).await,
        vec![Some("statistical".to_string())]
    );
    assert_eq!(auto_wire_types(&pool, untyped).await, vec![None]);
}

/// Ruling Q-U027F-2: an owner's `/claims/:id/assess` slot (the owner's slot
/// perspective, keyed by the owner) is written only by assess. A
/// `submit_ds_evidence` call naming the calling agent's own slot perspective is
/// refused and writes nothing; the same call with no perspective lands.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_ds_evidence_cannot_write_into_the_callers_assessment_slot(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let agent = server.server_agent_id().await.expect("server agent");
    let frame_id = epigraph_mcp::tools::ds_auto::ensure_binary_frame(
        &mut pool.acquire().await.expect("acquire"),
        &viewer,
    )
    .await
    .expect("binary frame");
    let slot = epigraph_db::repos::mass_function::assessment_slot_perspective(Some(agent));
    // The slot perspective exists (assess created it), so only the slot rule
    // can refuse the call.
    epigraph_db::PerspectiveRepository::ensure_evidence_perspective(&pool, slot, Some(agent))
        .await
        .expect("the slot perspective");
    let claim = seed_claim(
        &pool,
        &format!("assess slot via ds {}", Uuid::new_v4()),
        0.5,
    )
    .await;
    let mut params = ds_params(claim, frame_id, None);
    params.perspective_id = Some(slot.to_string());
    let err = tools::ds::submit_ds_evidence(&server, &viewer, params, None)
        .await
        .expect_err("the caller's assessment slot is refused");
    assert!(err.message.contains("assessment slot"), "{err:?}");
    let written: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(written, 0, "nothing written");

    tools::ds::submit_ds_evidence(&server, &viewer, ds_params(claim, frame_id, None), None)
        .await
        .expect("control: no perspective lands");
}
