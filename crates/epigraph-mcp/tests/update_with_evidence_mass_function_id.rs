//! Backlog b191f198: `update_with_evidence` must return the id of the BBA it
//! stored, so a caller can hand it to `retract_bba`.
//!
//! The BBA was always stored in `mass_functions`, keyed on the evidence row's
//! slot, but the response carried only `evidence_id`, and `retract_bba` takes a
//! `mass_function_id`: passing it the evidence id answers "mass function ...
//! not found". The caller had no handle on the row its own call wrote.
//!
//! Driven on the application role (no BYPASSRLS), over HTTP auth, on a claim
//! the caller owns, so the handle is exercised exactly as a client would use
//! it: update, then retract the returned id.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::bba_retract::{retract_bba, RetractBbaParams};
use epigraph_mcp::types::UpdateWithEvidenceParams;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: the app-role premise is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    build_scoped_test_server(plain, scoped)
}

async fn owned_public_claim(pool: &PgPool, agent: Uuid, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.7, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("b191f198 update handle {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_returned_mass_function_id_is_this_calls_bba_and_retract_bba_accepts_it(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (owner, auth, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let group = personal_group_of(&pool, owner).await;
    let claim = owned_public_claim(&pool, owner, group).await;

    let result = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim.to_string(),
            evidence_type: "empirical".into(),
            evidence_data: format!("b191f198 evidence for {claim}"),
            source_url: None,
            supports: true,
            strength: 0.8,
            labels: Vec::new(),
        },
        Some(&auth),
    )
    .await
    .expect("update_with_evidence ok");
    let json = first_text(&result);

    let mf_id: Uuid = json["mass_function_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            panic!(
                "update_with_evidence must return the id of the BBA it stored \
                 (mass_function_id); got {json}"
            )
        });
    let evidence_id: Uuid = json["evidence_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("evidence_id");
    assert_ne!(
        mf_id, evidence_id,
        "the BBA id is the mass_functions row, not the evidence row"
    );

    // It names THIS call's evidence BBA: the row carrying this evidence id on
    // this claim, not the truth_value seed the same first update also wrote.
    let (row_claim, row_evidence, row_method): (Uuid, Option<Uuid>, Option<String>) =
        sqlx::query_as(
            "SELECT claim_id, evidence_id, combination_method FROM mass_functions WHERE id = $1",
        )
        .bind(mf_id)
        .fetch_one(&pool)
        .await
        .expect("the returned id is a mass_functions row");
    assert_eq!(row_claim, claim);
    assert_eq!(row_evidence, Some(evidence_id));
    assert_eq!(row_method.as_deref(), Some("auto_wire"));
    let seeds: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions WHERE claim_id = $1 \
           AND combination_method = 'truth_value_seed'",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("count seeds");
    assert_eq!(
        seeds, 1,
        "fixture: the first update on a BBA-less claim also seeds its truth_value, \
         so the returned id is distinguishable from that row"
    );

    // The handle works: retract_bba accepts it and retracts that row.
    let retracted = retract_bba(
        &server,
        &viewer,
        RetractBbaParams {
            mass_function_id: mf_id.to_string(),
            reason: "b191f198: undo an update_with_evidence BBA".to_string(),
        },
        Some(&auth),
    )
    .await
    .unwrap_or_else(|e| panic!("retract_bba refused the returned id: {}", e.message));
    let body = first_text(&retracted);
    assert_eq!(body["status"].as_str(), Some("retracted"), "{body}");
    let retracted_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT retracted_at FROM mass_functions WHERE id = $1")
            .bind(mf_id)
            .fetch_one(&pool)
            .await
            .expect("read retracted_at");
    assert!(retracted_at.is_some(), "the row is retracted");
}
