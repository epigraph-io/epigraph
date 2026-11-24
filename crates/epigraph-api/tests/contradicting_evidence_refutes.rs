#![cfg(feature = "db")]
//! `GET /api/v1/claims/:id/contradicting-evidence` returns the evidence the
//! current writers store as `refutes`, not only legacy `CONTRADICTS` rows
//! (backlog 548a3c42).
//!
//! Every evidence write stores its `evidence -> claim` edge with the canonical
//! spelling of its direction (`supports` / `refutes`, backlog 2d60f619). The
//! route used to ask `by_relationship_for_claim` for `CONTRADICTS`, which
//! expands to `contradicts` / `CONTRADICTS` and never to `refutes`, so a claim
//! whose refuting evidence was written through the current path looked
//! uncontested.
//!
//! Each test seeds, against ONE subject claim:
//!
//! * `refuting`: evidence written through `EvidenceRepository::create` with
//!   `EvidenceEdge::refutes`, the current write path (`refutes` edge);
//! * `legacy`: an evidence row hosted on a DIFFERENT claim (so the repository
//!   writes none of its own edges onto the subject) with a hand-written legacy
//!   upper-case `CONTRADICTS` edge to the subject;
//! * `supporting`: evidence written with `EvidenceEdge::supports`, the polarity
//!   control that must never appear among the objections.
//!
//! Assertions compare id SETS, so a route that returns the right count of the
//! wrong rows still fails.

mod viewer_fixture;

use axum::extract::{Path, Query, State};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::edges::{
    contradicting_evidence, supporting_evidence, EvidenceAccessParams,
};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_core::{AgentId, ClaimId, Evidence, EvidenceType};
use epigraph_db::{EvidenceEdge, EvidenceRepository};
use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;
use viewer_fixture::{
    public_viewer, scoped_pool, seed_agent_with_group, seed_evidence, seed_public_claim,
};

/// A text `Document` evidence row by `agent` on `claim`.
fn document(agent: Uuid, claim: Uuid, body: &str) -> Evidence {
    Evidence::new(
        AgentId::from_uuid(agent),
        [0u8; 32],
        *blake3::hash(body.as_bytes()).as_bytes(),
        EvidenceType::Document {
            source_url: None,
            mime_type: "text/plain".to_string(),
            checksum: None,
        },
        Some(body.to_string()),
        ClaimId::from_uuid(claim),
    )
}

/// One `evidence -> claim` edge with an explicit relationship spelling, as a
/// writer that predates the canonical spelling stored it. Tenancy is left to
/// migration 070's trigger: both endpoints are public, so the edge is too.
async fn legacy_edge(pool: &PgPool, evidence: Uuid, claim: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'evidence', $2, 'claim', $3)",
    )
    .bind(evidence)
    .bind(claim)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed legacy edge");
}

struct Seeded {
    subject: Uuid,
    refuting: Uuid,
    legacy: Uuid,
    supporting: Uuid,
}

async fn seed(pool: &PgPool) -> Seeded {
    let (agent, _) = seed_agent_with_group(pool, "t40-contra").await;
    let subject = seed_public_claim(pool, agent, "t40: the contested claim").await;
    let elsewhere = seed_public_claim(pool, agent, "t40: the legacy row's host").await;

    let refuting = EvidenceRepository::create(
        pool,
        &document(agent, subject, "t40: evidence against the claim"),
        EvidenceEdge::refutes(None),
    )
    .await
    .expect("refuting evidence through the current write path")
    .id
    .as_uuid();

    let supporting = EvidenceRepository::create(
        pool,
        &document(agent, subject, "t40: evidence for the claim"),
        EvidenceEdge::supports(None),
    )
    .await
    .expect("supporting evidence through the current write path")
    .id
    .as_uuid();

    let legacy = seed_evidence(pool, elsewhere, "figure").await;
    legacy_edge(pool, legacy, subject, "CONTRADICTS").await;

    // Calibration: the write path stored exactly the spellings this file is
    // about. If a future writer changes them, the route assertions below
    // would be measuring something else.
    let stored: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT source_id, relationship FROM edges \
          WHERE target_id = $1 AND target_type = 'claim' AND source_type = 'evidence' \
          ORDER BY relationship",
    )
    .bind(subject)
    .fetch_all(pool)
    .await
    .expect("stored edges");
    let stored: BTreeSet<(Uuid, String)> = stored.into_iter().collect();
    assert_eq!(
        stored,
        BTreeSet::from([
            (legacy, "CONTRADICTS".to_string()),
            (refuting, "refutes".to_string()),
            (supporting, "supports".to_string()),
        ]),
        "CALIBRATION: the subject's evidence edges must be one refutes (current \
         writer), one legacy CONTRADICTS and one supports"
    );

    Seeded {
        subject,
        refuting,
        legacy,
        supporting,
    }
}

async fn state(pool: &PgPool) -> AppState {
    AppState::with_scoped_pool(scoped_pool(pool).await, ApiConfig::default())
}

#[sqlx::test(migrations = "../../migrations")]
async fn contradicting_evidence_returns_refutes_and_legacy_contradicts(pool: PgPool) {
    let s = seed(&pool).await;
    let viewer = public_viewer(&pool).await;

    let out = contradicting_evidence(
        State(state(&pool).await),
        Path(s.subject),
        Query(EvidenceAccessParams { agent_id: None }),
        ViewerExtractor(viewer),
    )
    .await
    .expect("a public claim's contradicting evidence must serve")
    .0;

    let got: BTreeSet<Uuid> = out.evidence.iter().map(|e| e.evidence_id).collect();
    assert_eq!(
        got,
        BTreeSet::from([s.refuting, s.legacy]),
        "contradicting-evidence must return the refutes row the current writer stored \
         ({}) AND the legacy CONTRADICTS row ({}), and never the supports row ({})",
        s.refuting,
        s.legacy,
        s.supporting
    );
    assert_eq!(out.total, 2, "total must count what the body lists");
    assert_eq!(
        out.relationship, "CONTRADICTS",
        "the response label is part of the route's contract and is unchanged"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn supporting_evidence_returns_only_supports(pool: PgPool) {
    let s = seed(&pool).await;
    let viewer = public_viewer(&pool).await;

    let out = supporting_evidence(
        State(state(&pool).await),
        Path(s.subject),
        Query(EvidenceAccessParams { agent_id: None }),
        ViewerExtractor(viewer),
    )
    .await
    .expect("a public claim's supporting evidence must serve")
    .0;

    let got: BTreeSet<Uuid> = out.evidence.iter().map(|e| e.evidence_id).collect();
    assert_eq!(
        got,
        BTreeSet::from([s.supporting]),
        "supporting-evidence must return the supports row ({}) and neither the refutes \
         ({}) nor the legacy CONTRADICTS ({}) row",
        s.supporting,
        s.refuting,
        s.legacy
    );
    assert_eq!(out.relationship, "SUPPORTS");
}

/// One evidence row can carry BOTH weakening relationships to the same claim:
/// the writer's `refutes` edge plus an explicit `contradicts` edge posted
/// through the generic edge route. Matching `contradicts` and `refutes`
/// together must still list that evidence once, and `total` must count
/// evidence, not edges.
#[sqlx::test(migrations = "../../migrations")]
async fn contradicting_evidence_lists_an_evidence_row_once_across_relationships(pool: PgPool) {
    let s = seed(&pool).await;
    legacy_edge(&pool, s.refuting, s.subject, "contradicts").await;
    let viewer = public_viewer(&pool).await;

    let out = contradicting_evidence(
        State(state(&pool).await),
        Path(s.subject),
        Query(EvidenceAccessParams { agent_id: None }),
        ViewerExtractor(viewer),
    )
    .await
    .expect("a public claim's contradicting evidence must serve")
    .0;

    let mut got: Vec<Uuid> = out.evidence.iter().map(|e| e.evidence_id).collect();
    got.sort();
    let mut want = vec![s.refuting, s.legacy];
    want.sort();
    assert_eq!(
        got, want,
        "the refuting evidence ({}) has a refutes AND a contradicts edge to the claim; \
         it must be listed once, next to the legacy row ({})",
        s.refuting, s.legacy
    );
    assert_eq!(
        out.total, 2,
        "total counts evidence rows, not matching edges"
    );
}
