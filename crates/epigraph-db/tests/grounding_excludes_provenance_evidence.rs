//! Provenance-only evidence does not ground a claim (backlog 2d60f619 review).
//!
//! `ClaimRepository::has_grounded_evidence` (the experiment loop's circularity
//! guard, HTTP and CLI) and `ClaimRepository::grounded_neighborhood` (the
//! hypothesis neighbourhood) count an `evidence -> claim` `supports` edge as
//! grounding, and their documented rule is that a claim supported only by
//! other claims is NOT grounded. Since 2d60f619 every evidence row stores that
//! edge, including two kinds of row that carry no evidence of their own:
//!
//! * a DERIVATION row, written by `EvidenceRepository::record_derivation_conn`
//!   (`POST /claims {derived_from}`, decomposition): its text is the parent
//!   claim's, so its edge is claim-to-claim propagation;
//! * a MEMORIZE stamp (`properties.source = 'mcp-memorize'`): its text is
//!   "stored via MCP memorize tool".
//!
//! Each reader is tested on its own (each spells the rule separately), with a
//! control row of ordinary evidence whose edge does ground. Both readers fail
//! on the commit before this rule: the derivation and stamp edges grounded.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{ClaimRepository, DerivationEvidence, EvidenceDirection, EvidenceRepository};
use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;

/// A pgvector literal of 1536 copies of `x`.
fn vec_literal(x: f32) -> String {
    let v: Vec<String> = (0..1536).map(|_| format!("{x}")).collect();
    format!("[{}]", v.join(","))
}

async fn public_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, content).await;
    fixture::set_claim_embedding(pool, id, &vec_literal(0.5)).await;
    id
}

/// Link `evidence` to `claim` through the one evidence-edge helper.
async fn link(pool: &PgPool, evidence: Uuid, claim: Uuid) {
    let mut conn = pool.acquire().await.expect("conn");
    let links = EvidenceRepository::link_to_claims_signed_conn(
        &mut conn,
        None,
        evidence,
        &[claim],
        EvidenceDirection::Supports,
    )
    .await
    .expect("link evidence");
    assert!(links.iter().all(|l| l.created), "{links:?}");
}

struct Fx {
    agent: Uuid,
    /// Ordinary evidence with a `supports` edge: grounded (the control).
    grounded: Uuid,
    /// Only a derivation row from `parent`: not grounded.
    derived: Uuid,
    /// Only a memorize stamp: not grounded.
    memorized: Uuid,
}

async fn seed(pool: &PgPool, tag: &str) -> Fx {
    let (agent, _) = fixture::seed_agent_with_group(pool, tag).await;
    let grounded = public_claim(pool, agent, "grounded by evidence").await;
    let parent = public_claim(pool, agent, "the parent's text").await;
    let derived = public_claim(pool, agent, "derived from the parent").await;
    let memorized = public_claim(pool, agent, "a memorized claim").await;

    let ev = fixture::seed_evidence(pool, grounded, "observation").await;
    link(pool, ev, grounded).await;

    // The real derivation writer, which stores its edge itself.
    let viewer = fixture::public_viewer(pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    let rec = EvidenceRepository::record_derivation_conn(
        &mut conn,
        &viewer,
        None,
        derived,
        parent,
        "decomposition",
    )
    .await
    .expect("record derivation");
    assert!(
        matches!(rec, DerivationEvidence::Recorded(_)),
        "control: the derivation row is written: {rec:?}"
    );
    let derivation_edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_type = 'evidence' \
            AND target_type = 'claim' AND target_id = $1 AND relationship = 'supports'",
    )
    .bind(derived)
    .fetch_one(pool)
    .await
    .expect("count");
    assert_eq!(derivation_edges, 1, "control: the derivation row has its edge");

    // The shape `memorize` writes: a testimony whose source is the tool.
    let stamp: Uuid = sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content, properties) \
         VALUES ($1, 'testimony', $2, 'Memory stored via MCP memorize tool', $3) RETURNING id",
    )
    .bind(memorized)
    .bind(vec![7u8; 32])
    .bind(serde_json::json!({
        "type": "testimony",
        "source": "mcp-memorize",
        "testified_at": "2026-11-13T00:00:00Z",
        "verification": null
    }))
    .fetch_one(pool)
    .await
    .expect("memorize stamp");
    link(pool, stamp, memorized).await;

    Fx {
        agent,
        grounded,
        derived,
        memorized,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn has_grounded_evidence_ignores_derivation_and_memorize_edges(pool: PgPool) {
    let fx = seed(&pool, "grounding-has").await;
    let viewer = fixture::public_viewer(&pool).await;
    let mut got = Vec::new();
    for c in [fx.grounded, fx.derived, fx.memorized] {
        got.push(
            ClaimRepository::has_grounded_evidence(&pool, &viewer, c)
                .await
                .expect("has_grounded_evidence"),
        );
    }
    assert!(got[0], "control: ordinary evidence grounds");
    assert!(
        !got[1],
        "a derivation row is the parent claim's text: claim-to-claim, not grounding"
    );
    assert!(!got[2], "a memorize stamp is not grounding");
}

#[sqlx::test(migrations = "../../migrations")]
async fn grounded_neighborhood_ignores_derivation_and_memorize_edges(pool: PgPool) {
    let fx = seed(&pool, "grounding-nbhd").await;
    let probe = public_claim(&pool, fx.agent, "the probe").await;
    let viewer = fixture::public_viewer(&pool).await;
    let near: BTreeSet<Uuid> =
        ClaimRepository::grounded_neighborhood(&pool, &viewer, &vec_literal(0.5), probe, 0.5, 50)
            .await
            .expect("grounded_neighborhood")
            .into_iter()
            .map(|n| n.id)
            .collect();
    assert_eq!(
        near,
        BTreeSet::from([fx.grounded]),
        "only the claim with real evidence is a grounded neighbour"
    );
}
