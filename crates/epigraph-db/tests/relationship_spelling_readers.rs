//! Readers that match an UPPER-case relationship literal must also see the
//! lower-case spelling of the same relationship (U014 PR-1, backlog
//! `3ce5e00c`).
//!
//! `edges.relationship` holds the four case-folded relationships
//! (`epigraph_core::edge::relationships::CASE_FOLDED_RELATIONSHIPS`) in two
//! spellings: MCP `link_epistemic` writes `supports` / `contradicts` /
//! `corroborates`, while the HTTP edge route, the DS evidence writers
//! (`routes/belief.rs`, `routes/assess.rs`, `routes/submit.rs`) and the
//! cross-source matcher write `SUPPORTS` / `CONTRADICTS` / `CORROBORATES`. A
//! reader that names one spelling silently drops the other's rows, and the
//! planned normalise-on-write (PR-2) and data fold (PR-3) would then blind it
//! completely. Each test below seeds the SAME relationship in both spellings
//! over different endpoints and asserts the reader returns both; the
//! upper-case row is the control that proves the read is live at all.
//!
//! Scope guard: PR-1 only adds lower-case twins to UPPER readers. It does NOT
//! widen the lower-case-only claim/claim readers to UPPER (scope §4.1 is an
//! operator ruling), so `semantic_graph_neighbors` keeps ignoring an upper-case
//! claim/claim `SUPPORTS` row, pinned below.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{ClaimRepository, EvidenceRepository, MatchCandidateRepo, StructuralRepository};
use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// A pgvector literal of 1536 copies of `x` (non-zero, so cosine is defined).
fn vec_literal(x: f32) -> String {
    let v: Vec<String> = (0..1536).map(|_| format!("{x}")).collect();
    format!("[{}]", v.join(","))
}

/// Insert one edge with an explicit relationship spelling and return its id.
/// Tenancy is left to migration 070's `edges_tenancy` trigger, which stamps a
/// public/public pair `('public', world)`.
async fn edge(
    pool: &PgPool,
    source: Uuid,
    source_type: &str,
    target: Uuid,
    target_type: &str,
    relationship: &str,
    properties: serde_json::Value,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(target_type)
    .bind(relationship)
    .bind(properties)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {relationship} edge: {e}"));
    id
}

async fn public_claim(pool: &PgPool, agent: Uuid, content: &str, emb: Option<f32>) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, content).await;
    if let Some(x) = emb {
        fixture::set_claim_embedding(pool, id, &vec_literal(x)).await;
    }
    id
}

/// `MatchCandidateRepo::corroborates_edges_for_claim` (backs
/// `GET /api/v1/claims/:id/cross-source-matches` and MCP
/// `find_cross_source_matches`) matched only `'CORROBORATES'`.
#[sqlx::test(migrations = "../../migrations")]
async fn corroborates_edges_for_claim_sees_both_spellings(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "spelling-matcher").await;
    let a = public_claim(&pool, agent, "matcher anchor", None).await;
    let b = public_claim(&pool, agent, "matcher partner upper", None).await;
    let c = public_claim(&pool, agent, "matcher partner lower", None).await;
    let props = serde_json::json!({ "source": "cross_source_matcher", "score": 0.9 });
    let upper = edge(&pool, a, "claim", b, "claim", "CORROBORATES", props.clone()).await;
    let lower = edge(&pool, c, "claim", a, "claim", "corroborates", props).await;

    let viewer = fixture::public_viewer(&pool).await;
    let got: BTreeSet<Uuid> = MatchCandidateRepo::new(pool.clone())
        .corroborates_edges_for_claim(&viewer, a)
        .await
        .expect("corroborates_edges_for_claim")
        .into_iter()
        .map(|(id, _, _, _)| id)
        .collect();

    assert!(
        got.contains(&upper),
        "control: the CORROBORATES row is read"
    );
    assert_eq!(
        got,
        BTreeSet::from([upper, lower]),
        "a lower-case `corroborates` edge is the same corroboration and must be returned"
    );
}

/// `ClaimRepository::semantic_graph_neighbors` (backs `POST /api/v1/search/
/// semantic`'s graph expansion) listed `'CORROBORATES'` but not
/// `'corroborates'`, so MCP-filed corroborations never expanded.
#[sqlx::test(migrations = "../../migrations")]
async fn semantic_graph_neighbors_sees_lowercase_corroborates(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "spelling-semantic").await;
    let a = public_claim(&pool, agent, "semantic anchor", Some(0.5)).await;
    let upper = public_claim(&pool, agent, "semantic upper neighbour", Some(0.5)).await;
    let lower = public_claim(&pool, agent, "semantic lower neighbour", Some(0.5)).await;
    let not_widened = public_claim(&pool, agent, "semantic SUPPORTS neighbour", Some(0.5)).await;
    let none = serde_json::json!({});
    edge(
        &pool,
        a,
        "claim",
        upper,
        "claim",
        "CORROBORATES",
        none.clone(),
    )
    .await;
    edge(
        &pool,
        a,
        "claim",
        lower,
        "claim",
        "corroborates",
        none.clone(),
    )
    .await;
    // Claim/claim SUPPORTS: the reader matches only lower-case `supports`
    // today, and widening it is the operator's §4.1 ruling, not PR-1.
    edge(&pool, a, "claim", not_widened, "claim", "SUPPORTS", none).await;

    let viewer = fixture::public_viewer(&pool).await;
    let got: BTreeSet<Uuid> = ClaimRepository::semantic_graph_neighbors(
        &pool,
        &viewer,
        "embedding",
        &vec_literal(0.5),
        &[a],
    )
    .await
    .expect("semantic_graph_neighbors")
    .into_iter()
    .map(|h| h.neighbor_id)
    .collect();

    assert!(
        got.contains(&upper),
        "control: the CORROBORATES neighbour is read"
    );
    assert!(
        got.contains(&lower),
        "a lower-case `corroborates` neighbour must be expanded too; got {got:?}"
    );
    assert!(
        !got.contains(&not_widened),
        "PR-1 must not widen the lower-case-only arms to upper-case SUPPORTS"
    );
}

/// Seed three public claims for the grounded readers: `g_upper` grounded by an
/// `evidence --SUPPORTS--> claim` edge, `g_lower` grounded by the same edge in
/// the lower-case spelling, and `ungrounded` with no evidence edge. Returns
/// `(agent, g_upper, g_lower, ungrounded)`.
async fn seed_grounded_pair(pool: &PgPool, tag: &str) -> (Uuid, Uuid, Uuid, Uuid) {
    let (agent, _) = fixture::seed_agent_with_group(pool, tag).await;
    let g_upper = public_claim(pool, agent, "grounded via SUPPORTS", Some(0.5)).await;
    let g_lower = public_claim(pool, agent, "grounded via supports", Some(0.5)).await;
    let ungrounded = public_claim(pool, agent, "no evidence edge", Some(0.5)).await;
    let ev_upper = fixture::seed_evidence(pool, g_upper, "document").await;
    let ev_lower = fixture::seed_evidence(pool, g_lower, "document").await;
    let none = serde_json::json!({});
    edge(
        pool,
        ev_upper,
        "evidence",
        g_upper,
        "claim",
        "SUPPORTS",
        none.clone(),
    )
    .await;
    edge(
        pool, ev_lower, "evidence", g_lower, "claim", "supports", none,
    )
    .await;
    (agent, g_upper, g_lower, ungrounded)
}

/// `ClaimRepository::has_grounded_evidence` counted
/// `evidence --SUPPORTS--> claim` as grounding but not
/// `evidence --supports--> claim`.
#[sqlx::test(migrations = "../../migrations")]
async fn has_grounded_evidence_sees_lowercase_evidence_supports(pool: PgPool) {
    let (_, g_upper, g_lower, ungrounded) =
        seed_grounded_pair(&pool, "spelling-has-grounded").await;

    let viewer = fixture::public_viewer(&pool).await;
    let mut grounded = BTreeMap::new();
    for c in [g_upper, g_lower, ungrounded] {
        let g = ClaimRepository::has_grounded_evidence(&pool, &viewer, c)
            .await
            .expect("has_grounded_evidence");
        grounded.insert(c, g);
    }
    assert!(grounded[&g_upper], "control: SUPPORTS grounds");
    assert!(!grounded[&ungrounded], "control: no edge, not grounded");
    assert!(
        grounded[&g_lower],
        "an evidence -> claim `supports` edge is grounding evidence"
    );
}

/// `ClaimRepository::grounded_neighborhood` names its grounding literal
/// separately from `has_grounded_evidence`, so it gets its own test: a revert
/// of either literal alone must go red on its own.
#[sqlx::test(migrations = "../../migrations")]
async fn grounded_neighborhood_sees_lowercase_evidence_supports(pool: PgPool) {
    let (agent, g_upper, g_lower, _ungrounded) =
        seed_grounded_pair(&pool, "spelling-grounded-nbhd").await;
    let probe = public_claim(&pool, agent, "grounded probe", Some(0.5)).await;

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
        BTreeSet::from([g_upper, g_lower]),
        "both grounded claims, and only they, are grounded neighbours"
    );
}

/// `EvidenceRepository::by_relationship_for_claim` (backs
/// `GET /api/v1/claims/:id/supporting-evidence` and `/contradicting-evidence`)
/// compared `relationship = $2` byte-exactly, and the routes pass the UPPER
/// spelling.
#[sqlx::test(migrations = "../../migrations")]
async fn evidence_by_relationship_sees_both_spellings(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "spelling-evidence").await;
    let claim = public_claim(&pool, agent, "claim with evidence", None).await;
    let e_upper = fixture::seed_evidence(&pool, claim, "document").await;
    let e_lower = fixture::seed_evidence(&pool, claim, "observation").await;
    let e_contra = fixture::seed_evidence(&pool, claim, "testimony").await;
    let none = serde_json::json!({});
    edge(
        &pool,
        e_upper,
        "evidence",
        claim,
        "claim",
        "SUPPORTS",
        none.clone(),
    )
    .await;
    edge(
        &pool,
        e_lower,
        "evidence",
        claim,
        "claim",
        "supports",
        none.clone(),
    )
    .await;
    edge(
        &pool,
        e_contra,
        "evidence",
        claim,
        "claim",
        "contradicts",
        none,
    )
    .await;

    let viewer = fixture::public_viewer(&pool).await;
    let mut read = BTreeMap::new();
    for rel in ["SUPPORTS", "supports", "CONTRADICTS"] {
        let ids: BTreeSet<Uuid> =
            EvidenceRepository::by_relationship_for_claim(&pool, &viewer, claim, rel)
                .await
                .expect("by_relationship_for_claim")
                .into_iter()
                .map(|r| r.evidence_id)
                .collect();
        read.insert(rel, ids);
    }
    // The route's spelling, then the MCP spelling: same answer.
    assert_eq!(read["SUPPORTS"], BTreeSet::from([e_upper, e_lower]));
    assert_eq!(read["supports"], BTreeSet::from([e_upper, e_lower]));
    assert_eq!(
        read["CONTRADICTS"],
        BTreeSet::from([e_contra]),
        "the contradicting-evidence route must see a lower-case `contradicts` edge"
    );
}

/// `StructuralRepository::edge_counts` filters on `COARSE_EDGE_TYPES`
/// (SCREAMING_SNAKE) and groups by the stored spelling. Both spellings of a
/// folded relationship must land in ONE coarse bucket; a non-folded pair
/// (`relates_to` vs `RELATES_TO`) is a different relationship and stays out.
#[sqlx::test(migrations = "../../migrations")]
async fn edge_counts_merge_spellings_into_one_coarse_bucket(pool: PgPool) {
    let (owner, _) = fixture::seed_agent_with_group(&pool, "spelling-structural").await;
    let a = public_claim(&pool, owner, "structural a", None).await;
    let b = public_claim(&pool, owner, "structural b", None).await;
    let c = public_claim(&pool, owner, "structural c", None).await;
    let none = serde_json::json!({});
    edge(&pool, a, "claim", b, "claim", "SUPPORTS", none.clone()).await;
    edge(&pool, a, "claim", c, "claim", "supports", none.clone()).await;
    edge(&pool, b, "claim", c, "claim", "contradicts", none.clone()).await;
    edge(&pool, a, "claim", b, "claim", "RELATES_TO", none.clone()).await;
    edge(&pool, a, "claim", c, "claim", "relates_to", none).await;

    let viewer = fixture::public_viewer(&pool).await;
    let counts: Vec<(String, i64)> = StructuralRepository::edge_counts(&pool, &viewer, owner)
        .await
        .expect("edge_counts");

    // Compared as a Vec, not a map: the merge re-sorts after folding (the SQL
    // `ORDER BY count DESC` saw `SUPPORTS` and `supports` as 1 each), so the
    // order contract (count descending, name ascending on a tie) is the
    // merge's to keep.
    assert_eq!(
        counts,
        vec![
            ("SUPPORTS".to_string(), 2),
            ("CONTRADICTS".to_string(), 1),
            ("RELATES_TO".to_string(), 1),
        ],
        "folded spellings share one bucket, ordered by count then name; \
         lower-case relates_to is not a coarse type"
    );
}
