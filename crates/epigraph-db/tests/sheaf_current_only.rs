//! The sheaf edge readers must leave out an edge whose endpoint is a retired
//! (`is_current = false`) claim (backlog 174ffd23, DD-20: non-current claims do
//! not take part in the factor graph).
//!
//! How a retired endpoint arises: `ClaimRepository::supersede` deliberately
//! does NOT migrate the weakening relationships (`contradicts`, `refutes`) to
//! the replacement (issue #398), so `A -contradicts-> B` stays on B after B is
//! superseded. Before this fix both readers joined `claims` with no
//! `is_current` predicate, so that edge kept producing a sheaf obstruction
//! (inflating `obstruction_count` / H1) long after the conflict was resolved
//! by superseding B.
//!
//! Both readers are pinned: `get_epistemic_edge_pairs` backs MCP
//! `sheaf_cohomology` / `reconcile_sheaf` and the HTTP cohomology / reconcile
//! routes; `get_claim_neighbor_betp_pairs` backs `check_sheaf_consistency` and
//! `GET /api/v1/sheaf/consistency`. Every test keeps a current-current control
//! edge, so a dead query cannot pass for a filtered one.

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::repos::claim::ClaimRepository;
use epigraph_db::repos::sheaf::SheafRepository;
use sqlx::PgPool;
use uuid::Uuid;

#[path = "viewer_fixture.rs"]
mod fixture;

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

/// A claim with a concrete belief interval (both readers require
/// `pignistic_prob IS NOT NULL`, so a bare claim would drop out for that
/// reason instead). `current = false` is a retired claim with no embedding,
/// which `chk_deprecated_no_embedding` (migration 052) admits.
async fn insert_claim(pool: &PgPool, agent: Uuid, bel: f64, pl: f64, current: bool) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("sheaf current-only claim {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id,
                             belief, plausibility, pignistic_prob, is_current)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .bind(bel)
    .bind(pl)
    .bind((bel + pl) / 2.0)
    .bind(current)
    .execute(pool)
    .await
    .expect("claim");
    id
}

async fn insert_edge(pool: &PgPool, src: Uuid, tgt: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, $2, 'claim', $3, 'claim', $4)",
    )
    .bind(Uuid::new_v4())
    .bind(src)
    .bind(tgt)
    .bind(relationship)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {relationship} edge: {e}"));
}

async fn pairs(pool: &PgPool) -> Vec<(Uuid, Uuid)> {
    SheafRepository::get_epistemic_edge_pairs(pool, &fixture::public_viewer(pool).await, None)
        .await
        .expect("get_epistemic_edge_pairs")
        .into_iter()
        .map(|r| (r.source_id, r.target_id))
        .collect()
}

/// `(claim_id, neighbor_id)` for every neighbourhood row.
async fn neighbour_rows(pool: &PgPool) -> Vec<(Uuid, Uuid)> {
    SheafRepository::get_claim_neighbor_betp_pairs(pool, &fixture::public_viewer(pool).await, None)
        .await
        .expect("get_claim_neighbor_betp_pairs")
        .into_iter()
        .map(|r| (r.claim_id, r.neighbor_id))
        .collect()
}

/// The reported shape: a current claim contradicts a retired one, and a second
/// edge runs FROM a retired claim. Neither may reach either reader; the
/// current-current control must.
#[sqlx::test(migrations = "../../migrations")]
async fn edges_touching_a_retired_claim_are_not_read(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    // Control: both ends current (a BeliefConflict-shaped contradicts pair).
    let ctl_src = insert_claim(&pool, agent, 0.9, 0.9, true).await;
    let ctl_tgt = insert_claim(&pool, agent, 0.8, 0.9, true).await;
    insert_edge(&pool, ctl_src, ctl_tgt, "contradicts").await;
    // Retired TARGET (463f1056 -contradicts-> a6821df8 in the report).
    let live = insert_claim(&pool, agent, 0.9, 0.9, true).await;
    let retired_tgt = insert_claim(&pool, agent, 0.8, 0.9, false).await;
    insert_edge(&pool, live, retired_tgt, "CONTRADICTS").await;
    // Retired SOURCE.
    let retired_src = insert_claim(&pool, agent, 0.9, 0.9, false).await;
    let live_tgt = insert_claim(&pool, agent, 0.1, 0.2, true).await;
    insert_edge(&pool, retired_src, live_tgt, "supports").await;

    let p = pairs(&pool).await;
    assert!(
        p.contains(&(ctl_src, ctl_tgt)),
        "control: a current-current contradicts edge must be read; got {p:?}"
    );
    assert!(
        !p.contains(&(live, retired_tgt)),
        "an edge whose TARGET is retired must not reach the cohomology scan"
    );
    assert!(
        !p.contains(&(retired_src, live_tgt)),
        "an edge whose SOURCE is retired must not reach the cohomology scan"
    );

    let n = neighbour_rows(&pool).await;
    assert!(
        n.contains(&(ctl_src, ctl_tgt)) && n.contains(&(ctl_tgt, ctl_src)),
        "control: the current pair is read from both sides; got {n:?}"
    );
    for retired in [retired_tgt, retired_src] {
        assert!(
            !n.iter().any(|(c, nb)| *c == retired || *nb == retired),
            "no neighbourhood row may have the retired claim {retired} as its \
             centre or its neighbour; got {n:?}"
        );
    }
    assert!(
        !n.iter().any(|(c, _)| *c == live || *c == live_tgt),
        "a current claim whose only edge runs to a retired claim has no \
         neighbourhood rows; got {n:?}"
    );
}

/// End to end through the real supersession: the contradicts edge stays on the
/// superseded claim (issue #398 policy), and from then on neither reader
/// returns it, while it was read before.
#[sqlx::test(migrations = "../../migrations")]
async fn superseding_a_contradicted_claim_takes_its_edge_out_of_the_scan(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let contester = insert_claim(&pool, agent, 0.9, 0.9, true).await;
    let proposal = insert_claim(&pool, agent, 0.8, 0.9, true).await;
    insert_edge(&pool, contester, proposal, "contradicts").await;

    assert!(
        pairs(&pool).await.contains(&(contester, proposal)),
        "precondition: while both claims are current the edge is read"
    );

    let (_replacement, old) = ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(proposal),
        "sheaf current-only proposal, revised",
        TruthValue::clamped(0.5),
        "174ffd23 regression: conflict resolved by superseding the target",
        epigraph_db::SupersedeActor::new(agent, epigraph_db::SupersedeTool::SupersedeClaim),
    )
    .await
    .expect("supersede");
    assert_eq!(old, proposal);

    let (still_on_old, current): (i64, bool) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM edges
                  WHERE source_id = $1 AND target_id = $2 AND relationship = 'contradicts'),
                (SELECT is_current FROM claims WHERE id = $2)",
    )
    .bind(contester)
    .bind(proposal)
    .fetch_one(&pool)
    .await
    .expect("read back");
    assert_eq!(
        (still_on_old, current),
        (1, false),
        "PREMISE: supersede retires the claim and leaves the contradicts edge on it"
    );

    assert!(
        !pairs(&pool).await.contains(&(contester, proposal)),
        "after supersession the retired endpoint's edge must leave the cohomology scan"
    );
    let n = neighbour_rows(&pool).await;
    assert!(
        !n.iter().any(|(c, nb)| *c == proposal || *nb == proposal),
        "after supersession the retired claim must leave the consistency scan; got {n:?}"
    );
}
