//! `ClaimRepository::graph_expand_seeds_since` — the emission budget must be
//! spent on IN-WINDOW destinations, not on the out-of-window claims the walk
//! passes through.
//!
//! Why this test lives in `epigraph-db` and not in
//! `epigraph-mcp/tests/recall_temporal.rs`: the pre-registration decides G4 by
//! copying `recall_temporal.rs` into an `origin/main` worktree and requiring it
//! to FAIL on an assertion rather than a compile error. Naming a branch-only
//! symbol (`graph_expand_seeds_since`) in that file would break its
//! compilation on base and destroy the G4 check. Here the contract under test
//! is the repository function itself, so the direct call is the right one.
//!
//! Schema notes: `agents` row first (FK), `content_hash bytea NOT NULL` with
//! `(content_hash, agent_id)` UNIQUE, and `EdgeRepository::get_by_source`
//! orders `created_at DESC` — which is how the fixture below controls the
//! order in which the BFS meets its neighbours.

use chrono::{DateTime, TimeZone, Utc};
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// The out-of-window neighbourhood is deliberately larger than
/// `ClaimRepository::MAX_EXPANSION_NODES` (200, private), so a single shared
/// budget is provably exhausted before the walk reaches the in-window claim.
const PRE_WINDOW_FANOUT: usize = 250;

fn epoch_old() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap()
}

fn epoch_cut() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap()
}

fn epoch_recent() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 10, 9, 30, 0).unwrap()
}

fn hash_for(id: Uuid) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[..16].copy_from_slice(id.as_bytes());
    h
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'expand-window', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_claim_at(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    created_at: DateTime<Utc>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, created_at) \
         VALUES ($1, $2, $3, $4, 0.8, true, $5)",
    )
    .bind(id)
    .bind(content)
    .bind(hash_for(id))
    .bind(agent)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// `edges.created_at` is what `EdgeRepository::get_by_source`'s
/// `ORDER BY created_at DESC` sorts on, so it decides BFS visit order — this
/// is the knob that lets the fixture bury the in-window claim behind the
/// pre-window fan-out.
async fn seed_edge_at(pool: &PgPool, from: Uuid, to: Uuid, edge_created_at: DateTime<Utc>) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, created_at) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'supports', $3)",
    )
    .bind(from)
    .bind(to)
    .bind(edge_created_at)
    .execute(pool)
    .await
    .expect("seed edge");
}

/// One seed with 250 pre-window one-hop neighbours plus ONE in-window one-hop
/// neighbour, arranged so the in-window neighbour is visited last.
///
/// Before the two-budget fix, all 250 pre-window claims were inserted into the
/// discovery map, `MAX_EXPANSION_NODES` fired at 200, the walk stopped, and the
/// post-walk window filter then discarded all 200 — returning `[]` for a
/// question with a real answer. An empty expansion reads to the caller as
/// "nothing changed since T", which is the inverse of the truth: this is
/// BCH-J01's inversion reproduced on the graph surface.
#[sqlx::test(migrations = "../../migrations")]
async fn in_window_destination_survives_a_pre_window_fanout(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let seed = seed_claim_at(&pool, agent, "grendlewick seed", epoch_recent()).await;

    // Pre-window neighbours, edges created LATE so they sort first.
    let late_edge = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
    for i in 0..PRE_WINDOW_FANOUT {
        let old = seed_claim_at(&pool, agent, &format!("grendlewick old {i}"), epoch_old()).await;
        seed_edge_at(&pool, seed, old, late_edge).await;
    }

    // The one in-window destination, edge created EARLY so it sorts last.
    let early_edge = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
    let fresh = seed_claim_at(&pool, agent, "grendlewick fresh", epoch_recent()).await;
    seed_edge_at(&pool, seed, fresh, early_edge).await;

    // Control: unwindowed, the emission cap still binds at 200 and the
    // fresh claim is (legitimately) crowded out. This is the pre-existing
    // relevance-free truncation, and the fix must NOT change it.
    let unwindowed = ClaimRepository::graph_expand_seeds(&pool, &[seed], 2)
        .await
        .expect("unwindowed expansion");
    assert_eq!(
        unwindowed.len(),
        200,
        "unwindowed expansion must still stop at MAX_EXPANSION_NODES=200; \
         changing that would be an unrelated behaviour change"
    );

    // The criterion: with a window set, the 200-slot emission budget belongs
    // to in-window claims. The 250 pre-window bridges are walked through, not
    // counted.
    let windowed = ClaimRepository::graph_expand_seeds_since(&pool, &[seed], 2, Some(epoch_cut()))
        .await
        .expect("windowed expansion");
    let ids: Vec<Uuid> = windowed.iter().map(|h| h.claim_id).collect();

    assert!(
        ids.contains(&fresh),
        "the in-window destination {fresh} was starved by the expansion budget: \
         {} pre-window neighbours consumed it and the call returned {:?}. \
         An empty/short windowed expansion reads as \"nothing changed since T\" — \
         the exact inversion the window exists to avoid.",
        PRE_WINDOW_FANOUT,
        ids
    );
    assert_eq!(
        ids.len(),
        1,
        "only the single in-window claim is reachable, so nothing else may be emitted: {ids:?}"
    );
}

/// The window filters DESTINATIONS, not the PATH: an out-of-window claim is a
/// legitimate bridge to an in-window one, and cutting the walk at it would
/// silently sever reachability the unwindowed call has.
#[sqlx::test(migrations = "../../migrations")]
async fn an_out_of_window_claim_still_bridges_to_an_in_window_one(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let seed = seed_claim_at(&pool, agent, "grendlewick seed", epoch_recent()).await;
    let bridge = seed_claim_at(&pool, agent, "grendlewick bridge", epoch_old()).await;
    let far = seed_claim_at(&pool, agent, "grendlewick far", epoch_recent()).await;

    let e = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
    seed_edge_at(&pool, seed, bridge, e).await;
    seed_edge_at(&pool, bridge, far, e).await;

    let windowed = ClaimRepository::graph_expand_seeds_since(&pool, &[seed], 2, Some(epoch_cut()))
        .await
        .expect("windowed expansion");
    let ids: Vec<Uuid> = windowed.iter().map(|h| h.claim_id).collect();

    assert!(
        ids.contains(&far),
        "the 2-hop in-window claim {far} is only reachable THROUGH the pre-window \
         bridge {bridge}; pruning the walk at the bridge would lose it. Got {ids:?}"
    );
    assert!(
        !ids.contains(&bridge),
        "the pre-window bridge {bridge} must not be EMITTED — it is a path, not a hit: {ids:?}"
    );
    assert_eq!(
        windowed
            .iter()
            .find(|h| h.claim_id == far)
            .map(|h| h.hops)
            .unwrap(),
        2,
        "hop count must still be the true BFS depth, not renumbered by the filter"
    );
}
