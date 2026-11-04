//! Shared fixtures for the targeted edge-factor rewire tests
//! (`backfill_factors_rewire_targeted.rs`, `..._passes.rs`, `..._predict.rs`,
//! `edge_bba_builder_pin.rs`).
//!
//! Every world here is built the way production builds it, so a guard that
//! holds an edge is measured against real rows: a claim's cache is the fold
//! of its own evidence BBA (`recompute_claim_belief_binary`), an edge row is
//! written by the real wire (`auto_wire_ds_for_edge`, which also refolds the
//! target), and a wave "moves" a claim the way the calibration recompute
//! does: its own row changes and its cache is refolded, recorded as a
//! `WaveRecord` with the cache before and after.
#![allow(dead_code)]

use epigraph_cli::belief_cache::{read_cache_columns, CacheColumns, WaveRecord};
use epigraph_db::visibility::Viewer;
use epigraph_engine::edge_factor::{
    auto_wire_ds_for_edge, ensure_binary_frame, recompute_claim_belief_binary, EdgeFactorOutcome,
};
use sqlx::PgPool;
use uuid::Uuid;

/// A believed claim's own evidence BBA (Bel 0.60, Pl 0.90).
pub const EVIDENCE_A: &str = r#"{"0": 0.60, "1": 0.10, "0,1": 0.30}"#;
/// The same claim after a wave moved it (Bel 0.72, Pl 0.94).
pub const EVIDENCE_B: &str = r#"{"0": 0.72, "1": 0.06, "0,1": 0.22}"#;
/// A third value, for a second organic move.
pub const EVIDENCE_C: &str = r#"{"0": 0.40, "1": 0.30, "0,1": 0.30}"#;
/// A target's own evidence BBA.
pub const TARGET_EVIDENCE: &str = r#"{"0": 0.50, "1": 0.10, "0,1": 0.40}"#;
/// The pre-#401 shape of a supports row: stale for a reason other than any
/// source move (row class `mixed`).
pub const STALE_PRE_401: &str = r#"{"0": 0.16, "1": 0.04, "0,1": 0.20, "~0,1": 0.60}"#;

pub async fn seed_agent(pool: &PgPool, name: &str) -> Uuid {
    let pk: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    sqlx::query_scalar("INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id")
        .bind(&pk)
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("seed agent")
}

/// A claim with the given cache (`None`: factorless) and open-world mass.
pub async fn seed_claim(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    interval: Option<(f64, f64)>,
    open_world: f64,
) -> Uuid {
    let hash =
        epigraph_crypto::ContentHasher::hash(format!("{content} {}", Uuid::new_v4()).as_bytes());
    let (bel, pl) = interval.unzip();
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, \
                             belief, plausibility, open_world_mass, pignistic_prob) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6, ($4 + $5) / 2) RETURNING id",
    )
    .bind(content)
    .bind(hash.as_slice())
    .bind(agent)
    .bind(bel)
    .bind(pl)
    .bind(open_world)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

pub async fn seed_edge(pool: &PgPool, src: Uuid, tgt: Uuid, rel: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(src)
    .bind(tgt)
    .bind(rel)
    .fetch_one(pool)
    .await
    .expect("seed edge")
}

pub async fn binary_frame(pool: &PgPool, viewer: &Viewer) -> Uuid {
    let mut conn = pool.acquire().await.expect("conn");
    ensure_binary_frame(&mut conn, viewer)
        .await
        .expect("binary_truth frame")
}

/// A claim's own evidence BBA on `frame`; returns its row id.
pub async fn seed_evidence_bba(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Uuid,
    masses: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses, locality_tag) \
         VALUES ($1, $2, $3, $4::jsonb, 'unknown') RETURNING id",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(masses)
    .fetch_one(pool)
    .await
    .expect("seed evidence BBA")
}

/// Refold `claim`'s binary cache from its rows (what a recompute writes).
pub async fn refold(pool: &PgPool, viewer: &Viewer, claim: Uuid) {
    let mut conn = pool.acquire().await.expect("conn");
    recompute_claim_belief_binary(&mut conn, viewer, claim)
        .await
        .expect("refold");
}

/// A claim whose cache is the fold of its own evidence BBA `masses`.
pub async fn fresh_claim(
    pool: &PgPool,
    viewer: &Viewer,
    agent: Uuid,
    frame: Uuid,
    content: &str,
    masses: &str,
) -> Uuid {
    let c = seed_claim(pool, agent, content, None, 0.0).await;
    seed_evidence_bba(pool, c, frame, agent, masses).await;
    refold(pool, viewer, c).await;
    c
}

/// Wire `edge` for real (stores the row from the source's current cache and
/// refolds the target).
pub async fn wire(
    pool: &PgPool,
    viewer: &Viewer,
    edge: Uuid,
    agent: Uuid,
    src: Uuid,
    tgt: Uuid,
    rel: &str,
) -> EdgeFactorOutcome {
    let mut conn = pool.acquire().await.expect("conn");
    auto_wire_ds_for_edge(&mut conn, viewer, edge, agent, src, tgt, rel)
        .await
        .expect("wire")
}

/// Seed and wire `src —[rel]→ tgt` under `agent`.
pub async fn wired_edge(
    pool: &PgPool,
    viewer: &Viewer,
    agent: Uuid,
    src: Uuid,
    tgt: Uuid,
    rel: &str,
) -> Uuid {
    let e = seed_edge(pool, src, tgt, rel).await;
    assert_eq!(
        wire(pool, viewer, e, agent, src, tgt, rel).await,
        EdgeFactorOutcome::Wired,
        "fixture edge must wire"
    );
    e
}

pub async fn cache(pool: &PgPool, claim: Uuid) -> CacheColumns {
    read_cache_columns(pool, &[claim])
        .await
        .expect("cache")
        .remove(&claim)
        .expect("claim exists")
}

pub async fn updated_at(pool: &PgPool, claim: Uuid) -> chrono::DateTime<chrono::Utc> {
    sqlx::query_scalar("SELECT updated_at FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("updated_at")
}

/// A wave's move of `claim`: its own evidence row becomes `masses` and its
/// cache is refolded; returns the wave record (before, written).
pub async fn move_claim(pool: &PgPool, viewer: &Viewer, claim: Uuid, masses: &str) -> WaveRecord {
    let before = cache(pool, claim).await;
    sqlx::query(
        "UPDATE mass_functions SET masses = $2::jsonb \
          WHERE claim_id = $1 AND perspective_id IS NULL",
    )
    .bind(claim)
    .bind(masses)
    .execute(pool)
    .await
    .expect("move the claim's own row");
    refold(pool, viewer, claim).await;
    let written = cache(pool, claim).await;
    assert_ne!(before, written, "fixture move must move the cache");
    WaveRecord {
        claim_id: claim,
        before,
        written,
        wave: "l1-fixture".to_string(),
        at: chrono::Utc::now(),
    }
}

/// The stored edge-factor row(s) of `edge`, exactly:
/// `(id, masses::text, source_strength, evidence_type, locality_tag, created_at, retracted)`.
pub type RowText = (
    Uuid,
    String,
    Option<f64>,
    Option<String>,
    String,
    chrono::DateTime<chrono::Utc>,
    bool,
);

pub async fn edge_rows(pool: &PgPool, edge: Uuid) -> Vec<RowText> {
    sqlx::query_as(
        "SELECT id, masses::text, source_strength, evidence_type, locality_tag, created_at, \
                retracted_at IS NOT NULL \
           FROM mass_functions WHERE perspective_id = $1 ORDER BY created_at, id",
    )
    .bind(edge)
    .fetch_all(pool)
    .await
    .expect("edge rows")
}

/// Whether the JSON `value` is the same `jsonb` as the stored text `stored`
/// (compared by the database, so the comparison is the column's own).
pub async fn same_jsonb(pool: &PgPool, value: &serde_json::Value, stored: &str) -> bool {
    sqlx::query_scalar("SELECT $1::jsonb = $2::jsonb")
        .bind(value)
        .bind(stored)
        .fetch_one(pool)
        .await
        .expect("jsonb compare")
}

/// Make `claim` a compound: an in-force `decomposes_to` edge to a fresh
/// current claim.
pub async fn make_compound(pool: &PgPool, claim: Uuid, agent: Uuid) {
    let child = seed_claim(pool, agent, "compound child", Some((0.5, 0.5)), 0.0).await;
    seed_edge(pool, claim, child, "decomposes_to").await;
}

pub fn assert_close(got: f64, want: f64, eps: f64, what: &str) {
    assert!(
        (got - want).abs() <= eps,
        "{what}: expected {want}, got {got}"
    );
}
