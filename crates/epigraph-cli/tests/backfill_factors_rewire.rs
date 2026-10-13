//! `backfill_factors --phase rewire-edges` (backlog 9e95689e, drain U028).
//!
//! Edge-factor BBAs are serialized once, when the edge is wired, and every
//! combine re-reads the stored JSON. Rows written before #401 still carry the
//! source's UNDISCOUNTED open-world mass, and nothing heals them:
//! `recompute_beliefs` re-reads them, and the edge phase of this binary
//! (`EDGE_QUERY`) selects only factorless targets, which a target holding such
//! a row is not. These tests pin the rewire phase that rewrites them.
//!
//! The fixture's stale row is the pre-#401 shape of a `supports` (f = 0.80)
//! edge from a source [Bel 0.20, Pl 0.95, open_world 0.60]: TRUE 0.16,
//! FALSE 0.04, Θ 0.20, missing 0.60. Re-derived today (Option 1, operator
//! ruling 2026-10-13: open_world transmitted at ow·f) it is TRUE 0.16,
//! FALSE 0.04, Θ 0.32, missing 0.48. The stale row is keyed on an agent that
//! is NOT `COALESCE(edge.signer_id, source.agent_id)`, which is what a
//! re-wire keyed the edge phase's way would bind.
#![cfg(feature = "db")]

mod viewer_fixture;

use epigraph_cli::backfill_factors::{
    run_rewire_phase, select_rewire_edges, RewireEdge, RewireOptions, EDGE_QUERY,
};
use epigraph_db::PerspectiveRepository;
use sqlx::PgPool;
use uuid::Uuid;

const STALE_PRE_401: &str = r#"{"0": 0.16, "1": 0.04, "0,1": 0.20, "~0,1": 0.60}"#;
const EVIDENCE_BBA: &str = r#"{"0": 0.75, "0,1": 0.25}"#;
const SENTINEL: f64 = 0.0123;

async fn seed_agent(pool: &PgPool, name: &str) -> Uuid {
    let pk: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    sqlx::query_scalar("INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id")
        .bind(&pk)
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("seed agent")
}

/// A claim with a cached interval; `None` belief means factorless.
async fn seed_claim(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    interval: Option<(f64, f64, f64)>,
) -> Uuid {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    let (bel, pl, ow) = match interval {
        Some((b, p, o)) => (Some(b), Some(p), o),
        // `open_world_mass` is NOT NULL (default 0); a factorless claim is NULL
        // belief and plausibility.
        None => (None, None, 0.0),
    };
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, \
                             belief, plausibility, open_world_mass, pignistic_prob) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6, $4) RETURNING id",
    )
    .bind(content)
    .bind(hash.as_slice())
    .bind(agent)
    .bind(bel)
    .bind(pl)
    .bind(ow)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn seed_edge(pool: &PgPool, src: Uuid, tgt: Uuid, rel: &str) -> Uuid {
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

async fn binary_frame(pool: &PgPool) -> Uuid {
    let viewer = viewer_fixture::public_viewer(pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    epigraph_engine::edge_factor::ensure_binary_frame(&mut conn, &viewer)
        .await
        .expect("binary_truth frame")
}

/// A target's own (non-edge) evidence BBA, so the target is NOT factorless.
async fn seed_evidence_bba(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses, locality_tag) \
         VALUES ($1, $2, $3, $4::jsonb, 'unknown')",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(EVIDENCE_BBA)
    .execute(pool)
    .await
    .expect("seed evidence BBA");
}

/// A stored edge-factor row in the pre-#401 shape, keyed on `agent`.
async fn seed_stale_edge_factor(pool: &PgPool, edge: Uuid, target: Uuid, frame: Uuid, agent: Uuid) {
    PerspectiveRepository::ensure_edge_perspective(pool, edge, Some(agent))
        .await
        .expect("edge perspective");
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, perspective_id, masses, \
                                     combination_method, source_strength, evidence_type, locality_tag) \
         VALUES ($1, $2, $3, $4, $5::jsonb, 'edge_factor', 0.8, 'derived_support', 'cross')",
    )
    .bind(target)
    .bind(frame)
    .bind(agent)
    .bind(edge)
    .bind(STALE_PRE_401)
    .execute(pool)
    .await
    .expect("seed stale edge factor");
}

async fn edge_rows(pool: &PgPool, edge: Uuid) -> Vec<(Uuid, serde_json::Value)> {
    sqlx::query_as("SELECT source_agent_id, masses FROM mass_functions WHERE perspective_id = $1")
        .bind(edge)
        .fetch_all(pool)
        .await
        .expect("edge rows")
}

async fn claim_rows(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim rows")
}

async fn cached_belief(pool: &PgPool, claim: Uuid) -> Option<f64> {
    sqlx::query_scalar("SELECT belief FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("cached belief")
}

fn mass(masses: &serde_json::Value, key: &str) -> f64 {
    masses
        .get(key)
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0)
}

fn assert_close(got: f64, want: f64, what: &str) {
    assert!(
        (got - want).abs() < 1e-9,
        "{what}: expected {want}, got {got}"
    );
}

struct World {
    frame: Uuid,
    stale_agent: Uuid,
    source: Uuid,
    target: Uuid,
    edge: Uuid,
}

/// Source S [0.20, 0.95, ow 0.60] —supports→ target T, where T holds its own
/// evidence BBA plus S's stale edge-factor row keyed on `stale_agent`.
async fn seed_world(pool: &PgPool, tag: &str) -> World {
    let author = seed_agent(pool, &format!("rewire-author-{tag}")).await;
    let stale_agent = seed_agent(pool, &format!("rewire-wirer-{tag}")).await;
    let frame = binary_frame(pool).await;
    let source = seed_claim(
        pool,
        author,
        &format!("source {tag}"),
        Some((0.20, 0.95, 0.60)),
    )
    .await;
    let target = seed_claim(
        pool,
        author,
        &format!("target {tag}"),
        Some((0.75, 1.0, 0.0)),
    )
    .await;
    seed_evidence_bba(pool, target, frame, author).await;
    let edge = seed_edge(pool, source, target, "supports").await;
    seed_stale_edge_factor(pool, edge, target, frame, stale_agent).await;
    World {
        frame,
        stale_agent,
        source,
        target,
        edge,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn rewire_selects_already_wired_edge_factor_and_keeps_one_row_per_edge(pool: PgPool) {
    let w = seed_world(&pool, "a").await;
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;

    // Why the old remedy is a no-op: the edge phase never selects a target
    // that already holds a BBA.
    let factorless: Vec<(Uuid, Uuid, Uuid, Uuid, String)> = sqlx::query_as(EDGE_QUERY)
        .bind(i64::MAX)
        .bind(0_i64)
        .fetch_all(&pool)
        .await
        .expect("EDGE_QUERY");
    assert!(
        factorless.iter().all(|(_, _, _, tgt, _)| *tgt != w.target),
        "EDGE_QUERY must not select a target that holds a BBA: {factorless:?}"
    );

    // The rewire selection finds the edge and keys it on the STORED agent.
    let selected = select_rewire_edges(&pool, &RewireOptions::default())
        .await
        .expect("select");
    assert_eq!(
        selected,
        vec![RewireEdge {
            edge_id: w.edge,
            agent_id: w.stale_agent,
            source_id: w.source,
            target_id: w.target,
            relationship: "supports".to_string(),
            frame_id: w.frame,
        }],
    );

    // A dry run reports the edge and writes nothing.
    let dry = run_rewire_phase(
        &pool,
        &viewer,
        &RewireOptions {
            dry_run: true,
            ..RewireOptions::default()
        },
    )
    .await
    .expect("dry run");
    assert_eq!((dry.eligible, dry.rewired), (1, 0), "{dry:?}");
    let rows = edge_rows(&pool, w.edge).await;
    assert_eq!(rows.len(), 1);
    assert_close(
        mass(&rows[0].1, "~0,1"),
        0.60,
        "dry run left the stale missing mass",
    );

    let summary = run_rewire_phase(&pool, &viewer, &RewireOptions::default())
        .await
        .expect("rewire");
    assert_eq!(
        (summary.eligible, summary.rewired, summary.failed),
        (1, 1, 0),
        "{summary:?}"
    );

    // ONE row for the edge, still attributed to the agent that wired it, in
    // today's shape: open-world transmitted at ow·f = 0.60 × 0.8.
    let rows = edge_rows(&pool, w.edge).await;
    assert_eq!(
        rows.len(),
        1,
        "one BBA per edge, not one per agent key: {rows:?}"
    );
    let (agent, masses) = &rows[0];
    assert_eq!(
        *agent, w.stale_agent,
        "the rewritten row keeps the stored agent"
    );
    assert_close(mass(masses, "~0,1"), 0.48, "missing mass");
    assert_close(mass(masses, "0,1"), 0.32, "closed-world Θ mass");
    assert_close(mass(masses, "0"), 0.16, "TRUE mass");
    assert_close(mass(masses, "1"), 0.04, "FALSE mass");

    // The target's own evidence BBA is untouched.
    assert_eq!(claim_rows(&pool, w.target).await, 2);
    let evidence: serde_json::Value = sqlx::query_scalar(
        "SELECT masses FROM mass_functions WHERE claim_id = $1 AND perspective_id IS NULL",
    )
    .bind(w.target)
    .fetch_one(&pool)
    .await
    .expect("evidence BBA");
    assert_eq!(
        evidence,
        serde_json::from_str::<serde_json::Value>(EVIDENCE_BBA).unwrap()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn rewire_skips_retracted_edge(pool: PgPool) {
    let live = seed_world(&pool, "live").await;
    let retracted = seed_world(&pool, "retracted").await;
    sqlx::query(
        "UPDATE edges SET valid_from = now() - interval '2 hours', \
                          valid_to = now() - interval '1 hour' WHERE id = $1",
    )
    .bind(retracted.edge)
    .execute(&pool)
    .await
    .expect("retract edge");
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;

    let selected: Vec<Uuid> = select_rewire_edges(&pool, &RewireOptions::default())
        .await
        .expect("select")
        .into_iter()
        .map(|e| e.edge_id)
        .collect();
    assert_eq!(
        selected,
        vec![live.edge],
        "only the in-force edge is selected"
    );

    let summary = run_rewire_phase(&pool, &viewer, &RewireOptions::default())
        .await
        .expect("rewire");
    assert_eq!((summary.eligible, summary.rewired), (1, 1), "{summary:?}");

    let rows = edge_rows(&pool, retracted.edge).await;
    assert_eq!(rows.len(), 1);
    assert_close(
        mass(&rows[0].1, "~0,1"),
        0.60,
        "a retracted edge's row is not rewritten (nor resurrected)",
    );
    let rows = edge_rows(&pool, live.edge).await;
    assert_close(
        mass(&rows[0].1, "~0,1"),
        0.48,
        "the live edge was rewritten",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn rewire_removes_edge_factors_it_cannot_rederive_and_recomputes_targets(pool: PgPool) {
    let author = seed_agent(&pool, "rewire-author-c").await;
    let wirer = seed_agent(&pool, "rewire-wirer-c").await;
    let frame = binary_frame(&pool).await;

    // A factorless source (no interval) and a vacuous one ([0, 1]: a
    // `supports` restriction of it is [0, 1], which wires nothing).
    let factorless = seed_claim(&pool, author, "factorless source", None).await;
    let vacuous = seed_claim(&pool, author, "vacuous source", Some((0.0, 1.0, 0.0))).await;

    // T keeps its own evidence BBA; T2 is backed by nothing but the stale row.
    let target = seed_claim(&pool, author, "target c", Some((SENTINEL, 1.0, 0.0))).await;
    seed_evidence_bba(&pool, target, frame, author).await;
    let only_edge_backed = seed_claim(&pool, author, "target c2", Some((SENTINEL, 1.0, 0.0))).await;

    let e_factorless = seed_edge(&pool, factorless, target, "supports").await;
    let e_vacuous = seed_edge(&pool, vacuous, target, "supports").await;
    let e_only = seed_edge(&pool, factorless, only_edge_backed, "supports").await;
    for (edge, tgt) in [
        (e_factorless, target),
        (e_vacuous, target),
        (e_only, only_edge_backed),
    ] {
        seed_stale_edge_factor(&pool, edge, tgt, frame, wirer).await;
    }
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;

    let summary = run_rewire_phase(&pool, &viewer, &RewireOptions::default())
        .await
        .expect("rewire");
    assert_eq!(summary.eligible, 3, "{summary:?}");
    assert_eq!(summary.removed_source_factorless, 2, "{summary:?}");
    assert_eq!(summary.removed_vacuous, 1, "{summary:?}");
    assert_eq!((summary.rewired, summary.failed), (0, 0), "{summary:?}");

    // A fresh wire of these edges would store nothing, so neither does the
    // rewire: the stale rows are gone.
    for edge in [e_factorless, e_vacuous, e_only] {
        assert!(
            edge_rows(&pool, edge).await.is_empty(),
            "edge {edge} still has a BBA"
        );
    }

    // T was recomputed AFTER the removal: its cache is no longer the sentinel
    // and equals a fresh combine over the BBA that survives (its evidence).
    assert_eq!(claim_rows(&pool, target).await, 1);
    let cached = cached_belief(&pool, target).await.expect("T stays backed");
    assert!(
        (cached - SENTINEL).abs() > 1e-6,
        "T was not recomputed: {cached}"
    );
    let mut conn = pool.acquire().await.expect("conn");
    let fresh = epigraph_engine::edge_factor::preview_claim_belief_on_frame(
        &mut conn, &viewer, target, frame,
    )
    .await
    .expect("preview")
    .expect("T has a BBA");
    assert_close(cached, fresh.belief, "T's cache matches its surviving BBAs");

    // T2 lost its only BBA, so its cached belief is cleared, not left stale.
    assert_eq!(claim_rows(&pool, only_edge_backed).await, 0);
    assert_eq!(cached_belief(&pool, only_edge_backed).await, None);
}
