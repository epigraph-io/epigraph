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
    rewire_edges, run_rewire_phase, select_rewire_edges, RewireEdge, RewireOptions, RewireSummary,
    EDGE_QUERY,
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
    // A sentinel cache, so the rewire's recompute of the target is visible.
    sqlx::query("UPDATE claims SET belief = $2, pignistic_prob = $2 WHERE id = $1")
        .bind(w.target)
        .bind(SENTINEL)
        .execute(&pool)
        .await
        .expect("sentinel target cache");
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

    // The target was recomputed over its evidence plus the REWRITTEN BBA.
    let cached = cached_belief(&pool, w.target)
        .await
        .expect("T stays backed");
    assert!(
        (cached - SENTINEL).abs() > 1e-6,
        "T was not recomputed: {cached}"
    );
    let mut conn = pool.acquire().await.expect("conn");
    let fresh = epigraph_engine::edge_factor::preview_claim_belief_on_frame(
        &mut conn, &viewer, w.target, w.frame,
    )
    .await
    .expect("preview")
    .expect("T has BBAs");
    assert_close(cached, fresh.belief, "T's cache matches its current BBAs");

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

/// `(owner_group_id, visibility, writer_owned)` of an edge's BBA rows.
async fn edge_row_tenancy(pool: &PgPool, edge: Uuid) -> Vec<(Uuid, String, bool)> {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text, writer_owned FROM mass_functions \
          WHERE perspective_id = $1",
    )
    .bind(edge)
    .fetch_all(pool)
    .await
    .expect("edge row tenancy")
}

/// Migration 114: a BBA a non-owner attached to a public claim is the WRITER's
/// (`writer_owned`, owned by the writer's group). The rewire runs on the
/// privileged maintenance pool, whose fresh INSERT takes 114's arm (b) and
/// inherits the CLAIM's tenancy instead. Rewriting the row in place keeps the
/// writer's ownership; a delete-then-insert would hand the writer's
/// contribution to the claim's owner, irreversibly.
#[sqlx::test(migrations = "../../migrations")]
async fn rewire_keeps_a_writer_owned_edge_factor_owned_by_its_writer(pool: PgPool) {
    let w = seed_world(&pool, "writer").await;
    let (_writer_agent, writer_group) =
        viewer_fixture::seed_agent_with_group(&pool, "rewire-writer-group").await;
    // The privileged test session passes 114's owner guard, so it can declare
    // what a non-owner's attach would have stamped.
    sqlx::query(
        "UPDATE mass_functions SET owner_group_id = $2, visibility = 'public', writer_owned = true \
          WHERE perspective_id = $1",
    )
    .bind(w.edge)
    .bind(writer_group)
    .execute(&pool)
    .await
    .expect("make the edge factor writer-owned");
    let claim_owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(w.target)
        .fetch_one(&pool)
        .await
        .expect("claim owner");
    let before = edge_row_tenancy(&pool, w.edge).await;
    assert_eq!(
        before,
        vec![(writer_group, "public".to_string(), true)],
        "precondition: the row is the writer's"
    );
    assert_ne!(
        claim_owner, writer_group,
        "precondition: the claim is owned by another group"
    );
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;

    let summary = run_rewire_phase(&pool, &viewer, &RewireOptions::default())
        .await
        .expect("rewire");
    assert_eq!((summary.rewired, summary.failed), (1, 0), "{summary:?}");

    // The masses were rewritten (so this is not a no-op pass) ...
    let rows = edge_rows(&pool, w.edge).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_close(mass(&rows[0].1, "~0,1"), 0.48, "rewritten missing mass");
    // ... and the row is still the writer's.
    assert_eq!(
        edge_row_tenancy(&pool, w.edge).await,
        before,
        "the rewire must not re-own a writer-owned edge factor"
    );
}

/// A stored row that is NOT at the key the wire writes (here: a NULL
/// `source_agent_id`, so the selection keys it on the source's author) is
/// replaced by a fresh INSERT, which 114 stamps with the claim's tenancy. The
/// rewire copies the selected row's tenancy back onto it.
#[sqlx::test(migrations = "../../migrations")]
async fn rewire_replacing_a_row_off_the_wire_key_keeps_its_writer_owner(pool: PgPool) {
    let w = seed_world(&pool, "nullagent").await;
    let (_writer_agent, writer_group) =
        viewer_fixture::seed_agent_with_group(&pool, "rewire-writer-null").await;
    sqlx::query(
        "UPDATE mass_functions SET source_agent_id = NULL, owner_group_id = $2, \
                visibility = 'public', writer_owned = true WHERE perspective_id = $1",
    )
    .bind(w.edge)
    .bind(writer_group)
    .execute(&pool)
    .await
    .expect("NULL-agent writer-owned edge factor");
    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(w.source)
        .fetch_one(&pool)
        .await
        .expect("source author");
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;

    let summary = run_rewire_phase(&pool, &viewer, &RewireOptions::default())
        .await
        .expect("rewire");
    assert_eq!(
        (
            summary.rewired,
            summary.duplicate_rows_deleted,
            summary.failed
        ),
        (1, 0, 0),
        "the replaced row is not a duplicate: {summary:?}"
    );
    let rows = edge_rows(&pool, w.edge).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0].0, author,
        "keyed on COALESCE(signer, source author)"
    );
    assert_close(mass(&rows[0].1, "~0,1"), 0.48, "rewritten missing mass");
    assert_eq!(
        edge_row_tenancy(&pool, w.edge).await,
        vec![(writer_group, "public".to_string(), true)],
        "the fresh row carries the replaced row's owner"
    );
}

/// An edge wired twice (two agent keys) is merged into ONE row under the
/// selected (earliest) row's agent, and the merge is counted.
#[sqlx::test(migrations = "../../migrations")]
async fn rewire_merges_a_double_wired_edge_and_counts_it(pool: PgPool) {
    let w = seed_world(&pool, "double").await;
    let second = seed_agent(&pool, "rewire-second-wirer").await;
    // Strictly later than the first row, so the selection is deterministic.
    sqlx::query("UPDATE mass_functions SET created_at = now() - interval '1 minute' WHERE perspective_id = $1")
        .bind(w.edge)
        .execute(&pool)
        .await
        .expect("age the first row");
    seed_stale_edge_factor(&pool, w.edge, w.target, w.frame, second).await;
    assert_eq!(edge_rows(&pool, w.edge).await.len(), 2, "precondition");
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;

    let summary = run_rewire_phase(&pool, &viewer, &RewireOptions::default())
        .await
        .expect("rewire");
    assert_eq!(
        (
            summary.eligible,
            summary.rewired,
            summary.duplicate_rows_deleted
        ),
        (1, 1, 1),
        "{summary:?}"
    );
    let rows = edge_rows(&pool, w.edge).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, w.stale_agent, "the earliest row's agent wins");
    assert_close(mass(&rows[0].1, "~0,1"), 0.48, "rewritten missing mass");
}

/// The selection is one snapshot and the run can take hours; an edge
/// retracted (or an endpoint superseded) after it was selected must not be
/// re-wired when its turn comes, or the rewire resurrects what the retraction
/// cascade removed. Re-checked inside the edge's transaction.
#[sqlx::test(migrations = "../../migrations")]
async fn rewire_rechecks_that_the_edge_is_still_in_force(pool: PgPool) {
    let retracted = seed_world(&pool, "late-retract").await;
    let superseded = seed_world(&pool, "late-supersede").await;
    let live = seed_world(&pool, "late-live").await;
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;

    let snapshot = select_rewire_edges(&pool, &RewireOptions::default())
        .await
        .expect("select");
    assert_eq!(snapshot.len(), 3, "precondition: all three in force");

    // After selection: retract one edge, supersede another's target.
    sqlx::query(
        "UPDATE edges SET valid_from = now() - interval '2 hours', \
                          valid_to = now() - interval '1 hour' WHERE id = $1",
    )
    .bind(retracted.edge)
    .execute(&pool)
    .await
    .expect("retract edge");
    sqlx::query("UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL WHERE id = $1")
        .bind(superseded.target)
        .execute(&pool)
        .await
        .expect("supersede target");

    let mut summary = RewireSummary {
        eligible: snapshot.len(),
        ..RewireSummary::default()
    };
    rewire_edges(&pool, &viewer, &snapshot, &mut summary).await;
    assert_eq!(
        (summary.rewired, summary.skipped_stale, summary.failed),
        (1, 2, 0),
        "{summary:?}"
    );
    for (w, what) in [
        (&retracted, "retracted edge"),
        (&superseded, "superseded target"),
    ] {
        let rows = edge_rows(&pool, w.edge).await;
        assert_eq!(rows.len(), 1, "{what}: {rows:?}");
        assert_close(
            mass(&rows[0].1, "~0,1"),
            0.60,
            &format!("{what}: not rewired"),
        );
    }
    let rows = edge_rows(&pool, live.edge).await;
    assert_close(mass(&rows[0].1, "~0,1"), 0.48, "the live edge was rewired");
}

/// `--written-before` limits the rewrite to rows last written before an
/// instant (the operator's lever for "only pre-#401 rows"), and a rewritten
/// row drops out of it because the upsert restamps `created_at`: re-selecting
/// with the same cutoff finds nothing left to do.
#[sqlx::test(migrations = "../../migrations")]
async fn rewire_written_before_selects_only_older_rows_and_rewritten_rows_drop_out(pool: PgPool) {
    let old = seed_world(&pool, "old").await;
    let new = seed_world(&pool, "new").await;
    sqlx::query(
        "UPDATE mass_functions SET created_at = now() - interval '1 day' WHERE perspective_id = $1",
    )
    .bind(old.edge)
    .execute(&pool)
    .await
    .expect("backdate the old row");
    // The DB's clock, not this host's: the cutoff is compared with now().
    let cutoff: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT now() - interval '1 hour'")
            .fetch_one(&pool)
            .await
            .expect("cutoff");
    let opts = RewireOptions {
        written_before: Some(cutoff),
        ..RewireOptions::default()
    };
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;

    let selected: Vec<Uuid> = select_rewire_edges(&pool, &opts)
        .await
        .expect("select")
        .into_iter()
        .map(|e| e.edge_id)
        .collect();
    assert_eq!(
        selected,
        vec![old.edge],
        "only the row written before the cutoff"
    );

    let summary = run_rewire_phase(&pool, &viewer, &opts)
        .await
        .expect("rewire");
    assert_eq!((summary.eligible, summary.rewired), (1, 1), "{summary:?}");
    assert_close(
        mass(&edge_rows(&pool, old.edge).await[0].1, "~0,1"),
        0.48,
        "the old row was rewritten",
    );
    assert_close(
        mass(&edge_rows(&pool, new.edge).await[0].1, "~0,1"),
        0.60,
        "the newer row was left alone",
    );

    assert!(
        select_rewire_edges(&pool, &opts)
            .await
            .expect("re-select")
            .is_empty(),
        "a rewritten row is restamped and drops out of the same cutoff"
    );
}

/// A stored edge-factor row whose relationship now maps to no epistemic
/// restriction (`cites`) is left untouched and counted, and it PERSISTS in the
/// selection: paging must step past it (`RewireSummary::persisting`), or a
/// page at the same offset reselects it forever.
#[sqlx::test(migrations = "../../migrations")]
async fn rewire_leaves_a_non_epistemic_edge_factor_and_reports_it_as_persisting(pool: PgPool) {
    let author = seed_agent(&pool, "rewire-author-cites").await;
    let wirer = seed_agent(&pool, "rewire-wirer-cites").await;
    let frame = binary_frame(&pool).await;
    let source = seed_claim(&pool, author, "cites source", Some((0.20, 0.95, 0.60))).await;
    let target = seed_claim(&pool, author, "cites target", Some((0.75, 1.0, 0.0))).await;
    let edge = seed_edge(&pool, source, target, "cites").await;
    seed_stale_edge_factor(&pool, edge, target, frame, wirer).await;
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let page = RewireOptions {
        limit: 1,
        ..RewireOptions::default()
    };

    let summary = run_rewire_phase(&pool, &viewer, &page)
        .await
        .expect("rewire");
    assert_eq!(
        (
            summary.eligible,
            summary.skipped_non_epistemic,
            summary.rewired
        ),
        (1, 1, 0),
        "{summary:?}"
    );
    assert_eq!(summary.persisting(), 1, "{summary:?}");
    assert!(!summary.made_progress(), "{summary:?}");
    let rows = edge_rows(&pool, edge).await;
    assert_eq!(rows.len(), 1);
    assert_close(mass(&rows[0].1, "~0,1"), 0.60, "the cites row is untouched");

    let again: Vec<Uuid> = select_rewire_edges(&pool, &page)
        .await
        .expect("reselect")
        .into_iter()
        .map(|e| e.edge_id)
        .collect();
    assert_eq!(again, vec![edge], "it persists at offset 0");
    let past = RewireOptions {
        offset: summary.persisting(),
        ..page
    };
    assert!(
        select_rewire_edges(&pool, &past)
            .await
            .expect("next page")
            .is_empty(),
        "advancing --offset by persisting() steps past it"
    );
}

/// Every test above runs as the harness superuser, which skips row security
/// and every grant. The binary runs on a maintenance LOGIN: a member of
/// `epigraph_maintenance`, NOSUPERUSER NOBYPASSRLS. The phase's row locks
/// (`FOR SHARE OF e`, `FOR UPDATE` on the selected BBA), its deletes and its
/// tenancy-restoring UPDATE must all work there; a lock read that row
/// security filtered would come back empty and be miscounted as
/// `skipped_stale` with no error at all.
#[sqlx::test(migrations = "../../migrations")]
async fn rewire_runs_on_a_maintenance_login_without_bypassrls(pool: PgPool) {
    // In place, writer-owned.
    let owned = seed_world(&pool, "maint-owned").await;
    let (_wa, writer_group) = viewer_fixture::seed_agent_with_group(&pool, "maint-writer").await;
    sqlx::query(
        "UPDATE mass_functions SET owner_group_id = $2, visibility = 'public', writer_owned = true \
          WHERE perspective_id = $1",
    )
    .bind(owned.edge)
    .bind(writer_group)
    .execute(&pool)
    .await
    .expect("writer-owned row");
    // Replaced off the wire key (NULL agent), writer-owned: the restore UPDATE.
    let replaced = seed_world(&pool, "maint-replaced").await;
    sqlx::query(
        "UPDATE mass_functions SET source_agent_id = NULL, owner_group_id = $2, \
                visibility = 'public', writer_owned = true WHERE perspective_id = $1",
    )
    .bind(replaced.edge)
    .bind(writer_group)
    .execute(&pool)
    .await
    .expect("NULL-agent writer-owned row");
    // Removed: a vacuous source.
    let author = seed_agent(&pool, "maint-author").await;
    let vacuous = seed_claim(&pool, author, "maint vacuous source", Some((0.0, 1.0, 0.0))).await;
    let removed = seed_edge(&pool, vacuous, owned.target, "supports").await;
    seed_stale_edge_factor(&pool, removed, owned.target, owned.frame, author).await;

    let role = format!("u028_maint_{}", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}' \
         IN ROLE epigraph_maintenance"
    ))
    .execute(&pool)
    .await
    .expect("maintenance login");
    let base = viewer_fixture::database_url_for(&pool).await;
    let scheme_end = base.find("://").expect("scheme") + 3;
    let host_path = &base[base.find('@').expect("credentials") + 1..];
    let url = format!("{}{role}:{password}@{host_path}", &base[..scheme_end]);
    let maint = sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .expect("connect as the maintenance login");
    let privileged: bool =
        sqlx::query_scalar("SELECT public.epigraph_session_is_privileged_writer()")
            .fetch_one(&maint)
            .await
            .expect("privilege probe");
    assert!(
        privileged,
        "precondition: a maintenance member is a privileged writer"
    );
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;

    let summary = run_rewire_phase(&maint, &viewer, &RewireOptions::default())
        .await
        .expect("rewire as the maintenance login");
    maint.close().await;
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(&pool)
        .await;

    assert_eq!(
        (
            summary.eligible,
            summary.rewired,
            summary.removed_vacuous,
            summary.skipped_stale,
            summary.failed
        ),
        (3, 2, 1, 0, 0),
        "{summary:?}"
    );
    for (edge, what) in [(owned.edge, "in place"), (replaced.edge, "replaced")] {
        let rows = edge_rows(&pool, edge).await;
        assert_eq!(rows.len(), 1, "{what}: {rows:?}");
        assert_close(mass(&rows[0].1, "~0,1"), 0.48, what);
        assert_eq!(
            edge_row_tenancy(&pool, edge).await,
            vec![(writer_group, "public".to_string(), true)],
            "{what}: still the writer's"
        );
    }
    assert!(
        edge_rows(&pool, removed).await.is_empty(),
        "vacuous row removed"
    );
}
