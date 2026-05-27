//! 19-supporter synthetic regression for locality-aware discounting.
//!
//! Mirrors the NEMS shape from issue #142: one target T, 19 supporting claims
//! S1..S19. With cross-source `source_strength = 1.0` the combined BetP
//! approaches 1.0 (the un-discounted Dempster product). With intra-source
//! `source_strength = 0.3` from calibration.toml, BetP drops into the
//! [0.70, 0.85] band the issue requires.
//!
//! The test exercises the centralized BBA write path
//! `epigraph_engine::edge_factor::auto_wire_ds_for_edge` directly. No HTTP /
//! MCP server is required.
//!
//! Schema notes (mirrors `crates/epigraph-db/tests/same_source_papers_truth_table.rs`):
//!   * `claims.agent_id` is NOT NULL — seed an `agents` row first.
//!   * `(content_hash, agent_id)` is UNIQUE — hand-build distinct 32-byte hashes.
//!   * `edges.source_type` / `target_type` are NOT NULL and validated against
//!     the entity-type allowlist; we use `'paper'` / `'claim'` for `asserts`,
//!     `'claim'` / `'claim'` for `supports`.
//!
//! IMPORTANT: `auto_wire_ds_for_edge` short-circuits to `SourceFactorless`
//! when the source claim has NULL belief or plausibility. Each supporter
//! must be seeded with `belief = plausibility = 0.68` (a certain interval
//! at the NEMS mean from the issue body), not just `truth_value = 0.68`.

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_engine::edge_factor::{auto_wire_ds_for_edge, EdgeFactorOutcome};

// ── Fixtures ───────────────────────────────────────────────────────────────

/// Build a 32-byte hash with the first three bytes set from `tag` so each
/// claim/agent/paper gets a distinct `content_hash` without depending on
/// pgcrypto. Caller passes a `u32` tag to avoid collisions across the 19
/// supporters + 19 papers + 1 target seeded by `cross_source_19_supporters`.
fn distinct_hash(tag: u32) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[0] = (tag & 0xff) as u8;
    h[1] = ((tag >> 8) & 0xff) as u8;
    h[2] = ((tag >> 16) & 0xff) as u8;
    h
}

async fn seed_agent(pool: &PgPool, tag: u32) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind(distinct_hash(tag))
        .execute(pool)
        .await
        .expect("seed agent");
    agent_id
}

async fn seed_paper(pool: &PgPool, doi: &str, title: &str) -> Uuid {
    let paper_id = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, $3)")
        .bind(paper_id)
        .bind(doi)
        .bind(title)
        .execute(pool)
        .await
        .expect("seed paper");
    paper_id
}

/// Seed a claim with a populated belief / plausibility interval so that
/// `auto_wire_ds_for_edge` can read it as the source of a `supports` edge.
/// Without `belief` and `plausibility`, the auto-wire path returns
/// `SourceFactorless` and writes no BBA.
async fn seed_claim_with_belief(
    pool: &PgPool,
    agent_id: Uuid,
    content: &str,
    tag: u32,
    truth_value: f64,
    belief: f64,
    plausibility: f64,
) -> Uuid {
    let claim_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims \
         (id, content, content_hash, agent_id, truth_value, belief, plausibility, open_world_mass, is_current) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 0.0, true)",
    )
    .bind(claim_id)
    .bind(content)
    .bind(distinct_hash(tag))
    .bind(agent_id)
    .bind(truth_value)
    .bind(belief)
    .bind(plausibility)
    .execute(pool)
    .await
    .expect("seed claim");
    claim_id
}

async fn insert_edge(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    source_type: &str,
    target_type: &str,
    relationship: &str,
) -> Uuid {
    let edge_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(edge_id)
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(target_type)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("insert edge");
    edge_id
}

async fn read_betp(pool: &PgPool, claim_id: Uuid) -> Option<f64> {
    sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("read pignistic_prob")
}

async fn count_target_bbas(pool: &PgPool, claim_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM mass_functions WHERE claim_id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("count BBAs")
}

const NEMS_BELIEF: f64 = 0.68;

// ── Intra-source: 19 supporters, all from one paper ────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn intra_source_19_supporters_betp_in_band(pool: PgPool) {
    let agent = seed_agent(&pool, 0xA0_0001).await;
    let paper = seed_paper(&pool, "10.intra/p1", "Synthesis paper").await;

    // Target — start with NULL belief/plausibility so the only BBAs on the
    // target's row come from the 19 supporter edges (no self-evidence).
    let target_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current) \
         VALUES ($1, $2, $3, $4, 0.5, true)",
    )
    .bind(target_id)
    .bind("GEN-2 NEMS target")
    .bind(distinct_hash(0x10_0000))
    .bind(agent)
    .execute(&pool)
    .await
    .expect("seed target");

    // The same paper asserts the target and all 19 supporters → same_source_papers
    // must return true for every (supporter, target) pair.
    insert_edge(&pool, paper, target_id, "paper", "claim", "asserts").await;

    for i in 0..19u32 {
        let supporter = seed_claim_with_belief(
            &pool,
            agent,
            &format!("intra supporter {i}"),
            0x20_0000 + i,
            NEMS_BELIEF,
            NEMS_BELIEF,
            NEMS_BELIEF,
        )
        .await;

        insert_edge(&pool, paper, supporter, "paper", "claim", "asserts").await;

        // Fire the centralized BBA write path — same code path 5 entry
        // points use (HTTP edges, HTTP workflows, MCP ingestion,
        // MCP workflow_ingest, CLI backfill_factors).
        let edge_id = insert_edge(&pool, supporter, target_id, "claim", "claim", "supports").await;
        let outcome =
            auto_wire_ds_for_edge(&pool, edge_id, agent, supporter, target_id, "supports")
                .await
                .expect("auto_wire_ds_for_edge");
        assert_eq!(
            outcome,
            EdgeFactorOutcome::Wired,
            "supporter {i}: expected Wired, got {outcome:?} (missing belief/plausibility on the source?)"
        );
    }

    // Sanity: exactly 19 BBAs landed on the target.
    let bba_count = count_target_bbas(&pool, target_id).await;
    assert_eq!(
        bba_count, 19,
        "expected 19 BBAs on the target, got {bba_count} — auto-wire short-circuited somewhere"
    );

    // Spot-check: every BBA carries the intra-source discount.
    let intra_row_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions \
         WHERE claim_id = $1 AND source_strength = 0.25",
    )
    .bind(target_id)
    .fetch_one(&pool)
    .await
    .expect("count intra rows");
    assert_eq!(
        intra_row_count, 19,
        "expected all 19 BBAs to be discounted to 0.25, got {intra_row_count}"
    );

    let betp = read_betp(&pool, target_id)
        .await
        .expect("target should have computed BetP after 19 supporter wires");
    eprintln!("[intra_source_19_supporters_betp_in_band] BetP = {betp}");
    assert!(
        (0.70..=0.85).contains(&betp),
        "expected intra-source-discounted BetP in [0.70, 0.85], got {betp}"
    );
}

// ── Cross-source: 19 supporters, each from its own paper ───────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn cross_source_19_supporters_keeps_high_betp(pool: PgPool) {
    let agent = seed_agent(&pool, 0xB0_0001).await;

    // Target paper is distinct from all 19 supporter papers — none of the
    // 19 supporters share a source paper with the target, so
    // `same_source_papers` returns false for every pair and the cross-source
    // strength (1.0) is applied.
    let target_paper = seed_paper(&pool, "10.cross/target", "Target paper").await;
    let target_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current) \
         VALUES ($1, $2, $3, $4, 0.5, true)",
    )
    .bind(target_id)
    .bind("cross-source target")
    .bind(distinct_hash(0x30_0000))
    .bind(agent)
    .execute(&pool)
    .await
    .expect("seed target");
    insert_edge(&pool, target_paper, target_id, "paper", "claim", "asserts").await;

    for i in 0..19u32 {
        let paper = seed_paper(
            &pool,
            &format!("10.cross/p{i}"),
            &format!("supporter paper {i}"),
        )
        .await;
        let supporter = seed_claim_with_belief(
            &pool,
            agent,
            &format!("cross supporter {i}"),
            0x40_0000 + i,
            NEMS_BELIEF,
            NEMS_BELIEF,
            NEMS_BELIEF,
        )
        .await;
        insert_edge(&pool, paper, supporter, "paper", "claim", "asserts").await;

        let edge_id = insert_edge(&pool, supporter, target_id, "claim", "claim", "supports").await;
        let outcome =
            auto_wire_ds_for_edge(&pool, edge_id, agent, supporter, target_id, "supports")
                .await
                .expect("auto_wire_ds_for_edge");
        assert_eq!(
            outcome,
            EdgeFactorOutcome::Wired,
            "supporter {i}: expected Wired, got {outcome:?}"
        );
    }

    let bba_count = count_target_bbas(&pool, target_id).await;
    assert_eq!(
        bba_count, 19,
        "expected 19 BBAs on the target, got {bba_count}"
    );

    // Spot-check: every BBA carries the cross-source (no-discount) strength.
    let cross_row_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions \
         WHERE claim_id = $1 AND source_strength = 1.0",
    )
    .bind(target_id)
    .fetch_one(&pool)
    .await
    .expect("count cross rows");
    assert_eq!(
        cross_row_count, 19,
        "expected all 19 BBAs to use source_strength=1.0, got {cross_row_count}"
    );

    let betp = read_betp(&pool, target_id)
        .await
        .expect("target should have computed BetP after 19 supporter wires");
    eprintln!("[cross_source_19_supporters_keeps_high_betp] BetP = {betp}");
    assert!(
        betp > 0.9,
        "cross-source 19-supporter BetP should stay > 0.9, got {betp}"
    );
}
