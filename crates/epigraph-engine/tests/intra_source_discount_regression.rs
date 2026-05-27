//! 19-supporter synthetic regression for locality-aware discounting.
//!
//! Mirrors the NEMS shape from issue #142: one target T, 19 supporting claims
//! S1..S19. With no locality discount (cross-source) the combined BetP
//! approaches 1.0 (the un-discounted Dempster product). With evidence-mediated
//! intra-source detection composing the per-BBA source_strength with the
//! `intra_evidence_locality_factor` from calibration.toml (default 0.3),
//! BetP drops into the [0.70, 0.85] band the issue requires.
//!
//! Locality detection lives in the evidence table: the supporter has an
//! `evidence` row whose `properties->>'doi'` matches the doi of the paper
//! that asserts the target via the `asserts` edge. The intra-source
//! regression fixture seeds such a row on every supporter; the cross-source
//! fixture does not.
//!
//! The test exercises the centralized BBA write path
//! `epigraph_engine::edge_factor::auto_wire_ds_for_edge` directly. No HTTP /
//! MCP server is required.
//!
//! Schema notes:
//!   * `claims.agent_id` is NOT NULL — seed an `agents` row first.
//!   * `(content_hash, agent_id)` is UNIQUE — hand-build distinct 32-byte hashes.
//!   * `edges.source_type` / `target_type` are NOT NULL and validated against
//!     the entity-type allowlist; we use `'paper'` / `'claim'` for `asserts`,
//!     `'claim'` / `'claim'` for `supports`.
//!   * `evidence.content_hash` and `evidence.evidence_type` are NOT NULL.
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

/// Seed an evidence row on `claim_id` whose `properties->>'doi'` is set to
/// `doi`. Used by `intra_source_19_supporters_betp_in_band` to make each
/// supporter "cite" the target's paper, which is the signal the new
/// evidence-mediated locality check looks for in
/// `edge_factor::auto_wire_ds_for_edge`.
async fn seed_doi_evidence(pool: &PgPool, claim_id: Uuid, doi: &str, tag: u32) {
    sqlx::query(
        "INSERT INTO evidence (id, content_hash, evidence_type, claim_id, properties) \
         VALUES (gen_random_uuid(), $1, 'reference', $2, jsonb_build_object('doi', $3))",
    )
    .bind(distinct_hash(tag))
    .bind(claim_id)
    .bind(doi)
    .execute(pool)
    .await
    .expect("seed evidence row");
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
    let target_doi = "10.intra/p1";
    let paper = seed_paper(&pool, target_doi, "Synthesis paper").await;

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

    // The target's asserting-paper edge gives the new evidence-mediated
    // locality check something to compare each supporter's doi-evidence
    // against. (Pre-2026-05-27 the regression also relied on the
    // `same_source_papers` recursive CTE traversing supporter→same_paper
    // edges; the new check is strictly evidence-table-mediated and does
    // not need the supporter assertions to fire — see the seed_doi_evidence
    // call in the loop below.)
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

        // Each supporter cites the target's paper via an evidence row —
        // this is the signal the new evidence-mediated intra-source check
        // looks for. (Distinct tags so the evidence rows don't collide on
        // the content_hash check constraint.)
        seed_doi_evidence(&pool, supporter, target_doi, 0x70_0000 + i).await;

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

    // Spot-check: every BBA carries the composed intra-source discount.
    // For "supports" the transmission factor f is RestrictionProfile::scientific().supports
    // (currently 0.7); composed with intra_evidence_locality_factor 0.3
    // yields source_strength = 0.21.
    //
    // We use a tolerance band instead of `=` because the transmission
    // factor is read from RestrictionProfile and may drift with future
    // calibration. The intra_evidence_locality_factor band [0.15, 0.45]
    // (per intra_source_discount_calibration.rs) combined with a plausible
    // supports-transmission range [0.5, 0.9] gives [0.075, 0.405].
    let composed_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions \
         WHERE claim_id = $1 AND source_strength > 0.075 AND source_strength < 0.405",
    )
    .bind(target_id)
    .fetch_one(&pool)
    .await
    .expect("count composed-intra rows");
    assert_eq!(
        composed_count, 19,
        "expected all 19 BBAs to carry the composed intra-source discount, got {composed_count}"
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

    // Target paper is distinct from all 19 supporter papers AND no supporter
    // gets an evidence row citing the target's doi — so the evidence-mediated
    // intra-source check in edge_factor returns false for every supporter,
    // locality_factor = 1.0, source_strength = transmission_factor unscaled.
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

    // Spot-check: every BBA's source_strength equals the un-discounted
    // transmission factor f (locality_factor = 1.0 when cross-source).
    // For "supports" with the scientific profile, f is currently 0.7.
    // The band [0.5, 0.9] tracks plausible future-calibration drift.
    let cross_row_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions \
         WHERE claim_id = $1 AND source_strength >= 0.5 AND source_strength <= 0.9",
    )
    .bind(target_id)
    .fetch_one(&pool)
    .await
    .expect("count cross rows");
    assert_eq!(
        cross_row_count, 19,
        "expected all 19 BBAs to land in the cross-source transmission band [0.5, 0.9], got {cross_row_count}"
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
