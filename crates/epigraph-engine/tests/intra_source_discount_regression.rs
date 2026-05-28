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

use epigraph_engine::edge_factor::{
    auto_wire_ds_for_edge, recompute_claim_belief_binary, EdgeFactorOutcome,
};

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

    // Phase 1a (#197): every supporter BBA was written through edge_factor
    // with is_intra = true, so locality_tag must persist as
    // 'intra_self_cite' (Phase 2 vocabulary expansion: DOI-match implies
    // the self-cite case; see Q3 decision in the Phase 2 prompt).
    // This assertion locks the typing column independent of the numeric
    // source_strength band — a future calibration shift that nudged the
    // composed value outside [0.075, 0.405] would not break the typing
    // contract.
    let intra_tag_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions \
         WHERE claim_id = $1 AND locality_tag = 'intra_self_cite'",
    )
    .bind(target_id)
    .fetch_one(&pool)
    .await
    .expect("count locality_tag = intra_self_cite rows");
    assert_eq!(
        intra_tag_count, 19,
        "expected all 19 BBAs to carry locality_tag = 'intra_self_cite', got {intra_tag_count}"
    );

    // Phase 2 (#197): every supporter BBA's `evidence_type` must be the
    // canonical SciFact key `derived_support` (resolved from the raw
    // `supports` relationship via `[evidence_type_aliases]` in
    // calibration.toml). Without this, the combine path's tier-2 lookup
    // would fall through to the 0.5 unknown-key fallback and the BetP
    // band would shift.
    let derived_support_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions \
         WHERE claim_id = $1 AND evidence_type = 'derived_support'",
    )
    .bind(target_id)
    .fetch_one(&pool)
    .await
    .expect("count evidence_type = derived_support rows");
    assert_eq!(
        derived_support_count, 19,
        "expected all 19 BBAs to carry evidence_type = 'derived_support' (canonical key resolution), got {derived_support_count}"
    );

    let betp = read_betp(&pool, target_id)
        .await
        .expect("target should have computed BetP after 19 supporter wires");
    eprintln!("[intra_source_19_supporters_betp_in_band] BetP = {betp}");
    assert!(
        (0.70..=0.85).contains(&betp),
        "expected intra-source-discounted BetP in [0.70, 0.85], got {betp}"
    );

    // ── Phase 2 recalibration canary ────────────────────────────────────
    //
    // The whole point of Phase 2 is that changing the per-frame factor
    // flows through to combined BetP at recompute time, with NO BBA row
    // rewrite. Without this assertion, Phase 2 ships green but the
    // dynamic-recalibration property is dead code — every existing test
    // would mechanically pass against either the old "read stored
    // source_strength" path OR the new "compute from tag" path.
    //
    // Lower the per-frame intra factor from the default 0.3 to 0.1.
    // This deepens the intra-source discount so combined BetP drops
    // further toward 0.5. We assert the shift is observable in BetP
    // (not just the stored cache, which the helper bypasses).
    use epigraph_db::FrameRepository;
    let frame_id = sqlx::query_scalar::<_, Uuid>("SELECT id FROM frames WHERE name = $1")
        .bind("binary_truth")
        .fetch_one(&pool)
        .await
        .expect("binary_truth frame id");
    FrameRepository::set_property(
        &pool,
        frame_id,
        "intra_evidence_locality_factor",
        &serde_json::json!(0.1),
    )
    .await
    .expect("set per-frame intra factor");

    recompute_claim_belief_binary(&pool, target_id)
        .await
        .expect("recompute after per-frame override");

    let recal_betp = read_betp(&pool, target_id)
        .await
        .expect("BetP after recalibration");
    eprintln!("[intra_source_19_supporters_betp_in_band] recalibrated BetP = {recal_betp}");
    // The stored cache is unchanged (Phase 2 makes the cache a
    // write-through; the helper reads tag + factor dynamically). So
    // this assertion would NOT pass if the combine path were still
    // reading row.source_strength.
    assert!(
        recal_betp < betp - 0.02,
        "expected per-frame factor 0.1 (deeper discount than default 0.3) to shift BetP downward: \
         baseline={betp}, recalibrated={recal_betp}"
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

    // Phase 1a (#197): typing column must reflect cross-source classification.
    let cross_tag_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions \
         WHERE claim_id = $1 AND locality_tag = 'cross'",
    )
    .bind(target_id)
    .fetch_one(&pool)
    .await
    .expect("count locality_tag = cross rows");
    assert_eq!(
        cross_tag_count, 19,
        "expected all 19 BBAs to carry locality_tag = 'cross', got {cross_tag_count}"
    );

    let betp = read_betp(&pool, target_id)
        .await
        .expect("target should have computed BetP after 19 supporter wires");
    eprintln!("[cross_source_19_supporters_keeps_high_betp] BetP = {betp}");
    assert!(
        betp > 0.9,
        "cross-source 19-supporter BetP should stay > 0.9, got {betp}"
    );

    // ── Phase 2 recalibration canary (cross side) ───────────────────────
    //
    // Counterpart to the intra recalibration canary above. Changing the
    // per-frame intra factor should have NO effect on cross-source BBAs
    // because the helper's tier-2 path only multiplies by the intra
    // factor when `locality_tag.starts_with("intra")`. This asserts the
    // helper isn't accidentally applying the discount to every BBA.
    use epigraph_db::FrameRepository;
    let frame_id = sqlx::query_scalar::<_, Uuid>("SELECT id FROM frames WHERE name = $1")
        .bind("binary_truth")
        .fetch_one(&pool)
        .await
        .expect("binary_truth frame id");
    FrameRepository::set_property(
        &pool,
        frame_id,
        "intra_evidence_locality_factor",
        &serde_json::json!(0.05),
    )
    .await
    .expect("set per-frame intra factor (should be a no-op for cross-source)");

    recompute_claim_belief_binary(&pool, target_id)
        .await
        .expect("recompute after per-frame override");

    let recal_betp = read_betp(&pool, target_id)
        .await
        .expect("BetP after recalibration");
    eprintln!("[cross_source_19_supporters_keeps_high_betp] cross BetP under per-frame override = {recal_betp}");
    assert!(
        (recal_betp - betp).abs() < 0.01,
        "cross-source BetP must NOT shift under intra-factor recalibration: \
         baseline={betp}, recalibrated={recal_betp}"
    );
}

// ── Per-frame override: intra-source with a custom locality factor ─────────

/// Phase 2 (#197) rewrite of the pre-Phase-2 invariant.
///
/// **Old invariant (pre-Phase-2)**: per-frame factor was read at write
/// time. The `source_strength` column stored the composed result, so a
/// later operator override of `intra_evidence_locality_factor` did NOT
/// retroactively change combined BetP — it only affected future writes.
/// The original test asserted that the primer's stored `source_strength`
/// stayed at the default-factor discount even after the override.
///
/// **Phase 2 invariant (THIS test pins)**: per-frame factor is read at
/// COMBINE time via `effective_source_strength`. The `source_strength`
/// column is now a write-through cache — it still captures the
/// write-time value (for the audit trail and for the legacy-null
/// fallback), but the helper at combine time reads `locality_tag` and
/// `evidence_type` and composes with the current per-frame factor. So:
///
///   * The stored `source_strength` on the primer still lands at the
///     default-factor write-time value (the cache assertion mechanically
///     passes the same way it did pre-Phase-2 — this is the
///     write-through behaviour we kept on purpose).
///   * But the COMBINED BetP on the target reflects the per-frame
///     override applied to BOTH the primer and the override-affected
///     supporter, because the combine path no longer reads the stored
///     value. **This is the inversion**.
///
/// The new combined-BetP assertions are the canary that Phase 2 actually
/// does what it's supposed to. Without them, Phase 2 ships green but the
/// recalibration-without-DB-rewrite property is dead code at combine
/// time.
#[sqlx::test(migrations = "../../migrations")]
async fn per_frame_locality_factor_override_applied(pool: PgPool) {
    use epigraph_db::FrameRepository;

    let agent = seed_agent(&pool, 0xC0_0001).await;
    let target_doi = "10.perframe/p1";
    let paper = seed_paper(&pool, target_doi, "per-frame override").await;

    let target_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current) \
         VALUES ($1, $2, $3, $4, 0.5, true)",
    )
    .bind(target_id)
    .bind("per-frame override target")
    .bind(distinct_hash(0x50_0000))
    .bind(agent)
    .execute(&pool)
    .await
    .expect("seed target");
    insert_edge(&pool, paper, target_id, "paper", "claim", "asserts").await;

    // ensure_binary_frame() inside edge_factor creates the binary_truth
    // frame lazily, but we need it materialized BEFORE the edge writes so
    // we can set the per-frame property. Fire one supporter just to
    // materialize the frame row, then set the override, then run the
    // real check.
    let primer = seed_claim_with_belief(
        &pool,
        agent,
        "primer supporter",
        0x51_0000,
        NEMS_BELIEF,
        NEMS_BELIEF,
        NEMS_BELIEF,
    )
    .await;
    seed_doi_evidence(&pool, primer, target_doi, 0x71_0000).await;
    let primer_edge = insert_edge(&pool, primer, target_id, "claim", "claim", "supports").await;
    auto_wire_ds_for_edge(&pool, primer_edge, agent, primer, target_id, "supports")
        .await
        .expect("auto_wire primer");

    // Capture the BetP at the default per-frame factor (calibration's
    // 0.3) — this is the Phase 2 baseline we'll later compare against.
    let baseline_betp = read_betp(&pool, target_id)
        .await
        .expect("baseline BetP after primer wire");
    eprintln!("[per_frame_locality_factor_override_applied] baseline BetP (default factor 0.3) = {baseline_betp}");

    // Now binary_truth exists. Override its locality factor.
    let frame = FrameRepository::get_by_name(&pool, "binary_truth")
        .await
        .expect("query binary_truth")
        .expect("binary_truth must exist after primer wire");
    FrameRepository::set_property(
        &pool,
        frame.id,
        "intra_evidence_locality_factor",
        &serde_json::json!(0.9),
    )
    .await
    .expect("set frame property");

    // Fire a fresh supporter under the override. Pre-Phase-2, this BBA
    // would have stored a different `source_strength` than the primer.
    // Under Phase 2 it still does (write-through cache), but more
    // importantly: the combine on next recompute reads BOTH BBAs through
    // the helper, which reads the CURRENT per-frame factor — so both
    // contribute under the 0.9 factor at recompute time.
    let supporter = seed_claim_with_belief(
        &pool,
        agent,
        "override-affected supporter",
        0x52_0000,
        NEMS_BELIEF,
        NEMS_BELIEF,
        NEMS_BELIEF,
    )
    .await;
    seed_doi_evidence(&pool, supporter, target_doi, 0x72_0000).await;
    let edge_id = insert_edge(&pool, supporter, target_id, "claim", "claim", "supports").await;
    let outcome = auto_wire_ds_for_edge(&pool, edge_id, agent, supporter, target_id, "supports")
        .await
        .expect("auto_wire override");
    assert_eq!(outcome, EdgeFactorOutcome::Wired);

    // ── Write-through cache assertion (carried forward from pre-Phase-2) ──
    //
    // The override BBA's stored `source_strength` is the write-time
    // value composed with the per-frame override that was in effect at
    // write time. This assertion still passes mechanically because the
    // write path (`auto_wire_ds_for_edge`) still writes the composed
    // value into the cache. What Phase 2 changes is that this stored
    // value is no longer the authority at combine time.
    let override_ss: f64 =
        sqlx::query_scalar("SELECT source_strength FROM mass_functions WHERE perspective_id = $1")
            .bind(edge_id)
            .fetch_one(&pool)
            .await
            .expect("fetch override BBA's source_strength");
    eprintln!(
        "[per_frame_locality_factor_override_applied] override source_strength = {override_ss}"
    );
    assert!(
        (0.50..=0.75).contains(&override_ss),
        "expected per-frame override (factor 0.9) to land source_strength in [0.50, 0.75], got {override_ss}"
    );

    // Primer was written BEFORE the override, so its cached value is
    // still the default-factor discount (~0.21). Write-through cache
    // preserves the audit trail.
    let primer_ss: f64 =
        sqlx::query_scalar("SELECT source_strength FROM mass_functions WHERE perspective_id = $1")
            .bind(primer_edge)
            .fetch_one(&pool)
            .await
            .expect("fetch primer BBA's source_strength");
    assert!(
        primer_ss < 0.30,
        "primer BBA's stored cache (written pre-override) should still reflect default-factor discount (<0.30), got {primer_ss}"
    );

    // ── Phase 2 (#197) Q3: locality_tag vocabulary expansion ──
    //
    // 'intra_self_cite' (DOI-match → self-cite case) replaces the
    // bare 'intra' tag from Phase 1a. Per-frame factor changes ONLY
    // the discount, not the classification.
    let primer_tag: String =
        sqlx::query_scalar("SELECT locality_tag FROM mass_functions WHERE perspective_id = $1")
            .bind(primer_edge)
            .fetch_one(&pool)
            .await
            .expect("fetch primer locality_tag");
    assert_eq!(
        primer_tag, "intra_self_cite",
        "primer BBA must carry locality_tag = 'intra_self_cite'"
    );

    let override_tag: String =
        sqlx::query_scalar("SELECT locality_tag FROM mass_functions WHERE perspective_id = $1")
            .bind(edge_id)
            .fetch_one(&pool)
            .await
            .expect("fetch override locality_tag");
    assert_eq!(
        override_tag, "intra_self_cite",
        "override BBA must carry locality_tag = 'intra_self_cite' (per-frame factor changes only the discount, not the classification)"
    );

    // ── Phase 2 inverted invariant: combined BetP reflects override ──
    //
    // This is the assertion the Phase 2 spec § 6 calls out as the canary.
    // The combine path (`recompute_combined_belief`) does NOT read the
    // stored `source_strength`; it derives reliability from
    // `effective_source_strength(row, per_frame_intra, &calibration)`.
    // So at recompute time, the 0.9 per-frame factor is applied to
    // BOTH BBAs (primer and supporter, both `intra_self_cite`), even
    // though the primer's cache row still reflects the 0.3 default
    // from its write time.
    //
    // Compared to the baseline (single supporter at 0.3 default
    // factor): combined BetP under 0.9 with two supporters must
    // be visibly different — specifically HIGHER, because the
    // discount is much weaker AND there's a second supporter
    // adding weight.
    let combined_betp = read_betp(&pool, target_id)
        .await
        .expect("BetP after override + second supporter");
    eprintln!(
        "[per_frame_locality_factor_override_applied] combined BetP (override 0.9, 2 BBAs) = {combined_betp}"
    );
    assert!(
        combined_betp > baseline_betp,
        "combined BetP must reflect the weaker (0.9) per-frame discount: \
         baseline={baseline_betp}, combined={combined_betp}"
    );

    // Direct recompute canary: pin the override factor higher (0.99,
    // nearly no discount) and recompute. BetP must shift even further
    // toward 1.0 under the same stored cache values — this proves the
    // helper, not the cache, drives the combine.
    FrameRepository::set_property(
        &pool,
        frame.id,
        "intra_evidence_locality_factor",
        &serde_json::json!(0.99),
    )
    .await
    .expect("set frame property to 0.99");
    recompute_claim_belief_binary(&pool, target_id)
        .await
        .expect("recompute after second override");
    let nearly_undiscounted_betp = read_betp(&pool, target_id)
        .await
        .expect("BetP after second recalibration");
    eprintln!(
        "[per_frame_locality_factor_override_applied] nearly-undiscounted BetP (factor 0.99) = {nearly_undiscounted_betp}"
    );
    assert!(
        nearly_undiscounted_betp > combined_betp,
        "raising per-frame factor 0.9 → 0.99 must further increase combined BetP \
         WITHOUT touching the stored cache: prev={combined_betp}, new={nearly_undiscounted_betp}"
    );

    // Push the factor the other way (0.05, near-total discount) and
    // recompute. BetP must shift back DOWN — proves the helper reads
    // the current factor on every combine call.
    FrameRepository::set_property(
        &pool,
        frame.id,
        "intra_evidence_locality_factor",
        &serde_json::json!(0.05),
    )
    .await
    .expect("set frame property to 0.05");
    recompute_claim_belief_binary(&pool, target_id)
        .await
        .expect("recompute after third override");
    let deeply_discounted_betp = read_betp(&pool, target_id)
        .await
        .expect("BetP after deeper discount");
    eprintln!(
        "[per_frame_locality_factor_override_applied] deeply-discounted BetP (factor 0.05) = {deeply_discounted_betp}"
    );
    assert!(
        deeply_discounted_betp < nearly_undiscounted_betp - 0.05,
        "lowering per-frame factor 0.99 → 0.05 must shift combined BetP downward by ≥0.05: \
         prev={nearly_undiscounted_betp}, new={deeply_discounted_betp}"
    );
}

// ── Phase 4 (#197): per-frame evidence-type weight override ────────────────

/// **The key Phase 4 invariant**: a per-frame `evidence_type_weights`
/// JSONB override flows through `recompute_claim_belief_binary` to
/// combined BetP without any BBA rewrite. The override map is read
/// at combine time via the new `effective_source_strength` Tier 1
/// lookup. Without this assertion, Phase 4 ships green but the per-
/// frame override is dead code at combine time.
///
/// Fixture key choice: this test exercises the same `auto_wire_ds_for_edge`
/// write path as the Phase 2 regression. That write path resolves the
/// `"supports"` relationship through `[evidence_type_aliases]` to the
/// canonical SciFact key `"derived_support"` and stores THAT in
/// `mass_functions.evidence_type` (see calibration.toml's alias section
/// and the assertion at line ~292 of this file). So the Phase 4 override
/// MUST be keyed on `"derived_support"`, not `"supports"` and not
/// `"empirical"` — the BBAs aren't tagged either of those. This is the
/// load-bearing detail the advisor flagged.
///
/// Q10 ([0.0, 1.0] clamp) constrains the upward-shift test: the global
/// calibration `derived_support = 0.7`. An override `< 0.7` shifts BetP
/// down, but an override `> 1.0` clamps to 1.0. We exercise a single
/// down-shift + restore round-trip per the task's allowance ("if the
/// upward case isn't possible under [0,1] clamp ... a single down-shift
/// + restore round-trip is sufficient").
#[sqlx::test(migrations = "../../migrations")]
async fn per_frame_evidence_type_weight_override_applied(pool: PgPool) {
    use epigraph_db::FrameRepository;

    let agent = seed_agent(&pool, 0xD0_0001).await;
    let target_doi = "10.phase4/evtw";
    let paper = seed_paper(&pool, target_doi, "phase 4 evidence-type override").await;

    // Target — start with NULL belief/plausibility so the only BBAs on
    // the target come from the supporter wires.
    let target_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current) \
         VALUES ($1, $2, $3, $4, 0.5, true)",
    )
    .bind(target_id)
    .bind("phase 4 evidence-type override target")
    .bind(distinct_hash(0x60_0000))
    .bind(agent)
    .execute(&pool)
    .await
    .expect("seed target");
    insert_edge(&pool, paper, target_id, "paper", "claim", "asserts").await;

    // Seed two intra-source supporters, both citing the target's DOI.
    // Each fires through `auto_wire_ds_for_edge("supports")` → BBA
    // tagged `evidence_type = "derived_support"` (canonical), `locality_tag
    // = "intra_self_cite"`.
    for i in 0..2u32 {
        let supporter = seed_claim_with_belief(
            &pool,
            agent,
            &format!("phase 4 supporter {i}"),
            0x61_0000 + i,
            NEMS_BELIEF,
            NEMS_BELIEF,
            NEMS_BELIEF,
        )
        .await;
        seed_doi_evidence(&pool, supporter, target_doi, 0x73_0000 + i).await;
        let edge_id = insert_edge(&pool, supporter, target_id, "claim", "claim", "supports").await;
        let outcome =
            auto_wire_ds_for_edge(&pool, edge_id, agent, supporter, target_id, "supports")
                .await
                .expect("auto_wire");
        assert_eq!(outcome, EdgeFactorOutcome::Wired);
    }

    // Sanity: 2 BBAs landed, all tagged with the canonical key.
    let bba_count = count_target_bbas(&pool, target_id).await;
    assert_eq!(
        bba_count, 2,
        "expected 2 BBAs on the target, got {bba_count}"
    );
    let canonical_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions \
         WHERE claim_id = $1 AND evidence_type = 'derived_support'",
    )
    .bind(target_id)
    .fetch_one(&pool)
    .await
    .expect("count derived_support rows");
    assert_eq!(
        canonical_count, 2,
        "expected both BBAs tagged 'derived_support' (auto-wire alias resolution), got {canonical_count}"
    );

    // Baseline BetP at calibration's global derived_support = 0.7.
    let baseline_betp = read_betp(&pool, target_id)
        .await
        .expect("baseline BetP after supporter wires");
    eprintln!(
        "[per_frame_evidence_type_weight_override_applied] baseline BetP (global derived_support=0.7) = {baseline_betp}"
    );

    // ── Phase 4 Tier 1 down-shift: override derived_support to 0.1 ──
    //
    // 0.1 << 0.7 global → each supporter's reliability discount
    // shrinks roughly 7x (composed with intra locality 0.3, the
    // discount weight drops from 0.21 to 0.03), so each contributes
    // far less mass to TRUE through the discount step, and combined
    // BetP shifts downward.
    //
    // Why such a deep override: the BetP combine is non-linear, and
    // a moderate override (e.g. 0.3) shifts BetP only ~0.03 in this
    // 2-supporter fixture — within combination noise tolerance. The
    // deep override produces a visibly-larger shift that survives the
    // ≥0.02 threshold without false positives. Wider fixtures would
    // amplify smaller overrides, but this 2-supporter shape is the
    // simplest Phase 4 canary and matches the spec § 7 recipe.
    let frame_id = sqlx::query_scalar::<_, Uuid>("SELECT id FROM frames WHERE name = $1")
        .bind("binary_truth")
        .fetch_one(&pool)
        .await
        .expect("binary_truth frame id");
    FrameRepository::set_evidence_type_weight(&pool, frame_id, "derived_support", 0.1)
        .await
        .expect("set per-frame derived_support override");

    // Recompute — the helper reads the override at combine time.
    // **No BBA row rewrite** in between. This is the canary.
    recompute_claim_belief_binary(&pool, target_id)
        .await
        .expect("recompute after per-frame evidence-type override");

    let downshifted_betp = read_betp(&pool, target_id)
        .await
        .expect("BetP after override");
    eprintln!(
        "[per_frame_evidence_type_weight_override_applied] override 0.1 BetP = {downshifted_betp}"
    );
    // Threshold 0.02: combination noise from `combine_multiple`'s
    // conflict-renormalisation is empirically << 1e-3 on a fixture
    // this small with no random seeding. 0.02 is conservative
    // headroom; observed shift is ~0.05+ with this override.
    assert!(
        downshifted_betp < baseline_betp - 0.02,
        "per-frame override derived_support=0.1 (vs global 0.7) must shift BetP downward by ≥0.02: \
         baseline={baseline_betp}, downshifted={downshifted_betp}"
    );

    // ── Round-trip: remove the override, BetP returns to baseline ──
    //
    // We remove the whole `evidence_type_weights` key — this exercises
    // the "operator rolls back per-frame override" rollback path from
    // Phase 4 spec § 9.6.
    sqlx::query(
        "UPDATE frames SET properties = properties - 'evidence_type_weights' WHERE id = $1",
    )
    .bind(frame_id)
    .execute(&pool)
    .await
    .expect("remove evidence_type_weights key");
    recompute_claim_belief_binary(&pool, target_id)
        .await
        .expect("recompute after override removal");

    let restored_betp = read_betp(&pool, target_id)
        .await
        .expect("BetP after removal");
    eprintln!("[per_frame_evidence_type_weight_override_applied] restored BetP = {restored_betp}");
    assert!(
        (restored_betp - baseline_betp).abs() < 1e-6,
        "removing per-frame override must return BetP to baseline within float tolerance: \
         baseline={baseline_betp}, restored={restored_betp}, delta={}",
        (restored_betp - baseline_betp).abs()
    );
}
