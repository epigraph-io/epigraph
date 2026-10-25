//! The bulk belief recompute leaves compounds and ingest-template-only claims
//! alone (atom-level belief program, PR-0; SPEC §2.1 roles, §6.1 compound
//! caches frozen, §10.1 hazards H1 and H2, §10.5 the template-only residue,
//! §10.6 freeze list).
//!
//! Three bulk recomputers resolve a claim's cache owner through the ONE choke
//! point `MassFunctionRepository::cache_owner_frame_for_claim`:
//!
//! * `epigraph_cli::recompute_betp::run_claim` (the `recompute_betp` binary),
//! * `epigraph_engine::edge_factor::recompute_claim_cached_belief` (the
//!   `recompute_claim_belief` binary),
//! * `epigraph_mcp::tools::cdst_maintenance::recompute_beliefs` (MCP).
//!
//! Before the guard, every one of them rewrote the cache of
//!
//! * a claim whose only input is the ingest template (a `research_validity`
//!   row with no combination method, source strength 0.3 and at least 0.80 of
//!   its mass on the whole frame) with the fold of that template alone, which
//!   replaces whatever value the cache held with a near-vacuous one; and
//! * a compound (a claim with an in-force `decomposes_to` out-edge to a
//!   current claim), whose belief is a query over its leaves, not a fold of
//!   the BBAs that sit on it.
//!
//! The guard returns "no owner" (leave the cache alone) in both cases, and
//! nowhere else. The over-breadth arms matter as much as the guarded arms: a
//! template next to real evidence is still recomputed, a near-miss of the
//! template signature is real evidence, a compound whose only decomposition is
//! retired is not a compound, and a workflow-rooted (procedural) tree keeps
//! today's behaviour.
//!
//! Every assertion compares the cache against a sentinel the fold cannot
//! produce, or against a TWIN claim that carries only the rows the guarded
//! claim should be folded from. No expected value is computed here by the
//! formula the recompute uses.

use sqlx::PgPool;
use uuid::Uuid;

#[path = "viewer_fixture.rs"]
mod fixture;

// ── the three callers ──────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Caller {
    RecomputeBetpRunClaim,
    EngineRecomputeClaimCachedBelief,
    McpRecomputeBeliefs,
}

const CALLERS: [Caller; 3] = [
    Caller::RecomputeBetpRunClaim,
    Caller::EngineRecomputeClaimCachedBelief,
    Caller::McpRecomputeBeliefs,
];

/// Run one bulk recompute of `claim` through `caller`. Returns whether the
/// caller REPORTS that it wrote the claim's cache.
async fn recompute_via(pool: &PgPool, caller: Caller, claim: Uuid) -> bool {
    match caller {
        Caller::RecomputeBetpRunClaim => {
            let viewer = fixture::public_viewer(pool).await;
            let written = epigraph_cli::recompute_betp::run_claim(pool, &viewer, claim)
                .await
                .expect("recompute_betp::run_claim");
            written > 0
        }
        Caller::EngineRecomputeClaimCachedBelief => {
            let viewer = fixture::public_viewer(pool).await;
            epigraph_engine::edge_factor::recompute_claim_cached_belief(
                &mut pool.acquire().await.expect("acquire"),
                &viewer,
                claim,
            )
            .await
            .expect("edge_factor::recompute_claim_cached_belief")
        }
        Caller::McpRecomputeBeliefs => {
            let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x5au8; 32]).expect("signer");
            let embedder = epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None);
            let server = epigraph_mcp::EpiGraphMcpFull::new(pool.clone(), signer, embedder, false);
            let out = epigraph_mcp::tools::cdst_maintenance::recompute_beliefs(
                &server,
                &mut fixture::scoped_pool(pool)
                    .await
                    .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
                    .await
                    .expect("a maintenance session over the test database"),
                epigraph_mcp::types::RecomputeBeliefsParams {
                    claim_ids: Some(vec![claim.to_string()]),
                    labels: None,
                    limit: None,
                    offset: None,
                },
            )
            .await
            .expect("cdst_maintenance::recompute_beliefs");
            let envelope = serde_json::to_value(&out).expect("tool result serializes");
            let text = envelope["content"][0]["text"]
                .as_str()
                .unwrap_or_else(|| panic!("text content in {envelope}"));
            let json: serde_json::Value = serde_json::from_str(text).expect("result is JSON");
            assert_eq!(
                json["errors"].as_array().map(Vec::len),
                Some(0),
                "recompute_beliefs must not report errors: {json}"
            );
            // One candidate, counted in exactly one bucket: a claim the guard
            // leaves alone is reported as skipped (no recomputable input), not
            // as an error and not silently dropped.
            assert_eq!(json["claims_considered"], 1, "{json}");
            let recomputed = json["claims_recomputed"] == 1;
            let skipped = json["claims_skipped_no_bba"] == 1;
            assert!(
                recomputed != skipped,
                "exactly one of claims_recomputed / claims_skipped_no_bba: {json}"
            );
            recomputed
        }
    }
}

// ── the cache ──────────────────────────────────────────────────────────────

/// Every column the cache writer owns on `claims`.
#[derive(Debug, Clone, PartialEq)]
struct Cache {
    belief: Option<f64>,
    plausibility: Option<f64>,
    pignistic_prob: Option<f64>,
    mass_on_empty: Option<f64>,
    mass_on_missing: Option<f64>,
    belief_frame_id: Option<Uuid>,
    classification: Option<String>,
}

async fn cache(pool: &PgPool, claim: Uuid) -> Cache {
    use sqlx::Row as _;
    let r = sqlx::query(
        "SELECT belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing, \
                belief_frame_id, classification \
           FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the claim's cache");
    Cache {
        belief: r.get("belief"),
        plausibility: r.get("plausibility"),
        pignistic_prob: r.get("pignistic_prob"),
        mass_on_empty: r.get("mass_on_empty"),
        mass_on_missing: r.get("mass_on_missing"),
        belief_frame_id: r.get("belief_frame_id"),
        classification: r.get("classification"),
    }
}

/// Put a cache on `claim` that no fold in this file can produce (odd
/// three-decimal values that are not a function of any seeded mass), recorded
/// on `frame`. A claim that keeps exactly this cache was not rewritten.
async fn set_sentinel_cache(pool: &PgPool, claim: Uuid, frame: Uuid) -> Cache {
    sqlx::query(
        "UPDATE claims SET belief = 0.613, plausibility = 0.887, pignistic_prob = 0.741, \
                mass_on_empty = 0.017, mass_on_missing = 0.029, belief_frame_id = $2, \
                classification = 'sentinel' \
          WHERE id = $1",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("set the sentinel cache");
    let c = cache(pool, claim).await;
    assert_eq!(c.pignistic_prob, Some(0.741), "sentinel in place");
    c
}

// ── seeding ────────────────────────────────────────────────────────────────

async fn agent(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'system', ARRAY['test']) \
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// An agent registered as the `workflow-ingest` system agent (migration 148):
/// the only author whose `source_type: workflow` root stamp makes a tree
/// procedural. Planted with triggers off (one per test database: the role is
/// the registry's primary key).
async fn workflow_ingest_agent(pool: &PgPool, name: &str) -> Uuid {
    let id = agent(pool, name).await;
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .expect("replica");
    sqlx::query(
        "INSERT INTO public.system_agents (role, agent_id, registered_public_key, reason) \
         SELECT 'workflow-ingest', a.id, a.public_key, 'bulk-guard test plant' \
           FROM public.agents a WHERE a.id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .expect("plant the workflow-ingest system agent");
    tx.commit().await.expect("commit");
    id
}

/// Get-or-create a two-hypothesis frame by name (`frames.name` is UNIQUE).
async fn frame(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query(
        "INSERT INTO frames (name, description, hypotheses) \
         VALUES ($1, 'bulk recompute guard test frame', ARRAY['TRUE', 'FALSE']) \
         ON CONFLICT (name) DO NOTHING",
    )
    .bind(name)
    .execute(pool)
    .await
    .expect("insert frame");
    sqlx::query_scalar("SELECT id FROM frames WHERE name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("frame by name")
}

async fn claim_with_properties(
    pool: &PgPool,
    owner: Uuid,
    what: &str,
    properties: serde_json::Value,
) -> Uuid {
    let content = format!("{what} {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, properties) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, true, $3) RETURNING id",
    )
    .bind(&content)
    .bind(owner)
    .bind(properties)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn claim(pool: &PgPool, owner: Uuid, what: &str) -> Uuid {
    claim_with_properties(pool, owner, what, serde_json::json!({})).await
}

/// One BBA row, shaped by its stored columns only.
struct Row<'a> {
    frame: Uuid,
    source: Option<Uuid>,
    masses: serde_json::Value,
    method: Option<&'a str>,
    source_strength: Option<f64>,
    evidence_type: Option<&'a str>,
}

async fn insert_row(pool: &PgPool, claim: Uuid, row: &Row<'_>) {
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) \
         VALUES ($1, $2, 0) ON CONFLICT DO NOTHING",
    )
    .bind(claim)
    .bind(row.frame)
    .execute(pool)
    .await
    .expect("assign claim to frame");
    sqlx::query(
        "INSERT INTO mass_functions \
           (claim_id, frame_id, source_agent_id, masses, conflict_k, combination_method, \
            source_strength, evidence_type, locality_tag) \
         VALUES ($1, $2, $3, $4, 0.0, $5, $6, $7, 'unknown')",
    )
    .bind(claim)
    .bind(row.frame)
    .bind(row.source)
    .bind(&row.masses)
    .bind(row.method)
    .bind(row.source_strength)
    .bind(row.evidence_type)
    .execute(pool)
    .await
    .expect("insert BBA");
}

/// The ingest template's shape: `research_validity`, no combination method,
/// source strength 0.3, `theta` of the mass on the whole frame.
fn template_row(research_validity: Uuid, ingest: Uuid, theta: f64) -> Row<'static> {
    Row {
        frame: research_validity,
        source: Some(ingest),
        masses: serde_json::json!({ "0": 1.0 - theta, "0,1": theta }),
        method: None,
        source_strength: Some(0.3),
        evidence_type: None,
    }
}

/// A substantive, support-leaning input row.
fn evidence_row(frame: Uuid, source: Uuid, method: &'static str) -> Row<'static> {
    Row {
        frame,
        source: Some(source),
        masses: serde_json::json!({ "0": 0.7, "0,1": 0.3 }),
        method: Some(method),
        source_strength: Some(0.9),
        evidence_type: Some("empirical"),
    }
}

/// A `decomposes_to` edge `parent -> child`; `retired` puts it out of force.
async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid, retired: bool) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_from, valid_to) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
                 now() - interval '2 days', \
                 CASE WHEN $3 THEN now() - interval '1 day' END)",
    )
    .bind(parent)
    .bind(child)
    .bind(retired)
    .execute(pool)
    .await
    .expect("seed decomposes_to edge");
}

/// Write a real `update_with_evidence`-shaped input (the MCP evidence writer,
/// `binary_truth`, `auto_wire`, linked to an evidence row) on `claim`.
async fn update_with_evidence_row(pool: &PgPool, claim: Uuid, source: Uuid) {
    let evidence = fixture::seed_evidence(pool, claim, "observation").await;
    let viewer = fixture::public_viewer(pool).await;
    epigraph_mcp::tools::ds_auto::auto_wire_ds_update(
        &mut pool.acquire().await.expect("acquire"),
        &viewer,
        claim,
        source,
        0.8,  // confidence
        1.0,  // weight
        true, // supports
        Some("empirical"),
        Some(evidence),
        false, // no truth_value seed: the row under test is the evidence alone
    )
    .await
    .expect("auto_wire_ds_update");
}

// ── (1) a template-only atom keeps its cache, under each caller ─────────────

/// A leaf atom (target of an in-force `decomposes_to`) whose only input is the
/// ingest template, with a non-NULL cache. A bulk recompute must report no
/// write and leave every cache column exactly as it was.
async fn template_only_atom_keeps_its_cache(pool: &PgPool, caller: Caller) {
    let owner = agent(pool, "guard-owner").await;
    let ingest = agent(pool, "guard-ingest").await;
    let rv = frame(pool, "research_validity").await;

    let parent = claim(pool, owner, "compound paragraph").await;
    let atom = claim(pool, owner, "template-only atom").await;
    decomposes_to(pool, parent, atom, false).await;
    insert_row(pool, atom, &template_row(rv, ingest, 0.9)).await;
    let before = set_sentinel_cache(pool, atom, rv).await;

    let wrote = recompute_via(pool, caller, atom).await;

    assert!(
        !wrote,
        "{caller:?} reported a cache write for a claim whose only input is the \
         ingest template"
    );
    assert_eq!(
        cache(pool, atom).await,
        before,
        "{caller:?} rewrote a template-only atom's cache"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn template_only_atom_keeps_its_cache_under_recompute_betp_run_claim(pool: PgPool) {
    template_only_atom_keeps_its_cache(&pool, Caller::RecomputeBetpRunClaim).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn template_only_atom_keeps_its_cache_under_engine_recompute_claim_cached_belief(
    pool: PgPool,
) {
    template_only_atom_keeps_its_cache(&pool, Caller::EngineRecomputeClaimCachedBelief).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn template_only_atom_keeps_its_cache_under_mcp_recompute_beliefs(pool: PgPool) {
    template_only_atom_keeps_its_cache(&pool, Caller::McpRecomputeBeliefs).await;
}

/// The template signature is "every" input, not "some": several template rows
/// from different ingest agents are still template-only.
#[sqlx::test(migrations = "../../migrations")]
async fn several_template_rows_are_still_template_only(pool: PgPool) {
    let owner = agent(&pool, "guard-owner").await;
    let rv = frame(&pool, "research_validity").await;
    for caller in CALLERS {
        let atom = claim(&pool, owner, "atom with two template rows").await;
        let ingest_a = agent(&pool, "guard-ingest-a").await;
        let ingest_b = agent(&pool, "guard-ingest-b").await;
        insert_row(&pool, atom, &template_row(rv, ingest_a, 0.9)).await;
        // Exactly the 0.80 boundary: the signature is `>=`.
        insert_row(&pool, atom, &template_row(rv, ingest_b, 0.8)).await;
        let before = set_sentinel_cache(&pool, atom, rv).await;

        assert!(!recompute_via(&pool, caller, atom).await, "{caller:?}");
        assert_eq!(cache(&pool, atom).await, before, "{caller:?}");
    }
}

// ── (2) a template next to a real input is recomputed ───────────────────────

/// Template + an `auto_cdst` row on the SAME frame: the template exclusion is
/// per row, so the claim still has an input and is recomputed by every caller.
#[sqlx::test(migrations = "../../migrations")]
async fn template_plus_auto_cdst_atom_is_recomputed(pool: PgPool) {
    let owner = agent(&pool, "guard-owner").await;
    let ingest = agent(&pool, "guard-ingest").await;
    let cdst = agent(&pool, "guard-cdst").await;
    let rv = frame(&pool, "research_validity").await;

    for caller in CALLERS {
        let atom = claim(&pool, owner, "template + auto_cdst atom").await;
        insert_row(&pool, atom, &template_row(rv, ingest, 0.9)).await;
        insert_row(&pool, atom, &evidence_row(rv, cdst, "auto_cdst")).await;
        let before = set_sentinel_cache(&pool, atom, rv).await;

        assert!(
            recompute_via(&pool, caller, atom).await,
            "{caller:?} skipped an atom that has a real (auto_cdst) input"
        );
        let after = cache(&pool, atom).await;
        assert_ne!(
            after.pignistic_prob, before.pignistic_prob,
            "{caller:?} reported a write but left the sentinel"
        );
        assert_eq!(after.belief_frame_id, Some(rv), "{caller:?}");

        // KNOWN GAP, pinned so it stays visible: the template is excluded only
        // from the choice of OWNER frame, not from the owner frame's fold. A
        // template that shares the owner frame with a real input is still
        // folded there, so this atom's value differs from a twin carrying the
        // auto_cdst row alone. Dropping the template from the fold belongs to
        // the atom-fold change; when it lands, this assertion flips to
        // `assert_eq!` and must be updated with it.
        let twin = claim(&pool, owner, "auto_cdst alone").await;
        insert_row(&pool, twin, &evidence_row(rv, cdst, "auto_cdst")).await;
        set_sentinel_cache(&pool, twin, rv).await;
        assert!(recompute_via(&pool, caller, twin).await, "{caller:?} twin");
        assert_ne!(
            after.pignistic_prob,
            cache(&pool, twin).await.pignistic_prob,
            "{caller:?}: the legacy per-frame fold still includes a same-frame template"
        );
    }
}

/// Each coordinate of the template signature is load-bearing: a row that
/// differs from the template in exactly one of them is real input, and the
/// claim is recomputed.
#[sqlx::test(migrations = "../../migrations")]
async fn a_near_miss_of_the_template_signature_is_recomputed(pool: PgPool) {
    let owner = agent(&pool, "guard-owner").await;
    let ingest = agent(&pool, "guard-ingest").await;
    let rv = frame(&pool, "research_validity").await;
    let other = frame(&pool, "research_validity_lookalike").await;

    let base = template_row(rv, ingest, 0.9);
    let variants: Vec<(&str, Row<'_>)> = vec![
        (
            "theta just under 0.80",
            Row {
                masses: serde_json::json!({ "0": 0.21, "0,1": 0.79 }),
                ..template_row(rv, ingest, 0.9)
            },
        ),
        (
            "source strength 0.35",
            Row {
                source_strength: Some(0.35),
                ..template_row(rv, ingest, 0.9)
            },
        ),
        (
            "a combination method",
            Row {
                method: Some("auto_wire"),
                ..template_row(rv, ingest, 0.9)
            },
        ),
        (
            "another frame",
            Row {
                frame: other,
                ..template_row(rv, ingest, 0.9)
            },
        ),
    ];
    // Calibration: the unmodified base row IS the template (not recomputed),
    // so a variant being recomputed is caused by its one changed coordinate.
    let calibration = claim(&pool, owner, "exact template").await;
    insert_row(&pool, calibration, &base).await;
    let before = set_sentinel_cache(&pool, calibration, rv).await;
    assert!(
        !recompute_via(&pool, Caller::EngineRecomputeClaimCachedBelief, calibration).await,
        "calibration: the base row must be read as the template"
    );
    assert_eq!(cache(&pool, calibration).await, before);

    for (what, row) in variants {
        let atom = claim(&pool, owner, what).await;
        insert_row(&pool, atom, &row).await;
        let before = set_sentinel_cache(&pool, atom, rv).await;
        assert!(
            recompute_via(&pool, Caller::EngineRecomputeClaimCachedBelief, atom).await,
            "{what}: a row that is not the template must be recomputed"
        );
        assert_ne!(
            cache(&pool, atom).await.pignistic_prob,
            before.pignistic_prob,
            "{what}"
        );
    }
}

// ── (3) a compound with BBAs is untouched ───────────────────────────────────

/// A non-workflow tree `root -> mid -> leaf`, every node carrying the same
/// real row. "Compound" is the SOURCE end of an in-force `decomposes_to`, at
/// any depth:
///
/// * the root (source only) and the mid node (source AND target) keep their
///   caches;
/// * the leaf (target only) is an atom and is recomputed exactly as a
///   standalone twin carrying the same row.
///
/// The leaf arm fails a compound test that matches either edge end; the mid
/// arm fails one that freezes only roots.
#[sqlx::test(migrations = "../../migrations")]
async fn compound_with_bbas_is_untouched(pool: PgPool) {
    let owner = agent(&pool, "guard-owner").await;
    let source = agent(&pool, "guard-source").await;
    let bt = frame(&pool, "binary_truth").await;

    for caller in CALLERS {
        let compound = claim(&pool, owner, "compound with BBAs").await;
        let mid = claim(&pool, owner, "mid compound with BBAs").await;
        let leaf = claim(&pool, owner, "its leaf").await;
        decomposes_to(&pool, compound, mid, false).await;
        decomposes_to(&pool, mid, leaf, false).await;
        let twin = claim(&pool, owner, "standalone twin").await;
        for c in [compound, mid, leaf, twin] {
            insert_row(&pool, c, &evidence_row(bt, source, "auto_wire")).await;
        }

        for (what, c) in [("root compound", compound), ("mid compound", mid)] {
            let before = set_sentinel_cache(&pool, c, bt).await;
            assert!(
                !recompute_via(&pool, caller, c).await,
                "{caller:?} reported a cache write on a {what}"
            );
            assert_eq!(
                cache(&pool, c).await,
                before,
                "{caller:?} rewrote a {what}'s cache"
            );
        }

        set_sentinel_cache(&pool, twin, bt).await;
        assert!(recompute_via(&pool, caller, twin).await, "{caller:?} twin");
        let expected = cache(&pool, twin).await;
        assert_ne!(expected.pignistic_prob, Some(0.741), "twin recomputed");

        set_sentinel_cache(&pool, leaf, bt).await;
        assert!(
            recompute_via(&pool, caller, leaf).await,
            "{caller:?}: an evidenced leaf of a compound is an atom and must be recomputed"
        );
        assert_eq!(
            cache(&pool, leaf).await,
            expected,
            "{caller:?}: the leaf must fold its own row exactly as a standalone does"
        );
    }
}

/// "Compound" is decided by IN-FORCE edges to CURRENT claims: a claim whose
/// only decomposition was retired, or whose only child was superseded, is not
/// a compound, and is recomputed.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_or_dangling_decomposition_does_not_make_a_compound(pool: PgPool) {
    let owner = agent(&pool, "guard-owner").await;
    let source = agent(&pool, "guard-source").await;
    let bt = frame(&pool, "binary_truth").await;

    let retired = claim(&pool, owner, "decomposition retired").await;
    let leaf = claim(&pool, owner, "former leaf").await;
    decomposes_to(&pool, retired, leaf, true).await;

    let superseded_child = claim(&pool, owner, "child superseded").await;
    let old_leaf = claim(&pool, owner, "superseded leaf").await;
    decomposes_to(&pool, superseded_child, old_leaf, false).await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(old_leaf)
        .execute(&pool)
        .await
        .expect("supersede the leaf");

    for (what, c) in [
        ("retired edge", retired),
        ("non-current child", superseded_child),
    ] {
        insert_row(&pool, c, &evidence_row(bt, source, "auto_wire")).await;
        let before = set_sentinel_cache(&pool, c, bt).await;
        assert!(
            recompute_via(&pool, Caller::EngineRecomputeClaimCachedBelief, c).await,
            "{what}: not a compound, must be recomputed"
        );
        assert_ne!(
            cache(&pool, c).await.pignistic_prob,
            before.pignistic_prob,
            "{what}"
        );
    }
}

// ── (4) a workflow-rooted compound is still recomputed ──────────────────────

/// Procedural trees (rooted at a `source_type = 'workflow'` claim) are out of
/// scope of the atom program and keep today's behaviour: their compounds are
/// recomputed. Checked on the stamped root itself AND on an unstamped mid node
/// under it, each against a standalone twin carrying the same row.
#[sqlx::test(migrations = "../../migrations")]
async fn workflow_rooted_compound_is_still_recomputed(pool: PgPool) {
    let owner = workflow_ingest_agent(&pool, "guard-owner").await;
    let source = agent(&pool, "guard-source").await;
    let bt = frame(&pool, "binary_truth").await;

    for caller in CALLERS {
        let root = claim_with_properties(
            &pool,
            owner,
            "workflow thesis",
            serde_json::json!({ "source_type": "workflow", "level": 0 }),
        )
        .await;
        let mid = claim(&pool, owner, "workflow step").await;
        let leaf = claim(&pool, owner, "workflow atom").await;
        decomposes_to(&pool, root, mid, false).await;
        decomposes_to(&pool, mid, leaf, false).await;

        let twin = claim(&pool, owner, "standalone twin").await;
        for c in [root, mid, twin] {
            insert_row(&pool, c, &evidence_row(bt, source, "auto_wire")).await;
            set_sentinel_cache(&pool, c, bt).await;
        }

        assert!(recompute_via(&pool, caller, twin).await, "{caller:?} twin");
        let expected = cache(&pool, twin).await;
        assert_ne!(expected.pignistic_prob, Some(0.741), "twin recomputed");

        for (what, c) in [("workflow root", root), ("mid node under it", mid)] {
            assert!(
                recompute_via(&pool, caller, c).await,
                "{caller:?}: the {what} of a procedural tree must still be recomputed"
            );
            assert_eq!(
                cache(&pool, c).await,
                expected,
                "{caller:?}: the {what} must fold its own row exactly as a standalone does"
            );
        }
    }
}

/// A git-history tree, shaped the way `ingest_git` writes one (a repository
/// root stamped `source: git-history`, `node: repo`; a PR node under it; a
/// commit under the PR), is an ORDINARY compound tree: its procedural marker
/// is still pending (SPEC §2.1, Q-F1), and `source` / `node` are caller-set
/// properties. Its compounds stay frozen like any compound, even when the
/// registered system agent authored them.
#[sqlx::test(migrations = "../../migrations")]
async fn a_git_history_stamped_compound_is_frozen_like_any_compound(pool: PgPool) {
    let owner = workflow_ingest_agent(&pool, "guard-owner").await;
    let source = agent(&pool, "guard-source").await;
    let bt = frame(&pool, "binary_truth").await;

    for caller in CALLERS {
        let repo = claim_with_properties(
            &pool,
            owner,
            "repository root",
            serde_json::json!({ "source": "git-history", "node": "repo", "repo": "o/r" }),
        )
        .await;
        let pr = claim_with_properties(
            &pool,
            owner,
            "pull request",
            serde_json::json!({ "source": "git-history", "node": "pr", "pr_number": 1 }),
        )
        .await;
        let commit = claim_with_properties(
            &pool,
            owner,
            "commit",
            serde_json::json!({ "source": "git-history", "commit_type": "fix" }),
        )
        .await;
        decomposes_to(&pool, repo, pr, false).await;
        decomposes_to(&pool, pr, commit, false).await;
        for c in [repo, pr] {
            insert_row(&pool, c, &evidence_row(bt, source, "auto_wire")).await;
        }
        assert_frozen(&pool, caller, repo, bt, "a git repository root").await;
        assert_frozen(&pool, caller, pr, bt, "a PR node under it").await;
    }
}

/// A workflow stamp on a root authored by anyone but the registered
/// `workflow-ingest` system agent exempts nothing: `source_type` is a
/// caller-set property, so the stamped root and the compound under it stay
/// frozen. (`workflow_rooted_compound_is_still_recomputed` is the positive
/// control: the same tree authored by the system agent is recomputed.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_stamp_by_any_other_author_exempts_nothing(pool: PgPool) {
    let _registered = workflow_ingest_agent(&pool, "the real workflow-ingest agent").await;
    let stranger = agent(&pool, "stranger").await;
    let source = agent(&pool, "guard-source").await;
    let bt = frame(&pool, "binary_truth").await;

    for caller in CALLERS {
        let root = workflow_claim(&pool, stranger, "stranger's workflow-stamped thesis").await;
        let mid = claim(&pool, stranger, "step under it").await;
        let leaf = claim(&pool, stranger, "atom under it").await;
        decomposes_to(&pool, root, mid, false).await;
        decomposes_to(&pool, mid, leaf, false).await;
        for c in [root, mid] {
            insert_row(&pool, c, &evidence_row(bt, source, "auto_wire")).await;
        }
        assert_frozen(&pool, caller, root, bt, "a stranger's stamped root").await;
        assert_frozen(&pool, caller, mid, bt, "a compound under it").await;
    }
}

// ── (5) template + update_with_evidence: recomputed, template excluded ─────

/// A standalone carrying the ingest template AND an `update_with_evidence`
/// row, with a cache recorded on the template's frame. A bulk recompute
/// rewrites it, and the value equals that of a twin that carries the evidence
/// row alone: the template contributes nothing to the recomputed cache.
///
/// An over-breadth arm: the evidence row lands on `binary_truth`, which owns
/// the cache by rule 1 whatever the template does, so this passes without the
/// template exclusion too. The ownership move off a template-only frame is
/// pinned by `a_template_only_frame_cannot_own_a_claim_with_real_input_elsewhere`.
#[sqlx::test(migrations = "../../migrations")]
async fn standalone_with_template_and_evidence_recomputes_without_the_template(pool: PgPool) {
    let owner = agent(&pool, "guard-owner").await;
    let ingest = agent(&pool, "guard-ingest").await;
    let source = agent(&pool, "guard-evidence-source").await;
    let rv = frame(&pool, "research_validity").await;

    for caller in CALLERS {
        let standalone = claim(&pool, owner, "template + evidence").await;
        insert_row(&pool, standalone, &template_row(rv, ingest, 0.9)).await;
        update_with_evidence_row(&pool, standalone, source).await;

        let twin = claim(&pool, owner, "evidence only").await;
        update_with_evidence_row(&pool, twin, source).await;

        // Both caches start from the same sentinel, recorded on the template's
        // frame.
        let before = set_sentinel_cache(&pool, standalone, rv).await;
        set_sentinel_cache(&pool, twin, rv).await;

        assert!(recompute_via(&pool, caller, twin).await, "{caller:?} twin");
        assert!(
            recompute_via(&pool, caller, standalone).await,
            "{caller:?} skipped a standalone with a real evidence row"
        );
        let got = cache(&pool, standalone).await;
        assert_ne!(got, before, "{caller:?}: recomputed");
        assert_ne!(
            got.belief_frame_id,
            Some(rv),
            "{caller:?}: the template's frame must not own the recomputed cache"
        );
        assert_eq!(
            got,
            cache(&pool, twin).await,
            "{caller:?}: the template must not contribute to the recomputed value"
        );
    }
}

// ── (6) a template-only frame cannot own a claim with real input elsewhere ──

/// Backdate every row `claim` has on `frame`, so it is the claim's earliest
/// input (owner rule 4 is "the frame holding the earliest input").
async fn backdate_rows(pool: &PgPool, claim: Uuid, frame: Uuid) {
    sqlx::query(
        "UPDATE mass_functions SET created_at = now() - interval '1 hour' \
          WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("backdate rows");
}

/// The ingest template on `research_validity` (inserted first, so it is the
/// earliest input) and ONE real input on a frame that is neither
/// `binary_truth` nor `claim_validity`, so owner rules 1 and 2 do not apply
/// and ownership is decided by rule 3 (the recorded frame) or rule 4 (the
/// first writer). Either way the template's frame must not win: the cache
/// must be the real frame's fold, exactly as on a twin that carries only the
/// real row.
///
/// * rule 3: the sentinel is recorded on `research_validity`, which holds
///   nothing but the template;
/// * rule 4: the sentinel is recorded on a frame the claim has no row on, so
///   the earliest input (the template) would otherwise decide.
#[sqlx::test(migrations = "../../migrations")]
async fn a_template_only_frame_cannot_own_a_claim_with_real_input_elsewhere(pool: PgPool) {
    let owner = agent(&pool, "guard-owner").await;
    let ingest = agent(&pool, "guard-ingest").await;
    let assessor = agent(&pool, "guard-assessor").await;
    let rv = frame(&pool, "research_validity").await;
    let paper = frame(&pool, "paper_validity_guard").await;
    let elsewhere = frame(&pool, "guard_unrelated_frame").await;

    for caller in CALLERS {
        for (rule, recorded) in [("rule 3", rv), ("rule 4", elsewhere)] {
            let c = claim(&pool, owner, "template + real input on another frame").await;
            insert_row(&pool, c, &template_row(rv, ingest, 0.9)).await;
            backdate_rows(&pool, c, rv).await;
            insert_row(&pool, c, &evidence_row(paper, assessor, "discount")).await;
            let before = set_sentinel_cache(&pool, c, recorded).await;

            let twin = claim(&pool, owner, "real input alone").await;
            insert_row(&pool, twin, &evidence_row(paper, assessor, "discount")).await;
            set_sentinel_cache(&pool, twin, recorded).await;

            assert!(
                recompute_via(&pool, caller, twin).await,
                "{caller:?} {rule}: twin"
            );
            let expected = cache(&pool, twin).await;
            assert_eq!(
                expected.belief_frame_id,
                Some(paper),
                "CALIBRATION {caller:?} {rule}: the twin's only frame owns its cache"
            );

            assert!(
                recompute_via(&pool, caller, c).await,
                "{caller:?} {rule}: a claim with a real input must be recomputed"
            );
            let got = cache(&pool, c).await;
            assert_ne!(got, before, "{caller:?} {rule}: recomputed");
            assert_eq!(
                got.belief_frame_id,
                Some(paper),
                "{caller:?} {rule}: a frame holding only the ingest template owned the cache"
            );
            assert_eq!(
                got, expected,
                "{caller:?} {rule}: the cache must be the real frame's fold"
            );
        }
    }
}

// ── (7) the procedural exemption's edges ────────────────────────────────────

/// `claim` (carrying a real row) keeps its sentinel cache under `caller`.
async fn assert_frozen(pool: &PgPool, caller: Caller, claim: Uuid, frame: Uuid, what: &str) {
    let before = set_sentinel_cache(pool, claim, frame).await;
    assert!(
        !recompute_via(pool, caller, claim).await,
        "{caller:?}: {what} must stay frozen, but a write was reported"
    );
    assert_eq!(
        cache(pool, claim).await,
        before,
        "{caller:?}: {what} must stay frozen"
    );
}

/// `claim` is recomputed under `caller` to exactly the cache of `twin`, a
/// standalone carrying the same row (recomputed first, from a sentinel).
async fn assert_recomputed_like_twin(
    pool: &PgPool,
    caller: Caller,
    claim: Uuid,
    twin: Uuid,
    frame: Uuid,
    what: &str,
) {
    set_sentinel_cache(pool, twin, frame).await;
    assert!(recompute_via(pool, caller, twin).await, "{caller:?} twin");
    let expected = cache(pool, twin).await;
    assert_ne!(expected.pignistic_prob, Some(0.741), "twin recomputed");

    set_sentinel_cache(pool, claim, frame).await;
    assert!(
        recompute_via(pool, caller, claim).await,
        "{caller:?}: {what} must be recomputed"
    );
    assert_eq!(
        cache(pool, claim).await,
        expected,
        "{caller:?}: {what} must fold its own row exactly as a standalone does"
    );
}

async fn workflow_claim(pool: &PgPool, owner: Uuid, what: &str) -> Uuid {
    claim_with_properties(
        pool,
        owner,
        what,
        serde_json::json!({ "source_type": "workflow", "level": 0 }),
    )
    .await
}

/// A workflow stamp makes a tree procedural only on its ROOT, reached over
/// IN-FORCE edges. Each of these compounds stays frozen:
///
/// * a workflow-stamped compound that is itself the child of an ordinary
///   compound (it is not a root, and the real root is not a workflow);
/// * a compound whose only link up to a workflow root was retired.
#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_stamp_off_the_root_or_behind_a_retired_edge_exempts_nothing(pool: PgPool) {
    let owner = workflow_ingest_agent(&pool, "guard-owner").await;
    let source = agent(&pool, "guard-source").await;
    let bt = frame(&pool, "binary_truth").await;

    for caller in CALLERS {
        // ordinary -> stamped -> leaf
        let ordinary = claim(&pool, owner, "ordinary paragraph").await;
        let stamped = workflow_claim(&pool, owner, "workflow-stamped, not a root").await;
        let leaf = claim(&pool, owner, "leaf").await;
        decomposes_to(&pool, ordinary, stamped, false).await;
        decomposes_to(&pool, stamped, leaf, false).await;
        insert_row(&pool, stamped, &evidence_row(bt, source, "auto_wire")).await;
        assert_frozen(
            &pool,
            caller,
            stamped,
            bt,
            "a workflow-stamped compound under an ordinary compound",
        )
        .await;

        // workflow root -(retired)-> compound -> leaf
        let root = workflow_claim(&pool, owner, "workflow thesis").await;
        let compound = claim(&pool, owner, "compound cut off from the workflow").await;
        let leaf = claim(&pool, owner, "leaf").await;
        decomposes_to(&pool, root, compound, true).await;
        decomposes_to(&pool, compound, leaf, false).await;
        insert_row(&pool, compound, &evidence_row(bt, source, "auto_wire")).await;
        assert_frozen(
            &pool,
            caller,
            compound,
            bt,
            "a compound whose only path to a workflow root is retired",
        )
        .await;
    }
}

/// The upward search for a workflow root reaches exactly 6 in-force hops: in a
/// chain `W -> n1 -> ... -> n7 -> leaf` under a workflow root W, n6 is
/// procedural (recomputed like a standalone twin) and n7 is frozen.
#[sqlx::test(migrations = "../../migrations")]
async fn the_workflow_root_search_reaches_six_hops_and_no_further(pool: PgPool) {
    let owner = workflow_ingest_agent(&pool, "guard-owner").await;
    let source = agent(&pool, "guard-source").await;
    let bt = frame(&pool, "binary_truth").await;

    for caller in CALLERS {
        let mut chain = vec![workflow_claim(&pool, owner, "workflow thesis").await];
        for i in 1..=8 {
            chain.push(claim(&pool, owner, &format!("chain node {i}")).await);
        }
        for pair in chain.windows(2) {
            decomposes_to(&pool, pair[0], pair[1], false).await;
        }
        let twin = claim(&pool, owner, "standalone twin").await;
        for c in [chain[6], chain[7], twin] {
            insert_row(&pool, c, &evidence_row(bt, source, "auto_wire")).await;
        }

        assert_recomputed_like_twin(
            &pool,
            caller,
            chain[6],
            twin,
            bt,
            "a compound 6 hops below a workflow root",
        )
        .await;
        assert_frozen(
            &pool,
            caller,
            chain[7],
            bt,
            "a compound 7 hops below a workflow root",
        )
        .await;
    }
}

/// A manual `decomposes_to` cycle `A -> B -> A` has no root, so neither node
/// is procedural even though A carries the workflow stamp, and the owner
/// lookup must terminate. The lookup is run first under a statement timeout,
/// so an unbounded walk fails here with a timeout instead of hanging the run.
///
/// A is stamped on purpose: with no workflow-stamped claim in the database
/// at all, the server can answer the root search from an empty candidate set
/// without walking the cycle, and an uncapped walk would go unnoticed.
#[sqlx::test(migrations = "../../migrations")]
async fn a_decomposition_cycle_terminates_and_stays_frozen(pool: PgPool) {
    let owner = workflow_ingest_agent(&pool, "guard-owner").await;
    let source = agent(&pool, "guard-source").await;
    let bt = frame(&pool, "binary_truth").await;

    let a = workflow_claim(&pool, owner, "cycle node A").await;
    let b = claim(&pool, owner, "cycle node B").await;
    decomposes_to(&pool, a, b, false).await;
    decomposes_to(&pool, b, a, false).await;
    for c in [a, b] {
        insert_row(&pool, c, &evidence_row(bt, source, "auto_wire")).await;
    }

    {
        let viewer = fixture::public_viewer(&pool).await;
        let mut conn = pool.acquire().await.expect("acquire");
        sqlx::query("SET statement_timeout = '10s'")
            .execute(&mut *conn)
            .await
            .expect("set statement_timeout");
        let owner_frame = epigraph_db::MassFunctionRepository::cache_owner_frame_for_claim(
            &mut *conn, &viewer, a,
        )
        .await
        .expect("the owner lookup on a cycle must terminate");
        assert_eq!(owner_frame, None, "a node of a cycle is a frozen compound");
        sqlx::query("RESET statement_timeout")
            .execute(&mut *conn)
            .await
            .expect("reset statement_timeout");
    }

    for caller in CALLERS {
        for (what, c) in [("cycle node A", a), ("cycle node B", b)] {
            assert_frozen(&pool, caller, c, bt, what).await;
        }
    }
}

// ── (7b) what the shared role spelling changed in the guard ────────────────

/// An in-force `relationship` edge `source -> target` between claims.
async fn claim_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_from) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3, now() - interval '2 days')",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed claim edge");
}

/// The guard reads the one role spelling, where `rule` outranks `compound`
/// (SPEC §2.1): a rule claim (label `rule` AND an in-force `rule_conclusion`
/// edge) with a decomposition is NOT a compound, and its cache is refolded
/// from its own rows, like a standalone twin's. Control: the same shape
/// without the `rule` label is a compound and stays frozen.
#[sqlx::test(migrations = "../../migrations")]
async fn a_decomposed_rule_is_recomputed_and_a_decomposed_non_rule_is_not(pool: PgPool) {
    let owner = agent(&pool, "guard-owner").await;
    let source = agent(&pool, "guard-source").await;
    let bt = frame(&pool, "binary_truth").await;

    for caller in CALLERS {
        let conclusion = claim(&pool, owner, "rule conclusion").await;

        let rule = claim(&pool, owner, "decomposed rule").await;
        sqlx::query("UPDATE claims SET labels = ARRAY['rule'] WHERE id = $1")
            .bind(rule)
            .execute(&pool)
            .await
            .expect("label the rule");
        claim_edge(&pool, rule, conclusion, "rule_conclusion").await;
        let premise = claim(&pool, owner, "rule part").await;
        decomposes_to(&pool, rule, premise, false).await;

        let unlabelled = claim(&pool, owner, "same shape, no rule label").await;
        claim_edge(&pool, unlabelled, conclusion, "rule_conclusion").await;
        let part = claim(&pool, owner, "its part").await;
        decomposes_to(&pool, unlabelled, part, false).await;

        let twin = claim(&pool, owner, "standalone twin").await;
        for c in [rule, unlabelled, twin] {
            insert_row(&pool, c, &evidence_row(bt, source, "auto_wire")).await;
        }

        assert_recomputed_like_twin(&pool, caller, rule, twin, bt, "a decomposed rule").await;
        assert_frozen(
            &pool,
            caller,
            unlabelled,
            bt,
            "a decomposed claim with a conclusion edge but no rule label",
        )
        .await;
    }
}

/// Only an `ingest_git` repository node (`source: git-history` AND
/// `node: repo`) roots a procedural git tree. `ingest_git` stamps
/// `source: git-history` on every commit too, so a flat commit that was later
/// decomposed is an ordinary compound and stays frozen.
#[sqlx::test(migrations = "../../migrations")]
async fn a_decomposed_git_commit_is_a_frozen_compound(pool: PgPool) {
    let owner = agent(&pool, "guard-owner").await;
    let source = agent(&pool, "guard-source").await;
    let bt = frame(&pool, "binary_truth").await;

    for caller in CALLERS {
        let commit = claim_with_properties(
            &pool,
            owner,
            "lone commit",
            serde_json::json!({ "source": "git-history", "commit_type": "fix" }),
        )
        .await;
        let atom = claim(&pool, owner, "commit atom").await;
        decomposes_to(&pool, commit, atom, false).await;
        insert_row(&pool, commit, &evidence_row(bt, source, "auto_wire")).await;
        assert_frozen(&pool, caller, commit, bt, "a decomposed git commit").await;
    }
}

// ── (8) the role is decided without a viewer splice ─────────────────────────

/// A PUBLIC compound whose only decomposition edge points at a group-private
/// leaf (so the edge is stamped group-private too). Its role is structure, so
/// a public viewer that cannot see the edge or the leaf must still find it a
/// compound and leave its cache alone.
///
/// The test harness connects as a superuser, where row security does not
/// apply, so this pins the SQL: no `VISIBILITY` splice on the compound test.
/// (On a connection where row security applies, the server's own filtering
/// still hides the edge; see the `claim_role` module doc.) The two public
/// viewer callers are the arms that can see a splice; the MCP caller runs on a
/// maintenance session and is kept for completeness.
#[sqlx::test(migrations = "../../migrations")]
async fn a_viewer_that_cannot_see_the_decomposition_cannot_refold_the_compound(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "guard-private").await;
    let source = agent(&pool, "guard-source").await;
    let bt = frame(&pool, "binary_truth").await;

    for caller in CALLERS {
        let compound =
            fixture::seed_public_claim(&pool, author, &format!("public compound {caller:?}")).await;
        let leaf =
            fixture::seed_group_claim(&pool, author, group, &format!("private leaf {caller:?}"))
                .await;
        decomposes_to(&pool, compound, leaf, false).await;
        let edge_visibility: String = sqlx::query_scalar(
            "SELECT visibility FROM edges WHERE source_id = $1 AND target_id = $2",
        )
        .bind(compound)
        .bind(leaf)
        .fetch_one(&pool)
        .await
        .expect("edge visibility");
        assert_eq!(
            edge_visibility, "group",
            "CALIBRATION: an edge onto a group-private leaf is group-private"
        );

        // Calibration: the same row on a public standalone IS recomputed by
        // this caller, so the compound's row is visible to it and "no write"
        // below is the guard, not an empty input set.
        let twin =
            fixture::seed_public_claim(&pool, author, &format!("public standalone {caller:?}"))
                .await;
        insert_row(&pool, twin, &evidence_row(bt, source, "auto_wire")).await;
        let twin_before = set_sentinel_cache(&pool, twin, bt).await;
        assert!(
            recompute_via(&pool, caller, twin).await,
            "CALIBRATION {caller:?}: the public twin is recomputed"
        );
        assert_ne!(
            cache(&pool, twin).await,
            twin_before,
            "CALIBRATION {caller:?}"
        );

        insert_row(&pool, compound, &evidence_row(bt, source, "auto_wire")).await;
        assert_frozen(
            &pool,
            caller,
            compound,
            bt,
            "a public compound whose decomposition the viewer cannot see",
        )
        .await;
    }
}

// ── (9) the dry-run prediction shares the guard ─────────────────────────────

/// `recompute_betp`'s dry run predicts the cache through the same owner lookup
/// (`predict_cached_after`): nothing for a template-only claim or a compound,
/// and the owner frame for a standalone with a real row.
#[sqlx::test(migrations = "../../migrations")]
async fn the_dry_run_predicts_no_write_for_guarded_claims(pool: PgPool) {
    let owner = agent(&pool, "guard-owner").await;
    let ingest = agent(&pool, "guard-ingest").await;
    let source = agent(&pool, "guard-source").await;
    let rv = frame(&pool, "research_validity").await;
    let bt = frame(&pool, "binary_truth").await;

    let template_only = claim(&pool, owner, "template-only").await;
    insert_row(&pool, template_only, &template_row(rv, ingest, 0.9)).await;

    let compound = claim(&pool, owner, "compound").await;
    let leaf = claim(&pool, owner, "leaf").await;
    decomposes_to(&pool, compound, leaf, false).await;
    insert_row(&pool, compound, &evidence_row(bt, source, "auto_wire")).await;

    let standalone = claim(&pool, owner, "standalone").await;
    insert_row(&pool, standalone, &evidence_row(bt, source, "auto_wire")).await;

    let viewer = fixture::public_viewer(&pool).await;
    let predict = |c: Uuid| {
        let pool = pool.clone();
        let viewer = &viewer;
        async move {
            epigraph_cli::recompute_betp::predict_cached_after(&pool, viewer, c)
                .await
                .expect("predict_cached_after")
        }
    };
    assert!(
        predict(template_only).await.is_none(),
        "a template-only claim has no predicted write"
    );
    assert!(
        predict(compound).await.is_none(),
        "a compound has no predicted write"
    );
    let (frame_owner, _) = predict(standalone)
        .await
        .expect("CALIBRATION: a standalone with a real row has a predicted write");
    assert_eq!(frame_owner, bt, "CALIBRATION: its only frame owns it");
}
