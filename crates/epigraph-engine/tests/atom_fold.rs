//! The atom evidence fold (AEF) and the single atom-cache writer
//! (atom-level belief program, PR-5; SPEC §3.3 item keys and lens context,
//! §3.4 Display and Pure, §4.2 the single atom-cache writer, §6.3
//! compound-source edges, §10.2 `EPIGRAPH_ATOM_FOLD`, §11.4 axiom input).
//!
//! What is pinned here, as properties of the rows an atom's fold reads and of
//! what the writer does with them:
//!
//! * the AEF reads every 2-hypothesis frame plus `claim_validity` (coarsened),
//!   so a new `binary_truth` row never evicts another frame's evidence (the
//!   owner-frame rule's frame flip);
//! * it never reads a cached combination, an ingest template row, or any row
//!   of a compound (role is structure, whatever the viewer sees, on a
//!   connection that bypasses row security; on an application session row
//!   security can hide a compound, which one test pins as a known gap);
//! * `Pure` is evidence only; `Display` adds the inferred classes, and reads a
//!   compound-source edge row one-sided while compound-source edges are frozen;
//! * one paper's two citations are one item (the max), and `~` mass meets a
//!   second item exactly as CDST Dempster does (D11, atom side);
//! * a seed counts only while it is the atom's sole input;
//! * the writer never writes a compound, folds only the roles its flag covers,
//!   stamps `binary_truth`, and never NULLs an atom.
//!
//! Expected values are absolute numbers from the SPEC's worked examples or
//! from sentinels and twin claims; none is computed here by the operator
//! under test.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::{BTreeSet, HashMap};

use epigraph_db::repos::claim_role::leaf_closure_batch;
use epigraph_db::{FrameRepository, MassFunctionRepository, PerspectiveRepository, Viewer};
use epigraph_engine::atom_items::{
    atom_axiom_rows_under, atom_fold, AtomFoldMode, AxiomMode, AxiomRow, CompoundSourceEdges,
};
use epigraph_engine::belief_query::FramedBeliefContext;
use epigraph_engine::calibration::CalibrationConfig;
use epigraph_engine::edge_factor::{
    aef_input_before, compound_cache_write_skipped, recompute_atom_cache_with, AefInputBefore,
    AtomCacheOutcome, AtomCacheSettings, CacheWriteCause, LegacyFold, PerspectiveReliability,
    CLAIM_VALIDITY_FRAME_ID,
};
use sqlx::PgPool;
use uuid::Uuid;

const TOL: f64 = 1e-9;

/// Held by every test that sends a compound through the writer, so the
/// process-wide `compound_cache_write_skipped` counter moves only by that
/// test's own writes while it measures them (sqlx tests in one binary run
/// concurrently).
static COMPOUND_WRITES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ── fixtures ────────────────────────────────────────────────────────────────

async fn agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("agent")
}

async fn claim(pool: &PgPool, author: Uuid, what: &str) -> Uuid {
    fixture::seed_public_claim(pool, author, &format!("aef {what} {}", Uuid::new_v4())).await
}

/// Register `agent` as the `workflow-ingest` system agent (migration 148): a
/// `source_type: workflow` root stamp makes a tree procedural only when that
/// agent authored the root (`claim_role`). Planted directly, with triggers
/// off, as `epigraph-db/tests/claim_role.rs` does. One plant per test
/// database: the role is the registry's primary key.
async fn plant_workflow_ingest_agent(pool: &PgPool, agent: Uuid) {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .expect("replica");
    let planted = sqlx::query(
        "INSERT INTO public.system_agents (role, agent_id, registered_public_key, reason) \
         SELECT 'workflow-ingest', a.id, a.public_key, 'atom-fold test plant' \
           FROM public.agents a WHERE a.id = $1",
    )
    .bind(agent)
    .execute(&mut *tx)
    .await
    .expect("plant the workflow-ingest system agent");
    assert_eq!(planted.rows_affected(), 1);
    tx.commit().await.expect("commit");
}

async fn frame(pool: &PgPool, name: &str, hyps: &[&str]) -> Uuid {
    if let Some(f) = FrameRepository::get_by_name(pool, &fixture::public_viewer(pool).await, name)
        .await
        .expect("frame lookup")
    {
        return f.id;
    }
    FrameRepository::create(
        pool,
        name,
        None,
        &hyps.iter().map(|h| (*h).to_string()).collect::<Vec<_>>(),
    )
    .await
    .expect("frame")
    .id
}

async fn binary(pool: &PgPool) -> Uuid {
    frame(pool, "binary_truth", &["TRUE", "FALSE"]).await
}

async fn research_validity(pool: &PgPool) -> Uuid {
    frame(pool, "research_validity", &["valid", "invalid"]).await
}

/// One BBA row. With `evidence_type` `None` and `source_strength` 1.0 its
/// reliability is exactly 1 whatever the calibration (the stored-strength
/// tier of `effective_source_strength`).
#[derive(Clone)]
struct Row {
    agent: Option<Uuid>,
    perspective: Option<Uuid>,
    method: Option<&'static str>,
    strength: Option<f64>,
    evidence_type: Option<&'static str>,
    evidence: Option<Uuid>,
}

impl Row {
    fn plain(agent: Uuid) -> Self {
        Self {
            agent: Some(agent),
            perspective: None,
            method: None,
            strength: Some(1.0),
            evidence_type: None,
            evidence: None,
        }
    }
}

async fn store(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    row: Row,
    masses: serde_json::Value,
) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        row.agent,
        row.perspective,
        &masses,
        None,
        row.method,
        row.strength,
        row.evidence_type,
        "unknown",
        row.evidence,
    )
    .await
    .expect("store BBA")
}

/// The ingest template: `research_validity`, no method, strength .3, m(Θ) ≥ .80.
async fn store_template(pool: &PgPool, claim: Uuid, ingest_agent: Uuid) -> Uuid {
    let rv = research_validity(pool).await;
    store(
        pool,
        claim,
        rv,
        Row {
            strength: Some(0.3),
            ..Row::plain(ingest_agent)
        },
        serde_json::json!({"0": 0.1, "0,1": 0.9}),
    )
    .await
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("edge")
}

/// An edge-factor row on `target` for edge `edge_id`: perspective = edge id.
async fn store_edge_factor(
    pool: &PgPool,
    edge_id: Uuid,
    target: Uuid,
    writer: Uuid,
    masses: serde_json::Value,
) -> Uuid {
    sqlx::query("INSERT INTO perspectives (id, name) VALUES ($1, 'edge') ON CONFLICT DO NOTHING")
        .bind(edge_id)
        .execute(pool)
        .await
        .expect("edge perspective");
    let b = binary(pool).await;
    store(
        pool,
        target,
        b,
        Row {
            perspective: Some(edge_id),
            method: Some("edge_factor"),
            ..Row::plain(writer)
        },
        masses,
    )
    .await
}

/// `parent` decomposes into `child`.
async fn decompose(pool: &PgPool, parent: Uuid, child: Uuid) -> Uuid {
    edge(pool, parent, child, "decomposes_to").await
}

/// An evidence row on `holder` carrying `properties.doi`, plus the evidence
/// perspective a citation of it uses.
async fn doi_evidence(pool: &PgPool, holder: Uuid, doi: &str, cite_agent: Uuid) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, properties) \
         VALUES ($1, 'document', sha256(gen_random_uuid()::text::bytea), \
                 jsonb_build_object('doi', $2::text)) RETURNING id",
    )
    .bind(holder)
    .bind(doi)
    .fetch_one(pool)
    .await
    .expect("evidence");
    PerspectiveRepository::ensure_evidence_perspective(pool, id, Some(cite_agent))
        .await
        .expect("evidence perspective");
    id
}

/// An `attributed_v1` row citing evidence `ev` on `atom`.
async fn store_attributed(pool: &PgPool, atom: Uuid, ev: Uuid, writer: Uuid, t: f64) -> Uuid {
    let b = binary(pool).await;
    store(
        pool,
        atom,
        b,
        Row {
            perspective: Some(ev),
            evidence: Some(ev),
            method: Some("attributed_v1"),
            ..Row::plain(writer)
        },
        serde_json::json!({"0": t, "0,1": 1.0 - t}),
    )
    .await
}

fn ctx() -> FramedBeliefContext {
    FramedBeliefContext::new(CalibrationConfig::default_for_phase2_fallback(), None)
}

async fn rows(
    pool: &PgPool,
    ids: &[Uuid],
    mode: AxiomMode,
    edges: CompoundSourceEdges,
) -> HashMap<Uuid, Vec<AxiomRow>> {
    let viewer = fixture::public_viewer(pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    atom_axiom_rows_under(&mut conn, &viewer, ids, mode, &ctx(), edges)
        .await
        .expect("atom_axiom_rows")
}

async fn rows_as(
    pool: &PgPool,
    viewer: &Viewer,
    ids: &[Uuid],
    mode: AxiomMode,
    edges: CompoundSourceEdges,
) -> HashMap<Uuid, Vec<AxiomRow>> {
    let mut conn = pool.acquire().await.expect("conn");
    atom_axiom_rows_under(&mut conn, viewer, ids, mode, &ctx(), edges)
        .await
        .expect("atom_axiom_rows")
}

/// Make an edge private to `group` (its owner group, no co-owner).
async fn hide_edge(pool: &PgPool, edge_id: Uuid, group: Uuid) {
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(edge_id)
    .bind(group)
    .execute(pool)
    .await
    .expect("make the edge private");
}

async fn display(pool: &PgPool, id: Uuid) -> Vec<AxiomRow> {
    rows(pool, &[id], AxiomMode::Display, CompoundSourceEdges::Frozen)
        .await
        .remove(&id)
        .unwrap_or_default()
}

fn ids_of(rows: &[AxiomRow]) -> BTreeSet<Uuid> {
    rows.iter().map(AxiomRow::row_id).collect()
}

fn set(ids: &[Uuid]) -> BTreeSet<Uuid> {
    ids.iter().copied().collect()
}

#[derive(Debug, PartialEq)]
struct Cache {
    belief: Option<f64>,
    plausibility: Option<f64>,
    pignistic: Option<f64>,
    frame: Option<Uuid>,
}

async fn cache(pool: &PgPool, id: Uuid) -> Cache {
    let (belief, plausibility, pignistic, frame): (
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<Uuid>,
    ) = sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob, belief_frame_id FROM claims WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("cache");
    Cache {
        belief,
        plausibility,
        pignistic,
        frame,
    }
}

/// A cache value no fold of the fixture rows can produce.
async fn set_sentinel(pool: &PgPool, id: Uuid) -> Cache {
    sqlx::query(
        "UPDATE claims SET belief = 0.123, plausibility = 0.877, pignistic_prob = 0.5, \
         mass_on_empty = 0, mass_on_missing = 0, belief_frame_id = NULL WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("sentinel");
    cache(pool, id).await
}

fn settings(fold: AtomFoldMode, vacate: bool) -> AtomCacheSettings {
    AtomCacheSettings {
        fold,
        compound_source_edges: CompoundSourceEdges::Frozen,
        vacate_on_evidence_removal: vacate,
    }
}

async fn write(
    pool: &PgPool,
    id: Uuid,
    cause: CacheWriteCause,
    legacy: LegacyFold,
    s: AtomCacheSettings,
) -> AtomCacheOutcome {
    let viewer = fixture::public_viewer(pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    recompute_atom_cache_with(&mut conn, &viewer, id, cause, legacy, s)
        .await
        .expect("recompute_atom_cache")
}

/// What the atom's AEF input is before a lifecycle act, read as the public
/// viewer the test writes with.
async fn before_act(pool: &PgPool, id: Uuid, s: AtomCacheSettings) -> AefInputBefore {
    let viewer = fixture::public_viewer(pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    aef_input_before(&mut conn, &viewer, id, s)
        .await
        .expect("aef_input_before")
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < TOL
}

// ── (1) frame flip ──────────────────────────────────────────────────────────

/// Plan test (1). Under the owner-frame rule the first `binary_truth` row
/// evicts every other frame from the cache (hazard H7). The AEF reads every
/// 2-hypothesis frame, so adding that row only ADDS to the input.
#[sqlx::test(migrations = "../../migrations")]
async fn a_new_binary_row_keeps_research_validity_and_auto_cdst_rows_in_the_fold(pool: PgPool) {
    let author = agent(&pool).await;
    let atom = claim(&pool, author, "frame flip").await;
    let rv = research_validity(&pool).await;
    let b = binary(&pool).await;

    let substantive = store(
        &pool,
        atom,
        rv,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
    )
    .await;
    let cdst = store(
        &pool,
        atom,
        b,
        Row {
            method: Some("auto_cdst"),
            ..Row::plain(agent(&pool).await)
        },
        serde_json::json!({"0": 0.3, "0,1": 0.7}),
    )
    .await;
    let before = ids_of(&display(&pool, atom).await);
    assert!(
        before.contains(&substantive) && before.contains(&cdst),
        "the AEF input must hold the research_validity and auto_cdst rows, got {before:?}"
    );

    let new_binary = store(
        &pool,
        atom,
        b,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.5, "0,1": 0.5}),
    )
    .await;
    let after_rows = display(&pool, atom).await;
    let after = ids_of(&after_rows);
    assert!(
        before.is_subset(&after) && after.contains(&new_binary),
        "a binary_truth row must add to the input, never evict: before {before:?}, after {after:?}"
    );
    let fold = atom_fold(&after_rows).expect("fold");
    assert_eq!(fold.items(), 3, "three distinct sources are three items");
}

// ── (2) template-only ───────────────────────────────────────────────────────

/// Plan test (2): the ingest template is never AEF input, so a template-only
/// atom folds empty (Unproven), and a template beside real evidence is not
/// read.
#[sqlx::test(migrations = "../../migrations")]
async fn a_template_only_atom_folds_empty_and_a_template_is_never_read(pool: PgPool) {
    let author = agent(&pool).await;
    let ingest = agent(&pool).await;
    let only = claim(&pool, author, "template only").await;
    store_template(&pool, only, ingest).await;
    let mixed = claim(&pool, author, "template plus evidence").await;
    store_template(&pool, mixed, ingest).await;
    let real = store(
        &pool,
        mixed,
        binary(&pool).await,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.7, "0,1": 0.3}),
    )
    .await;

    let got = rows(
        &pool,
        &[only, mixed],
        AxiomMode::Display,
        CompoundSourceEdges::Frozen,
    )
    .await;
    let only_rows = got.get(&only).cloned().unwrap_or_default();
    assert!(
        only_rows.is_empty(),
        "a template-only atom has no AEF input"
    );
    let fold = atom_fold(&only_rows).expect("empty fold");
    assert!(fold.is_unproven());
    assert!(close(fold.belief(), 0.0) && close(fold.plausibility(), 1.0));

    assert_eq!(
        ids_of(got.get(&mixed).map(Vec::as_slice).unwrap_or_default()),
        set(&[real]),
        "beside real evidence the template is still not read"
    );
}

// ── (3) Pure vs Display ─────────────────────────────────────────────────────

/// Plan test (3). Pure is the engine's premise input: evidence only. Display
/// adds the inferred classes; an edge-factor row from an ATOM source is kept.
#[sqlx::test(migrations = "../../migrations")]
async fn pure_reads_evidence_only_and_display_adds_the_inferred_classes(pool: PgPool) {
    let author = agent(&pool).await;
    let b = binary(&pool).await;
    let atom = claim(&pool, author, "pure vs display").await;
    let source = claim(&pool, author, "atom source").await;

    let evidence = store(
        &pool,
        atom,
        b,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
    )
    .await;
    let e = edge(&pool, source, atom, "supports").await;
    let edge_row = store_edge_factor(
        &pool,
        e,
        atom,
        agent(&pool).await,
        serde_json::json!({"0": 0.4, "0,1": 0.6}),
    )
    .await;
    let mut inferred = vec![edge_row];
    for method in [
        "propagated_from_parent",
        "propagated_from_neighbor",
        "auto_cdst",
    ] {
        inferred.push(
            store(
                &pool,
                atom,
                b,
                Row {
                    method: Some(method),
                    ..Row::plain(agent(&pool).await)
                },
                serde_json::json!({"0": 0.2, "0,1": 0.8}),
            )
            .await,
        );
    }

    let pure = rows(&pool, &[atom], AxiomMode::Pure, CompoundSourceEdges::Frozen).await;
    assert_eq!(
        ids_of(pure.get(&atom).map(Vec::as_slice).unwrap_or_default()),
        set(&[evidence]),
        "Pure must read the evidence row and nothing inferred"
    );
    let mut all = inferred.clone();
    all.push(evidence);
    assert_eq!(
        ids_of(&display(&pool, atom).await),
        set(&all),
        "Display must read the evidence row and every inferred row"
    );
}

// ── (4) D11, atom side ──────────────────────────────────────────────────────

/// Plan test (4), the atom half of D11. Two `attributed_v1` rows citing one
/// paper (two evidence rows, one DOI) are one item: .8, not Dempster's .96.
/// Two different papers still reinforce.
///
/// The other half, single-leaf `conj_belief` == `atom_fold` on this fixture
/// and on the `~` fixture below (.8 and .897), needs `conj_belief` (PR-3), so
/// it is carried into PR-6's red tests by name.
#[sqlx::test(migrations = "../../migrations")]
async fn one_papers_two_attributed_items_fold_to_the_max(pool: PgPool) {
    let author = agent(&pool).await;
    let holder = claim(&pool, author, "the compound the citations were filed on").await;
    let (x, y) = (agent(&pool).await, agent(&pool).await);

    let same = claim(&pool, author, "one paper twice").await;
    let e1 = doi_evidence(&pool, holder, "10.5555/aef-one", x).await;
    let e2 = doi_evidence(&pool, holder, "https://doi.org/10.5555/AEF-ONE", y).await;
    store_attributed(&pool, same, e1, x, 0.8).await;
    store_attributed(&pool, same, e2, y, 0.8).await;
    let fold = atom_fold(&display(&pool, same).await).expect("fold");
    assert!(
        close(fold.belief(), 0.8),
        "one paper cited twice is one item at .8, got Bel {}",
        fold.belief()
    );

    let two = claim(&pool, author, "two papers").await;
    let p = doi_evidence(&pool, holder, "10.5555/aef-p", x).await;
    let q = doi_evidence(&pool, holder, "10.5555/aef-q", y).await;
    store_attributed(&pool, two, p, x, 0.8).await;
    store_attributed(&pool, two, q, y, 0.8).await;
    let fold = atom_fold(&display(&pool, two).await).expect("fold");
    assert!(
        close(fold.belief(), 0.96),
        "two papers are two items, 1 - .2·.2 = .96, got Bel {}",
        fold.belief()
    );
}

/// Plan test (4), second half: an edge-factor row carrying `~` mass plus one
/// other item. SPEC §3.3's worked example: {T .5, ~ .3, Θ .2} with
/// {T .64, Θ .36} gives K .3 and Bel .897 (exact CDST Dempster: `~` meets
/// T and Θ as conflict).
#[sqlx::test(migrations = "../../migrations")]
async fn an_open_world_edge_row_meets_a_second_item_as_cdst_dempster(pool: PgPool) {
    let author = agent(&pool).await;
    let atom = claim(&pool, author, "open world").await;
    let source = claim(&pool, author, "source with open-world mass").await;
    let e = edge(&pool, source, atom, "supports").await;
    store_edge_factor(
        &pool,
        e,
        atom,
        agent(&pool).await,
        serde_json::json!({"0": 0.5, "~0,1": 0.3, "0,1": 0.2}),
    )
    .await;
    store(
        &pool,
        atom,
        binary(&pool).await,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.64, "0,1": 0.36}),
    )
    .await;

    let fold = atom_fold(&display(&pool, atom).await).expect("fold");
    assert!(
        (fold.belief() - 0.628 / 0.7).abs() < 1e-9,
        "Bel must be .628/.7 = .897, got {}",
        fold.belief()
    );
    assert!(
        close(fold.mass_on_conflict(), 0.3),
        "the fold saw K = .3, got {}",
        fold.mass_on_conflict()
    );
}

// ── (5) claim_validity ──────────────────────────────────────────────────────

/// Plan test (5): `claim_validity` is coarsened supported → T, refuted → F,
/// uncertain → Θ. Uncertain mass is neither belief nor disbelief.
#[sqlx::test(migrations = "../../migrations")]
async fn claim_validity_uncertain_mass_lands_on_theta(pool: PgPool) {
    let author = agent(&pool).await;
    let leaning = claim(&pool, author, "supported .3, uncertain .7").await;
    store(
        &pool,
        leaning,
        CLAIM_VALIDITY_FRAME_ID,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.3, "2": 0.7}),
    )
    .await;
    let doubted = claim(&pool, author, "refuted .4, uncertain .6").await;
    store(
        &pool,
        doubted,
        CLAIM_VALIDITY_FRAME_ID,
        Row::plain(agent(&pool).await),
        serde_json::json!({"1": 0.4, "2": 0.6}),
    )
    .await;

    let f = atom_fold(&display(&pool, leaning).await).expect("fold");
    assert!(
        close(f.belief(), 0.3) && close(f.plausibility(), 1.0),
        "supported .3 + uncertain .7 is Bel .3, Pl 1; got Bel {} Pl {}",
        f.belief(),
        f.plausibility()
    );
    let f = atom_fold(&display(&pool, doubted).await).expect("fold");
    assert!(
        close(f.belief(), 0.0) && close(f.plausibility(), 0.6),
        "refuted .4 + uncertain .6 is Bel 0, Pl .6; got Bel {} Pl {}",
        f.belief(),
        f.plausibility()
    );
}

// ── (6) the writer never writes a compound ──────────────────────────────────

/// Plan test (6), under every fold mode and through a legacy fold that names
/// a frame directly (the per-write sites, which the owner-frame guard does not
/// cover).
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_atom_cache_never_writes_a_compound(pool: PgPool) {
    let author = agent(&pool).await;
    let b = binary(&pool).await;
    let compound = claim(&pool, author, "compound").await;
    let leaf = claim(&pool, author, "its leaf").await;
    decompose(&pool, compound, leaf).await;
    store(
        &pool,
        compound,
        b,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.9, "0,1": 0.1}),
    )
    .await;

    let _counter = COMPOUND_WRITES.lock().await;
    for fold in [
        AtomFoldMode::Legacy,
        AtomFoldMode::AefStandalone,
        AtomFoldMode::Aef,
    ] {
        let sentinel = set_sentinel(&pool, compound).await;
        let skipped_before = compound_cache_write_skipped();
        let outcome = write(
            &pool,
            compound,
            CacheWriteCause::Organic,
            LegacyFold::Frame(b),
            settings(fold, true),
        )
        .await;
        assert_eq!(outcome, AtomCacheOutcome::CompoundSkipped, "{fold:?}");
        assert_eq!(
            cache(&pool, compound).await,
            sentinel,
            "{fold:?}: compound cache moved"
        );
        assert_eq!(
            compound_cache_write_skipped(),
            skipped_before + 1,
            "{fold:?}: the skip must be counted, once"
        );
    }
}

// ── (7) the seed ────────────────────────────────────────────────────────────

/// Plan test (7), ruling O16: a `truth_value` seed is read only while it is
/// the atom's sole input.
#[sqlx::test(migrations = "../../migrations")]
async fn a_seed_counts_only_while_it_is_the_sole_input(pool: PgPool) {
    let author = agent(&pool).await;
    let b = binary(&pool).await;
    let seed_row = |a| Row {
        method: Some("truth_value_seed"),
        ..Row::plain(a)
    };

    let alone = claim(&pool, author, "seed alone").await;
    let seed = store(
        &pool,
        alone,
        b,
        seed_row(author),
        serde_json::json!({"0": 0.7, "0,1": 0.3}),
    )
    .await;
    assert_eq!(ids_of(&display(&pool, alone).await), set(&[seed]));

    let both = claim(&pool, author, "seed plus evidence").await;
    store(
        &pool,
        both,
        b,
        seed_row(author),
        serde_json::json!({"0": 0.7, "0,1": 0.3}),
    )
    .await;
    let evidence = store(
        &pool,
        both,
        b,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
    )
    .await;
    let got = display(&pool, both).await;
    assert_eq!(ids_of(&got), set(&[evidence]), "the seed must drop out");
    let fold = atom_fold(&got).expect("fold");
    assert!(
        close(fold.belief(), 0.6),
        "the fold is the evidence alone, got Bel {}",
        fold.belief()
    );
}

// ── (8) compound-source edge rows ───────────────────────────────────────────

/// Plan test (8), SPEC §6.3. While compound-source edges are `frozen`, a
/// POSITIVE compound-source edge row is read one-sided: its m(F) moves to Θ.
/// A negative one keeps its F. A row whose edge source is an ancestor
/// compound of the target is skipped. Under `excluded` none is read, and Pure
/// never reads them.
#[sqlx::test(migrations = "../../migrations")]
async fn compound_source_edge_rows_are_one_sided_while_frozen(pool: PgPool) {
    let author = agent(&pool).await;
    let writer = agent(&pool).await;
    let compound = claim(&pool, author, "compound source").await;
    let own_leaf = claim(&pool, author, "the compound's own leaf").await;
    decompose(&pool, compound, own_leaf).await;

    let supported = claim(&pool, author, "supported by a compound").await;
    let e = edge(&pool, compound, supported, "supports").await;
    store_edge_factor(
        &pool,
        e,
        supported,
        writer,
        serde_json::json!({"0": 0.5, "1": 0.2, "0,1": 0.3}),
    )
    .await;

    let contradicted = claim(&pool, author, "contradicted by a compound").await;
    let e = edge(&pool, compound, contradicted, "contradicts").await;
    store_edge_factor(
        &pool,
        e,
        contradicted,
        writer,
        serde_json::json!({"1": 0.4, "0,1": 0.6}),
    )
    .await;

    let e = edge(&pool, compound, own_leaf, "supports").await;
    store_edge_factor(
        &pool,
        e,
        own_leaf,
        writer,
        serde_json::json!({"0": 0.5, "0,1": 0.5}),
    )
    .await;

    let f = atom_fold(&display(&pool, supported).await).expect("fold");
    assert!(
        close(f.belief(), 0.5) && close(f.plausibility(), 1.0),
        "frozen positive compound-source row contributes no F: Bel .5, Pl 1; got Bel {} Pl {}",
        f.belief(),
        f.plausibility()
    );
    let f = atom_fold(&display(&pool, contradicted).await).expect("fold");
    assert!(
        close(f.plausibility(), 0.6),
        "a negative compound-source row keeps its F: Pl .6, got {}",
        f.plausibility()
    );
    assert!(
        display(&pool, own_leaf).await.is_empty(),
        "an edge from an ancestor compound of the target is skipped"
    );

    // The guard reaches every ancestor, not only a direct parent:
    // grand → mid → deep, with a supports edge grand → deep.
    let grand = claim(&pool, author, "grandparent compound").await;
    let mid = claim(&pool, author, "mid compound").await;
    let deep = claim(&pool, author, "leaf two levels down").await;
    decompose(&pool, grand, mid).await;
    decompose(&pool, mid, deep).await;
    let e = edge(&pool, grand, deep, "supports").await;
    store_edge_factor(
        &pool,
        e,
        deep,
        writer,
        serde_json::json!({"0": 0.5, "0,1": 0.5}),
    )
    .await;
    assert!(
        display(&pool, deep).await.is_empty(),
        "an edge from a grandparent compound of the target is skipped"
    );

    // CONTROL for `excluded`: an atom carrying a compound-source row, an
    // atom-source edge row and an evidence row keeps exactly the last two.
    let mixed = claim(
        &pool,
        author,
        "compound-source, atom-source and evidence rows",
    )
    .await;
    let e = edge(&pool, compound, mixed, "supports").await;
    let compound_row = store_edge_factor(
        &pool,
        e,
        mixed,
        writer,
        serde_json::json!({"0": 0.5, "0,1": 0.5}),
    )
    .await;
    let atom_source = claim(&pool, author, "atom source").await;
    let e = edge(&pool, atom_source, mixed, "supports").await;
    let atom_row = store_edge_factor(
        &pool,
        e,
        mixed,
        writer,
        serde_json::json!({"0": 0.4, "0,1": 0.6}),
    )
    .await;
    let evidence_row = store(
        &pool,
        mixed,
        binary(&pool).await,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.3, "0,1": 0.7}),
    )
    .await;
    assert_eq!(
        ids_of(&display(&pool, mixed).await),
        set(&[compound_row, atom_row, evidence_row]),
        "frozen reads all three"
    );

    let ids = [supported, contradicted, own_leaf, mixed];
    for (mode, edges, keep_on_mixed) in [
        (
            AxiomMode::Display,
            CompoundSourceEdges::Excluded,
            set(&[atom_row, evidence_row]),
        ),
        (
            AxiomMode::Pure,
            CompoundSourceEdges::Frozen,
            set(&[evidence_row]),
        ),
    ] {
        let mut got = rows(&pool, &ids, mode, edges).await;
        assert_eq!(
            ids_of(&got.remove(&mixed).unwrap_or_default()),
            keep_on_mixed,
            "{mode:?}/{edges:?}: exactly the rows that are not compound-source"
        );
        assert!(
            got.values().all(Vec::is_empty),
            "{mode:?}/{edges:?} must read no compound-source edge row"
        );
    }
}

// ── (9) D1 ──────────────────────────────────────────────────────────────────

/// Plan test (9), D1. A compound's own rows are never AEF input, whether or
/// not the viewer can see its decomposition (role is structure).
///
/// This holds on the superuser pool the harness connects with, where row
/// security does not apply; on an application session it does not
/// (`on_an_app_session_row_security_hides_a_compound_from_the_fold`).
#[sqlx::test(migrations = "../../migrations")]
async fn atom_fold_never_reads_compound_rows(pool: PgPool) {
    let author = agent(&pool).await;
    let b = binary(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "aef-d1").await;

    let visible = claim(&pool, author, "compound, visible decomposition").await;
    let leaf = claim(&pool, author, "visible leaf").await;
    decompose(&pool, visible, leaf).await;

    let hidden = claim(&pool, author, "compound, hidden decomposition").await;
    let hidden_leaf = claim(&pool, author, "leaf behind a private edge").await;
    let private_edge = decompose(&pool, hidden, hidden_leaf).await;
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(private_edge)
    .bind(group)
    .execute(&pool)
    .await
    .expect("make the decomposition private");

    let mut atom_rows = Vec::new();
    for c in [visible, leaf, hidden, hidden_leaf] {
        let r = store(
            &pool,
            c,
            b,
            Row::plain(agent(&pool).await),
            serde_json::json!({"0": 0.6, "0,1": 0.4}),
        )
        .await;
        if c == leaf || c == hidden_leaf {
            atom_rows.push((c, r));
        }
    }

    // CONTROL: the public viewer really cannot see the hidden decomposition
    // (for it, `hidden` has no leaves), while the owner group can.
    let public = fixture::public_viewer(&pool).await;
    let owner = Viewer::resolve(&pool, member).await.expect("owner viewer");
    {
        let mut conn = pool.acquire().await.expect("conn");
        let public_closure = leaf_closure_batch(&mut *conn, &public, &[hidden])
            .await
            .expect("public closure");
        assert_eq!(
            public_closure.get(&hidden),
            Some(&Vec::new()),
            "the public viewer sees no leaf of the hidden decomposition"
        );
        let owner_closure = leaf_closure_batch(&mut *conn, &owner, &[hidden])
            .await
            .expect("owner closure");
        assert_eq!(owner_closure.get(&hidden), Some(&vec![hidden_leaf]));
    }

    for (who, viewer) in [("public", &public), ("owner", &owner)] {
        let got = rows_as(
            &pool,
            viewer,
            &[visible, leaf, hidden, hidden_leaf],
            AxiomMode::Display,
            CompoundSourceEdges::Frozen,
        )
        .await;
        for c in [visible, hidden] {
            assert!(
                got.get(&c).is_none_or(Vec::is_empty),
                "{who}: a compound's own rows must never be read (claim {c})"
            );
        }
        for (c, r) in &atom_rows {
            assert_eq!(
                ids_of(got.get(c).map(Vec::as_slice).unwrap_or_default()),
                set(&[*r]),
                "{who}: the atom's own row is read"
            );
        }
    }
}

// ── (10) lens ───────────────────────────────────────────────────────────────

/// Plan test (10), SPEC §3.3 "Lens context": under a lens {empirical: .2} a
/// leaf with one empirical item at .8 folds to .16.
#[sqlx::test(migrations = "../../migrations")]
async fn a_lens_discounts_each_row_by_its_evidence_type(pool: PgPool) {
    let author = agent(&pool).await;
    let atom = claim(&pool, author, "lens").await;
    store(
        &pool,
        atom,
        binary(&pool).await,
        Row {
            strength: None,
            evidence_type: Some("empirical"),
            ..Row::plain(agent(&pool).await)
        },
        serde_json::json!({"0": 0.8, "0,1": 0.2}),
    )
    .await;

    let lens = FramedBeliefContext::new(
        CalibrationConfig::default_for_phase2_fallback(),
        Some(PerspectiveReliability {
            source_reliability: HashMap::from([("empirical".to_string(), 0.2)]),
            locality_reliability: HashMap::new(),
        }),
    );
    let viewer = fixture::public_viewer(&pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    let got = atom_axiom_rows_under(
        &mut conn,
        &viewer,
        &[atom],
        AxiomMode::Display,
        &lens,
        CompoundSourceEdges::Frozen,
    )
    .await
    .expect("rows");
    let f = atom_fold(got.get(&atom).map(Vec::as_slice).unwrap_or_default()).expect("fold");
    assert!(
        close(f.belief(), 0.16),
        "lens .2 x item .8 = .16, got {}",
        f.belief()
    );
}

// ── (11) empty fold after a lifecycle act ───────────────────────────────────

/// Plan test (11), SPEC §4.2 "Empty fold" and ruling O24. An atom whose only
/// AEF row a lifecycle act removed gets an explicit vacuous cache (Bel 0,
/// Pl 1, BetP .5, `binary_truth`) when O24 is on, and keeps its cache when it
/// is off. An organic write with no input leaves the cache alone. No arm
/// NULLs it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_atom_that_lost_its_only_input_is_vacated_never_nulled(pool: PgPool) {
    let author = agent(&pool).await;
    let b = binary(&pool).await;
    let aef = |vacate| settings(AtomFoldMode::Aef, vacate);

    let mut atoms = Vec::new();
    for what in ["vacate on", "vacate off", "organic"] {
        let a = claim(&pool, author, what).await;
        let row = store(
            &pool,
            a,
            b,
            Row::plain(agent(&pool).await),
            serde_json::json!({"0": 0.7, "0,1": 0.3}),
        )
        .await;
        write(
            &pool,
            a,
            CacheWriteCause::Organic,
            LegacyFold::OwnerFrame,
            aef(true),
        )
        .await;
        let before = cache(&pool, a).await;
        assert!(
            before.belief.is_some_and(|v| close(v, 0.7)),
            "{what}: the AEF wrote the fold first, got {before:?}"
        );
        let input = before_act(&pool, a, aef(true)).await;
        assert!(input.had_input(), "{what}: the atom had AEF input");
        sqlx::query("DELETE FROM mass_functions WHERE id = $1")
            .bind(row)
            .execute(&pool)
            .await
            .expect("remove the atom's only row");
        atoms.push((a, before, input));
    }

    let (on, _, input) = &atoms[0];
    let outcome = write(
        &pool,
        *on,
        CacheWriteCause::EvidenceRemoved(*input),
        LegacyFold::OwnerFrame,
        aef(true),
    )
    .await;
    assert!(
        matches!(outcome, AtomCacheOutcome::Vacated { written: true }),
        "{outcome:?}"
    );
    let c = cache(&pool, *on).await;
    assert_eq!(
        (c.belief, c.plausibility, c.pignistic, c.frame),
        (Some(0.0), Some(1.0), Some(0.5), Some(b)),
        "O24 on: explicit vacuous cache on binary_truth"
    );

    let (off, before_off, input) = &atoms[1];
    write(
        &pool,
        *off,
        CacheWriteCause::EvidenceRemoved(*input),
        LegacyFold::OwnerFrame,
        aef(false),
    )
    .await;
    assert_eq!(
        &cache(&pool, *off).await,
        before_off,
        "O24 off: the old cache is kept"
    );

    let (organic, before_organic, _) = &atoms[2];
    let outcome = write(
        &pool,
        *organic,
        CacheWriteCause::Organic,
        LegacyFold::OwnerFrame,
        aef(true),
    )
    .await;
    assert_eq!(outcome, AtomCacheOutcome::KeptEmpty);
    assert_eq!(
        &cache(&pool, *organic).await,
        before_organic,
        "organic empty fold: untouched"
    );
}

// ── role scope of EPIGRAPH_ATOM_FOLD ────────────────────────────────────────

/// SPEC §4.2 / §10.2: `aef_standalone` folds standalones with the AEF and
/// leaves leaves on their legacy fold; `aef` folds both; `legacy` neither. An
/// AEF write stamps `binary_truth`.
///
/// Each atom carries a research_validity row (T .6) and a binary row (T .5).
/// The owner-frame rule folds only the binary row (Bel .5); the AEF folds
/// both (1 − .4·.5 = .8).
#[sqlx::test(migrations = "../../migrations")]
async fn the_fold_flag_scopes_the_aef_by_role(pool: PgPool) {
    let author = agent(&pool).await;
    let b = binary(&pool).await;
    let rv = research_validity(&pool).await;
    let parent = claim(&pool, author, "parent").await;

    async fn atom_with_two_frames(pool: &PgPool, a: Uuid, rv: Uuid, b: Uuid) {
        store(
            pool,
            a,
            rv,
            Row::plain(agent(pool).await),
            serde_json::json!({"0": 0.6, "0,1": 0.4}),
        )
        .await;
        store(
            pool,
            a,
            b,
            Row::plain(agent(pool).await),
            serde_json::json!({"0": 0.5, "0,1": 0.5}),
        )
        .await;
    }

    for (fold, leaf_bel, standalone_bel) in [
        (AtomFoldMode::Legacy, 0.5, 0.5),
        (AtomFoldMode::AefStandalone, 0.5, 0.8),
        (AtomFoldMode::Aef, 0.8, 0.8),
    ] {
        let leaf = claim(&pool, author, "leaf").await;
        decompose(&pool, parent, leaf).await;
        atom_with_two_frames(&pool, leaf, rv, b).await;
        let standalone = claim(&pool, author, "standalone").await;
        atom_with_two_frames(&pool, standalone, rv, b).await;

        for (id, want) in [(leaf, leaf_bel), (standalone, standalone_bel)] {
            write(
                &pool,
                id,
                CacheWriteCause::Organic,
                LegacyFold::OwnerFrame,
                settings(fold, true),
            )
            .await;
            let c = cache(&pool, id).await;
            assert!(
                c.belief.is_some_and(|v| close(v, want)),
                "{fold:?}: {} expected Bel {want}, got {c:?}",
                if id == leaf { "leaf" } else { "standalone" }
            );
            assert_eq!(
                c.frame,
                Some(b),
                "{fold:?}: the cache is stamped binary_truth"
            );
        }
    }

    // A research_validity-only standalone: the owner rule stamps
    // research_validity, the AEF stamps binary_truth.
    let rv_only = claim(&pool, author, "research_validity only").await;
    store(
        &pool,
        rv_only,
        rv,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
    )
    .await;
    write(
        &pool,
        rv_only,
        CacheWriteCause::Organic,
        LegacyFold::OwnerFrame,
        settings(AtomFoldMode::Aef, true),
    )
    .await;
    assert_eq!(
        cache(&pool, rv_only).await.frame,
        Some(b),
        "an AEF write stamps binary_truth"
    );
}

// ── hypothesis promotion and the axis index ─────────────────────────────────

/// SPEC §11.4: a hypothesis reads its `hypothesis_assessment` rows until
/// promotion and the promoted `research_validity` copy after it, never both.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hypothesis_reads_one_frame_either_side_of_promotion(pool: PgPool) {
    let author = agent(&pool).await;
    let ha = frame(
        &pool,
        "hypothesis_assessment",
        &["supported", "unsupported"],
    )
    .await;
    let rv = research_validity(&pool).await;
    let experimenter = agent(&pool).await;

    let mut by_status = Vec::new();
    for promoted in [false, true] {
        let h = claim(&pool, author, "hypothesis").await;
        let assessment = store(
            &pool,
            h,
            ha,
            Row {
                method: Some("error_derived"),
                ..Row::plain(experimenter)
            },
            serde_json::json!({"0": 0.7, "0,1": 0.3}),
        )
        .await;
        let copy = store(
            &pool,
            h,
            rv,
            Row {
                method: Some("error_derived"),
                ..Row::plain(experimenter)
            },
            serde_json::json!({"0": 0.7, "0,1": 0.3}),
        )
        .await;
        if promoted {
            sqlx::query(
                "UPDATE claims SET properties = properties || '{\"hypothesis_status\": \"promoted\"}' \
                 WHERE id = $1",
            )
            .bind(h)
            .execute(&pool)
            .await
            .expect("promote");
        }
        by_status.push((h, if promoted { copy } else { assessment }));
    }
    for (h, want) in by_status {
        assert_eq!(ids_of(&display(&pool, h).await), set(&[want]));
    }
}

/// A claim placed at hypothesis index 1 of a 2-hypothesis axis frame is TRUE
/// when index 1 holds: its row is coarsened with the literals swapped.
#[sqlx::test(migrations = "../../migrations")]
async fn an_axis_claim_at_index_one_is_coarsened_with_its_literals_swapped(pool: PgPool) {
    let author = agent(&pool).await;
    let axis = frame(&pool, "aef_axis_test", &["low", "high"]).await;
    let high = claim(&pool, author, "the high end of an axis").await;
    FrameRepository::assign_claim(&pool, high, axis, Some(1))
        .await
        .expect("assign index 1");
    store(
        &pool,
        high,
        axis,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.7, "0,1": 0.3}),
    )
    .await;
    let f = atom_fold(&display(&pool, high).await).expect("fold");
    assert!(
        close(f.belief(), 0.0) && close(f.plausibility(), 0.3),
        "mass on index 0 is disbelief for an index-1 claim: Bel 0, Pl .3; got Bel {} Pl {}",
        f.belief(),
        f.plausibility()
    );
}

// ── review: the residue is never vacated by an evidence-removal write ───────

/// SPEC §4.2 "Empty fold", first case, and §10.5: an atom that NEVER had AEF
/// input (the residue: its only row is the ingest template) is left
/// untouched when a lifecycle act removes that template row. Only an atom
/// that LOST AEF input is vacated; the residue is vacated only through the
/// operator accept list.
#[sqlx::test(migrations = "../../migrations")]
async fn a_residue_atom_is_never_vacated_by_an_evidence_removal_write(pool: PgPool) {
    let author = agent(&pool).await;
    let residue = claim(&pool, author, "template-only residue").await;
    let template = store_template(&pool, residue, agent(&pool).await).await;
    let sentinel = set_sentinel(&pool, residue).await;
    let s = settings(AtomFoldMode::Aef, true);

    let input = before_act(&pool, residue, s).await;
    sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(template)
        .execute(&pool)
        .await
        .expect("a lifecycle act removes the template row");
    let outcome = write(
        &pool,
        residue,
        CacheWriteCause::EvidenceRemoved(input),
        LegacyFold::OwnerFrame,
        s,
    )
    .await;
    assert_eq!(
        outcome,
        AtomCacheOutcome::KeptEmpty,
        "the residue never had AEF input, so it is not vacated"
    );
    assert_eq!(
        cache(&pool, residue).await,
        sentinel,
        "the residue's cache must not move"
    );

    // What was read before one act never stands in for another atom.
    let other = claim(&pool, author, "another atom").await;
    let viewer = fixture::public_viewer(&pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    let refused = recompute_atom_cache_with(
        &mut conn,
        &viewer,
        other,
        CacheWriteCause::EvidenceRemoved(input),
        LegacyFold::OwnerFrame,
        s,
    )
    .await;
    assert!(
        refused.is_err(),
        "a pre-act read for another claim is refused, got {refused:?}"
    );
}

// ── review: an edge-factor row whose edge the viewer cannot see ─────────────

/// SPEC §6.3: a compound-source edge row is read "through the target's own
/// viewer splice". A viewer who cannot see the edge cannot tell whether its
/// source is a compound, so the row must not be read two-sided as an
/// atom-source row, and `excluded` must not keep it: it is not in that
/// viewer's fold at all.
///
/// CONTROL: the owner group sees the edge, so for it the row is a
/// compound-source row: one-sided under `frozen` (Bel .5, Pl 1), dropped
/// under `excluded`.
#[sqlx::test(migrations = "../../migrations")]
async fn an_edge_row_whose_edge_the_viewer_cannot_see_is_not_read(pool: PgPool) {
    let author = agent(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "aef-hidden-edge").await;
    let compound = claim(&pool, author, "compound behind a private edge").await;
    decompose(&pool, compound, claim(&pool, author, "its leaf").await).await;
    let target = claim(&pool, author, "public target").await;
    let e = edge(&pool, compound, target, "supports").await;
    let row = store_edge_factor(
        &pool,
        e,
        target,
        agent(&pool).await,
        serde_json::json!({"0": 0.5, "1": 0.2, "0,1": 0.3}),
    )
    .await;
    hide_edge(&pool, e, group).await;

    let public = fixture::public_viewer(&pool).await;
    let owner = Viewer::resolve(&pool, member).await.expect("owner viewer");
    for edges in [CompoundSourceEdges::Frozen, CompoundSourceEdges::Excluded] {
        let got = rows_as(&pool, &public, &[target], AxiomMode::Display, edges).await;
        assert!(
            got.get(&target).is_none_or(Vec::is_empty),
            "{edges:?}: a row whose edge the viewer cannot see is not read, got {:?}",
            got.get(&target).map(|r| ids_of(r))
        );
    }

    let frozen = rows_as(
        &pool,
        &owner,
        &[target],
        AxiomMode::Display,
        CompoundSourceEdges::Frozen,
    )
    .await
    .remove(&target)
    .unwrap_or_default();
    assert_eq!(
        ids_of(&frozen),
        set(&[row]),
        "the owner group reads the row"
    );
    let f = atom_fold(&frozen).expect("fold");
    assert!(
        close(f.belief(), 0.5) && close(f.plausibility(), 1.0),
        "for the owner group it is a frozen compound-source row, one-sided: got Bel {} Pl {}",
        f.belief(),
        f.plausibility()
    );
    let excluded = rows_as(
        &pool,
        &owner,
        &[target],
        AxiomMode::Display,
        CompoundSourceEdges::Excluded,
    )
    .await;
    assert!(excluded.get(&target).is_none_or(Vec::is_empty));
}

// ── review: the seed rule counts only rows a fold reads ─────────────────────

/// Ruling O16: a seed is kept while it is the atom's sole input. A row that
/// no fold reads is not input: a compound-source edge row under `excluded`,
/// a row the self-reference guard skips, or an edge row whose edge the viewer
/// cannot see. Beside any of them the seed is still the sole input.
///
/// CONTROL: under `frozen`, a compound-source row the fold does read counts,
/// and the seed drops out.
#[sqlx::test(migrations = "../../migrations")]
async fn a_seed_beside_rows_no_fold_reads_is_still_the_sole_input(pool: PgPool) {
    let author = agent(&pool).await;
    let b = binary(&pool).await;
    let writer = agent(&pool).await;
    let (_member, group) = fixture::seed_agent_with_group(&pool, "aef-seed-order").await;
    let seed_on = |pool: PgPool, c: Uuid| async move {
        store(
            &pool,
            c,
            b,
            Row {
                method: Some("truth_value_seed"),
                ..Row::plain(author)
            },
            serde_json::json!({"0": 0.7, "0,1": 0.3}),
        )
        .await
    };
    let compound = claim(&pool, author, "compound source").await;
    let own_leaf = claim(&pool, author, "the compound's own leaf").await;
    decompose(&pool, compound, own_leaf).await;

    // (a) a standalone with a seed and a compound-source edge row
    let standalone = claim(&pool, author, "seeded standalone").await;
    let seed_a = seed_on(pool.clone(), standalone).await;
    let e = edge(&pool, compound, standalone, "supports").await;
    let edge_row = store_edge_factor(
        &pool,
        e,
        standalone,
        writer,
        serde_json::json!({"0": 0.5, "0,1": 0.5}),
    )
    .await;
    for mode in [AxiomMode::Display, AxiomMode::Pure] {
        let got = rows(&pool, &[standalone], mode, CompoundSourceEdges::Excluded).await;
        assert_eq!(
            ids_of(got.get(&standalone).map(Vec::as_slice).unwrap_or_default()),
            set(&[seed_a]),
            "{mode:?}/excluded: the excluded row is not input, so the seed stays"
        );
    }
    assert_eq!(
        ids_of(&display(&pool, standalone).await),
        set(&[edge_row]),
        "control: under frozen the edge row is read, so the seed drops out"
    );

    // (b) the compound's own leaf: a seed and a row the guard skips
    let seed_b = seed_on(pool.clone(), own_leaf).await;
    let e = edge(&pool, compound, own_leaf, "supports").await;
    store_edge_factor(
        &pool,
        e,
        own_leaf,
        writer,
        serde_json::json!({"0": 0.5, "0,1": 0.5}),
    )
    .await;
    assert_eq!(
        ids_of(&display(&pool, own_leaf).await),
        set(&[seed_b]),
        "a row the self-reference guard skips is not input, so the seed stays"
    );

    // (c) a seed and an edge row whose edge the viewer cannot see
    let hidden = claim(&pool, author, "seeded, behind a private edge").await;
    let seed_c = seed_on(pool.clone(), hidden).await;
    let source = claim(&pool, author, "atom source").await;
    let e = edge(&pool, source, hidden, "supports").await;
    store_edge_factor(
        &pool,
        e,
        hidden,
        writer,
        serde_json::json!({"0": 0.5, "0,1": 0.5}),
    )
    .await;
    hide_edge(&pool, e, group).await;
    assert_eq!(
        ids_of(&display(&pool, hidden).await),
        set(&[seed_c]),
        "a row whose edge the viewer cannot see is not input, so the seed stays"
    );
}

// ── review: one unreadable row costs only that row ──────────────────────────

/// A stored BBA that cannot be parsed is skipped (and logged); the batch read
/// still returns every other row of every requested atom, including the
/// readable rows of the atom that carries the bad one.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_row_is_skipped_and_never_fails_the_batch(pool: PgPool) {
    let author = agent(&pool).await;
    let b = binary(&pool).await;
    let good = claim(&pool, author, "every row readable").await;
    let good_row = store(
        &pool,
        good,
        b,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
    )
    .await;
    let mixed = claim(&pool, author, "one unreadable row").await;
    let readable = store(
        &pool,
        mixed,
        b,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.7, "0,1": 0.3}),
    )
    .await;
    store(
        &pool,
        mixed,
        b,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": "not a mass", "0,1": 0.3}),
    )
    .await;

    let viewer = fixture::public_viewer(&pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    let got = atom_axiom_rows_under(
        &mut conn,
        &viewer,
        &[good, mixed],
        AxiomMode::Display,
        &ctx(),
        CompoundSourceEdges::Frozen,
    )
    .await
    .expect("one unreadable row must not fail the batch");
    assert_eq!(
        ids_of(got.get(&good).map(Vec::as_slice).unwrap_or_default()),
        set(&[good_row])
    );
    assert_eq!(
        ids_of(got.get(&mixed).map(Vec::as_slice).unwrap_or_default()),
        set(&[readable]),
        "the unreadable row is skipped, the readable one is kept"
    );
}

// ── review: a row citing evidence through its perspective only ─────────────

/// A row that cites its evidence only through an evidence perspective
/// (`evidence_id` NULL) keys on that evidence row even when the viewer cannot
/// read it, as a row citing a hidden `evidence_id` does: two agents citing one
/// evidence row are one item (.8) for every viewer, never one item per row
/// (.96) for the viewer who cannot read the evidence.
#[sqlx::test(migrations = "../../migrations")]
async fn two_rows_citing_one_evidence_perspective_are_one_item_for_every_viewer(pool: PgPool) {
    let author = agent(&pool).await;
    let b = binary(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "aef-hidden-evidence").await;
    let (x, y) = (agent(&pool).await, agent(&pool).await);
    let holder = claim(&pool, author, "evidence holder").await;
    let ev = doi_evidence(&pool, holder, "10.5555/aef-hidden", x).await;
    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(ev)
        .bind(group)
        .execute(&pool)
        .await
        .expect("make the evidence private");

    let atom = claim(&pool, author, "cited through a perspective").await;
    for a in [x, y] {
        store(
            &pool,
            atom,
            b,
            Row {
                perspective: Some(ev),
                ..Row::plain(a)
            },
            serde_json::json!({"0": 0.8, "0,1": 0.2}),
        )
        .await;
    }

    let public = fixture::public_viewer(&pool).await;
    let owner = Viewer::resolve(&pool, member).await.expect("owner viewer");
    for (who, viewer) in [("public", &public), ("owner", &owner)] {
        let got = rows_as(
            &pool,
            viewer,
            &[atom],
            AxiomMode::Display,
            CompoundSourceEdges::Frozen,
        )
        .await
        .remove(&atom)
        .unwrap_or_default();
        assert_eq!(got.len(), 2, "{who}: both rows are read");
        let f = atom_fold(&got).expect("fold");
        assert!(
            close(f.belief(), 0.8),
            "{who}: one cited evidence row is one item at .8, got Bel {}",
            f.belief()
        );
    }
}

// ── review: a claim_validity complement keeps its open-world share ──────────

/// CDST complement(A) is "outside A, including propositions not in the
/// frame". On `claim_validity`, complement({refuted, uncertain}) is
/// "supported or open-world", which coarsens to complement({F}) (`~1`) on
/// `binary_truth`, not to a closed T. Complement elements carry neither Bel
/// nor Pl, so the fold is Bel 0, Pl .6, exactly as the same row stored on
/// `binary_truth`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_validity_complement_keeps_its_open_world_share(pool: PgPool) {
    let author = agent(&pool).await;
    let cv = claim(&pool, author, "claim_validity complement").await;
    store(
        &pool,
        cv,
        CLAIM_VALIDITY_FRAME_ID,
        Row::plain(agent(&pool).await),
        serde_json::json!({"~1,2": 0.4, "0,1,2": 0.6}),
    )
    .await;
    let twin = claim(&pool, author, "the same row on binary_truth").await;
    store(
        &pool,
        twin,
        binary(&pool).await,
        Row::plain(agent(&pool).await),
        serde_json::json!({"~1": 0.4, "0,1": 0.6}),
    )
    .await;

    let f = atom_fold(&display(&pool, cv).await).expect("fold");
    assert!(
        close(f.belief(), 0.0) && close(f.plausibility(), 0.6),
        "complement({{refuted, uncertain}}) is not a closed T: want Bel 0, Pl .6, got Bel {} Pl {}",
        f.belief(),
        f.plausibility()
    );
    let t = atom_fold(&display(&pool, twin).await).expect("fold");
    assert_eq!(
        (
            f.belief(),
            f.plausibility(),
            f.pignistic_prob(),
            f.mass_on_missing()
        ),
        (
            t.belief(),
            t.plausibility(),
            t.pignistic_prob(),
            t.mass_on_missing()
        ),
        "the coarsened row folds as its binary_truth twin"
    );
}

// ── review: the row-security limit of "role is structure" ───────────────────

/// The documented limit of D1 (module doc of `epigraph_db::repos::atom_axiom`,
/// and of `claim_role`): on an `epigraph_app` session, row security filters
/// `edges` whatever the query splices, so for an anonymous session a public
/// compound whose whole decomposition is private reads as a standalone, and
/// its own rows ARE returned. This pins the gap as it stands, so the fix that
/// PR-5b1 needs before it wires a per-request site (fail closed, or a
/// definer-rights role read) turns it red and has to update it.
///
/// CALIBRATION: in the same session a compound whose decomposition is public
/// is still never read, so the hidden compound's rows are row security at
/// work, not a session that skips the role test.
#[sqlx::test(migrations = "../../migrations")]
async fn on_an_app_session_row_security_hides_a_compound_from_the_fold(pool: PgPool) {
    let author = agent(&pool).await;
    let b = binary(&pool).await;
    let (_member, group) = fixture::seed_agent_with_group(&pool, "aef-rls").await;
    let hidden = claim(&pool, author, "public compound, private decomposition").await;
    let e = decompose(&pool, hidden, claim(&pool, author, "leaf").await).await;
    hide_edge(&pool, e, group).await;
    let open = claim(&pool, author, "public compound, public decomposition").await;
    decompose(&pool, open, claim(&pool, author, "public leaf").await).await;
    let mut hidden_row = Uuid::nil();
    for c in [hidden, open] {
        let r = store(
            &pool,
            c,
            b,
            Row::plain(agent(&pool).await),
            serde_json::json!({"0": 0.6, "0,1": 0.4}),
        )
        .await;
        if c == hidden {
            hidden_row = r;
        }
    }

    let anonymous = fixture::public_viewer(&pool).await;
    let got = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let got = {
            let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
            sqlx::query(
                "SELECT set_config('epigraph.group_ids', '', true), \
                        set_config('epigraph.writable_group_ids', '', true), \
                        set_config('epigraph.principal_id', '', true)",
            )
            .execute(&mut *tx)
            .await
            .expect("stamp the app session");
            let got = atom_axiom_rows_under(
                &mut tx,
                &anonymous,
                &[hidden, open],
                AxiomMode::Display,
                &ctx(),
                CompoundSourceEdges::Frozen,
            )
            .await
            .expect("atom_axiom_rows on an app session");
            tx.rollback().await.expect("rollback");
            got
        };
        (conn, got)
    })
    .await;
    assert!(
        got.get(&open).is_none_or(Vec::is_empty),
        "calibration: a compound the session can see is never read"
    );
    assert_eq!(
        ids_of(got.get(&hidden).map(Vec::as_slice).unwrap_or_default()),
        set(&[hidden_row]),
        "KNOWN GAP (PR-5b1): row security hides the decomposition, so the compound's row is read"
    );
}

// ── review: total conflict ──────────────────────────────────────────────────

/// Two dogmatic items that contradict each other (K = 1) do not fail the
/// fold: `combine_multiple` falls back to Yager's closed rule, so the
/// conflict mass goes to Θ (Bel 0, Pl 1), and the fold reports the K = 1 it
/// saw. A one-leaf derivation that must equal `atom_fold` (D11) has to adopt
/// the same convention.
#[sqlx::test(migrations = "../../migrations")]
async fn two_dogmatic_contradicting_items_fold_to_ignorance_not_an_error(pool: PgPool) {
    let author = agent(&pool).await;
    let b = binary(&pool).await;
    let atom = claim(&pool, author, "dogmatic conflict").await;
    for masses in [serde_json::json!({"0": 1.0}), serde_json::json!({"1": 1.0})] {
        store(&pool, atom, b, Row::plain(agent(&pool).await), masses).await;
    }
    let f = atom_fold(&display(&pool, atom).await).expect("total conflict is not an error");
    assert!(
        close(f.belief(), 0.0) && close(f.plausibility(), 1.0),
        "Yager closed: all mass on Θ, got Bel {} Pl {}",
        f.belief(),
        f.plausibility()
    );
    assert!(
        close(f.mass_on_conflict(), 1.0),
        "the fold saw K = 1, got {}",
        f.mass_on_conflict()
    );
}

// ── review: what an AEF write stores, and what it does not cover ────────────

/// An AEF write stores the classification of the fold (a strongly supported
/// atom reads `supported`, a strongly refuted one `contradicted`), and the
/// fold's open-world mass in `mass_on_missing`. A procedural claim keeps its
/// legacy fold under `aef`, and a claim the viewer cannot see is not written.
#[sqlx::test(migrations = "../../migrations")]
async fn an_aef_write_stores_classification_and_open_world_mass_and_skips_what_it_does_not_cover(
    pool: PgPool,
) {
    let author = agent(&pool).await;
    let b = binary(&pool).await;
    let aef = settings(AtomFoldMode::Aef, true);

    async fn classification(pool: &PgPool, id: Uuid) -> Option<String> {
        sqlx::query_scalar("SELECT classification FROM claims WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("classification")
    }

    for (what, masses, want) in [
        (
            "strongly supported",
            serde_json::json!({"0": 0.9, "0,1": 0.1}),
            "supported",
        ),
        (
            "strongly refuted",
            serde_json::json!({"1": 0.9, "0,1": 0.1}),
            "contradicted",
        ),
    ] {
        let c = claim(&pool, author, what).await;
        store(&pool, c, b, Row::plain(agent(&pool).await), masses).await;
        assert_eq!(classification(&pool, c).await, None, "{what}: no label yet");
        let outcome = write(
            &pool,
            c,
            CacheWriteCause::Organic,
            LegacyFold::OwnerFrame,
            aef,
        )
        .await;
        assert!(
            matches!(outcome, AtomCacheOutcome::Folded { written: true, .. }),
            "{what}: {outcome:?}"
        );
        assert_eq!(
            classification(&pool, c).await.as_deref(),
            Some(want),
            "{what}"
        );
    }

    let open_world = claim(&pool, author, "open-world mass").await;
    store(
        &pool,
        open_world,
        b,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.5, "~0,1": 0.3, "0,1": 0.2}),
    )
    .await;
    write(
        &pool,
        open_world,
        CacheWriteCause::Organic,
        LegacyFold::OwnerFrame,
        aef,
    )
    .await;
    let missing: Option<f64> =
        sqlx::query_scalar("SELECT mass_on_missing FROM claims WHERE id = $1")
            .bind(open_world)
            .fetch_one(&pool)
            .await
            .expect("mass_on_missing");
    assert!(
        missing.is_some_and(|m| close(m, 0.3)),
        "the fold's `~` mass is stored, got {missing:?}"
    );

    let workflow_ingest = agent(&pool).await;
    plant_workflow_ingest_agent(&pool, workflow_ingest).await;
    let procedural = claim(&pool, workflow_ingest, "workflow root").await;
    sqlx::query(
        "UPDATE claims SET properties = properties || '{\"source_type\": \"workflow\"}' \
         WHERE id = $1",
    )
    .bind(procedural)
    .execute(&pool)
    .await
    .expect("stamp a workflow root");
    store(
        &pool,
        procedural,
        b,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
    )
    .await;
    let outcome = write(
        &pool,
        procedural,
        CacheWriteCause::Organic,
        LegacyFold::OwnerFrame,
        aef,
    )
    .await;
    assert!(
        matches!(outcome, AtomCacheOutcome::Legacy { .. }),
        "a procedural claim keeps its legacy fold under aef, got {outcome:?}"
    );

    let (_member, group) = fixture::seed_agent_with_group(&pool, "aef-not-visible").await;
    let private = fixture::seed_group_claim(
        &pool,
        author,
        group,
        &format!("aef private {}", Uuid::new_v4()),
    )
    .await;
    let sentinel = set_sentinel(&pool, private).await;
    let outcome = write(
        &pool,
        private,
        CacheWriteCause::Organic,
        LegacyFold::OwnerFrame,
        aef,
    )
    .await;
    assert_eq!(outcome, AtomCacheOutcome::NotVisible);
    assert_eq!(cache(&pool, private).await, sentinel, "nothing is written");
}

// ── review: open-world mass through claim_validity and the index-1 swap ─────

/// `~` on `claim_validity` stays `~` (SPEC §3.3's worked example, on the
/// three-hypothesis frame: K .3 and Bel .628/.7 beside {T .64}); and an
/// index-1 axis row swaps its complement elements as well as its positive
/// ones, so it folds exactly as its swapped twin on `binary_truth`, and not
/// as the unswapped one.
#[sqlx::test(migrations = "../../migrations")]
async fn open_world_mass_survives_claim_validity_and_the_index_one_swap(pool: PgPool) {
    let author = agent(&pool).await;
    let b = binary(&pool).await;
    let second_item = |pool: PgPool, c: Uuid| async move {
        store(
            &pool,
            c,
            b,
            Row::plain(agent(&pool).await),
            serde_json::json!({"0": 0.64, "0,1": 0.36}),
        )
        .await
    };

    let cv = claim(&pool, author, "claim_validity with open-world mass").await;
    store(
        &pool,
        cv,
        CLAIM_VALIDITY_FRAME_ID,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.5, "~0,1,2": 0.3, "0,1,2": 0.2}),
    )
    .await;
    second_item(pool.clone(), cv).await;
    let f = atom_fold(&display(&pool, cv).await).expect("fold");
    assert!(
        (f.belief() - 0.628 / 0.7).abs() < 1e-9 && close(f.mass_on_conflict(), 0.3),
        "claim_validity `~` meets the second item as conflict: want Bel .628/.7, K .3; got Bel {} K {}",
        f.belief(),
        f.mass_on_conflict()
    );

    let axis = frame(&pool, "aef_axis_open_world", &["low", "high"]).await;
    let row = serde_json::json!({"~1": 0.3, "~0,1": 0.1, "0,1": 0.6});
    let high = claim(&pool, author, "index 1 with complement mass").await;
    FrameRepository::assign_claim(&pool, high, axis, Some(1))
        .await
        .expect("assign index 1");
    store(&pool, high, axis, Row::plain(agent(&pool).await), row).await;
    second_item(pool.clone(), high).await;

    let swapped = claim(&pool, author, "the swapped twin").await;
    store(
        &pool,
        swapped,
        b,
        Row::plain(agent(&pool).await),
        serde_json::json!({"~0": 0.3, "~0,1": 0.1, "0,1": 0.6}),
    )
    .await;
    second_item(pool.clone(), swapped).await;
    let unswapped = claim(&pool, author, "the unswapped twin").await;
    store(
        &pool,
        unswapped,
        b,
        Row::plain(agent(&pool).await),
        serde_json::json!({"~1": 0.3, "~0,1": 0.1, "0,1": 0.6}),
    )
    .await;
    second_item(pool.clone(), unswapped).await;

    let shape = |f: &epigraph_engine::atom_items::EvidencedInterval| {
        (
            f.belief(),
            f.plausibility(),
            f.mass_on_conflict(),
            f.mass_on_missing(),
        )
    };
    let got = shape(&atom_fold(&display(&pool, high).await).expect("fold"));
    let want = shape(&atom_fold(&display(&pool, swapped).await).expect("fold"));
    let other = shape(&atom_fold(&display(&pool, unswapped).await).expect("fold"));
    assert_ne!(want, other, "control: the two twins must fold differently");
    assert!(
        (got.0 - want.0).abs() < TOL
            && (got.1 - want.1).abs() < TOL
            && (got.2 - want.2).abs() < TOL
            && (got.3 - want.3).abs() < TOL,
        "an index-1 row folds as its swapped twin: got {got:?}, want {want:?}"
    );
}
