//! Property tests: every belief cascade entry point in
//! `retraction_cascade` is IDEMPOTENT. Running it a second time on the state
//! the first run left changes no cached belief (nor the frame the cache
//! records), no stored mass, no frame assignment, no perspective row, no
//! factor and no edge.
//!
//! Entry points, each retired or withdrawn through the real repository act:
//!
//! * `cascade_after_supersede` (`ClaimRepository::supersede`);
//! * `cascade_after_edge_withdrawal` (`EdgeRepository::retract`, then the
//!   administrative `EdgeRepository::remove_withdrawn_edge_bbas_conn`);
//! * `cascade_after_dedup` (`ClaimRepository::mark_duplicate_with_repair_conn`;
//!   the re-run is the cascade on the same repair, which is what a deferred
//!   replay does);
//! * `sweep_retired_source_bbas` (a plain `is_current` flip the K10(2) arm
//!   never saw; each run re-measures its selection, as the operator binary
//!   does);
//! * `mark_duplicate_with_cascade` (the act and its cascade: a second call is
//!   refused by the act and changes nothing).
//!
//! Backlog 57c7779d added the last four; the supersede property came first.
//!
//! # Why this is the property
//!
//! The cascade invalidates the edge-keyed BBAs a retraction made stale,
//! re-derives the ones whose edge now hangs off the replacement, and
//! recomputes every target from what survives. Each of those steps must be a
//! function of state the cascade does not itself rewrite: if a re-derivation
//! read a value the same cascade had just written (a target's cached belief,
//! a mass it had just stored), a second run would move the numbers again, and
//! a retry after a partial failure, or a duplicate delivery, would drift the
//! graph.
//!
//! # Shape of the generated cases
//!
//! A retiring claim R with 2-4 outgoing edges, one relationship each from
//! `supports`, `corroborates` (re-sourced onto the replacement by the
//! supersede) and `refutes`, `contradicts` (they stay on R, so the cascade's
//! second walk runs). The first edge is always `supports`, so every case
//! re-derives at least one BBA. Each target may also hold an independent
//! supporter, and consecutive targets may be chained by a `supports` edge, so
//! the graph is a small DAG and some targets keep surviving evidence. The
//! replacement is given its own interval before the cascade runs, so the
//! re-derivation is real rather than `SourceFactorless`.
//!
//! # How cases are generated
//!
//! `#[sqlx::test]` owns the runtime, so proptest's runner (which would
//! `block_on`) cannot drive the async body. Cases are drawn from proptest
//! strategies with a deterministic `TestRunner` and run one after another in
//! one database with fresh ids; each case is logged, so a failure names its
//! input. There is no shrinking.
//!
//! The comparison is by CONTENT, never by row id or timestamp: a second run
//! legitimately deletes and re-creates the re-derived rows.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, EdgeRepository, PgPool, SupersedeActor, SupersedeTool};
use epigraph_engine::edge_factor::{auto_wire_ds_for_edge, EdgeFactorOutcome};
use epigraph_engine::retraction_cascade::{
    cascade_after_dedup, cascade_after_edge_withdrawal, cascade_after_supersede,
    mark_duplicate_with_cascade, sweep_retired_source_bbas,
};
use epigraph_engine::supersede_delta::retired_source_edge_bbas;
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use uuid::Uuid;

const CASES: usize = 12;

#[derive(Debug, Clone, Copy)]
struct Iv {
    bel: f64,
    pl: f64,
}

#[derive(Debug, Clone)]
struct TargetSpec {
    /// The relationship of R's edge onto this target.
    from_r: &'static str,
    /// An independent supporter of this target, with its interval.
    supporter: Option<Iv>,
    /// Whether the previous target also supports this one.
    chained: bool,
}

#[derive(Debug, Clone)]
struct Case {
    retiring: Iv,
    replacement: Iv,
    targets: Vec<TargetSpec>,
}

fn iv() -> impl Strategy<Value = Iv> {
    (0.05..=0.9_f64, 0.02..=1.0_f64).prop_map(|(bel, w)| Iv {
        bel,
        pl: (bel + w * (1.0 - bel)).clamp(bel + 0.02, 1.0),
    })
}

fn target(first: bool) -> impl Strategy<Value = TargetSpec> {
    let rel = if first {
        Just("supports").boxed()
    } else {
        prop_oneof![
            Just("supports"),
            Just("corroborates"),
            Just("refutes"),
            Just("contradicts"),
        ]
        .boxed()
    };
    (rel, proptest::option::of(iv()), any::<bool>()).prop_map(move |(from_r, supporter, ch)| {
        TargetSpec {
            from_r,
            supporter,
            chained: ch && !first,
        }
    })
}

fn case() -> impl Strategy<Value = Case> {
    (
        iv(),
        iv(),
        target(true),
        prop::collection::vec(target(false), 1..=3),
    )
        .prop_map(|(retiring, replacement, t0, rest)| {
            let mut targets = vec![t0];
            targets.extend(rest);
            Case {
                retiring,
                replacement,
                targets,
            }
        })
}

async fn believed(pool: &PgPool, agent: Uuid, tag: &str, iv: Iv) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, tag).await;
    plant(pool, id, iv).await;
    id
}

async fn plant(pool: &PgPool, id: Uuid, iv: Iv) {
    sqlx::query("UPDATE claims SET belief = $2, plausibility = $3 WHERE id = $1")
        .bind(id)
        .bind(iv.bel)
        .bind(iv.pl)
        .execute(pool)
        .await
        .expect("plant an interval");
}

async fn wire(pool: &PgPool, viewer: &Viewer, agent: Uuid, s: Uuid, t: Uuid, rel: &str) -> Uuid {
    let e: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(s)
    .bind(t)
    .bind(rel)
    .fetch_one(pool)
    .await
    .expect("insert edge");
    let mut conn = pool.acquire().await.expect("acquire");
    let out = auto_wire_ds_for_edge(&mut conn, viewer, e, agent, s, t, rel)
        .await
        .expect("auto-wire");
    assert_eq!(
        out,
        EdgeFactorOutcome::Wired,
        "PREMISE: {rel} {s}->{t} wires"
    );
    e
}

/// A claim's cached belief columns: id, belief, plausibility, pignistic,
/// mass on empty, mass on missing, classification, the frame the cache holds.
type CacheRow = (
    Uuid,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<String>,
    Option<Uuid>,
);

/// A frame assignment: claim, frame, hypothesis index.
type FrameRow = (Uuid, Uuid, Option<i32>);

/// A perspective row by content: id, name, owner agent, type.
type PerspectiveRow = (Uuid, String, Option<Uuid>, Option<String>);

/// A mass row by content: claim, frame, source agent, perspective, masses,
/// source strength, evidence type, retracted.
type MassRow = (
    Uuid,
    Uuid,
    Option<Uuid>,
    Option<Uuid>,
    String,
    Option<f64>,
    Option<String>,
    bool,
);

/// A factor by content: type, variables, potential, properties.
type FactorRow = (String, String, String, String);

/// An edge by content: source, target, relationship, in force.
type EdgeRow = (Uuid, Uuid, String, bool);

/// Every cached belief column, mass row and frame assignment of `claims`, the
/// perspectives of the edges touching them, and the size of the whole
/// perspectives table (a stray row keyed to nothing here still counts), the
/// factors over them and the edges touching them, by content.
#[derive(Debug, PartialEq)]
struct Snapshot {
    caches: Vec<CacheRow>,
    masses: Vec<MassRow>,
    frames: Vec<FrameRow>,
    perspectives: Vec<PerspectiveRow>,
    perspective_total: i64,
    factors: Vec<FactorRow>,
    edges: Vec<EdgeRow>,
}

async fn snapshot(pool: &PgPool, claims: &[Uuid]) -> Snapshot {
    let caches = sqlx::query_as(
        "SELECT id, belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing, \
                classification::text, belief_frame_id \
           FROM claims WHERE id = ANY($1) ORDER BY id",
    )
    .bind(claims)
    .fetch_all(pool)
    .await
    .expect("read the caches");
    let masses = sqlx::query_as(
        "SELECT claim_id, frame_id, source_agent_id, COALESCE(slot_id, perspective_id), \
                masses::text, source_strength, evidence_type::text, retracted_at IS NOT NULL \
           FROM mass_functions WHERE claim_id = ANY($1) \
          ORDER BY claim_id, frame_id, source_agent_id, COALESCE(slot_id, perspective_id), \
                   masses::text",
    )
    .bind(claims)
    .fetch_all(pool)
    .await
    .expect("read the masses");
    let frames = sqlx::query_as(
        "SELECT claim_id, frame_id, hypothesis_index FROM claim_frames \
          WHERE claim_id = ANY($1) ORDER BY claim_id, frame_id",
    )
    .bind(claims)
    .fetch_all(pool)
    .await
    .expect("read the frame assignments");
    let perspectives = sqlx::query_as(
        "SELECT p.id, p.name, p.owner_agent_id, p.perspective_type::text \
           FROM perspectives p \
          WHERE p.id IN (SELECT e.id FROM edges e \
                          WHERE e.source_id = ANY($1) OR e.target_id = ANY($1)) \
          ORDER BY p.id",
    )
    .bind(claims)
    .fetch_all(pool)
    .await
    .expect("read the edge perspectives");
    let perspective_total = sqlx::query_scalar("SELECT count(*) FROM perspectives")
        .fetch_one(pool)
        .await
        .expect("count the perspectives");
    let factors = sqlx::query_as(
        "SELECT factor_type::text, variable_ids::text, potential::text, properties::text \
           FROM factors WHERE variable_ids && $1 \
          ORDER BY 1, 2, 3, 4",
    )
    .bind(claims)
    .fetch_all(pool)
    .await
    .expect("read the factors");
    let edges = sqlx::query_as(
        "SELECT source_id, target_id, relationship::text, \
                (valid_to IS NULL OR valid_to > now()) \
           FROM edges WHERE source_id = ANY($1) OR target_id = ANY($1) \
          ORDER BY 1, 2, 3, 4",
    )
    .bind(claims)
    .fetch_all(pool)
    .await
    .expect("read the edges");
    Snapshot {
        caches,
        masses,
        frames,
        perspectives,
        perspective_total,
        factors,
        edges,
    }
}

/// A built case: the claim at the root (R, or the duplicate), every claim the
/// snapshot reads, the targets, and R's outgoing edges.
struct Built {
    root: Uuid,
    claims: Vec<Uuid>,
    root_edges: Vec<Uuid>,
}

/// Build case `n`'s DAG: a root with one edge onto each target, each target's
/// optional independent supporter and optional chain from its predecessor.
async fn build(pool: &PgPool, public: &Viewer, agent: Uuid, n: usize, case: &Case) -> Built {
    let root = believed(pool, agent, &format!("idem {n} R"), case.retiring).await;
    let mut claims = vec![root];
    let mut targets: Vec<Uuid> = Vec::new();
    let mut root_edges = Vec::new();
    for (i, spec) in case.targets.iter().enumerate() {
        let t = fixture::seed_public_claim(pool, agent, &format!("idem {n} T{i}")).await;
        claims.push(t);
        if let Some(s_iv) = spec.supporter {
            let s = believed(pool, agent, &format!("idem {n} S{i}"), s_iv).await;
            claims.push(s);
            wire(pool, public, agent, s, t, "supports").await;
        }
        if spec.chained {
            let prev = *targets.last().expect("a chained target has a predecessor");
            wire(pool, public, agent, prev, t, "supports").await;
        }
        root_edges.push(wire(pool, public, agent, root, t, spec.from_r).await);
        targets.push(t);
    }
    Built {
        root,
        claims,
        root_edges,
    }
}

/// A generated case whose first target always keeps an independent
/// supporter, so the entry points that only recompute have a claim a second
/// run rewrites from surviving evidence.
fn case_with_backed_first(mut case: Case) -> Case {
    if case.targets[0].supporter.is_none() {
        case.targets[0].supporter = Some(Iv { bel: 0.6, pl: 0.8 });
    }
    case
}

#[sqlx::test(migrations = "../../migrations")]
async fn running_the_supersede_cascade_twice_equals_running_it_once(pool: PgPool) {
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let public = fixture::public_viewer(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "idem-author").await;

    let mut runner = TestRunner::deterministic();
    let strategy = case();
    let mut second_runs_that_rederived = 0usize;

    for n in 0..CASES {
        let case = strategy
            .new_tree(&mut runner)
            .expect("generate a case")
            .current();
        eprintln!("case {n}: {case:?}");

        // ---- Build the DAG. ----
        let Built {
            root: retiring,
            mut claims,
            ..
        } = build(&pool, &public, agent, n, &case).await;

        // ---- Retire R through the real supersede act, and give the
        // replacement its own interval so the re-derivation is real. ----
        let (replacement, _) = ClaimRepository::supersede(
            &pool,
            ClaimId::from_uuid(retiring),
            &format!("idem {n} R, revised"),
            TruthValue::clamped(0.7),
            "revision",
            SupersedeActor::new(agent, SupersedeTool::SupersedeClaim),
        )
        .await
        .expect("supersede");
        plant(&pool, replacement, case.replacement).await;
        claims.push(replacement);

        let mut conn = pool.acquire().await.expect("acquire");
        let first = cascade_after_supersede(&mut conn, &bypass, retiring, replacement).await;
        assert!(first.errors.is_empty(), "case {n}: first run: {first:?}");
        assert!(
            first.invalidated_bbas > 0 && !first.targets.is_empty(),
            "CALIBRATION case {n}: the first run must invalidate and repair something, or the \
             comparison below is between two untouched states: {first:?}"
        );
        let once = snapshot(&pool, &claims).await;
        assert!(
            !once.frames.is_empty()
                && !once.masses.is_empty()
                && once.caches.iter().any(|c| c.7.is_some()),
            "CALIBRATION case {n}: the first run must leave frame assignments, edge-slot \
             BBAs and a cache frame, or their comparison below is vacuous: {once:?}"
        );

        let second = cascade_after_supersede(&mut conn, &bypass, retiring, replacement).await;
        assert!(second.errors.is_empty(), "case {n}: second run: {second:?}");
        if second.invalidated_bbas > 0 {
            second_runs_that_rederived += 1;
        }
        let twice = snapshot(&pool, &claims).await;

        assert_eq!(
            once, twice,
            "case {n}: a second cascade run changed the state the first one left.\nfirst: \
             {first:?}\nsecond: {second:?}"
        );
    }

    assert_eq!(
        second_runs_that_rederived, CASES,
        "CALIBRATION: every case's SECOND run must itself delete and re-derive the replacement's \
         edge BBAs, or idempotence is satisfied by a second run that does nothing"
    );
}

/// Generate case `n` (logged, so a failure names its input).
fn next_case(runner: &mut TestRunner, n: usize, backed_first: bool) -> Case {
    let case = case().new_tree(runner).expect("generate a case").current();
    let case = if backed_first {
        case_with_backed_first(case)
    } else {
        case
    };
    eprintln!("case {n}: {case:?}");
    case
}

/// Edge withdrawal (migration 120's `edge_retract` cascade): every edge out of
/// R is retracted through `EdgeRepository::retract`, its edge-keyed BBAs are
/// removed by the administrative `remove_withdrawn_edge_bbas_conn`, and the
/// claims they lived on are repaired. A second run of the repair (a replay of
/// the same deferral, or a retry) changes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn running_the_edge_withdrawal_cascade_twice_equals_running_it_once(pool: PgPool) {
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let public = fixture::public_viewer(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "idem-withdraw").await;
    let mut runner = TestRunner::deterministic();
    let mut second_runs_that_wrote = 0usize;

    for n in 0..CASES {
        let case = next_case(&mut runner, n, true);
        let built = build(&pool, &public, agent, n, &case).await;

        let closed = EdgeRepository::retract(&pool, &built.root_edges)
            .await
            .expect("retract R's edges");
        assert_eq!(
            closed.len(),
            built.root_edges.len(),
            "PREMISE case {n}: every edge out of R is withdrawn"
        );
        let mut conn = pool.acquire().await.expect("acquire");
        let mut affected = Vec::new();
        let mut deleted = 0u64;
        for e in &built.root_edges {
            let removed = EdgeRepository::remove_withdrawn_edge_bbas_conn(&mut conn, *e)
                .await
                .expect("remove the withdrawn edge's BBAs");
            assert!(removed.withdrawn, "PREMISE case {n}: edge {e} is withdrawn");
            deleted += removed.deleted;
            affected.extend(removed.claims);
        }
        affected.sort_unstable();
        affected.dedup();

        let first = cascade_after_edge_withdrawal(&mut conn, &bypass, &affected, deleted).await;
        assert!(first.errors.is_empty(), "case {n}: first run: {first:?}");
        assert!(
            deleted > 0 && !first.targets.is_empty(),
            "CALIBRATION case {n}: the withdrawal must remove BBAs and the first run repair \
             something: {first:?}"
        );
        let once = snapshot(&pool, &built.claims).await;

        let second = cascade_after_edge_withdrawal(&mut conn, &bypass, &affected, deleted).await;
        assert!(second.errors.is_empty(), "case {n}: second run: {second:?}");
        if !second.recomputed.is_empty() {
            second_runs_that_wrote += 1;
        }
        let twice = snapshot(&pool, &built.claims).await;
        assert_eq!(
            once, twice,
            "case {n}: a second edge-withdrawal repair changed the state the first one left.\n\
             first: {first:?}\nsecond: {second:?}"
        );
    }
    assert_eq!(
        second_runs_that_wrote, CASES,
        "CALIBRATION: every case's SECOND run must itself rewrite a cache (the first target \
         keeps a supporter), or idempotence is satisfied by a second run that writes nothing"
    );
}

/// A dedup graph: the duplicate D is case `n`'s root (with its edges onto the
/// targets), with an incoming supporter whose BBA moves onto the canonical C
/// when D is marked; C has its own planted interval, which the move makes
/// stale, so the cascade's canonical pre-refresh is real.
async fn build_dedup(
    pool: &PgPool,
    public: &Viewer,
    agent: Uuid,
    n: usize,
    case: &Case,
) -> (Built, Uuid) {
    let mut built = build(pool, public, agent, n, case).await;
    let canonical = believed(pool, agent, &format!("idem {n} C"), case.replacement).await;
    let feeder = believed(
        pool,
        agent,
        &format!("idem {n} D's supporter"),
        Iv { bel: 0.7, pl: 0.9 },
    )
    .await;
    wire(pool, public, agent, feeder, built.root, "supports").await;
    built.claims.extend([canonical, feeder]);
    (built, canonical)
}

/// Dedup: D is marked a duplicate of C through
/// `ClaimRepository::mark_duplicate_with_repair_conn`, and the cascade on
/// that repair runs twice (a deferred replay of the dedup runs exactly this
/// cascade again on the recorded repair). The second run re-derives every
/// re-sourced edge's BBA itself, and changes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn running_the_dedup_cascade_twice_equals_running_it_once(pool: PgPool) {
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let public = fixture::public_viewer(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "idem-dedup").await;
    let mut runner = TestRunner::deterministic();
    let mut second_runs_that_rederived = 0usize;

    for n in 0..CASES {
        let case = next_case(&mut runner, n, false);
        let (built, canonical) = build_dedup(&pool, &public, agent, n, &case).await;

        let mut conn = pool.acquire().await.expect("acquire");
        let repair = ClaimRepository::mark_duplicate_with_repair_conn(
            &mut conn,
            ClaimId::from_uuid(built.root),
            ClaimId::from_uuid(canonical),
        )
        .await
        .expect("mark the duplicate");
        assert!(
            !repair.resourced_edges.is_empty() && repair.moved_bbas > 0,
            "PREMISE case {n}: the mark re-sources D's edges and moves its supporter's BBA: \
             {repair:?}"
        );

        let first = cascade_after_dedup(&mut conn, &bypass, canonical, &repair).await;
        assert!(first.errors.is_empty(), "case {n}: first run: {first:?}");
        assert!(
            first.invalidated_bbas > repair.deleted_bbas && !first.targets.is_empty(),
            "CALIBRATION case {n}: the first run must re-derive and repair something: {first:?}"
        );
        let once = snapshot(&pool, &built.claims).await;

        let second = cascade_after_dedup(&mut conn, &bypass, canonical, &repair).await;
        assert!(second.errors.is_empty(), "case {n}: second run: {second:?}");
        if second.invalidated_bbas > repair.deleted_bbas {
            second_runs_that_rederived += 1;
        }
        let twice = snapshot(&pool, &built.claims).await;
        assert_eq!(
            once, twice,
            "case {n}: a second dedup cascade changed the state the first one left.\nfirst: \
             {first:?}\nsecond: {second:?}"
        );
    }
    assert_eq!(
        second_runs_that_rederived, CASES,
        "CALIBRATION: every case's SECOND run must itself delete and re-derive the re-sourced \
         edges' BBAs, or idempotence is satisfied by a second run that does nothing"
    );
}

/// The act and its cascade together: a second `mark_duplicate_with_cascade`
/// of the same pair is refused by the act (D is already retired) and leaves
/// the state the first call left. Its cascade's own re-run is the dedup
/// property above.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_mark_duplicate_with_cascade_is_refused_and_changes_nothing(pool: PgPool) {
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let public = fixture::public_viewer(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "idem-mark").await;
    let mut runner = TestRunner::deterministic();

    for n in 0..CASES {
        let case = next_case(&mut runner, n, false);
        let (built, canonical) = build_dedup(&pool, &public, agent, n, &case).await;

        let mut conn = pool.acquire().await.expect("acquire");
        let first = mark_duplicate_with_cascade(&mut conn, &bypass, built.root, canonical)
            .await
            .expect("the first mark");
        assert!(first.errors.is_empty(), "case {n}: first call: {first:?}");
        assert!(
            first.invalidated_bbas > 0 && !first.targets.is_empty(),
            "CALIBRATION case {n}: the first call must re-derive and repair something: {first:?}"
        );
        let once = snapshot(&pool, &built.claims).await;

        let second = mark_duplicate_with_cascade(&mut conn, &bypass, built.root, canonical).await;
        assert!(
            matches!(second, Err(epigraph_db::DbError::Refused { .. })),
            "case {n}: a second mark of the same pair must be refused, not re-applied: \
             {second:?}"
        );
        let twice = snapshot(&pool, &built.claims).await;
        assert_eq!(
            once, twice,
            "case {n}: a refused second mark changed the state the first call left"
        );
    }
}

/// The retroactive K10(3) sweep: R is retired by a plain `is_current` flip
/// (a retirement the supersede cascade's stayed-edge arm never saw), and the
/// sweep runs over the selection the dry-run delta measures. A retry on the
/// same plan and a second sweep on a fresh measurement (what the operator
/// binary does) both change nothing.
///
/// Unlike the other entry points, a second sweep is a no-op BY CONSTRUCTION
/// when the first one is complete: its selection is empty. So the property
/// pins completeness: a first run that left part of its selection behind (a
/// sweep that converges over several runs) changes the state on the second.
#[sqlx::test(migrations = "../../migrations")]
async fn running_the_retired_source_sweep_twice_equals_running_it_once(pool: PgPool) {
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let public = fixture::public_viewer(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "idem-sweep").await;
    let mut runner = TestRunner::deterministic();

    for n in 0..CASES {
        let case = next_case(&mut runner, n, false);
        let built = build(&pool, &public, agent, n, &case).await;
        sqlx::query(
            "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL \
              WHERE id = $1",
        )
        .bind(built.root)
        .execute(&pool)
        .await
        .expect("retire R by a plain flip");

        let mut conn = pool.acquire().await.expect("acquire");
        let rows = retired_source_edge_bbas(&mut conn, Some(&[built.root]))
            .await
            .expect("measure the selection");
        assert!(
            rows.len() >= 2,
            "PREMISE case {n}: R's edges hold live BBAs on current claims: {rows:?}"
        );

        let first = sweep_retired_source_bbas(&mut conn, &bypass, &rows).await;
        assert!(
            first.report.errors.is_empty(),
            "case {n}: first run: {first:?}"
        );
        assert_eq!(
            first.deleted.len(),
            rows.len(),
            "CALIBRATION case {n}: the first run deletes its whole selection"
        );
        let once = snapshot(&pool, &built.claims).await;

        let retry = sweep_retired_source_bbas(&mut conn, &bypass, &rows).await;
        assert!(retry.report.errors.is_empty(), "case {n}: retry: {retry:?}");
        let again = retired_source_edge_bbas(&mut conn, Some(&[built.root]))
            .await
            .expect("re-measure the selection");
        let second = sweep_retired_source_bbas(&mut conn, &bypass, &again).await;
        assert!(
            second.report.errors.is_empty(),
            "case {n}: second run: {second:?}"
        );
        let twice = snapshot(&pool, &built.claims).await;
        assert_eq!(
            once, twice,
            "case {n}: a second sweep changed the state the first one left.\nfirst: \
             {first:?}\nretry: {retry:?}\nsecond: {second:?}"
        );
        assert!(
            retry.deleted.is_empty() && second.deleted.is_empty(),
            "case {n}: a second sweep deletes nothing: {retry:?} {second:?}"
        );
    }
}
