//! Property test: the supersede belief cascade
//! (`retraction_cascade::cascade_after_supersede`) is IDEMPOTENT. Running it a
//! second time on the state the first run left changes no cached belief and no
//! stored mass.
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
use epigraph_db::{ClaimRepository, PgPool, SupersedeActor, SupersedeTool};
use epigraph_engine::edge_factor::{auto_wire_ds_for_edge, EdgeFactorOutcome};
use epigraph_engine::retraction_cascade::cascade_after_supersede;
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

async fn wire(pool: &PgPool, viewer: &Viewer, agent: Uuid, s: Uuid, t: Uuid, rel: &str) {
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
}

/// A claim's cached belief columns: id, belief, plausibility, pignistic,
/// mass on empty, mass on missing, classification.
type CacheRow = (
    Uuid,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<String>,
);

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

/// Every cached belief column and every mass row of `claims`, by content.
#[derive(Debug, PartialEq)]
struct Snapshot {
    caches: Vec<CacheRow>,
    masses: Vec<MassRow>,
}

async fn snapshot(pool: &PgPool, claims: &[Uuid]) -> Snapshot {
    let caches = sqlx::query_as(
        "SELECT id, belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing, \
                classification::text \
           FROM claims WHERE id = ANY($1) ORDER BY id",
    )
    .bind(claims)
    .fetch_all(pool)
    .await
    .expect("read the caches");
    let masses = sqlx::query_as(
        "SELECT claim_id, frame_id, source_agent_id, perspective_id, masses::text, \
                source_strength, evidence_type::text, retracted_at IS NOT NULL \
           FROM mass_functions WHERE claim_id = ANY($1) \
          ORDER BY claim_id, frame_id, source_agent_id, perspective_id, masses::text",
    )
    .bind(claims)
    .fetch_all(pool)
    .await
    .expect("read the masses");
    Snapshot { caches, masses }
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
        let retiring = believed(&pool, agent, &format!("idem {n} R"), case.retiring).await;
        let mut claims = vec![retiring];
        let mut targets = Vec::new();
        for (i, spec) in case.targets.iter().enumerate() {
            let t = fixture::seed_public_claim(&pool, agent, &format!("idem {n} T{i}")).await;
            claims.push(t);
            if let Some(s_iv) = spec.supporter {
                let s = believed(&pool, agent, &format!("idem {n} S{i}"), s_iv).await;
                claims.push(s);
                wire(&pool, &public, agent, s, t, "supports").await;
            }
            if spec.chained {
                let prev = *targets.last().expect("a chained target has a predecessor");
                wire(&pool, &public, agent, prev, t, "supports").await;
            }
            wire(&pool, &public, agent, retiring, t, spec.from_r).await;
            targets.push(t);
        }

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
