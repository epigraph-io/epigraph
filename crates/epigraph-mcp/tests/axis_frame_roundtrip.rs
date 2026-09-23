//! DB-backed round trip for declared labeled axes (issue #222).
//!
//! fc10c3d3 taught ingestion to place an atom on a declared multi-valued axis —
//! e.g. `anxiolytic_potency` over `{ineffective, mild, moderate, strong}` —
//! instead of the default `binary_truth` frame. Its own Verification section
//! recorded that the write path was covered by unit tests only (pgvector was
//! missing, so no `#[sqlx::test]` could run) and that it "wants a DB-backed
//! integration test asserting a 4-hypothesis frame round-trips through
//! `claim_frames.hypothesis_index` to `get_belief`". This is that test.
//!
//! Why it has to be DB-backed: every link in the chain is a DB hop, and
//! `auto_wire_ds_batch` turns an axis-frame or wiring failure into
//! warn-and-continue. So if any link broke — `ensure_axis_frame`'s
//! get/verify/create, `assign_claim` writing the index, the BBA row, the
//! cache writer's index lookup, or `get_belief`'s `unwrap_or(0)` read — an
//! axis ingest would still succeed. Its atoms would then silently report
//! belief about hypothesis 0 (`ineffective`), or nothing at all. Unit tests over
//! the in-memory builders cannot see any of that.
//!
//! The discriminating shape: every BBA here is simple support on ONE
//! hypothesis, with the remainder on Θ. After reliability discounting,
//! `m({h})` and `m(Θ)` are the only focal elements. So with `b = Bel(h)`, the
//! target hypothesis has `Pl = 1` and `BetP = b + (1 - b) / 4`. Reading any
//! OTHER index of the same mass gives `Bel = 0`, `Pl = 1 - b` and
//! `BetP = (1 - b) / 4`. Those two answers cannot be confused for any b > 0.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::FrameRepository;
use epigraph_ingest::common::plan::PlannedAxis;
use epigraph_mcp::tools::ds_auto::{auto_wire_ds_batch, ensure_axis_frame, BatchDsEntry};
use epigraph_mcp::types::{GetBeliefParams, RecomputeBeliefsParams};
use sqlx::PgPool;
use uuid::Uuid;

const POTENCY_FRAME: &str = "anxiolytic_potency";
const POTENCY: [&str; 4] = ["ineffective", "mild", "moderate", "strong"];
const MODERATE: usize = 2;

fn potency() -> Vec<String> {
    POTENCY.iter().map(|s| (*s).to_string()).collect()
}

fn potency_axis(hypothesis_index: usize) -> PlannedAxis {
    PlannedAxis {
        frame: POTENCY_FRAME.to_string(),
        hypotheses: potency(),
        hypothesis_index,
    }
}

// ── Raw reads ────────────────────────────────────────────────────────────────
// Raw SQL is fine in tests; the no-inline-SQL rule covers production tool code.
// These read the tables directly on purpose, so that a wrong row cannot be
// hidden by the very repo functions this test is checking.

/// Every `(frame_id, hypothesis_index)` the claim is assigned to, on any frame.
async fn assignments(pool: &PgPool, claim_id: Uuid) -> Vec<(Uuid, Option<i32>)> {
    sqlx::query_as::<_, (Uuid, Option<i32>)>(
        "SELECT frame_id, hypothesis_index FROM claim_frames WHERE claim_id = $1 ORDER BY frame_id",
    )
    .bind(claim_id)
    .fetch_all(pool)
    .await
    .expect("read claim_frames")
}

/// The stored `masses` of every BBA on the claim, with the frame each sits on.
async fn bbas(pool: &PgPool, claim_id: Uuid) -> Vec<(Uuid, serde_json::Value)> {
    sqlx::query_as::<_, (Uuid, serde_json::Value)>(
        "SELECT frame_id, masses FROM mass_functions WHERE claim_id = $1",
    )
    .bind(claim_id)
    .fetch_all(pool)
    .await
    .expect("read mass_functions")
}

/// The claim row's cached DS scalars and the frame they summarize.
#[derive(Debug)]
struct Cache {
    belief: Option<f64>,
    plausibility: Option<f64>,
    pignistic_prob: Option<f64>,
    belief_frame_id: Option<Uuid>,
}

async fn cache(pool: &PgPool, claim_id: Uuid) -> Cache {
    let (belief, plausibility, pignistic_prob, belief_frame_id) =
        sqlx::query_as::<_, (Option<f64>, Option<f64>, Option<f64>, Option<Uuid>)>(
            "SELECT belief, plausibility, pignistic_prob, belief_frame_id \
             FROM claims WHERE id = $1",
        )
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("read claim cache");
    Cache {
        belief,
        plausibility,
        pignistic_prob,
        belief_frame_id,
    }
}

async fn claim_id_by_content(pool: &PgPool, content: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("claim {content:?} not persisted: {e}"))
}

/// `get_belief` through the MCP tool, the surface the ingest description points
/// callers at. `frame_id = None` is the unframed cached read.
async fn get_belief_tool(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    frame_id: Option<Uuid>,
) -> serde_json::Value {
    let server = build_test_server(pool.clone());
    let result = epigraph_mcp::tools::ds::get_belief(
        &server,
        viewer,
        GetBeliefParams {
            claim_id: claim_id.to_string(),
            frame_id: frame_id.map(|f| f.to_string()),
            perspective_id: None,
        },
    )
    .await
    .expect("get_belief tool");
    first_text(&result)
}

fn f(json: &serde_json::Value, key: &str) -> f64 {
    json[key]
        .as_f64()
        .unwrap_or_else(|| panic!("missing numeric {key} in {json}"))
}

/// Assert `(bel, pl, betp)` is the reading AT the hypothesis a simple-support
/// BBA asserts, on a 4-hypothesis frame: some belief, full plausibility, and
/// BetP = Bel + (1 - Bel)/4.
fn assert_reading_at_asserted_hypothesis(bel: f64, pl: f64, betp: f64, what: &str) {
    assert!(
        bel > 0.0,
        "{what}: Bel must be > 0 at the asserted hypothesis, got {bel} \
         (0 is what reading index 0 of this mass returns)"
    );
    assert!(
        (pl - 1.0).abs() < 1e-9,
        "{what}: Pl must be 1 at the asserted hypothesis, got {pl}"
    );
    let want = bel + (1.0 - bel) / 4.0;
    assert!(
        (betp - want).abs() < 1e-9,
        "{what}: BetP must be Bel + (1-Bel)/4 = {want} on a 4-hypothesis frame, got {betp}"
    );
}

// ── 1. The round trip ────────────────────────────────────────────────────────

/// A claim wired onto `moderate` (index 2) of a declared 4-hypothesis axis has
/// the following, each checked against the DB:
///
/// - the frame persisted with its hypotheses in declared order;
/// - one `claim_frames` row at index 2, and nothing on `binary_truth`;
/// - one BBA whose focal elements are `{2}` and Θ;
/// - a framed `get_belief` that reads index 2;
/// - a cache that names the axis frame and agrees with the framed read.
///
/// The index-flip at the end is the discriminator. It re-points the SAME claim
/// to index 0, without touching its BBA, and checks that `get_belief` then
/// reports Bel(ineffective) = 0. That proves the reader takes the hypothesis
/// from `claim_frames.hypothesis_index`, rather than from the mass or from a
/// default.
#[sqlx::test(migrations = "../../migrations")]
async fn declared_axis_round_trips_through_claim_frames_to_get_belief(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let claim = seed_claim(&pool, "Compound X is moderately anxiolytic", 0.5).await;

    let (binary_frame_id, wired) = auto_wire_ds_batch(
        &pool,
        &viewer,
        &[BatchDsEntry {
            claim_id: claim,
            confidence: 0.9,
            weight: 1.0,
            evidence_type: Some("empirical".to_string()),
            axis: Some(potency_axis(MODERATE)),
        }],
        agent,
    )
    .await
    .expect("auto_wire_ds_batch");
    assert_eq!(
        wired, 1,
        "the one axis entry must be wired, not warn-skipped"
    );

    // The frame exists under the declared name, in the declared ORDER. Order is
    // identity here, because the label→index resolution is positional.
    let frame = FrameRepository::get_by_name(&pool, &viewer, POTENCY_FRAME)
        .await
        .expect("get_by_name")
        .expect("axis frame persisted");
    assert_eq!(frame.hypotheses, potency(), "stored hypotheses, in order");
    assert_ne!(
        frame.id, binary_frame_id,
        "an axis claim must be wired on its own frame, not binary_truth"
    );

    // Exactly one assignment: the axis frame, at the declared index.
    assert_eq!(
        assignments(&pool, claim).await,
        vec![(frame.id, Some(MODERATE as i32))],
        "claim_frames must hold the declared index 2, and no binary_truth row"
    );

    // Exactly one BBA, on the axis frame, with mass on {moderate} and Θ only.
    let stored = bbas(&pool, claim).await;
    assert_eq!(stored.len(), 1, "one BBA row, got {stored:?}");
    let (bba_frame, masses) = &stored[0];
    assert_eq!(*bba_frame, frame.id, "BBA must sit on the axis frame");
    let mut keys: Vec<&str> = masses
        .as_object()
        .expect("masses is a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["0,1,2,3", "2"],
        "focal elements must be {{moderate}} and Θ, got {masses}"
    );

    // Framed get_belief (MCP tool) reads index 2.
    let framed = get_belief_tool(&pool, &viewer, claim, Some(frame.id)).await;
    assert_eq!(framed["source"], "recomputed", "{framed}");
    let (bel, pl, betp) = (
        f(&framed, "belief"),
        f(&framed, "plausibility"),
        f(&framed, "pignistic_prob"),
    );
    assert_reading_at_asserted_hypothesis(bel, pl, betp, "framed get_belief");
    assert!(
        bel <= 0.9 + 1e-12,
        "discounting only moves mass to Θ, so Bel {bel} cannot exceed the raw 0.9"
    );

    // The initial cache written by the batch path names the axis frame, and
    // holds the same Bel(moderate) the framed read computes.
    let c = cache(&pool, claim).await;
    assert_eq!(
        c.belief_frame_id,
        Some(frame.id),
        "the cache must say it summarizes the axis frame: {c:?}"
    );
    for (name, cached, live) in [
        ("belief", c.belief, bel),
        ("plausibility", c.plausibility, pl),
        ("pignistic_prob", c.pignistic_prob, betp),
    ] {
        let cached = cached.unwrap_or_else(|| panic!("cached {name} unset: {c:?}"));
        assert!(
            (cached - live).abs() < 1e-9,
            "cached {name} {cached} disagrees with the framed read {live}"
        );
    }

    // Discriminator: the same BBA, with the assignment re-pointed at index 0.
    // Mass on {moderate} says nothing about `ineffective`, so Bel must drop to
    // 0 and Pl to 1 - Bel(moderate).
    FrameRepository::assign_claim(&pool, claim, frame.id, Some(0))
        .await
        .expect("re-point assignment to index 0");
    let at_zero = get_belief_tool(&pool, &viewer, claim, Some(frame.id)).await;
    assert!(
        f(&at_zero, "belief").abs() < 1e-12,
        "Bel(ineffective) must be 0 for mass on {{moderate}}: {at_zero}"
    );
    assert!(
        (f(&at_zero, "plausibility") - (1.0 - bel)).abs() < 1e-9,
        "Pl(ineffective) must be 1 - Bel(moderate) = {}: {at_zero}",
        1.0 - bel
    );
    assert!(
        (f(&at_zero, "pignistic_prob") - (1.0 - bel) / 4.0).abs() < 1e-9,
        "BetP(ineffective) must be (1 - Bel(moderate))/4: {at_zero}"
    );
}

// ── 2. The cache after recompute_beliefs ─────────────────────────────────────

/// `recompute_beliefs` lets exactly one frame own the shared `claims.*` cache
/// (backlog 696d3a1c, migration 100's `belief_frame_id`), and it prefers
/// `binary_truth`. An axis-only claim has no `binary_truth` BBA, so the owner
/// must be its axis. The written scalars must then be about the claim's
/// DECLARED hypothesis, not about index 0 of the axis, and must not be a
/// binary_truth default.
///
/// The unframed `get_belief` serves that cache. So a regression in the owner
/// rule, or in the cache writer's `hypothesis_index` lookup, shows up here as
/// an unframed Bel that disagrees with the framed Bel(moderate).
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_beliefs_keeps_an_axis_only_claims_cache_on_its_declared_hypothesis(
    pool: PgPool,
) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let claim = seed_claim(&pool, "Compound Y is moderately anxiolytic", 0.5).await;

    let (binary_frame_id, wired) = auto_wire_ds_batch(
        &pool,
        &viewer,
        &[BatchDsEntry {
            claim_id: claim,
            confidence: 0.8,
            weight: 1.0,
            evidence_type: Some("statistical".to_string()),
            axis: Some(potency_axis(MODERATE)),
        }],
        agent,
    )
    .await
    .expect("auto_wire_ds_batch");
    assert_eq!(wired, 1);
    let frame = FrameRepository::get_by_name(&pool, &viewer, POTENCY_FRAME)
        .await
        .expect("get_by_name")
        .expect("axis frame persisted");

    let server = build_test_server(pool.clone());
    let res = epigraph_mcp::tools::cdst_maintenance::recompute_beliefs(
        &server,
        &viewer,
        RecomputeBeliefsParams {
            claim_ids: Some(vec![claim.to_string()]),
            labels: None,
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");
    let report = first_text(&res);
    assert_eq!(report["claims_recomputed"], 1, "{report}");
    assert_eq!(
        report["frame_writes"], 1,
        "recompute must actually rewrite the cache: {report}"
    );
    assert_eq!(report["errors"], serde_json::json!([]), "{report}");

    let c = cache(&pool, claim).await;
    assert_eq!(
        c.belief_frame_id,
        Some(frame.id),
        "an axis-only claim's cache must be owned by its axis frame, not binary_truth \
         ({binary_frame_id}): {c:?}"
    );

    let framed = get_belief_tool(&pool, &viewer, claim, Some(frame.id)).await;
    let unframed = get_belief_tool(&pool, &viewer, claim, None).await;
    assert_eq!(unframed["source"], "cached", "{unframed}");
    assert_reading_at_asserted_hypothesis(
        f(&unframed, "belief"),
        f(&unframed, "plausibility"),
        f(&unframed, "pignistic_prob"),
        "unframed (cached) get_belief after recompute_beliefs",
    );
    for key in ["belief", "plausibility", "pignistic_prob"] {
        assert!(
            (f(&unframed, key) - f(&framed, key)).abs() < 1e-9,
            "cached {key} must equal the framed Bel(moderate) reading: \
             unframed={unframed} framed={framed}"
        );
    }
}

// ── 3. A frame-name collision ────────────────────────────────────────────────

/// A frame name denotes one ORDERED hypothesis list. If a same-named frame
/// already exists over a different order, the batch must not reuse it, since
/// index 2 there is `mild`, not `moderate`. It must also not fall back to
/// `binary_truth`, because that records a belief about TRUE for a claim placed
/// on a label. At the wire layer this is refuse-and-skip: the colliding entry
/// gets no assignment, no BBA and no cache, the stored frame is left as it was,
/// and the rest of the batch still wires.
///
/// An ingest now refuses such a clash before writing anything (test 5). What
/// is pinned here is the backstop for a clash that appears between that check
/// and the wire, i.e. a concurrent ingest that creates the frame in between.
#[sqlx::test(migrations = "../../migrations")]
async fn axis_frame_name_collision_is_refused_not_rebound(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let on_axis = seed_claim(&pool, "Compound Z is moderately anxiolytic", 0.5).await;
    let on_binary = seed_claim(&pool, "Compound Z crosses the blood-brain barrier", 0.5).await;

    let reordered: Vec<String> = POTENCY.iter().rev().map(|s| (*s).to_string()).collect();
    let existing = FrameRepository::create(&pool, POTENCY_FRAME, None, &reordered)
        .await
        .expect("pre-existing same-named frame");

    let err = ensure_axis_frame(&pool, &viewer, POTENCY_FRAME, &potency(), None)
        .await
        .expect_err("a same-named frame over a different order must be refused");
    assert!(err.contains("already exists"), "unexpected error: {err}");

    let (binary_frame_id, wired) = auto_wire_ds_batch(
        &pool,
        &viewer,
        &[
            BatchDsEntry {
                claim_id: on_axis,
                confidence: 0.9,
                weight: 1.0,
                evidence_type: None,
                axis: Some(potency_axis(MODERATE)),
            },
            BatchDsEntry {
                claim_id: on_binary,
                confidence: 0.9,
                weight: 1.0,
                evidence_type: None,
                axis: None,
            },
        ],
        agent,
    )
    .await
    .expect("auto_wire_ds_batch");
    assert_eq!(wired, 1, "only the binary entry may be wired");

    assert!(
        assignments(&pool, on_axis).await.is_empty(),
        "the colliding claim must not be assigned to the foreign frame or to binary_truth"
    );
    assert!(
        bbas(&pool, on_axis).await.is_empty(),
        "the colliding claim must carry no BBA"
    );
    let c = cache(&pool, on_axis).await;
    assert_eq!(c.belief_frame_id, None, "no cache may be written: {c:?}");

    let still = FrameRepository::get_by_id(&pool, &viewer, existing.id)
        .await
        .expect("get_by_id")
        .expect("pre-existing frame");
    assert_eq!(
        still.hypotheses, reordered,
        "the stored frame must not be rewritten"
    );

    assert_eq!(
        assignments(&pool, on_binary).await,
        vec![(binary_frame_id, Some(0))],
        "the non-colliding entry in the same batch must still wire on binary_truth"
    );
}

// ── 4. End to end through ingestion ──────────────────────────────────────────

const AXIS_FIXTURE: &str = r#"{
  "source": {
    "title": "Axis Round Trip Paper",
    "doi": "10.1234/axis-roundtrip",
    "source_type": "Paper",
    "authors": [
      {"name": "Ada Axis", "affiliations": [], "roles": ["author"]}
    ]
  },
  "thesis": "Anxiolytic potency varies across compounds",
  "thesis_derivation": "TopDown",
  "sections": [{
    "title": "Results",
    "paragraphs": [
      {
        "text": "Compound A was mild, compound B moderate, and compound C strong.",
        "atoms": [
          "Compound A shows mild anxiolytic potency",
          "Compound B shows moderate anxiolytic potency",
          "Compound C shows strong anxiolytic potency"
        ],
        "generality": [3, 3, 3],
        "confidence": 0.8,
        "axis": {
          "frame": "anxiolytic_potency",
          "hypotheses": ["ineffective", "mild", "moderate", "strong"],
          "label": "moderate"
        },
        "axis_labels": ["mild", "", "strong"]
      },
      {
        "text": "All three compounds were well tolerated.",
        "atoms": ["All three compounds were well tolerated"],
        "generality": [3],
        "confidence": 0.8
      }
    ]
  }]
}"#;

/// The whole path, driven through `do_ingest_document`: a paragraph `axis`
/// plus positional `axis_labels` goes through `validate_axes`, then
/// `build_ingest_plan`, then `auto_wire_ds_batch`, and lands on `claim_frames`
/// and `get_belief`. The atoms override to `mild` (1), inherit `moderate` (2)
/// through the empty string, and override to `strong` (3). An atom in an
/// axis-free paragraph stays on binary_truth.
#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_places_each_atom_on_its_declared_label(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());
    let extraction: epigraph_ingest::schema::DocumentExtraction =
        serde_json::from_str(AXIS_FIXTURE).expect("fixture parses");

    let result = epigraph_mcp::tools::ingestion::do_ingest_document(&server, &viewer, &extraction)
        .await
        .expect("ingest_document succeeds");
    let response = first_text(&result);
    assert_eq!(
        response["claims_ds_wired"], 4,
        "3 axis atoms + 1 binary atom must all be wired: {response}"
    );
    let binary_frame_id = parse_uuid_field(&response, "ds_frame_id");

    let frame = FrameRepository::get_by_name(&pool, &viewer, POTENCY_FRAME)
        .await
        .expect("get_by_name")
        .expect("ingest created the declared axis frame");
    assert_eq!(frame.hypotheses, potency());

    for (content, index) in [
        ("Compound A shows mild anxiolytic potency", 1_i32),
        ("Compound B shows moderate anxiolytic potency", 2),
        ("Compound C shows strong anxiolytic potency", 3),
    ] {
        let claim = claim_id_by_content(&pool, content).await;
        assert_eq!(
            assignments(&pool, claim).await,
            vec![(frame.id, Some(index))],
            "{content:?} must sit on the axis at index {index}, and only there"
        );
        let framed = get_belief_tool(&pool, &viewer, claim, Some(frame.id)).await;
        assert_reading_at_asserted_hypothesis(
            f(&framed, "belief"),
            f(&framed, "plausibility"),
            f(&framed, "pignistic_prob"),
            content,
        );
    }

    let tolerated = claim_id_by_content(&pool, "All three compounds were well tolerated").await;
    assert_eq!(
        assignments(&pool, tolerated).await,
        vec![(binary_frame_id, Some(0))],
        "an atom with no axis in effect stays on binary_truth at TRUE"
    );
}

// ── 5. A stored-frame clash fails the ingest call ────────────────────────────

/// The `ingest_document_inline` contract says an inconsistent axis "fails the
/// call rather than silently falling back to binary". `validate_axes` can only
/// see inconsistency inside one document. So when an axis clashed with a frame
/// an EARLIER ingest had stored under the same name, the call used to succeed.
/// The paper, the thesis and every atom were persisted, and the clashing atoms
/// were skipped by the wire with only a log line, so they carried no mass
/// function at all. The call must now fail with INVALID_PARAMS before anything
/// is written.
#[sqlx::test(migrations = "../../migrations")]
async fn ingest_with_an_axis_that_clashes_with_a_stored_frame_fails_before_any_write(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());
    let extraction: epigraph_ingest::schema::DocumentExtraction =
        serde_json::from_str(AXIS_FIXTURE).expect("fixture parses");

    let reordered: Vec<String> = POTENCY.iter().rev().map(|s| (*s).to_string()).collect();
    let existing = FrameRepository::create(&pool, POTENCY_FRAME, None, &reordered)
        .await
        .expect("frame stored by an earlier ingest");

    let err = epigraph_mcp::tools::ingestion::do_ingest_document(&server, &viewer, &extraction)
        .await
        .expect_err("an axis clashing with a stored frame must fail the call");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
    assert!(
        err.message.contains("axis declaration invalid") && err.message.contains("already exists"),
        "the error must name the clash: {}",
        err.message
    );

    let papers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM papers WHERE doi = $1")
        .bind("10.1234/axis-roundtrip")
        .fetch_one(&pool)
        .await
        .expect("count papers");
    assert_eq!(papers, 0, "no paper may be written by a refused ingest");
    let claims: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = ANY($1)")
        .bind(vec![
            "Anxiolytic potency varies across compounds",
            "Compound A shows mild anxiolytic potency",
            "Compound B shows moderate anxiolytic potency",
            "Compound C shows strong anxiolytic potency",
            "All three compounds were well tolerated",
        ])
        .fetch_one(&pool)
        .await
        .expect("count claims");
    assert_eq!(claims, 0, "no claim may be written by a refused ingest");

    let still = FrameRepository::get_by_id(&pool, &viewer, existing.id)
        .await
        .expect("get_by_id")
        .expect("stored frame");
    assert_eq!(
        still.hypotheses, reordered,
        "the stored frame must not be rewritten"
    );
}
