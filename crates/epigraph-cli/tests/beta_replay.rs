//! The Beta-track replay backfill (`replay_beta_track`, follow-up to backlog
//! f50344c0).
//!
//! What is pinned:
//! * the replay of a claim's stored BBAs equals the track the live MCP writers
//!   (`update_with_evidence`, `submit_ds_evidence`) built for the same
//!   sequence, including the `truth_value_seed` those writers store and do not
//!   count; and the comparison is not vacuous (counting the seed changes it);
//! * a dry run writes nothing; an apply writes only `beta_alpha` / `beta_beta`
//!   of claims still on the prior, records them in the manifest, and writes no
//!   `ds_bayesian_divergence` row;
//! * retracted rows, cached combinations and frames with no hypothesis index
//!   count nothing; a claim off the prior is never touched;
//! * the reversal puts the found parameters back on every claim that still
//!   holds what was written, and leaves a claim a live write moved since.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::collections::BTreeSet;

use epigraph_cli::beta_replay::{reverse, run, ManifestRecord, Options};
use epigraph_crypto::AgentSigner;
use epigraph_db::visibility::Viewer;
use epigraph_db::{FrameRepository, MassFunctionRepository};
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::types::{SubmitDsEvidenceParams, UpdateWithEvidenceParams};
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

/// A server on the test pool (a superuser, filtered by nothing) whose agent
/// writes `group`, a group it is an admin of, and its viewer.
async fn server_and_group(pool: &PgPool) -> (EpiGraphMcpFull, Viewer, Uuid) {
    let scoped = epigraph_db::ScopedPool::connect_lazy_for_tests(
        (*pool.connect_options()).clone(),
        epigraph_db::SessionGucMode::Session,
    );
    let signer = AgentSigner::from_bytes(&[0xB9u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    let server =
        EpiGraphMcpFull::new(pool.clone(), signer, embedder, false).with_scoped_pool(scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ('personal:' || $1::text, 'did:epigraph:personal:' || $1::text, ''::bytea, \
                 'personal', $1) \
         ON CONFLICT (did_key) DO UPDATE SET updated_at = now() RETURNING id",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("the server agent's personal group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin') \
         ON CONFLICT (group_id, agent_id, epoch) DO UPDATE SET revoked_at = NULL, role = 'admin'",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("its membership");
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    (server, viewer, group)
}

async fn binary_truth(pool: &PgPool) -> Uuid {
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM frames WHERE name = 'binary_truth'")
            .fetch_optional(pool)
            .await
            .expect("read binary_truth");
    if let Some(id) = existing {
        return id;
    }
    FrameRepository::create(
        pool,
        "binary_truth",
        Some("canonical binary frame"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("binary_truth")
    .id
}

async fn ternary_frame(pool: &PgPool) -> Uuid {
    FrameRepository::create(
        pool,
        &format!("b96-ternary-{}", Uuid::new_v4()),
        None,
        &["A".to_string(), "B".to_string(), "C".to_string()],
    )
    .await
    .expect("ternary frame")
    .id
}

async fn beta(pool: &PgPool, claim: Uuid) -> (Option<f64>, Option<f64>) {
    sqlx::query_as("SELECT beta_alpha, beta_beta FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("beta columns")
}

async fn reset_to_prior(pool: &PgPool, claim: Uuid) {
    sqlx::query("UPDATE claims SET beta_alpha = 1.0, beta_beta = 1.0 WHERE id = $1")
        .bind(claim)
        .execute(pool)
        .await
        .expect("reset the claim to the prior");
}

async fn divergence_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM ds_bayesian_divergence")
        .fetch_one(pool)
        .await
        .expect("count divergence rows")
}

/// Every claim, whole, and every divergence row: what a dry run must not move.
async fn snapshot(pool: &PgPool) -> (Vec<serde_json::Value>, i64) {
    let claims = sqlx::query_scalar("SELECT to_jsonb(c) FROM claims c ORDER BY c.id")
        .fetch_all(pool)
        .await
        .expect("claims snapshot");
    (claims, divergence_rows(pool).await)
}

fn sde(claim: Uuid, frame: Uuid, index: i32, masses: serde_json::Value) -> SubmitDsEvidenceParams {
    SubmitDsEvidenceParams {
        claim_id: claim.to_string(),
        frame_id: frame.to_string(),
        hypothesis_index: index,
        masses,
        reliability: None,
        combination_method: None,
        gamma: None,
        perspective_id: None,
        evidence_type: None,
        locality_tag: None,
    }
}

fn uwe(claim: Uuid, data: &str, supports: bool, strength: f64) -> UpdateWithEvidenceParams {
    UpdateWithEvidenceParams {
        canonical_name: None,
        step_index: None,
        claim_id: claim.to_string(),
        evidence_type: "empirical".into(),
        evidence_data: data.into(),
        source_url: None,
        supports,
        strength,
        labels: vec![],
    }
}

fn opts(apply: bool) -> Options {
    let mut o = Options::dry_run();
    o.apply = apply;
    o.batch = 2;
    o
}

fn manifest_records(bytes: &[u8]) -> Vec<ManifestRecord> {
    std::str::from_utf8(bytes)
        .expect("utf-8 manifest")
        .lines()
        .map(|l| serde_json::from_str(l).expect("manifest line"))
        .collect()
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-12
}

/// A claim the live MCP writers built a Beta track for: two
/// `update_with_evidence` calls (the first also stores a `truth_value_seed`)
/// and two `submit_ds_evidence` calls, one on a three-hypothesis frame on its
/// third hypothesis. Reset to the prior and replayed, it gets the same track
/// back. The seed is the row that makes the default exclusion necessary:
/// counted, the replay differs.
#[sqlx::test(migrations = "../../migrations")]
async fn replay_equals_the_live_track_of_the_mcp_writers(pool: PgPool) {
    let (server, viewer, group) = server_and_group(&pool).await;
    let (author, _) = viewer_fixture::seed_agent_with_group(&pool, "b96-author").await;
    let claim = viewer_fixture::seed_group_claim(&pool, author, group, "b96 live claim").await;
    let binary = binary_truth(&pool).await;
    let ternary = ternary_frame(&pool).await;

    epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        uwe(claim, "b96 first evidence", true, 0.8),
        None,
    )
    .await
    .expect("update_with_evidence 1");
    epigraph_mcp::tools::ds::submit_ds_evidence(
        &server,
        &viewer,
        sde(
            claim,
            binary,
            0,
            serde_json::json!({"0": 0.618_033_988_749_894_9, "1": 0.181_966_011_250_105_1, "~": 0.2}),
        ),
        None,
    )
    .await
    .expect("submit_ds_evidence on binary_truth");
    epigraph_mcp::tools::ds::submit_ds_evidence(
        &server,
        &viewer,
        sde(
            claim,
            ternary,
            2,
            serde_json::json!({"2": 0.37, "0,1": 0.43, "~": 0.2}),
        ),
        None,
    )
    .await
    .expect("submit_ds_evidence on the ternary frame");
    epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        uwe(claim, "b96 second evidence", false, 0.7),
        None,
    )
    .await
    .expect("update_with_evidence 2");

    let (live_a, live_b) = beta(&pool, claim).await;
    let (live_a, live_b) = (live_a.expect("alpha"), live_b.expect("beta"));
    assert!(
        live_a > 1.5 && live_b > 1.5,
        "the live writers moved the track: ({live_a}, {live_b})"
    );
    let seeds: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions WHERE claim_id = $1 \
            AND combination_method = 'truth_value_seed'",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("count seeds");
    assert_eq!(
        seeds, 1,
        "fixture: the first update_with_evidence seeds the claim"
    );

    reset_to_prior(&pool, claim).await;

    // Not vacuous: counting the seed gives a different track.
    let mut conn = pool.acquire().await.expect("conn");
    let mut with_seed = opts(false);
    with_seed.excluded_methods = BTreeSet::new();
    let counted_seed = run(&mut conn, &with_seed, None).await.expect("dry run");
    assert_eq!(counted_seed.sample.len(), 1, "{counted_seed:?}");
    let (sa, sb) = counted_seed.sample[0].replayed;
    assert!(
        !(close(sa, live_a) && close(sb, live_b)),
        "counting the truth_value_seed must change the replay, or this test proves nothing"
    );

    let mut manifest = Vec::new();
    let report = run(&mut conn, &opts(true), Some(&mut manifest))
        .await
        .expect("apply");
    assert_eq!((report.replayed, report.written), (1, 1), "{report:?}");
    assert_eq!(report.bbas_counted, 4, "{report:?}");
    assert_eq!(
        report.excluded_by_method.get("truth_value_seed"),
        Some(&1),
        "{report:?}"
    );

    let (a, b) = beta(&pool, claim).await;
    let (a, b) = (a.expect("alpha"), b.expect("beta"));
    assert!(
        close(a, live_a) && close(b, live_b),
        "replay ({a}, {b}) must equal the live track ({live_a}, {live_b})"
    );
    let records = manifest_records(&manifest);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].claim_id, claim);
    assert_eq!(
        (records[0].before_alpha, records[0].before_beta),
        (Some(1.0), Some(1.0))
    );
    assert_eq!(
        (records[0].written_alpha, records[0].written_beta),
        (Some(a), Some(b))
    );
}

/// One BBA row written as a legacy writer left it.
async fn store_bba(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Option<Uuid>,
    masses: serde_json::Value,
    method: &str,
) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        agent,
        None,
        &masses,
        None,
        Some(method),
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store bba")
}

async fn assign(pool: &PgPool, claim: Uuid, frame: Uuid, index: Option<i32>) {
    FrameRepository::assign_claim(pool, claim, frame, index)
        .await
        .expect("assign claim");
}

/// The corpus the dry-run / apply / reverse tests share, written directly as
/// legacy rows (oldest first per claim):
/// * `counted`: two inputs on binary_truth (index 0), a retracted input, a
///   cached combination row, and an input on a frame with no index;
/// * `seed_only`: only a `truth_value_seed` (left on the prior, unchanged);
/// * `moved`: one input, but its track already moved (never touched).
struct Corpus {
    counted: Uuid,
    seed_only: Uuid,
    moved: Uuid,
}

async fn corpus(pool: &PgPool) -> Corpus {
    let (agent, group) = viewer_fixture::seed_agent_with_group(pool, "b96-corpus").await;
    let (other, _) = viewer_fixture::seed_agent_with_group(pool, "b96-other").await;
    let (third, _) = viewer_fixture::seed_agent_with_group(pool, "b96-third").await;
    let binary = binary_truth(pool).await;
    let unindexed = ternary_frame(pool).await;

    let counted = viewer_fixture::seed_group_claim(pool, agent, group, "b96 counted").await;
    assign(pool, counted, binary, Some(0)).await;
    assign(pool, counted, unindexed, None).await;
    store_bba(
        pool,
        counted,
        binary,
        Some(agent),
        serde_json::json!({"0": 0.6, "~": 0.4}),
        "auto_wire",
    )
    .await;
    store_bba(
        pool,
        counted,
        binary,
        Some(other),
        serde_json::json!({"1": 0.5, "~": 0.5}),
        "Dempster",
    )
    .await;
    let retracted = store_bba(
        pool,
        counted,
        binary,
        Some(third),
        serde_json::json!({"0": 0.9, "~": 0.1}),
        "discount",
    )
    .await;
    sqlx::query(
        "UPDATE mass_functions SET retracted_at = now(), retracted_by = $2, \
                retract_reason = 'b96 fixture' WHERE id = $1",
    )
    .bind(retracted)
    .bind(third)
    .execute(pool)
    .await
    .expect("retract the third row");
    store_bba(
        pool,
        counted,
        binary,
        None,
        serde_json::json!({"0": 0.95, "~": 0.05}),
        epigraph_db::repos::mass_function::COMBINATION_METHOD_LABELS[1],
    )
    .await;
    store_bba(
        pool,
        counted,
        unindexed,
        Some(agent),
        serde_json::json!({"0": 0.8, "~": 0.2}),
        "auto_wire",
    )
    .await;

    let seed_only = viewer_fixture::seed_group_claim(pool, agent, group, "b96 seed only").await;
    assign(pool, seed_only, binary, Some(0)).await;
    store_bba(
        pool,
        seed_only,
        binary,
        Some(agent),
        serde_json::json!({"0": 0.8, "~": 0.2}),
        "truth_value_seed",
    )
    .await;

    let moved = viewer_fixture::seed_group_claim(pool, agent, group, "b96 moved").await;
    assign(pool, moved, binary, Some(0)).await;
    store_bba(
        pool,
        moved,
        binary,
        Some(agent),
        serde_json::json!({"0": 0.7, "~": 0.3}),
        "auto_wire",
    )
    .await;
    sqlx::query("UPDATE claims SET beta_alpha = 1.7, beta_beta = 1.3 WHERE id = $1")
        .bind(moved)
        .execute(pool)
        .await
        .expect("move the claim's track");

    Corpus {
        counted,
        seed_only,
        moved,
    }
}

/// The two live inputs count, by hand: alpha 1 + 0.6 + 0 = 1.6, beta
/// 1 + 0.4 + 1.0 = 2.4. The retracted row, the cached combination and the row
/// on the unindexed frame count nothing.
const COUNTED: (f64, f64) = (1.6, 2.4);

#[sqlx::test(migrations = "../../migrations")]
async fn a_dry_run_writes_nothing_and_reports_what_an_apply_would(pool: PgPool) {
    let c = corpus(&pool).await;
    let before = snapshot(&pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    let report = run(&mut conn, &opts(false), None).await.expect("dry run");
    drop(conn);
    assert_eq!(
        snapshot(&pool).await,
        before,
        "a dry run must write nothing"
    );

    assert!(!report.applied && report.complete, "{report:?}");
    assert_eq!(report.written, 0);
    assert_eq!(
        report.scanned, 2,
        "the moved claim is not a candidate: {report:?}"
    );
    assert_eq!((report.replayed, report.unchanged), (1, 1), "{report:?}");
    assert_eq!(report.bbas_counted, 3, "{report:?}");
    assert_eq!(report.bbas_without_hypothesis_index, 1, "{report:?}");
    assert_eq!(report.excluded_by_method.get("truth_value_seed"), Some(&1));
    assert_eq!(report.divergence_rows_written, 0);
    let s = &report.sample[0];
    assert_eq!(s.claim_id, c.counted);
    assert!(
        close(s.replayed.0, COUNTED.0) && close(s.replayed.1, COUNTED.1),
        "{s:?}"
    );
    assert!(close(s.replayed_posterior, 1.6 / 4.0), "{s:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_apply_writes_only_claims_on_the_prior_and_no_divergence_rows(pool: PgPool) {
    let c = corpus(&pool).await;
    let divergence_before = divergence_rows(&pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    let mut manifest = Vec::new();
    let report = run(&mut conn, &opts(true), Some(&mut manifest))
        .await
        .expect("apply");
    assert_eq!(report.written, 1, "{report:?}");

    let (a, b) = beta(&pool, c.counted).await;
    assert!(
        close(a.unwrap(), COUNTED.0) && close(b.unwrap(), COUNTED.1),
        "({a:?}, {b:?})"
    );
    assert_eq!(beta(&pool, c.seed_only).await, (Some(1.0), Some(1.0)));
    assert_eq!(beta(&pool, c.moved).await, (Some(1.7), Some(1.3)));
    assert_eq!(
        divergence_rows(&pool).await,
        divergence_before,
        "the replay records no divergence history"
    );
    assert_eq!(manifest_records(&manifest).len(), 1);

    // A re-run finds nothing left on the prior to move.
    let mut again = Vec::new();
    let second = run(&mut conn, &opts(true), Some(&mut again))
        .await
        .expect("second apply");
    assert_eq!((second.replayed, second.written), (0, 0), "{second:?}");
    assert!(again.is_empty());
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_apply_without_a_manifest_is_refused(pool: PgPool) {
    let c = corpus(&pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    assert!(run(&mut conn, &opts(true), None).await.is_err());
    assert_eq!(beta(&pool, c.counted).await, (Some(1.0), Some(1.0)));
}

/// The reversal restores what the run found, bit-exact, where the claim still
/// holds what the run wrote; a claim a live write moved since is reported and
/// left alone; a dry reversal only counts.
#[sqlx::test(migrations = "../../migrations")]
async fn the_reversal_restores_the_prior_unless_a_live_write_moved_the_claim(pool: PgPool) {
    let c = corpus(&pool).await;
    // A second replayable claim, which a live write moves after the apply.
    let (agent, group) = viewer_fixture::seed_agent_with_group(&pool, "b96-late").await;
    let binary = binary_truth(&pool).await;
    let late = viewer_fixture::seed_group_claim(&pool, agent, group, "b96 late").await;
    assign(&pool, late, binary, Some(0)).await;
    store_bba(
        &pool,
        late,
        binary,
        Some(agent),
        serde_json::json!({"0": 0.3, "~": 0.7}),
        "auto_wire",
    )
    .await;
    // NULL parameters read as the prior, and the reversal puts NULL back.
    sqlx::query("UPDATE claims SET beta_alpha = NULL, beta_beta = NULL WHERE id = $1")
        .bind(c.counted)
        .execute(&pool)
        .await
        .expect("null the counted claim's track");

    let mut conn = pool.acquire().await.expect("conn");
    let mut manifest = Vec::new();
    let report = run(&mut conn, &opts(true), Some(&mut manifest))
        .await
        .expect("apply");
    assert_eq!(report.written, 2, "{report:?}");

    // A live evidence write lands on `late` after the apply.
    sqlx::query("UPDATE claims SET beta_alpha = beta_alpha + 0.5 WHERE id = $1")
        .bind(late)
        .execute(&pool)
        .await
        .expect("a live increment");
    let late_now = beta(&pool, late).await;
    let counted_now = beta(&pool, c.counted).await;

    let dry = reverse(&mut conn, manifest.as_slice(), 1, false)
        .await
        .expect("dry reversal");
    assert_eq!(
        (dry.records, dry.restored, dry.not_at_written),
        (2, 1, 1),
        "{dry:?}"
    );
    assert_eq!(
        beta(&pool, c.counted).await,
        counted_now,
        "a dry reversal writes nothing"
    );

    let done = reverse(&mut conn, manifest.as_slice(), 1, true)
        .await
        .expect("reversal");
    assert_eq!((done.restored, done.not_at_written), (1, 1), "{done:?}");
    assert_eq!(done.not_at_written_claims, vec![late]);
    assert_eq!(
        beta(&pool, c.counted).await,
        (None, None),
        "restored bit-exact, NULL included"
    );
    assert_eq!(
        beta(&pool, late).await,
        late_now,
        "the moved claim keeps its live increment"
    );
    assert_eq!(beta(&pool, c.moved).await, (Some(1.7), Some(1.3)));
}
