//! Backlog f50344c0: the MCP DS write paths keep the claim's Beta track and
//! write its DS-vs-Bayesian divergence row, as `POST /frames/:id/evidence`
//! does, so `get_divergence` answers for a claim whose evidence came in over
//! MCP.
//!
//! Before this, only the REST handler wrote `ds_bayesian_divergence` (and only
//! it moved `claims.beta_alpha` / `beta_beta`), so `get_divergence` answered
//! "no divergence data for claim X" for every claim written through
//! `submit_ds_evidence` or `update_with_evidence`.
//!
//! Every arm runs on the APPLICATION ROLE (both of the server's pools are
//! `SET SESSION AUTHORIZATION epigraph_app`), because `ds_bayesian_divergence`
//! is claim-derived: on a bypassing role its insert is never refused, and the
//! foreign-claim arm (the insert IS refused, under a savepoint, and the
//! submission still lands) would pass vacuously.
//!
//! The expected posterior and KL are computed here by hand from the BBA the
//! call stored, not through the code under test.
//!
//! A claim's COLD START records no row (backlog candidate
//! 913-cold-start-divergence): the update that first moves the claim's Beta
//! track off the `Beta(1, 1)` prior compares a mature BetP against a posterior
//! holding one BBA's evidence, and that KL measures the empty track, not a
//! disagreement. So each arm here makes a first update (no row) and a second
//! (the row), and
//! `a_cold_start_on_a_mature_claim_stays_out_of_top_divergent` pins the
//! top-divergent list. Verified to fail with `record_divergence`'s
//! cold-start return removed: every cold-start assertion here then finds the
//! row.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{DivergenceRepository, MassFunctionRepository, ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::types::{GetDivergenceParams, SubmitDsEvidenceParams, UpdateWithEvidenceParams};
use sqlx::PgPool;
use uuid::Uuid;

/// `KL(p || q)` for two Bernoulli distributions, written out.
fn kl(p: f64, q: f64) -> f64 {
    p * (p / q).ln() + (1.0 - p) * ((1.0 - p) / (1.0 - q)).ln()
}

/// A server whose every connection is the application role, its agent's
/// personal group and its viewer (resolved on the superuser pool).
async fn app_role_server(pool: &PgPool) -> (EpiGraphMcpFull, Uuid, Viewer) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: the foreign-claim arm is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let server = build_scoped_test_server(plain, scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let group = personal_group_of(pool, agent).await;
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    (server, group, viewer)
}

async fn binary_truth(pool: &PgPool) -> (Uuid, i32) {
    let existing: Option<(Uuid, i32)> =
        sqlx::query_as("SELECT id, version FROM frames WHERE name = 'binary_truth'")
            .fetch_optional(pool)
            .await
            .expect("read binary_truth");
    if let Some(row) = existing {
        return row;
    }
    let f = epigraph_db::FrameRepository::create(
        pool,
        "binary_truth",
        Some("canonical binary frame"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("binary_truth");
    (f.id, f.version)
}

/// A claim in the server agent's own group (written by another agent, so the
/// agent writes it as a group member).
async fn own_claim(pool: &PgPool, group: Uuid, content: &str) -> Uuid {
    let claim = seed_claim(pool, content, 0.5).await;
    sqlx::query("UPDATE claims SET owner_group_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(group)
        .execute(pool)
        .await
        .expect("re-own the claim into the server agent's group");
    claim
}

/// A public claim owned by a group nobody can write (the world group, or the
/// seed group a superuser-seeded claim lands in).
async fn foreign_claim(pool: &PgPool, content: &str) -> Uuid {
    let claim = seed_claim(pool, content, 0.5).await;
    let owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("owner");
    let members: i64 =
        sqlx::query_scalar("SELECT count(*) FROM group_memberships WHERE group_id = $1")
            .bind(owner)
            .fetch_one(pool)
            .await
            .expect("members");
    assert_eq!(members, 0, "fixture: the owning group must be memberless");
    claim
}

async fn beta(pool: &PgPool, claim: Uuid) -> (f64, f64) {
    sqlx::query_as("SELECT beta_alpha, beta_beta FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("beta columns")
}

/// `(frame_id, pignistic_prob, bayesian_posterior, kl_divergence, frame_version)`.
async fn divergence_rows(pool: &PgPool, claim: Uuid) -> Vec<(Uuid, f64, f64, f64, Option<i32>)> {
    sqlx::query_as(
        "SELECT frame_id, pignistic_prob, bayesian_posterior, kl_divergence, frame_version \
           FROM ds_bayesian_divergence WHERE claim_id = $1 ORDER BY computed_at",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("divergence rows")
}

fn sde(claim: Uuid, frame: Uuid) -> SubmitDsEvidenceParams {
    SubmitDsEvidenceParams {
        claim_id: claim.to_string(),
        frame_id: frame.to_string(),
        hypothesis_index: 0,
        // m({TRUE}) = 0.8, m(Θ) = 0.2: Beta(1, 1) -> Beta(1.8, 1.2).
        masses: serde_json::json!({"0": 0.8, "~": 0.2}),
        reliability: None,
        combination_method: None,
        gamma: None,
        perspective_id: None,
        evidence_type: None,
        locality_tag: None,
    }
}

fn uwe(claim: Uuid, data: &str) -> UpdateWithEvidenceParams {
    UpdateWithEvidenceParams {
        canonical_name: None,
        step_index: None,
        claim_id: claim.to_string(),
        evidence_type: "empirical".into(),
        evidence_data: data.into(),
        source_url: None,
        supports: true,
        strength: 0.8,
        labels: vec![],
    }
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

/// `submit_ds_evidence` on the caller's own claim. The first call moves the
/// claim's Beta parameters by its BBA but, as a cold start, records no
/// divergence row. The identical resubmission does not count the BBA again,
/// and, its track no longer at the prior, records the row `get_divergence`
/// answers with: the BetP the call returned, the Beta posterior of the BBA,
/// and their KL.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_ds_evidence_writes_a_divergence_row_get_divergence_reads(pool: PgPool) {
    let (server, group, viewer) = app_role_server(&pool).await;
    let (frame, version) = binary_truth(&pool).await;
    let claim = own_claim(&pool, group, "a claim the agent's group owns").await;

    epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, sde(claim, frame), None)
        .await
        .expect("submit_ds_evidence on an own claim");

    let (a, b) = beta(&pool, claim).await;
    assert!(
        close(a, 1.8) && close(b, 1.2),
        "the stored BBA moves Beta(1,1) to Beta(1.8,1.2), got ({a}, {b})"
    );
    assert!(
        divergence_rows(&pool, claim).await.is_empty(),
        "the claim's first Beta update is a cold start and records no divergence row"
    );

    // The identical resubmission stores nothing new, so Beta stays; the
    // track is no longer at the prior, so this call records the row.
    let res =
        epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, sde(claim, frame), None)
            .await
            .expect("identical resubmission");
    let betp = first_text(&res)["pignistic_prob"]
        .as_f64()
        .expect("pignistic_prob");
    let (a2, b2) = beta(&pool, claim).await;
    assert!(
        close(a2, 1.8) && close(b2, 1.2),
        "an identical resubmission must not count its BBA twice, got ({a2}, {b2})"
    );

    let got = epigraph_mcp::tools::ds::get_divergence(
        &server,
        &viewer,
        GetDivergenceParams {
            claim_id: claim.to_string(),
        },
    )
    .await
    .expect("get_divergence answers for an MCP-written claim");
    let body = first_text(&got);
    let posterior = 1.8 / 3.0;
    assert!(
        close(body["pignistic_prob"].as_f64().unwrap(), betp),
        "{body}"
    );
    assert!(
        close(body["bayesian_posterior"].as_f64().unwrap(), posterior),
        "{body}"
    );
    assert!(
        close(body["kl_divergence"].as_f64().unwrap(), kl(betp, posterior)),
        "{body}"
    );

    let rows = divergence_rows(&pool, claim).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0].0, frame,
        "recorded on the frame the BBA was filed on"
    );
    assert_eq!(rows[0].4, Some(version));
}

/// One `update_with_evidence` call; its BetP and its evidence BBA's
/// m({TRUE}).
async fn uwe_call(
    server: &EpiGraphMcpFull,
    viewer: &Viewer,
    pool: &PgPool,
    claim: Uuid,
    data: &str,
) -> (f64, f64) {
    let res =
        epigraph_mcp::tools::claims::update_with_evidence(server, viewer, uwe(claim, data), None)
            .await
            .expect("update_with_evidence on an own claim");
    let body = first_text(&res);
    let betp = body["pignistic_prob"].as_f64().expect("pignistic_prob");
    let ev = parse_uuid_field(&body, "evidence_id");
    let masses: serde_json::Value =
        sqlx::query_scalar("SELECT masses FROM mass_functions WHERE evidence_id = $1")
            .bind(ev)
            .fetch_one(pool)
            .await
            .expect("the evidence's BBA");
    (
        betp,
        masses["0"].as_f64().expect("a supporting evidence BBA"),
    )
}

/// `update_with_evidence` on the caller's own claim: each evidence BBA
/// m({TRUE}) = e moves Beta by (e, 1 - e). The first call is a cold start and
/// records no divergence row; after the second, `get_divergence` answers with
/// that call's BetP against the posterior over both.
#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_writes_a_divergence_row_get_divergence_reads(pool: PgPool) {
    let (server, group, viewer) = app_role_server(&pool).await;
    let (frame, _) = binary_truth(&pool).await;
    let claim = own_claim(&pool, group, "another claim the agent's group owns").await;

    let (_, e1) = uwe_call(
        &server,
        &viewer,
        &pool,
        claim,
        "an observation supporting the claim",
    )
    .await;
    let (a, b) = beta(&pool, claim).await;
    assert!(
        close(a, 1.0 + e1) && close(b, 2.0 - e1),
        "expected Beta({}, {}), got ({a}, {b})",
        1.0 + e1,
        2.0 - e1
    );
    assert!(
        divergence_rows(&pool, claim).await.is_empty(),
        "the claim's first Beta update is a cold start and records no divergence row"
    );

    let (betp, e2) = uwe_call(
        &server,
        &viewer,
        &pool,
        claim,
        "a second, independent observation supporting the claim",
    )
    .await;
    let (a, b) = beta(&pool, claim).await;
    assert!(
        close(a, 1.0 + e1 + e2) && close(b, 3.0 - e1 - e2),
        "expected Beta({}, {}), got ({a}, {b})",
        1.0 + e1 + e2,
        3.0 - e1 - e2
    );

    let got = epigraph_mcp::tools::ds::get_divergence(
        &server,
        &viewer,
        GetDivergenceParams {
            claim_id: claim.to_string(),
        },
    )
    .await
    .expect("get_divergence answers for an MCP-written claim");
    let d = first_text(&got);
    let posterior = (1.0 + e1 + e2) / 4.0;
    assert!(close(d["pignistic_prob"].as_f64().unwrap(), betp), "{d}");
    assert!(
        close(d["bayesian_posterior"].as_f64().unwrap(), posterior),
        "{d}"
    );
    assert!(
        close(d["kl_divergence"].as_f64().unwrap(), kl(betp, posterior)),
        "{d}"
    );
    let rows = divergence_rows(&pool, claim).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0].0, frame,
        "recorded on binary_truth, the cache's frame"
    );
}

/// A non-owner attaching evidence to a public claim: both tools still
/// succeed. The divergence row is claim-derived (it would be owned by the
/// claim's group, which this caller does not write), so its insert is refused
/// and rolled back to its savepoint without taking the submission with it,
/// and the claim's Beta parameters are the owner's and do not move.
///
/// The claim's Beta track is seeded OFF the prior (as the owner's earlier
/// evidence would leave it): on a track still at `Beta(1, 1)` every update is
/// a cold start, `record_divergence` returns before it attempts the insert,
/// and this arm would no longer test the refusal. The precondition below pins
/// that the insert is reached.
#[sqlx::test(migrations = "../../migrations")]
async fn a_foreign_public_claim_still_takes_evidence_and_gets_no_divergence_row(pool: PgPool) {
    use epigraph_engine::ds_divergence::apply_beta_update;

    let (server, _group, viewer) = app_role_server(&pool).await;
    let (frame, _) = binary_truth(&pool).await;

    let claim = foreign_claim(&pool, "a world claim someone else wrote").await;
    sqlx::query("UPDATE claims SET beta_alpha = 1.8, beta_beta = 1.2 WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("seed the owner's Beta track off the prior");

    // Precondition: for this caller the update is not a cold start, so the
    // divergence insert below is attempted (and refused), not skipped.
    let url = fixture::database_url_for(&pool).await;
    let probe_pool =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let mut probe = probe_pool
        .begin_as(&viewer)
        .await
        .expect("stamped probe tx");
    let update = apply_beta_update(&mut probe, &viewer, claim, Some((0.8, 0.2)), "probe")
        .await
        .expect("probe update");
    probe.rollback().await.expect("roll back the probe");
    assert!(
        !update.cold_start,
        "the seeded track must not read as a cold start, or the insert is never \
         attempted and this arm is vacuous: {update:?}"
    );
    let res =
        epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, sde(claim, frame), None)
            .await;
    assert!(
        res.is_ok(),
        "a refused divergence row must not fail the submission: {res:?}"
    );
    let res = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        uwe(claim, "an observation on someone else's claim"),
        None,
    )
    .await;
    assert!(
        res.is_ok(),
        "a refused divergence row must not fail the submission: {res:?}"
    );

    let bbas: i64 = sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("count BBAs");
    assert_eq!(bbas, 2, "both submissions landed their BBA");
    assert!(divergence_rows(&pool, claim).await.is_empty());
    let (a, b) = beta(&pool, claim).await;
    assert!(
        close(a, 1.8) && close(b, 1.2),
        "the owner's track must not move: got ({a}, {b})"
    );
}

/// Two Beta updates on one claim that overlap in time both land.
///
/// The shared step is `epigraph_engine::ds_divergence::apply_beta_update`, which
/// both MCP DS tools and the REST route call. Transaction A adds (0.8, 0.2) and
/// holds the row. Transaction B adds (0.5, 0.5) while A is still open, then A
/// commits. A read-then-write update (the shape the step had when it was moved
/// out of the REST handler) lets B read the pre-A `Beta(1, 1)`, wait on A's row
/// lock, and store its stale sum `(1.5, 1.5)`, dropping A's increment. The
/// in-statement addition stores `(2.3, 1.7)`.
///
/// `submit_ds_evidence` reaches this step before anything else locks the claim
/// row, so two calls on one claim and different frames race exactly like this.
#[sqlx::test(migrations = "../../migrations")]
async fn overlapping_beta_updates_on_one_claim_lose_no_increment(pool: PgPool) {
    use epigraph_engine::ds_divergence::apply_beta_update;

    let (_server, group, viewer) = app_role_server(&pool).await;
    // One pool per transaction: on a shared pool B could wait for a
    // connection instead of for A's row lock, and then read after A commits,
    // which a read-then-write update survives too.
    let url = fixture::database_url_for(&pool).await;
    let pool_a =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool A");
    let pool_b =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool B");
    let claim = own_claim(&pool, group, "Two overlapping Beta updates both count.").await;

    let mut a = pool_a.begin_as(&viewer).await.expect("stamped tx A");
    let pa = apply_beta_update(&mut a, &viewer, claim, Some((0.8, 0.2)), "tx A")
        .await
        .expect("A's update");
    assert!(
        (pa.posterior - 1.8 / 3.0).abs() < 1e-9,
        "A sees its own update: {pa:?}"
    );
    assert!(pa.cold_start, "A moved the track off the prior: {pa:?}");

    let b = async {
        let mut b = pool_b.begin_as(&viewer).await.expect("stamped tx B");
        let pb = apply_beta_update(&mut b, &viewer, claim, Some((0.5, 0.5)), "tx B")
            .await
            .expect("B's update");
        b.commit().await.expect("commit B");
        pb
    };
    let commit_a_later = async move {
        // Long enough for B to reach its statement while A still holds the row.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        a.commit().await.expect("commit A");
    };
    let (pb, ()) = tokio::join!(b, commit_a_later);

    let (alpha, beta_param) = beta(&pool, claim).await;
    assert!(
        (alpha - 2.3).abs() < 1e-9 && (beta_param - 1.7).abs() < 1e-9,
        "both increments must be stored: Beta(1,1) + (0.8,0.2) + (0.5,0.5) = (2.3, 1.7), \
         got ({alpha}, {beta_param})"
    );
    assert!(
        (pb.posterior - 2.3 / 4.0).abs() < 1e-9,
        "B reports the posterior over both increments: {pb:?}"
    );
    assert!(
        !pb.cold_start,
        "B's update landed on A's, not on the prior, so it is not a cold start: {pb:?}"
    );
}

/// The claim's entry in the viewer's top-divergent list, if any.
async fn in_top(pool: &PgPool, viewer: &Viewer, claim: Uuid) -> Option<epigraph_db::DivergenceRow> {
    DivergenceRepository::top_divergent(pool, viewer, 1000)
        .await
        .expect("top_divergent")
        .into_iter()
        .find(|r| r.claim_id == claim)
}

/// The case the cold-start rule exists for. A claim that already holds a BBA
/// from a writer that does not keep the Beta track (as the seed and edge
/// wires do) still holds the `Beta(1, 1)` prior. Its first live update
/// compares the fold's BetP against a one-BBA posterior; on the old code that
/// KL went into `top_divergent`, and on a claim with a long history it
/// outranked every real disagreement.
/// Now the first update leaves the claim out of the list, and the second,
/// from a track that holds evidence, puts it in with the KL of that call.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cold_start_on_a_mature_claim_stays_out_of_top_divergent(pool: PgPool) {
    let (server, group, viewer) = app_role_server(&pool).await;
    let (frame, _) = binary_truth(&pool).await;
    let claim = own_claim(&pool, group, "a claim another writer already supports").await;
    let wire = seed_agent(&pool).await;
    MassFunctionRepository::store(
        &pool,
        claim,
        frame,
        Some(wire),
        &serde_json::json!({"0": 0.95, "~": 0.05}),
        None,
        Some("auto_wire"),
        None,
        "unknown",
        None,
    )
    .await
    .expect("a BBA from a writer that does not move Beta");

    let res =
        epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, sde(claim, frame), None)
            .await
            .expect("the claim's first live evidence");
    let betp = first_text(&res)["pignistic_prob"]
        .as_f64()
        .expect("pignistic_prob");
    let (a, b) = beta(&pool, claim).await;
    assert!(close(a, 1.8) && close(b, 1.2), "got ({a}, {b})");
    assert!(
        betp - 1.8 / 3.0 > 0.2 && kl(betp, 1.8 / 3.0) > 0.1,
        "PREMISE: a BetP well above the one-BBA posterior, so the cold start's row \
         would carry a visible KL: BetP {betp}, KL {}",
        kl(betp, 1.8 / 3.0)
    );
    assert_eq!(
        in_top(&pool, &viewer, claim).await.map(|r| r.kl_divergence),
        None,
        "the cold-start update must not put the claim in top_divergent"
    );

    // A different BBA from the same caller replaces its first and is counted:
    // m({TRUE}) = 0.7 adds (0.7, 0.3).
    let mut second = sde(claim, frame);
    second.masses = serde_json::json!({"0": 0.7, "~": 0.3});
    let res = epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, second, None)
        .await
        .expect("the claim's second live evidence");
    let betp2 = first_text(&res)["pignistic_prob"]
        .as_f64()
        .expect("pignistic_prob");
    let (a, b) = beta(&pool, claim).await;
    assert!(close(a, 2.5) && close(b, 1.5), "got ({a}, {b})");
    let row = in_top(&pool, &viewer, claim)
        .await
        .expect("the second update, from a track holding evidence, is in top_divergent");
    assert!(close(row.bayesian_posterior, 2.5 / 4.0), "{row:?}");
    assert!(close(row.pignistic_prob, betp2), "{row:?}");
    assert!(close(row.kl_divergence, kl(betp2, 2.5 / 4.0)), "{row:?}");
}

// ── Backlog d3648d3c: the other DS writers keep the track too ───────────
//
// The seed wire, the batch ingest wire, the edge wire and
// `report_workflow_outcome` used to store their BBA without counting it on
// the claim's Beta track, so the track stayed at the prior while the DS fold
// held that evidence, and `get_divergence` had no row for a claim whose belief
// moved through them. Each arm below pins that the writer counts its BBA (the
// increments computed by hand from the stored masses) and that the row
// `get_divergence` reads follows from it. Verified to fail with the writers'
// `track_counted_bba` calls removed (the tracks stay at `Beta(1, 1)`).

/// `(m({TRUE}), m(conflict))` of a stored BBA's masses, `0` when absent.
fn support_and_conflict(masses: &serde_json::Value) -> (f64, f64) {
    (
        masses["0"].as_f64().unwrap_or(0.0),
        masses[""].as_f64().unwrap_or(0.0),
    )
}

/// The app-role pool a test opens its own stamped transactions on.
async fn app_role_pool(pool: &PgPool) -> ScopedPool {
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

/// A target whose track already holds evidence, and a believed source.
async fn edge_fixture(pool: &PgPool, group: Uuid) -> (Uuid, Uuid) {
    let source = seed_claim_with_belief(pool, 0.8, 0.95, Some(0.9)).await;
    let target = own_claim(pool, group, "an edge target whose track holds evidence").await;
    sqlx::query("UPDATE claims SET beta_alpha = 1.8, beta_beta = 1.2 WHERE id = $1")
        .bind(target)
        .execute(pool)
        .await
        .expect("seed the target's track off the prior");
    (source, target)
}

/// The edge BBA on `target`, as `(row id, masses)`.
async fn edge_bba(pool: &PgPool, target: Uuid, edge: Uuid) -> (Uuid, serde_json::Value) {
    sqlx::query_as(
        "SELECT id, masses FROM mass_functions WHERE claim_id = $1 AND perspective_id = $2",
    )
    .bind(target)
    .bind(edge)
    .fetch_one(pool)
    .await
    .expect("the edge's BBA on the target")
}

async fn link(server: &EpiGraphMcpFull, viewer: &Viewer, source: Uuid, target: Uuid) -> Uuid {
    let res = epigraph_mcp::tools::link_epistemic::link_epistemic(
        server,
        viewer,
        epigraph_mcp::types::LinkEpistemicParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            relationship: "supports".into(),
            properties: None,
        },
        None,
    )
    .await
    .expect("link_epistemic on the app role");
    let body = first_text(&res);
    assert_eq!(body["belief_wired"], true, "{body}");
    parse_uuid_field(&body, "edge_id")
}

/// The edge wire counts the edge's BBA on its target's track once, at its
/// first materialization, and records the divergence of the BetP it wrote to
/// the target's cache. Re-asserting the edge (the gate finds its BBA) and
/// re-wiring it directly as `backfill_factors` does (the upsert replaces the
/// BBA at its key) move the track no further: the DS fold holds the edge's
/// BBA once, and so must the track.
#[sqlx::test(migrations = "../../migrations")]
async fn the_edge_wire_counts_the_first_materialization_once(pool: PgPool) {
    let (server, group, viewer) = app_role_server(&pool).await;
    let (frame, _) = binary_truth(&pool).await;
    let (source, target) = edge_fixture(&pool, group).await;

    let edge = link(&server, &viewer, source, target).await;
    let (_, masses) = edge_bba(&pool, target, edge).await;
    let (s, c) = support_and_conflict(&masses);
    assert!(
        s > 0.0,
        "PREMISE: a supports edge from a believed source: {masses}"
    );
    let (alpha, beta_param) = (1.8 + s, 2.2 - s - c);
    let (a, b) = beta(&pool, target).await;
    assert!(
        close(a, alpha) && close(b, beta_param),
        "the edge's BBA is counted: expected Beta({alpha}, {beta_param}), got ({a}, {b})"
    );

    let cached: f64 = sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(target)
        .fetch_one(&pool)
        .await
        .expect("the target's cache");
    let rows = divergence_rows(&pool, target).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let posterior = alpha / (alpha + beta_param);
    assert_eq!(
        rows[0].0, frame,
        "on binary_truth, where the wire filed the BBA"
    );
    assert!(
        close(rows[0].1, cached),
        "the BetP the wire wrote: {rows:?} vs {cached}"
    );
    assert!(close(rows[0].2, posterior), "{rows:?} vs {posterior}");
    assert!(close(rows[0].3, kl(cached, posterior)), "{rows:?}");

    // Re-asserting the edge: the gate finds its BBA and wires nothing.
    let res = epigraph_mcp::tools::link_epistemic::link_epistemic(
        &server,
        &viewer,
        epigraph_mcp::types::LinkEpistemicParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            relationship: "supports".into(),
            properties: None,
        },
        None,
    )
    .await
    .expect("re-asserting the edge");
    let _ = first_text(&res);
    // A direct re-wire, as `backfill_factors` runs it.
    let app = app_role_pool(&pool).await;
    let mut tx = app.begin_as(&viewer).await.expect("stamped tx");
    let agent = server.server_agent_id().await.expect("server agent");
    let outcome = epigraph_engine::edge_factor::auto_wire_ds_for_edge(
        &mut tx, &viewer, edge, agent, source, target, "supports",
    )
    .await
    .expect("direct re-wire");
    tx.commit().await.expect("commit the re-wire");
    assert_eq!(
        outcome,
        epigraph_engine::edge_factor::EdgeFactorOutcome::Wired
    );

    let (a, b) = beta(&pool, target).await;
    assert!(
        close(a, alpha) && close(b, beta_param),
        "a re-assert or re-wire must not count the edge again: got ({a}, {b})"
    );
    assert_eq!(divergence_rows(&pool, target).await.len(), 1);
}

/// The cascades RE-derive an edge's BBA: they delete it and wire it again
/// from the edge's current source (`invalidate_and_rewire`). The new BBA
/// replaces the one the track counted at the edge's creation, so the re-wire
/// must not count it again, even though, past the delete, the edge reads as
/// never wired. Driven through `cascade_after_supersede` with the source as
/// the replacement, which re-derives every edge it sources.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cascade_re_derivation_does_not_count_the_edge_again(pool: PgPool) {
    let (server, group, viewer) = app_role_server(&pool).await;
    binary_truth(&pool).await;
    let (source, target) = edge_fixture(&pool, group).await;
    let edge = link(&server, &viewer, source, target).await;
    let (first_row, _) = edge_bba(&pool, target, edge).await;
    let counted = beta(&pool, target).await;
    assert!(
        !close(counted.0, 1.8),
        "PREMISE: the creation counted the edge: {counted:?}"
    );

    let unrelated = own_claim(&pool, group, "a retired claim with no edges").await;
    let app = app_role_pool(&pool).await;
    let mut tx = app.begin_as(&viewer).await.expect("stamped tx");
    let report = epigraph_engine::retraction_cascade::cascade_after_supersede(
        &mut tx, &viewer, unrelated, source,
    )
    .await;
    tx.commit().await.expect("commit the cascade");
    assert!(report.errors.is_empty(), "{report:?}");
    let (second_row, _) = edge_bba(&pool, target, edge).await;
    assert_ne!(
        first_row, second_row,
        "PREMISE: the cascade deleted the edge's BBA and wired a new one: {report:?}"
    );

    let (a, b) = beta(&pool, target).await;
    assert!(
        close(a, counted.0) && close(b, counted.1),
        "a re-derivation must not count the edge again: {counted:?} -> ({a}, {b})"
    );
}

/// `report_workflow_outcome` counts its outcome BBA as `update_with_evidence`
/// counts its evidence: the first report moves the track (a cold start, no
/// row), and the second, from a track holding the first, records the row.
/// A failed outcome's BBA sits on FALSE, so all its non-conflict mass goes to
/// beta.
#[sqlx::test(migrations = "../../migrations")]
async fn report_workflow_outcome_counts_its_outcome_bba(pool: PgPool) {
    let (server, group, viewer) = app_role_server(&pool).await;
    let (frame, _) = binary_truth(&pool).await;
    let wf = seed_workflow_claim(&pool, "ship a team workflow", &["build", "test"]).await;
    sqlx::query("UPDATE claims SET owner_group_id = $2 WHERE id = $1")
        .bind(wf)
        .bind(group)
        .execute(&pool)
        .await
        .expect("re-own the workflow claim into the server agent's group");

    let report = |success: bool, details: &str| epigraph_mcp::types::ReportWorkflowOutcomeParams {
        idempotency_key: None,
        workflow_id: wf.to_string(),
        success,
        execution_log: vec![epigraph_mcp::types::StepExecution {
            step_index: 0,
            planned: "build".into(),
            actual: "build".into(),
            deviated: false,
            deviation_reason: None,
        }],
        outcome_details: details.into(),
        quality: Some(0.9),
        goal_text: None,
    };
    let outcome_masses = |body: serde_json::Value| {
        let ev = parse_uuid_field(&body, "evidence_id");
        let pool = pool.clone();
        async move {
            let m: serde_json::Value =
                sqlx::query_scalar("SELECT masses FROM mass_functions WHERE evidence_id = $1")
                    .bind(ev)
                    .fetch_one(&pool)
                    .await
                    .expect("the outcome's BBA");
            m
        }
    };

    let res = epigraph_mcp::tools::workflows::report_workflow_outcome(
        &server,
        &viewer,
        report(true, "ran clean"),
        None,
    )
    .await
    .expect("first outcome");
    let (s1, c1) = support_and_conflict(&outcome_masses(first_text(&res)).await);
    assert!(
        s1 > 0.0,
        "PREMISE: a successful outcome supports the workflow"
    );
    let (a, b) = beta(&pool, wf).await;
    assert!(
        close(a, 1.0 + s1) && close(b, 2.0 - s1 - c1),
        "the outcome BBA is counted: expected Beta({}, {}), got ({a}, {b})",
        1.0 + s1,
        2.0 - s1 - c1
    );
    assert!(
        divergence_rows(&pool, wf).await.is_empty(),
        "the first counted outcome is the workflow's cold start"
    );

    let res = epigraph_mcp::tools::workflows::report_workflow_outcome(
        &server,
        &viewer,
        report(false, "the test step failed"),
        None,
    )
    .await
    .expect("second outcome");
    let body = first_text(&res);
    let (s2, c2) = support_and_conflict(&outcome_masses(body.clone()).await);
    assert!(
        close(s2, 0.0),
        "PREMISE: a failed outcome puts nothing on TRUE"
    );
    let (alpha, beta_param) = (1.0 + s1, 3.0 - s1 - c1 - c2);
    let (a, b) = beta(&pool, wf).await;
    assert!(close(a, alpha) && close(b, beta_param), "got ({a}, {b})");

    let rows = divergence_rows(&pool, wf).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let posterior = alpha / (alpha + beta_param);
    assert_eq!(rows[0].0, frame);
    assert!(close(rows[0].2, posterior), "{rows:?} vs {posterior}");
    assert!(close(rows[0].3, kl(rows[0].1, posterior)), "{rows:?}");
    let cached: f64 = sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(wf)
        .fetch_one(&pool)
        .await
        .expect("the workflow's cache");
    assert!(
        close(rows[0].1, cached),
        "the row's BetP is the cached one: {rows:?}"
    );
}
