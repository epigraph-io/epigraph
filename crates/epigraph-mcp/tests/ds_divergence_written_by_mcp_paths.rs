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
    let update = apply_beta_update(&mut probe, &viewer, claim, Some((0.8, 0.2)), None, "probe")
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
    let pa = apply_beta_update(&mut a, &viewer, claim, Some((0.8, 0.2)), None, "tx A")
        .await
        .expect("A's update");
    assert!(
        (pa.posterior - 1.8 / 3.0).abs() < 1e-9,
        "A sees its own update: {pa:?}"
    );
    assert!(pa.cold_start, "A moved the track off the prior: {pa:?}");

    let b = async {
        let mut b = pool_b.begin_as(&viewer).await.expect("stamped tx B");
        let pb = apply_beta_update(&mut b, &viewer, claim, Some((0.5, 0.5)), None, "tx B")
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

    // A second, independent BBA from the same caller, under a perspective it
    // owns, is counted beside the first: m({TRUE}) = 0.7 adds (0.7, 0.3).
    // (Not a replacement of the first: a replacement withdraws the BBA it
    // replaces, backlog 862d8404, which would leave a track holding only the
    // new BBA, itself a cold start.)
    let agent = server.server_agent_id().await.expect("server agent");
    let perspective: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("cold-start-second-{}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("seed perspective");
    let mut second = sde(claim, frame);
    second.masses = serde_json::json!({"0": 0.7, "~": 0.3});
    second.perspective_id = Some(perspective.to_string());
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

fn assert_beta(got: (f64, f64), want: (f64, f64), what: &str) {
    assert!(
        (got.0 - want.0).abs() < 1e-12 && (got.1 - want.1).abs() < 1e-12,
        "{what}: want Beta{want:?}, got Beta{got:?}"
    );
}

/// Backlog 862d8404, the MCP transport: a `submit_ds_evidence` write that
/// REPLACES the caller's earlier BBA moves the Beta track by the difference
/// between the two. Replacing a BBA with the same masses (only
/// `evidence_type` differs, so the write is `replaced`, not `unchanged`)
/// leaves the track and the reported posterior where they were; replacing it
/// with different masses leaves the track a fresh claim holding only the new
/// BBA has. At origin/main every replacement added its full increment: the
/// first arm moved Beta(1.8, 1.2) to Beta(2.6, 1.4).
#[sqlx::test(migrations = "../../migrations")]
async fn a_replaced_bba_moves_the_beta_track_by_the_difference_only(pool: PgPool) {
    let (server, group, viewer) = app_role_server(&pool).await;
    let (frame, _) = binary_truth(&pool).await;
    let claim = own_claim(&pool, group, "862d8404 replaced over MCP").await;

    let first =
        epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, sde(claim, frame), None)
            .await
            .expect("first submission");
    assert_eq!(first_text(&first)["write_outcome"], "inserted");
    assert_beta(beta(&pool, claim).await, (1.8, 1.2), "first write");

    let mut retyped = sde(claim, frame);
    retyped.evidence_type = Some("statistical".into());
    let res = epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, retyped, None)
        .await
        .expect("same masses, another evidence_type");
    let body = first_text(&res);
    assert_eq!(body["write_outcome"], "replaced", "{body}");
    assert_beta(
        beta(&pool, claim).await,
        (1.8, 1.2),
        "a BBA replaced by the same masses leaves the track where it was",
    );

    let mut other = sde(claim, frame);
    other.evidence_type = Some("statistical".into());
    other.masses = serde_json::json!({"0": 0.3, "~": 0.7});
    let res = epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, other, None)
        .await
        .expect("different masses");
    let body = first_text(&res);
    assert_eq!(body["write_outcome"], "replaced", "{body}");
    assert_beta(
        beta(&pool, claim).await,
        (1.3, 1.7),
        "a replaced track holds only the new BBA, as a fresh claim would",
    );
}

/// The guard on the withdrawal, MCP transport: the seed wire's `auto_wire` BBA
/// sits in the author's slot with no perspective and was never counted by the
/// Beta track, so the author's first `submit_ds_evidence` on the claim
/// replaces it and withdraws nothing. (Holds at origin/main too; it pins that
/// the withdrawal is limited to the writers that count.)
#[sqlx::test(migrations = "../../migrations")]
async fn replacing_an_uncounted_seed_bba_withdraws_nothing(pool: PgPool) {
    let (server, group, viewer) = app_role_server(&pool).await;
    let (frame, _) = binary_truth(&pool).await;
    let claim = own_claim(&pool, group, "862d8404 seed replaced over MCP").await;
    let agent = server.server_agent_id().await.expect("server agent");
    // As the seed wire leaves it: linked at hypothesis 0 (TRUE), so a
    // withdrawal of the seed would have a singleton to read and would show.
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0)",
    )
    .bind(claim)
    .bind(frame)
    .execute(&pool)
    .await
    .expect("link the claim at hypothesis 0");
    MassFunctionRepository::store_with_perspective(
        &pool,
        claim,
        frame,
        Some(agent),
        None,
        &serde_json::json!({"0": 0.9, "0,1": 0.1}),
        None,
        Some("auto_wire"),
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("seed the author's auto_wire BBA");

    let res =
        epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, sde(claim, frame), None)
            .await
            .expect("evidence over the seed");
    let body = first_text(&res);
    assert_eq!(body["write_outcome"], "replaced", "{body}");
    assert_beta(
        beta(&pool, claim).await,
        (1.8, 1.2),
        "an uncounted seed's mass is not withdrawn",
    );
}
