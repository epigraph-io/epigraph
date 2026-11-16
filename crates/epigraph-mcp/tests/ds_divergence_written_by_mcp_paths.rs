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

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
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

/// `submit_ds_evidence` on the caller's own claim: `get_divergence` answers,
/// with the BetP the call returned, the Beta posterior of the BBA it stored,
/// and their KL; the claim's Beta parameters moved by that BBA. An identical
/// resubmission does not count the BBA again.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_ds_evidence_writes_a_divergence_row_get_divergence_reads(pool: PgPool) {
    let (server, group, viewer) = app_role_server(&pool).await;
    let (frame, version) = binary_truth(&pool).await;
    let claim = own_claim(&pool, group, "a claim the agent's group owns").await;

    let res =
        epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, sde(claim, frame), None)
            .await
            .expect("submit_ds_evidence on an own claim");
    let betp = first_text(&res)["pignistic_prob"]
        .as_f64()
        .expect("pignistic_prob");

    let (a, b) = beta(&pool, claim).await;
    assert!(
        close(a, 1.8) && close(b, 1.2),
        "the stored BBA moves Beta(1,1) to Beta(1.8,1.2), got ({a}, {b})"
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

    // The identical resubmission stores nothing new, so Beta stays.
    epigraph_mcp::tools::ds::submit_ds_evidence(&server, &viewer, sde(claim, frame), None)
        .await
        .expect("identical resubmission");
    let (a2, b2) = beta(&pool, claim).await;
    assert!(
        close(a2, 1.8) && close(b2, 1.2),
        "an identical resubmission must not count its BBA twice, got ({a2}, {b2})"
    );
}

/// `update_with_evidence` on the caller's own claim: the evidence BBA
/// m({TRUE}) = e moves Beta(1,1) to Beta(1+e, 2-e), and `get_divergence`
/// answers with the call's BetP against that posterior.
#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_writes_a_divergence_row_get_divergence_reads(pool: PgPool) {
    let (server, group, viewer) = app_role_server(&pool).await;
    let (frame, _) = binary_truth(&pool).await;
    let claim = own_claim(&pool, group, "another claim the agent's group owns").await;

    let res = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        uwe(claim, "an observation supporting the claim"),
        None,
    )
    .await
    .expect("update_with_evidence on an own claim");
    let body = first_text(&res);
    let betp = body["pignistic_prob"].as_f64().expect("pignistic_prob");
    let ev = parse_uuid_field(&body, "evidence_id");
    let masses: serde_json::Value =
        sqlx::query_scalar("SELECT masses FROM mass_functions WHERE evidence_id = $1")
            .bind(ev)
            .fetch_one(&pool)
            .await
            .expect("the evidence's BBA");
    let e = masses["0"].as_f64().expect("a supporting evidence BBA");

    let (a, b) = beta(&pool, claim).await;
    assert!(
        close(a, 1.0 + e) && close(b, 2.0 - e),
        "expected Beta({}, {}), got ({a}, {b})",
        1.0 + e,
        2.0 - e
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
    let posterior = (1.0 + e) / 3.0;
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
#[sqlx::test(migrations = "../../migrations")]
async fn a_foreign_public_claim_still_takes_evidence_and_gets_no_divergence_row(pool: PgPool) {
    let (server, _group, viewer) = app_role_server(&pool).await;
    let (frame, _) = binary_truth(&pool).await;

    let claim = foreign_claim(&pool, "a world claim someone else wrote").await;
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
    assert!(close(a, 1.0) && close(b, 1.0), "got ({a}, {b})");
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
    assert!((pa - 1.8 / 3.0).abs() < 1e-9, "A sees its own update: {pa}");

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
        (pb - 2.3 / 4.0).abs() < 1e-9,
        "B reports the posterior over both increments: {pb}"
    );
}
