//! MCP read tools read as the CALLER, on the application role: a member of a
//! group reads that group's private rows, a non-member does not, and public
//! rows read for both.
//!
//! # The defect this pins (measured on production 2026-11-05)
//!
//! The read tools resolved the caller's `Viewer` correctly and then ran their
//! repo queries on the server's plain pool. Those connections carry EMPTY
//! tenancy GUCs, and row security, FORCEd on the application login, then
//! admits `visibility = 'public'` rows only: the in-query predicate admitted a
//! member's group-private row and the session's policy dropped it. Every MCP
//! caller saw public rows only, its own groups' rows included. The fix reads on
//! `EpiGraphMcpFull::read_as`, a connection stamped with the viewer.
//!
//! # Why CI never saw it, and what this file does about it
//!
//! `#[sqlx::test]` connects as a BYPASSRLS superuser, on which no policy
//! filters anything, so a test server built on that pool reads every row
//! whatever the connection carries. Here the server is built ONLY from a
//! `ScopedPool` downgraded to `epigraph_app` (`rolbypassrls = false`), and its
//! plain pool is that `ScopedPool`'s own inner pool, exactly as `main.rs`
//! builds it. Seeding and viewer resolution run on the superuser pool.
//!
//! # Both directions, on purpose
//!
//! Each case asserts the member's positive (the half the pre-fix code failed:
//! its own private claim read as not found, its counts were the public-only
//! counts, its private frame did not exist) and the non-member's negative (the
//! half a fail-open regression would fail), plus a public control read by both.
//!
//! MEASURED against the pre-fix tool, engine and repo sources (this file and
//! the test harness kept): all four tests FAIL, each on the member's positive
//! half (its private claim read as not found, `system_stats` counted 1 where 2
//! are readable, its private frame reported missing) and the refusal test on
//! the plain-pool read succeeding.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, first_text};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::types::{GetBeliefParams, GetClaimParams, SystemStatsParams};
use epigraph_mcp::{tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

/// The server production runs: one `ScopedPool` on the application role, and
/// the plain pool IS that `ScopedPool`'s inner pool (`main.rs`). Refuses to
/// run vacuously if the role can bypass row security.
async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every assertion here would be vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = scoped.inner().clone();
    build_scoped_test_server(plain, scoped)
}

struct World {
    member: Viewer,
    non_member: Viewer,
    private_claim: Uuid,
    public_claim: Uuid,
    private_frame: Uuid,
}

/// Group G with member M; N in no group of G's; a claim private to G, a
/// public claim, and a frame private to G carrying one BBA on the private
/// claim (which inherits the claim's group, migration 070). All seeded on the
/// superuser pool.
async fn world(pool: &PgPool) -> World {
    let (member, group) = fixture::seed_agent_with_group(pool, "stamped-read-member").await;
    let (non_member, _) = fixture::seed_agent_with_group(pool, "stamped-read-outsider").await;
    let private_claim =
        fixture::seed_group_claim(pool, member, group, "stamped read: private claim").await;
    let public_claim =
        fixture::seed_public_claim(pool, non_member, "stamped read: public claim").await;

    let private_frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("stamped-read-frame-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame");
    sqlx::query("UPDATE frames SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(private_frame)
        .bind(group)
        .execute(pool)
        .await
        .expect("privatise frame");
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses) \
         VALUES ($1, $2, $3, '{\"0\": 0.6, \"0,1\": 0.4}'::jsonb)",
    )
    .bind(private_claim)
    .bind(private_frame)
    .bind(member)
    .execute(pool)
    .await
    .expect("seed a group-private BBA");
    let bba_visibility: String = sqlx::query_scalar(
        "SELECT visibility FROM mass_functions WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(private_claim)
    .bind(private_frame)
    .fetch_one(pool)
    .await
    .expect("read the BBA's tenancy");
    assert_eq!(
        bba_visibility, "group",
        "PREMISE: the BBA inherits its claim's group, so the belief read is a private read"
    );

    World {
        member: Viewer::resolve(pool, member).await.expect("member viewer"),
        non_member: Viewer::resolve(pool, non_member)
            .await
            .expect("non-member viewer"),
        private_claim,
        public_claim,
        private_frame,
    }
}

async fn get_claim(
    server: &EpiGraphMcpFull,
    viewer: &Viewer,
    claim: Uuid,
) -> Result<serde_json::Value, String> {
    tools::claims::get_claim(
        server,
        viewer,
        GetClaimParams {
            claim_id: claim.to_string(),
            frame_id: None,
            perspective_id: None,
        },
    )
    .await
    .map(|r| first_text(&r))
    .map_err(|e| e.message.to_string())
}

async fn claims_count(server: &EpiGraphMcpFull, viewer: &Viewer) -> i64 {
    let r = tools::batch::system_stats(server, viewer, SystemStatsParams { detailed: None })
        .await
        .expect("system_stats");
    first_text(&r)["claims"]
        .as_i64()
        .expect("system_stats reports a claims count")
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_claim_reads_the_members_private_claim_and_not_the_outsiders(pool: PgPool) {
    let w = world(&pool).await;
    let server = app_role_server(&pool).await;

    let mine = get_claim(&server, &w.member, w.private_claim)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "a member must read its own group's private claim on the application role \
                 (the pre-fix tool read it on an unstamped session and got not found): {e}"
            )
        });
    assert_eq!(mine["id"], w.private_claim.to_string());

    let theirs = get_claim(&server, &w.non_member, w.private_claim).await;
    assert!(
        matches!(&theirs, Err(m) if m.contains("not found")),
        "a non-member must get not found for another group's private claim: {theirs:?}"
    );

    for (who, v) in [("member", &w.member), ("non-member", &w.non_member)] {
        let public = get_claim(&server, v, w.public_claim)
            .await
            .unwrap_or_else(|e| panic!("the {who} must read a public claim: {e}"));
        assert_eq!(public["id"], w.public_claim.to_string());
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn system_stats_counts_the_members_private_claim_and_not_the_outsiders(pool: PgPool) {
    let w = world(&pool).await;
    let server = app_role_server(&pool).await;

    let public_total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE visibility = 'public'")
            .fetch_one(&pool)
            .await
            .expect("count public claims");
    assert!(
        public_total >= 1,
        "PREMISE: the public control claim exists"
    );

    let member = claims_count(&server, &w.member).await;
    let outsider = claims_count(&server, &w.non_member).await;
    assert_eq!(
        outsider, public_total,
        "a non-member counts the public claims only, the control included"
    );
    assert_eq!(
        member,
        public_total + 1,
        "a member's count must include its own group's private claim (the pre-fix tool \
         counted on an unstamped session and reported the public-only count)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_framed_belief_reads_the_members_private_frame_and_bba(pool: PgPool) {
    let w = world(&pool).await;
    let server = app_role_server(&pool).await;
    let params = |claim: Uuid| GetBeliefParams {
        claim_id: claim.to_string(),
        frame_id: Some(w.private_frame.to_string()),
        perspective_id: None,
    };

    let mine = tools::ds::get_belief(&server, &w.member, params(w.private_claim))
        .await
        .map(|r| first_text(&r))
        .unwrap_or_else(|e| {
            panic!(
                "a member's framed belief over its group's private frame must be served (the \
                 pre-fix engine read the frame on an unstamped session and reported it \
                 missing): {}",
                e.message
            )
        });
    assert_eq!(mine["source"], "recomputed", "{mine}");
    let belief = mine["belief"].as_f64().expect("belief");
    assert!(
        belief > 0.0,
        "the member's fold must include its group's private BBA (mass 0.6 on h0): {mine}"
    );

    let theirs = tools::ds::get_belief(&server, &w.non_member, params(w.private_claim)).await;
    assert!(
        matches!(&theirs, Err(e) if e.message.contains("not found")),
        "a non-member must not see another group's private frame: {:?}",
        theirs.map(|r| first_text(&r))
    );

    // Public control: the unframed (cached) read of the public claim, for both.
    for (who, v) in [("member", &w.member), ("non-member", &w.non_member)] {
        tools::ds::get_belief(
            &server,
            v,
            GetBeliefParams {
                claim_id: w.public_claim.to_string(),
                frame_id: None,
                perspective_id: None,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("the {who} must read a public claim's belief: {}", e.message));
    }
}

/// The fail-closed half: a server with no `ScopedPool` refuses a content read
/// rather than reading on its plain pool.
#[sqlx::test(migrations = "../../migrations")]
async fn a_read_refuses_on_a_server_without_a_scoped_pool(pool: PgPool) {
    let w = world(&pool).await;
    let server = common::build_unscoped_test_server(pool.clone());
    let err = get_claim(&server, &w.member, w.public_claim)
        .await
        .expect_err("a server with no ScopedPool must refuse, not read unstamped");
    assert!(
        err.contains("not built from a ScopedPool"),
        "the refusal must name the missing ScopedPool: {err}"
    );
}
