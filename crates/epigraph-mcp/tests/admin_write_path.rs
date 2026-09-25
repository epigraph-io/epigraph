//! Batch H-b, D2 over MCP: a `claims:admin` write into a group the admin cannot
//! write goes through the audited admin path (migration 111), records the ADMIN
//! as principal and writes a `security_events` audit row; everyone else stays
//! on their own stamp.
//!
//! This harness is BYPASSRLS, so it cannot see the clean-schema refusal the
//! admin path exists to get past — `epigraph-db/tests/admin_claim_write.rs`
//! measures that as `epigraph_app`, and `scripts/e2e/probe-batch-h.sh
//! caller_auth` through the real binary. What IS visible here is the ROUTING
//! (which writes take the path) and its data: the audit row, and the refusal of
//! a token whose client record holds no live grant, which the definer decides
//! on data rather than on a policy.
//!
//! Load-bearing, verified by reverting: `admin_write::takes_admin_path`
//! returning `false` fails the three "audited" arms (the write still lands on
//! this superuser harness, but with no audit row); returning `true`
//! unconditionally fails `an_admin_writing_a_group_it_can_write_keeps_its_own_stamp`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::build_scoped_test_server;
use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::visibility::Viewer;
use epigraph_mcp::tools;
use epigraph_mcp::types::{PatchClaimParams, ResolveBacklogItemParams, UpdateLabelsParams};
use sqlx::PgPool;
use uuid::Uuid;

struct Admin {
    agent: Uuid,
    group: Uuid,
    token: AuthContext,
    viewer: Viewer,
}

/// An admin agent with its own personal group, and a token whose `sub` is an
/// `oauth_clients` row bound to it. `grant = false` seeds no client row at all
/// (a token the definer cannot tie to any live grant).
async fn admin(pool: &PgPool, grant: bool) -> Admin {
    let (agent, group) = fixture::seed_agent_with_group(pool, "admin").await;
    let client = Uuid::new_v4();
    if grant {
        sqlx::query(
            "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, \
                                        granted_scopes, status, agent_id) \
             VALUES ($1, $2, 'admin', 'human', ARRAY['claims:admin'], ARRAY['claims:admin'], \
                     'active', $3)",
        )
        .bind(client)
        .bind(format!("admin-{client}"))
        .bind(agent)
        .execute(pool)
        .await
        .expect("seed the admin's client");
    }
    Admin {
        agent,
        group,
        token: AuthContext {
            client_id: client,
            agent_id: Some(agent),
            owner_id: None,
            client_type: ClientType::Human,
            scopes: vec![
                "claims:read".into(),
                "claims:write".into(),
                "claims:admin".into(),
            ],
            jti: Uuid::new_v4(),
        },
        viewer: Viewer::resolve(pool, agent).await.expect("admin viewer"),
    }
}

/// A public backlog claim owned by ANOTHER agent's personal group.
async fn foreign_claim(pool: &PgPool) -> Uuid {
    let (author, group) = fixture::seed_agent_with_group(pool, "author").await;
    let claim = fixture::seed_public_claim(pool, author, &format!("foreign item {author}")).await;
    sqlx::query("UPDATE claims SET owner_group_id = $2, labels = ARRAY['backlog'] WHERE id = $1")
        .bind(claim)
        .bind(group)
        .execute(pool)
        .await
        .expect("own the claim by its author's group");
    claim
}

async fn audit(pool: &PgPool, admin: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details FROM security_events \
          WHERE event_type = 'claims.admin_write' AND agent_id = $1 ORDER BY created_at",
    )
    .bind(admin)
    .fetch_all(pool)
    .await
    .expect("audit")
}

async fn labels(pool: &PgPool, claim: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("labels")
}

fn retire(claim: Uuid) -> UpdateLabelsParams {
    UpdateLabelsParams {
        claim_id: claim.to_string(),
        add: vec!["resolved".into()],
        remove: vec![],
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_relabels_a_foreign_group_claim_through_the_audited_path(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let a = admin(&pool, true).await;
    let claim = foreign_claim(&pool).await;

    let out = tools::claims::update_labels(&server, &a.viewer, retire(claim), Some(&a.token))
        .await
        .expect("claims:admin with a live grant retires a foreign item");
    let body = common::first_text(&out);
    assert_eq!(body["admin_path"], serde_json::json!(true), "{body}");
    assert!(labels(&pool, claim).await.contains(&"resolved".to_string()));

    let rows = audit(&pool, a.agent).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["action"], "update_labels");
    assert_eq!(rows[0]["admin_agent_id"], a.agent.to_string());
    assert_eq!(rows[0]["client_id"], a.token.client_id.to_string());
    assert_eq!(rows[0]["token_jti"], a.token.jti.to_string());
    assert_eq!(rows[0]["claim_id"], claim.to_string());
    assert_eq!(
        rows[0]["after"]["labels"],
        serde_json::json!(["backlog", "resolved"])
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_token_without_a_live_grant_is_refused_and_writes_nothing(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let a = admin(&pool, false).await;
    let claim = foreign_claim(&pool).await;

    let err = tools::claims::update_labels(&server, &a.viewer, retire(claim), Some(&a.token))
        .await
        .expect_err("a token whose client record holds no claims:admin grant is refused");
    assert!(
        err.message.contains("audited admin path refused"),
        "{}",
        err.message
    );
    assert!(!labels(&pool, claim).await.contains(&"resolved".to_string()));
    assert!(audit(&pool, a.agent).await.is_empty());
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_writing_a_group_it_can_write_keeps_its_own_stamp(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let a = admin(&pool, true).await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let claim = fixture::seed_public_claim(&pool, author, "an item in the admin's own group").await;
    sqlx::query("UPDATE claims SET owner_group_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(a.group)
        .execute(&pool)
        .await
        .expect("own it by the admin's group");

    let out = tools::claims::update_labels(&server, &a.viewer, retire(claim), Some(&a.token))
        .await
        .expect("an admin writing its own group");
    assert_eq!(
        common::first_text(&out)["admin_path"],
        serde_json::json!(false)
    );
    assert!(labels(&pool, claim).await.contains(&"resolved".to_string()));
    assert!(
        audit(&pool, a.agent).await.is_empty(),
        "a write the caller's own stamp can make is not an admin crossing"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_patch_of_a_foreign_group_claim_is_audited(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let a = admin(&pool, true).await;
    let claim = foreign_claim(&pool).await;

    let out = tools::claims::patch_claim(
        &server,
        &a.viewer,
        PatchClaimParams {
            claim_id: claim.to_string(),
            trace_id: None,
            properties: Some(serde_json::json!({"reviewed_by_admin": true})),
            add_labels: vec![],
            remove_labels: vec!["backlog".into()],
        },
        Some(&a.token),
    )
    .await
    .expect("admin patch");
    let body = common::first_text(&out);
    assert_eq!(body["admin_path"], serde_json::json!(true), "{body}");
    assert_eq!(
        body["after_properties"]["reviewed_by_admin"],
        serde_json::json!(true)
    );
    let rows = audit(&pool, a.agent).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["action"], "patch_claim");
    assert_eq!(rows[0]["before"]["labels"], serde_json::json!(["backlog"]));
    assert_eq!(rows[0]["after"]["labels"], serde_json::json!([]));
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_resolves_a_foreign_backlog_item_in_one_audited_unit(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let a = admin(&pool, true).await;
    let claim = foreign_claim(&pool).await;

    let out = tools::claims::resolve_backlog_item(
        &server,
        &a.viewer,
        ResolveBacklogItemParams {
            original_id: claim.to_string(),
            resolution_content: "retired by an admin across groups".to_string(),
            methodology: None,
            basis_claim_ids: Vec::new(),
        },
        Some(&a.token),
    )
    .await
    .expect("admin resolve");
    let body = common::first_text(&out);
    let resolution: Uuid = body["resolution_claim_id"]
        .as_str()
        .expect("resolution id")
        .parse()
        .expect("uuid");
    let (author, owner): (Uuid, Uuid) =
        sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE id = $1")
            .bind(resolution)
            .fetch_one(&pool)
            .await
            .expect("resolution row");
    assert_eq!(
        (author, owner),
        (a.agent, a.group),
        "the resolution is the ADMIN's own"
    );
    assert!(labels(&pool, claim).await.contains(&"resolved".to_string()));
    let rows = audit(&pool, a.agent).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["action"], "resolve_backlog_item");
}
