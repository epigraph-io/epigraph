//! A role-derived group member's MCP read lapses with its role assignment
//! (backlog 6e22596c, design #17's MCP leg).
//!
//! Migration 165 makes a registered human holding a role bound to a group a
//! live member of it, computed at every viewer resolve and never written as a
//! membership row, so the membership ends at the assignment's end with no job.
//! `group_role_membership.rs` pins that at the database. This pins it on the
//! MCP surface: the viewer is resolved the way the HTTP transport resolves it
//! for each tool call (`tools::viewer::request_viewer` from the token's
//! `AuthContext`), and `get_claim` runs on the server's application-role
//! pools, so row security decides as in production.
//!
//! This is a tool-level call with the transport's viewer resolution, not a
//! request through the HTTP listener: the listener adds the token check and
//! the scope ceiling in front of the same two calls, and neither depends on
//! group membership. The REST leg, with a minted token through the router,
//! is `epigraph-api/tests/group_routes_app_role.rs`
//! (`a_role_holder_reads_the_group_until_its_assignment_ends`).

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::claims::get_claim;
use epigraph_mcp::tools::viewer::request_viewer;
use epigraph_mcp::types::GetClaimParams;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    build_scoped_test_server(plain, scoped)
}

/// The `AuthContext` an HTTP token for `principal` carries.
fn token_context(principal: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(principal),
        owner_id: None,
        client_type: ClientType::Agent,
        scopes: vec!["claims:read".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        delegated_by: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Armed,
    }
}

/// Whether `caller` reads `claim` through `get_claim`, with a viewer resolved
/// afresh for this call as the HTTP transport resolves it.
async fn reads(server: &EpiGraphMcpFull, caller: Uuid, claim: Uuid) -> bool {
    let viewer = request_viewer(server, Some(&token_context(caller)))
        .await
        .expect("a registered human's token resolves a viewer");
    match get_claim(
        server,
        &viewer,
        GetClaimParams {
            claim_id: claim.to_string(),
            frame_id: None,
            perspective_id: None,
        },
    )
    .await
    {
        Ok(out) => {
            let body = first_text(&out);
            assert_eq!(
                body["id"].as_str(),
                Some(claim.to_string().as_str()),
                "a read answers the claim asked for: {body}"
            );
            true
        }
        Err(e) => {
            assert!(
                e.message.contains("not found"),
                "an unreadable claim is NOT FOUND, never another error: {}",
                e.message
            );
            false
        }
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_role_holders_mcp_read_lapses_when_its_assignment_ends(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (owner, _) = fixture::seed_human_operator(&pool, "6e22596c-owner").await;
    let (holder, _) = fixture::seed_human_operator(&pool, "6e22596c-holder").await;
    let (stranger, _) = fixture::seed_human_operator(&pool, "6e22596c-stranger").await;
    let group = fixture::verb_team_group(&pool, "Synthetic MCP Role Team", owner).await;
    let role = "role:synthetic-mcp-reader";
    fixture::bind_new_role_to_group(&pool, role, group, "reader", false).await;
    let claim =
        fixture::seed_group_claim(&pool, owner, group, "6e22596c group-private claim").await;

    assert!(
        reads(&server, owner, claim).await,
        "POSITIVE CONTROL: the group's admin reads its claim"
    );
    assert!(
        !reads(&server, holder, claim).await,
        "before the grant the holder-to-be is a stranger to the group"
    );

    let assignment = fixture::grant_role_now(&pool, role, holder).await;
    assert!(
        !fixture::has_unrevoked_row(&pool, group, holder).await,
        "PREMISE: the holder holds no membership row"
    );
    assert!(
        reads(&server, holder, claim).await,
        "while the assignment is live, the role-derived member reads the claim"
    );
    assert!(
        !reads(&server, stranger, claim).await,
        "NEGATIVE CONTROL: a registered human without the role does not"
    );

    fixture::end_role_assignment(&pool, assignment).await;
    assert!(
        !reads(&server, holder, claim).await,
        "once the assignment ends, the next call's viewer no longer reads the claim"
    );
    assert!(
        reads(&server, owner, claim).await,
        "POSITIVE CONTROL: the admin still reads it"
    );
}
