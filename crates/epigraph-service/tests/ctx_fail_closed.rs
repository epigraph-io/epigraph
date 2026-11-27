//! `Ctx` keeps the MCP server's fail-closed tenancy behaviour after the move
//! into the service crate (backlog 30133ca8): with no `ScopedPool`, a stamped
//! read and an author-stamped write each refuse with a designed error that
//! names the fix, before any I/O, and neither falls back to the plain pool.
//!
//! The pool here is lazy and points at a closed port, so a test that reached
//! the database would fail on the connection instead of passing.

use std::sync::Arc;

use epigraph_crypto::AgentSigner;
use epigraph_db::visibility::Viewer;
use epigraph_service::ctx::{begin_author_stamped_tx, begin_author_stamped_tx_for};
use epigraph_service::{Ctx, ServiceError};

fn unreachable_ctx() -> Ctx {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(300))
        .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
        .expect("a lazy pool never connects at construction");
    let signer = Arc::new(AgentSigner::from_bytes(&[0x5Eu8; 32]).expect("signer"));
    Ctx::new(pool, signer, None)
}

#[tokio::test]
async fn a_ctx_without_a_scoped_pool_refuses_the_stamped_read() {
    let ctx = unreachable_ctx();
    let err = ctx
        .read_as(&Viewer::public_only(), "probe_tool")
        .await
        .expect_err("no ScopedPool: the read must be refused, not run on the plain pool");
    match err {
        ServiceError::Internal(m) => {
            assert!(m.starts_with("probe_tool: "), "{m}");
            assert!(m.contains("was not built from a ScopedPool"), "{m}");
            assert!(m.contains("Nothing was read"), "{m}");
        }
        other => panic!("expected the designed internal refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_ctx_without_a_scoped_pool_refuses_the_author_stamped_write() {
    let ctx = unreachable_ctx();
    let agent = uuid::Uuid::new_v4();
    ctx.seed_agent_id_for_tests(agent).await;
    // stdio shape: no token, so the author is the process's own agent.
    let author = ctx
        .write_identity(None, &Viewer::public_only())
        .await
        .expect("the seeded agent resolves without the database");
    assert_eq!(author.agent_id(), agent);

    for result in [
        begin_author_stamped_tx(&ctx, author, "probe_write").await,
        begin_author_stamped_tx_for(&ctx, author, "probe_write", None).await,
    ] {
        match result.expect_err("no ScopedPool: the write must be refused") {
            ServiceError::Internal(m) => {
                assert!(m.starts_with("probe_write: "), "{m}");
                assert!(m.contains("was not built from a ScopedPool"), "{m}");
                assert!(m.contains("Nothing was"), "{m}");
                assert!(
                    m.contains("with_scoped_pool"),
                    "the refusal names the fix: {m}"
                );
            }
            other => panic!("expected the designed internal refusal, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn clones_share_one_resolved_agent_cell() {
    let ctx = unreachable_ctx();
    let clone = ctx.clone();
    assert!(ctx.shares_agent_cell_with(&clone));
    assert!(!ctx.shares_agent_cell_with(&unreachable_ctx()));

    let agent = uuid::Uuid::new_v4();
    ctx.seed_agent_id_for_tests(agent).await;
    assert_eq!(
        clone
            .agent_id()
            .await
            .expect("answered from the shared cell"),
        agent
    );
    assert_eq!(clone.signer_agent_id().await.expect("same cell"), agent);
}

#[tokio::test]
async fn an_unresolved_agent_on_an_unreachable_pool_is_a_fault_not_a_caller_error() {
    let ctx = unreachable_ctx();
    match ctx.agent_id().await {
        Err(e @ ServiceError::Fault(_)) => {
            assert_eq!(e.message(), None, "a fault's text is the server log's");
        }
        other => panic!("expected a fault, got {other:?}"),
    }
}

/// A token-bearing request whose viewer names another principal is refused,
/// and a token with no agent is a denial.
#[tokio::test]
async fn the_write_identity_resolver_refuses_diverging_or_missing_principals() {
    let ctx = unreachable_ctx();
    let mut auth = epigraph_auth::AuthContext {
        client_id: uuid::Uuid::new_v4(),
        agent_id: Some(uuid::Uuid::new_v4()),
        owner_id: None,
        client_type: epigraph_auth::ClientType::Agent,
        scopes: vec!["claims:write".to_string()],
        jti: uuid::Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        delegated_by: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Armed,
    };
    match ctx
        .write_identity(Some(&auth), &Viewer::public_only())
        .await
    {
        Err(ServiceError::Internal(m)) => assert!(m.contains("diverge"), "{m}"),
        other => panic!("expected the diverging-principals refusal, got {other:?}"),
    }
    auth.agent_id = None;
    match ctx
        .write_identity(Some(&auth), &Viewer::public_only())
        .await
    {
        Err(ServiceError::Denied(m)) => assert!(m.contains("no agent principal"), "{m}"),
        other => panic!("expected the no-principal denial, got {other:?}"),
    }
}
