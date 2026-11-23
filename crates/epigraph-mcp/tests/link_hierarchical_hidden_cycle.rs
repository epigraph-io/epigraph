//! MCP `link_hierarchical` refuses a workflow-reference cycle closed through
//! edges the caller cannot read, without naming them (backlog 7149132e).
//!
//! Before migration 254 the cycle guard walked on the caller's stamped
//! application session, so `edges_tenancy` hid another group's private edges
//! from it. With `W1 -executes-> S -invokes-> W2`, `S` private to another
//! group (both edges take its tenancy), a caller outside that group could
//! write `W2 -invokes-> W1` and close a cycle every wider walker then meets.
//!
//! Driven on the APPLICATION ROLE (a `ScopedPool` downgraded to
//! `epigraph_app`), where row security is in force: on the superuser harness
//! every edge is readable and the old guard already refused. Calibrated in the
//! same test: the edges are private to the other group, the caller's stamped
//! session reads neither, and once the hidden `executes` edge is retired the
//! same call is admitted on the same server (so the refusal came from the
//! hidden path, not from an application-role failure).

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::tools::link_hierarchical::do_link_hierarchical;
use epigraph_mcp::types::{LinkHierarchicalParams, StoreWorkflowParams};
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

/// `build_scoped_test_server`'s signer: the app-role server below is the same
/// agent, so it is the submitter of the workflows the harness stores.
const SIGNER: [u8; 32] = [0xA7; 32];

async fn store(server: &EpiGraphMcpFull, step: &str) -> Uuid {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("stdio viewer");
    let stored = epigraph_mcp::tools::workflows::store_workflow(
        server,
        &viewer,
        StoreWorkflowParams {
            tenancy: Some(stdio_public_tenancy(server).await),
            goal: format!("hidden cycle probe {}", Uuid::new_v4()),
            steps: vec![step.to_string()],
            prerequisites: None,
            expected_outcome: None,
            confidence: None,
            tags: None,
            force_new: None,
        },
        None,
    )
    .await
    .expect("store_workflow");
    parse_uuid_field(&first_text(&stored), "workflow_id")
}

/// An in-force edge written on the harness connection, its tenancy left to
/// the edges trigger (the meet of its endpoints).
async fn hidden_edge(
    pool: &PgPool,
    source: (Uuid, &str),
    target: (Uuid, &str),
    relationship: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(source.0)
    .bind(source.1)
    .bind(target.0)
    .bind(target.1)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("seed edge")
}

async fn in_force(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND target_id = $2 \
           AND relationship = $3 AND (valid_to IS NULL OR valid_to > now())",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("count edges")
}

fn invokes(source: Uuid, target: Uuid) -> LinkHierarchicalParams {
    LinkHierarchicalParams {
        source_claim_id: source.to_string(),
        target_claim_id: target.to_string(),
        relationship: "invokes".to_string(),
        source_type: Some("workflow".to_string()),
        target_type: Some("workflow".to_string()),
        ..Default::default()
    }
}

/// The app-role stdio server for [`SIGNER`], and its scoped pool.
async fn app_role_server(pool: &PgPool) -> (EpiGraphMcpFull, ScopedPool) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: the hidden arm is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&SIGNER).expect("signer");
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    let server = EpiGraphMcpFull::new(plain, signer, embedder, /* read_only */ false)
        .with_scoped_pool(scoped.clone());
    (server, scoped)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_cycle_closed_through_unreadable_edges_is_refused_without_naming_them(pool: PgPool) {
    let harness = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let w1 = store(&harness, "w1 runs a step another group owns").await;
    let w2 = store(&harness, "w2 sub step").await;

    // Another group's private step: W1 executes it and it invokes W2. Both
    // edges take the step's tenancy.
    let (other, theirs) = fixture::seed_agent_with_group(&pool, "7149132e-other").await;
    let step = fixture::seed_group_claim(&pool, other, theirs, "7149132e private step").await;
    let exec = hidden_edge(&pool, (w1, "workflow"), (step, "claim"), "executes").await;
    let inv = hidden_edge(&pool, (step, "claim"), (w2, "workflow"), "invokes").await;
    for id in [exec, inv] {
        let (vis, owner): (String, Uuid) =
            sqlx::query_as("SELECT visibility, owner_group_id FROM edges WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("read edge tenancy");
        assert_eq!(
            (vis.as_str(), owner),
            ("group", theirs),
            "calibration: edge {id} is private to the other group"
        );
    }

    let (app, scoped) = app_role_server(&pool).await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&app, None)
        .await
        .expect("app-role stdio viewer");
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped transaction");
    let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM edges WHERE id = ANY($1)")
        .bind(vec![exec, inv])
        .fetch_one(&mut *tx)
        .await
        .expect("count readable edges");
    tx.rollback().await.expect("rollback");
    assert_eq!(seen, 0, "calibration: the caller reads neither hidden edge");

    let result = do_link_hierarchical(&app, &viewer, invokes(w2, w1), None).await;
    let err = match result {
        Err(err) => err,
        Ok(ok) => panic!(
            "7149132e: W2 invokes W1 closes W1 -executes-> S -invokes-> W2 through edges the \
             caller cannot read, and was admitted: {}",
            first_text(&ok)
        ),
    };
    assert!(
        err.message.contains("would close a cycle"),
        "refused as a cycle: {}",
        err.message
    );
    for hidden in [step, exec, inv, theirs, other] {
        assert!(
            !err.message.contains(&hidden.to_string()),
            "the refusal must not name the hidden {hidden}: {}",
            err.message
        );
    }
    assert_eq!(
        in_force(&pool, w2, w1, "invokes").await,
        0,
        "nothing written"
    );

    // Control: retire the hidden executes edge. The path is gone, and the
    // same call on the same application-role server is admitted.
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 second' WHERE id = $1")
        .bind(exec)
        .execute(&pool)
        .await
        .expect("retire the hidden executes edge");
    let ok = do_link_hierarchical(&app, &viewer, invokes(w2, w1), None)
        .await
        .expect("with no path, W2 invokes W1 is admitted on the application role");
    assert_eq!(first_text(&ok)["created"], serde_json::json!(true));
    assert_eq!(in_force(&pool, w2, w1, "invokes").await, 1);
}
