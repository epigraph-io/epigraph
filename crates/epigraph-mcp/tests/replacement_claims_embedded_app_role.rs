//! `supersede_claim` and `evolve_step` embed the claim they insert (backlog
//! 7628ab2c).
//!
//! Both tools insert a new CURRENT claim (the replacement, or the new step on
//! `supersedes` and `revises` alike) and, before this fix, never embedded it:
//! the act commits, the response is a success, and the claim carries
//! `embedding IS NULL`, invisible to `recall()` until a maintenance backfill
//! happens to reach it. CLAUDE.md's write-path rule asks every claim insert to
//! embed post-commit, best-effort.
//!
//! The arms run on the APPLICATION ROLE (`epigraph_app`, no BYPASSRLS), as
//! `evolve_step_cascade_app_role.rs` does, so the stamped store's row security
//! is real: the harness superuser would store a vector whatever the stamp.
//!
//! The supersede arm with a FOREIGN author pins which identity stores the
//! vector. The replacement inherits the retired claim's author, who need not
//! write the group the claim lives in; the principal whose transaction just
//! INSERTed the row does. Stamping the store from the inherited author leaves
//! that arm unembedded.
//!
//! # Verified to fail
//!
//! With the four post-commit embed calls removed (`tools/supersede.rs::
//! supersede_claim`, `tools/evolve_step.rs::evolve_step`), every arm fails on
//! its `embedding IS NOT NULL` assertion. With `supersede_claim`'s store
//! stamped from the inherited author instead of `actor`, the foreign-author
//! arm fails the same way and the others pass.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::evolve_step::{evolve_step, EvolveStepParams};
use epigraph_mcp::tools::supersede::supersede_claim;
use epigraph_mcp::types::SupersedeClaimParams;
use sqlx::PgPool;
use uuid::Uuid;

/// An app-role stdio server whose own agent (the CALLER of every tool) is
/// pre-created and keyed by `seed`. Its embedder is a deterministic generator
/// (no request leaves the process), so a vector is always generated and only
/// the store can fail.
async fn app_role_server(pool: &PgPool, seed: u8) -> (EpiGraphMcpFull, Uuid) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let caller: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'mcp-agent') RETURNING id",
    )
    .bind(signer.public_key().as_slice())
    .fetch_one(pool)
    .await
    .expect("the caller's agent row");
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let embedder = epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|_text: &str| Ok(vec![0.01_f32; 1536])));
    let server = EpiGraphMcpFull::new(plain, signer, embedder, /* read_only */ false)
        .with_scoped_pool(scoped);
    (server, caller)
}

/// A human operator, the caller live-linked to it, and the database armed.
/// Returns the operator's group, which the caller writes.
async fn bind_and_arm(pool: &PgPool, caller: Uuid) -> Uuid {
    let (human, group) = fixture::seed_human_operator(pool, "embed-replacement-human").await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, caller, human)
        .await
        .expect("live link");
    drop(conn);
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(pool)
        .await
        .expect("arm (the harness stands in for the maintenance role)");
    group
}

/// `(is_current, embedding IS NOT NULL)` for `id`, read on the harness
/// superuser so row security hides nothing.
async fn current_and_embedded(pool: &PgPool, id: Uuid) -> (bool, bool) {
    sqlx::query_as("SELECT is_current, embedding IS NOT NULL FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("the claim")
}

fn supersede_params(old: Uuid, content: &str) -> SupersedeClaimParams {
    SupersedeClaimParams {
        claim_id: old.to_string(),
        content: content.to_string(),
        truth_value: 0.7,
        reason: "embed test".to_string(),
    }
}

fn evolve_params(parent: Uuid, edge_type: &str, content: &str) -> EvolveStepParams {
    EvolveStepParams {
        parent_id: parent.to_string(),
        canonical_name: None,
        step_index: None,
        step_lineage_id: String::new(),
        content: content.to_string(),
        edge_type: edge_type.to_string(),
        rationale: Some("embed test".to_string()),
        level: Some(2),
    }
}

async fn stdio_viewer(server: &EpiGraphMcpFull) -> epigraph_db::visibility::Viewer {
    epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("stdio viewer")
}

#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_embeds_the_replacement_on_the_app_role(pool: PgPool) {
    let (server, caller) = app_role_server(&pool, 0xE1).await;
    let group = bind_and_arm(&pool, caller).await;
    let old = fixture::seed_group_claim(&pool, caller, group, "the yield is 40%").await;

    let viewer = stdio_viewer(&server).await;
    let r = supersede_claim(
        &server,
        &viewer,
        supersede_params(old, "the yield is 42%"),
        None,
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("the bound author supersedes its own claim on the app role, armed");
    let body = first_text(&r);
    let new_id = parse_uuid_field(&body, "new_claim_id");

    assert_eq!(
        current_and_embedded(&pool, old).await,
        (false, false),
        "calibration: the retired claim is retired and unembedded"
    );
    assert_eq!(
        current_and_embedded(&pool, new_id).await,
        (true, true),
        "the replacement is current AND embedded: {body}"
    );
    assert_eq!(body["embedded"], true, "the response reports it: {body}");
}

/// A writer of the claim's group supersedes a claim ANOTHER agent authored.
/// The replacement keeps that author, who does not write the group; the
/// vector must be stored on the stamp that wrote the row, the caller's.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_of_a_foreign_authors_claim_embeds_on_the_writers_stamp(pool: PgPool) {
    let (server, _) = app_role_server(&pool, 0xE2).await;
    let (caller, auth, viewer) = seed_caller(&pool, &["claims:read", "claims:write"]).await;
    let caller_group = personal_group_of(&pool, caller).await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "embed-foreign-author").await;
    let old = fixture::seed_group_claim(&pool, author, caller_group, "a foreign claim").await;
    let author_writes: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM group_memberships WHERE group_id = $1 AND agent_id = $2)",
    )
    .bind(caller_group)
    .bind(author)
    .fetch_one(&pool)
    .await
    .expect("membership");
    assert!(
        !author_writes,
        "calibration: the inherited author is no member of the claim's group"
    );

    let r = supersede_claim(
        &server,
        &viewer,
        supersede_params(old, "a foreign claim, restated"),
        Some(&auth),
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("a writer of the owning group supersedes the claim");
    let body = first_text(&r);
    let new_id = parse_uuid_field(&body, "new_claim_id");
    let new_author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(new_id)
        .fetch_one(&pool)
        .await
        .expect("replacement");
    assert_eq!(
        new_author, author,
        "calibration: the replacement inherits the foreign author"
    );
    assert_eq!(
        current_and_embedded(&pool, new_id).await,
        (true, true),
        "the replacement is embedded on the writer's stamp: {body}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_embeds_the_new_step_on_supersedes_and_revises(pool: PgPool) {
    let (server, caller) = app_role_server(&pool, 0xE3).await;
    let group = bind_and_arm(&pool, caller).await;
    let viewer = stdio_viewer(&server).await;

    for edge_type in ["supersedes", "revises"] {
        let parent = fixture::seed_group_claim(
            &pool,
            caller,
            group,
            &format!("F1: filter the sample ({edge_type})"),
        )
        .await;
        let r = evolve_step(
            &server,
            &viewer,
            evolve_params(parent, edge_type, &format!("F1 v2 ({edge_type})")),
            None,
        )
        .await
        .map_err(|e| e.message.to_string())
        .unwrap_or_else(|e| panic!("{edge_type}: the bound caller evolves its step: {e}"));
        let body = first_text(&r);
        let new_id = parse_uuid_field(&body, "claim_id");
        assert_eq!(
            current_and_embedded(&pool, parent).await.0,
            edge_type == "revises",
            "calibration: {edge_type} retires the parent only on supersedes"
        );
        assert_eq!(
            current_and_embedded(&pool, new_id).await,
            (true, true),
            "{edge_type}: the new step is current AND embedded: {body}"
        );
        assert_eq!(body["embedded"], true, "{edge_type}: {body}");
    }
}
