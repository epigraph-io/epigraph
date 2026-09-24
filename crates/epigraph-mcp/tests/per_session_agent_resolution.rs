//! F1 (`da432f25`): a NEW HTTP session must not re-provision — and so must not
//! revive — the server agent's revoked personal membership.
//!
//! # The defect
//!
//! rmcp's streamable-HTTP transport calls its factory once per SESSION, and the
//! factory built each session's server with an EMPTY `agent_db_id` cell. The
//! first tool call of every session therefore re-ran
//! `EpiGraphMcpFull::agent_id`'s PR-09 `ensure_personal_group`, whose
//! migration-077 body is `ON CONFLICT … DO UPDATE SET revoked_at = NULL, role =
//! 'admin'`. MEASURED on the real binary as `epigraph_app`: the first
//! `ingest_document_inline` of a new session committed +4 claims under the
//! revived membership.
//!
//! # How these arms reach the real path
//!
//! They build sessions through `epigraph_mcp::SessionFactory` — the type
//! `main`'s factory closure now calls — from a template configured the way
//! `main` configures it (`new_shared_with_federation` + `with_scoped_pool`).
//!
//! The revival itself does NOT depend on the connection's role:
//! `epigraph_ensure_personal_group` is `SECURITY DEFINER`, so it revives whether
//! it is called as `epigraph_app` or as the `#[sqlx::test]` superuser. That is
//! why the superuser pool is a faithful instrument for THIS arm (unlike an arm
//! whose defect is a blind RLS read). The refusal that must follow is decided on
//! the transaction `ScopedPool::begin_as` stamps from the agent's viewer —
//! `IngestTx::owner_decl` asks `personal = ANY(epigraph_writable_groups())`, a
//! GUC read — so it is observable here too.
//!
//! # Verified to fail
//!
//! With `SessionFactory::session` reverted to give each session a fresh
//! `agent_db_id` cell (the pre-fix factory), [`a_new_session_does_not_revive_a_revoked_server_agent`]
//! FAILS: the new session's `agent_id()` revives the membership, the preflight
//! passes, and the detached walk commits claims. See the commit message for the
//! recorded output.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::tools::ingestion::ingest_document_inline;
use epigraph_mcp::types::IngestDocumentInlineParams;
use epigraph_mcp::{EpiGraphMcpFull, SessionFactory};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

/// The factory exactly as `main` builds it for the HTTP listener.
async fn factory_like_main(pool: &PgPool) -> SessionFactory {
    let scoped = fixture::scoped_pool(pool).await;
    let signer = Arc::new(AgentSigner::from_bytes(&[0x5Eu8; 32]).expect("signer"));
    let embedder = Arc::new(McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone()));
    let template = EpiGraphMcpFull::new_shared_with_federation(
        pool.clone(),
        signer,
        embedder,
        false,
        epigraph_mcp::federation::SharedFederation::empty(),
        None,
    )
    .with_scoped_pool(scoped);
    SessionFactory::new(template)
}

fn doc(doi: &str) -> DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {"title": format!("Per-session {doi}"), "doi": doi,
                   "source_type": "Paper", "authors": []},
        "thesis": format!("Per-session thesis {doi}"),
        "thesis_derivation": "TopDown",
        "sections": [{"title": "S", "paragraphs": [{
            "text": format!("Per-session paragraph {doi}"),
            "atoms": [format!("Per-session atom {doi}")],
            "generality": [3], "confidence": 0.8
        }]}],
        "relationships": []
    }))
    .expect("extraction")
}

async fn personal_group(pool: &PgPool, agent: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("personal group provisioned by the first session")
}

async fn membership_state(pool: &PgPool, agent: Uuid, group: Uuid) -> String {
    sqlx::query_scalar(
        "SELECT string_agg(role || CASE WHEN revoked_at IS NULL THEN '(live)' ELSE '(revoked)' END, ',') \
         FROM group_memberships WHERE agent_id = $1 AND group_id = $2",
    )
    .bind(agent)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("membership state")
}

async fn claims_by(pool: &PgPool, agent: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE agent_id = $1")
        .bind(agent)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// CONTROL: a new session of a server whose personal membership is LIVE
/// ingests. Without it the refusal arm could pass because ingest is broken.
#[sqlx::test(migrations = "../../migrations")]
async fn control_a_new_session_of_a_live_server_agent_ingests(pool: PgPool) {
    let sessions = factory_like_main(&pool).await;
    let agent = sessions.session().server_agent_id().await.expect("resolve");

    let second = sessions.session();
    let viewer = fixture::public_viewer(&pool).await;
    ingest_document_inline(
        &second,
        &viewer,
        IngestDocumentInlineParams {
            extraction: doc("10.9999/per-session-control"),
        },
    )
    .await
    .expect("a live personal membership must be admitted by a new session");
    let mut n = 0;
    for _ in 0..40 {
        n = claims_by(&pool, agent).await;
        if n > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    assert!(n > 0, "control: the detached walk wrote nothing");
}

/// F1: revoke the server agent's personal membership after the process has
/// resolved it, open a NEW session, call `ingest_document_inline`. Expect:
/// refused, still revoked, zero claims.
#[sqlx::test(migrations = "../../migrations")]
async fn a_new_session_does_not_revive_a_revoked_server_agent(pool: PgPool) {
    let sessions = factory_like_main(&pool).await;
    // Session 1 resolves the agent — and, on first boot, provisions it.
    let agent = sessions.session().server_agent_id().await.expect("resolve");
    let personal = personal_group(&pool, agent).await;
    assert_eq!(
        membership_state(&pool, agent, personal).await,
        "admin(live)"
    );

    // The operator revokes it.
    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() WHERE agent_id = $1 AND group_id = $2",
    )
    .bind(agent)
    .bind(personal)
    .execute(&pool)
    .await
    .unwrap();
    let before = claims_by(&pool, agent).await;

    // A NEW session, built the way the HTTP factory builds one.
    let fresh = sessions.session();
    let viewer = fixture::public_viewer(&pool).await;
    let res = ingest_document_inline(
        &fresh,
        &viewer,
        IngestDocumentInlineParams {
            extraction: doc("10.9999/per-session-revoked"),
        },
    )
    .await;

    // Give a (wrongly) spawned walk time to land before asserting it did not.
    tokio::time::sleep(std::time::Duration::from_millis(3000)).await;
    assert_eq!(
        membership_state(&pool, agent, personal).await,
        "admin(revoked)",
        "a new session must not revive the revoked personal membership"
    );
    assert_eq!(
        claims_by(&pool, agent).await - before,
        0,
        "nothing may be written under a revoked membership"
    );
    assert!(res.is_err(), "the ingest must be refused, got {res:?}");
}
