//! A document ingest by an OPERATOR-LINKED agent is owned by its operator's
//! personal group, the same owner rule `submit_claim` / `memorize` apply, and
//! every refusal of that rule reaches the caller synchronously.
//!
//! # The defect this pins
//!
//! `IngestTx::owner_decl` (the Stamped arm every MCP ingest takes) resolved the
//! owner group as the AGENT's own personal group, with no operator lookup.
//! `ClaimRepository::default_decl_for_author` (memorize, submit_claim, REST)
//! asks `epigraph_operator_actor` first. Once operator binding is armed
//! (migration 122), the claims trigger refuses a linked agent's claim owned by
//! a group its operator does not write (`OPL02`), and the agent's own personal
//! group is such a group. Observed in a deployment with binding armed: a
//! linked agent that still held a live membership in its own personal group
//! (provisioned before the link) passed the synchronous preflight, was told
//! `queued`, and then lost the whole background walk to `OPL02`. Only the
//! server log saw it, and only the `papers` row remained.
//!
//! These tests rebuild that state in that ORDER: the server's first call
//! provisions the agent's own personal group, THEN the agent is linked, THEN
//! the database is armed.
//!
//! Both server pools are downgraded to `epigraph_app`. A superuser session is
//! exempt from `OPL02` (`epigraph_operator_scope_exempt`), so on the harness
//! pool none of this reproduces. Links, revocations and arming run on the
//! harness pool, which stands in for the maintenance connection.
//!
//! Verified to fail: with `owner_decl`'s Stamped arm reverted to the pure
//! personal-group read, both prod-shape positives fail (the direct walk with
//! `OPL02`; the handler with no `processed_by` edge, because its background
//! walk wrote nothing). The never-had-a-personal-group positive fails with the
//! "no LIVE membership of its personal group" refusal. The spine positive
//! fails with `OPL02`. Both revoked-link negatives and the unlinked-armed
//! negative fail because the handler answers `queued` and writes a `papers`
//! row. The unlinked-unarmed control passes either way, by design.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::{
    do_ingest_document, ingest_document_inline, ingest_document_spine,
};
use epigraph_mcp::types::{IngestDocumentInlineParams, IngestDocumentSpineParams};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

/// The signer seed of the server under test; its agent is the INGESTING agent.
const SEED: u8 = 0xC3;

/// An app-role stdio server whose own agent (the author of every ingest) is
/// the one keyed by `seed`.
async fn app_role_server(pool: &PgPool, seed: u8) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(plain, signer, embedder, /* read_only */ false).with_scoped_pool(scoped)
}

/// A full document (thesis, one section, one paragraph, one atom).
fn doc(doi: &str) -> DocumentExtraction {
    extraction(doi, true)
}

/// The same document with no atoms: the spine tool's input.
fn spine_doc(doi: &str) -> DocumentExtraction {
    extraction(doi, false)
}

fn extraction(doi: &str, with_atom: bool) -> DocumentExtraction {
    let atoms: Vec<String> = if with_atom {
        vec![format!("Operator owner atom {doi}")]
    } else {
        Vec::new()
    };
    let generality: Vec<u8> = if with_atom { vec![3] } else { Vec::new() };
    serde_json::from_value(serde_json::json!({
        "source": {"title": format!("Operator owner {doi}"), "doi": doi,
                   "source_type": "Paper", "authors": []},
        "thesis": format!("Operator owner thesis {doi}"),
        "thesis_derivation": "TopDown",
        "sections": [{"title": "S", "paragraphs": [{
            "text": format!("Operator owner paragraph {doi}"),
            "atoms": atoms,
            "generality": generality, "confidence": 0.8
        }]}],
        "relationships": []
    }))
    .expect("extraction")
}

async fn arm(pool: &PgPool) {
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(pool)
        .await
        .expect("arm (the harness stands in for the maintenance role)");
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("live link");
}

/// The agent's memberships of its OWN personal group, e.g. `admin(live)`, or
/// `None` when it has no such group.
async fn own_personal_state(pool: &PgPool, agent: Uuid) -> Option<String> {
    sqlx::query_scalar(
        "SELECT string_agg(m.role || CASE WHEN m.revoked_at IS NULL THEN '(live)' \
                                          ELSE '(revoked)' END, ',') \
           FROM groups g JOIN group_memberships m ON m.group_id = g.id AND m.agent_id = $1 \
          WHERE g.did_key = 'did:epigraph:personal:' || $1::text",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("own personal membership state")
}

async fn own_personal_group(pool: &PgPool, agent: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text")
        .bind(agent)
        .fetch_optional(pool)
        .await
        .expect("own personal group")
}

/// `(owner_group_id, agent_id, count)` over the document's `doi:` claims.
async fn doc_owners(pool: &PgPool, doi: &str) -> Vec<(Uuid, Uuid, i64)> {
    sqlx::query_as(
        "SELECT owner_group_id, agent_id, count(*) FROM claims WHERE $1 = ANY(labels) \
          GROUP BY 1, 2 ORDER BY 1, 2",
    )
    .bind(format!("doi:{doi}"))
    .fetch_all(pool)
    .await
    .expect("doc owners")
}

async fn doc_claims(pool: &PgPool, doi: &str) -> i64 {
    doc_owners(pool, doi).await.iter().map(|r| r.2).sum()
}

async fn papers_with(pool: &PgPool, doi: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM papers WHERE doi = $1")
        .bind(doi)
        .fetch_one(pool)
        .await
        .expect("papers count")
}

/// The paper's `processed_by` edges: the walk's last write, in the walk's one
/// transaction, so it is present exactly when the walk committed.
async fn processed_by(pool: &PgPool, doi: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges e JOIN papers p ON p.id = e.source_id \
          WHERE p.doi = $1 AND e.source_type = 'paper' AND e.relationship = 'processed_by'",
    )
    .bind(doi)
    .fetch_one(pool)
    .await
    .expect("processed_by count")
}

/// Every `doi:` claim is authored by `agent` and owned by `group`, there is at
/// least one, and the paper's `processed_by` edge exists.
async fn assert_landed_in(pool: &PgPool, doi: &str, agent: Uuid, group: Uuid, what: &str) {
    let owners = doc_owners(pool, doi).await;
    let total: i64 = owners.iter().map(|r| r.2).sum();
    assert!(total > 0, "{what}: the ingest wrote no claims");
    assert_eq!(
        owners,
        vec![(group, agent, total)],
        "{what}: every claim must be the ingesting agent's and owned by {group}"
    );
    assert!(
        processed_by(pool, doi).await > 0,
        "{what}: no processed_by edge"
    );
}

/// The prod shape: the agent's own personal group exists (admin, live), THEN
/// it is linked to `human`, THEN the database is armed. Returns the agent.
async fn linked_after_own_group(pool: &PgPool, server: &EpiGraphMcpFull, human: Uuid) -> Uuid {
    let agent = server.server_agent_id().await.expect("server agent");
    assert_eq!(
        own_personal_state(pool, agent).await.as_deref(),
        Some("admin(live)"),
        "CALIBRATION: the first call must provision the agent's own personal group before the link"
    );
    link(pool, agent, human).await;
    arm(pool).await;
    assert_eq!(
        own_personal_state(pool, agent).await.as_deref(),
        Some("admin(live)"),
        "CALIBRATION: linking and arming leave the agent's own personal membership live"
    );
    agent
}

async fn inline(server: &EpiGraphMcpFull, doi: &str) -> Result<serde_json::Value, String> {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("stdio viewer");
    ingest_document_inline(
        server,
        &viewer,
        IngestDocumentInlineParams {
            extraction: doc(doi),
        },
        None,
    )
    .await
    .map(|r| common::first_text(&r))
    .map_err(|e| e.message.to_string())
}

/// After a synchronous refusal, give a (wrongly) spawned walk time to land,
/// then assert that nothing did: no `papers` row and no claims.
async fn assert_nothing_written(pool: &PgPool, doi: &str) {
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        papers_with(pool, doi).await,
        0,
        "the refusal must precede the papers row"
    );
    assert_eq!(doc_claims(pool, doi).await, 0, "the refusal wrote claims");
}

/// The incident, end to end through the tool handler: `queued`, and then the
/// background walk lands in the OPERATOR's personal group. Pre-fix the handler
/// also answers `queued`, but the walk dies on `OPL02` and no `processed_by`
/// edge ever appears.
#[sqlx::test(migrations = "../../migrations")]
async fn inline_ingest_by_a_linked_agent_lands_in_its_operators_group(pool: PgPool) {
    let (human, human_group) = fixture::seed_human_operator(&pool, "human").await;
    let server = app_role_server(&pool, SEED).await;
    let agent = linked_after_own_group(&pool, &server, human).await;
    let own = own_personal_group(&pool, agent)
        .await
        .expect("own personal group");

    let doi = "10.9999/operator-owner-inline";
    let queued = inline(&server, doi)
        .await
        .expect("the preflight passes for a linked, acting agent");
    assert_eq!(queued["status"], "queued", "{queued}");

    // The walk is a detached task: wait for its commit, bounded.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    while processed_by(&pool, doi).await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no processed_by edge within 90 s: the background walk wrote nothing \
             (pre-fix: OPL02 on the first claim INSERT); claims: {:?}",
            doc_owners(&pool, doi).await
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_landed_in(&pool, doi, agent, human_group, "inline").await;
    assert_ne!(own, human_group);
}

/// The same state, driving the walk directly so the failure is the walk's own
/// error rather than a timeout.
#[sqlx::test(migrations = "../../migrations")]
async fn walk_by_a_linked_agent_lands_in_its_operators_group(pool: PgPool) {
    let (human, human_group) = fixture::seed_human_operator(&pool, "human").await;
    let server = app_role_server(&pool, SEED).await;
    let agent = linked_after_own_group(&pool, &server, human).await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");

    let doi = "10.9999/operator-owner-walk";
    do_ingest_document(&server, &viewer, &doc(doi), None)
        .await
        .map_err(|e| e.message.to_string())
        .expect("a linked, acting agent's walk must commit");
    assert_landed_in(&pool, doi, agent, human_group, "walk").await;
}

/// Linked BEFORE it ever had a personal group (armed before its first call,
/// so `agent_id()` does not provision one). Pre-fix: refused, "no LIVE
/// membership of its personal group".
#[sqlx::test(migrations = "../../migrations")]
async fn a_linked_agent_with_no_personal_group_ingests_into_its_operators_group(pool: PgPool) {
    let (human, human_group) = fixture::seed_human_operator(&pool, "human").await;
    let key = epigraph_crypto::AgentSigner::from_bytes(&[SEED; 32])
        .expect("signer")
        .public_key();
    let pre = epigraph_db::AgentRepository::create(
        &pool,
        &epigraph_core::Agent::new(key, Some("mcp-agent".to_string())),
    )
    .await
    .expect("the agent row, created before the server's first call")
    .id
    .as_uuid();
    link(&pool, pre, human).await;
    arm(&pool).await;

    let server = app_role_server(&pool, SEED).await;
    let agent = server.server_agent_id().await.expect("server agent");
    assert_eq!(
        agent, pre,
        "CALIBRATION: the server must resolve the pre-created agent"
    );
    assert_eq!(
        own_personal_group(&pool, agent).await,
        None,
        "CALIBRATION: a linked agent's first call after the arm provisions no personal group"
    );

    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");
    let doi = "10.9999/operator-owner-no-own-group";
    do_ingest_document(&server, &viewer, &doc(doi), None)
        .await
        .map_err(|e| e.message.to_string())
        .expect("a linked agent with no personal group of its own must ingest");
    assert_landed_in(&pool, doi, agent, human_group, "no own group").await;
}

/// `ingest_document_spine` (synchronous) in the prod shape.
#[sqlx::test(migrations = "../../migrations")]
async fn spine_by_a_linked_agent_lands_in_its_operators_group(pool: PgPool) {
    let (human, human_group) = fixture::seed_human_operator(&pool, "human").await;
    let server = app_role_server(&pool, SEED).await;
    let agent = linked_after_own_group(&pool, &server, human).await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");

    let doi = "10.9999/operator-owner-spine";
    ingest_document_spine(
        &server,
        &viewer,
        IngestDocumentSpineParams {
            extraction: spine_doc(doi),
        },
        None,
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("a linked, acting agent's spine must commit");
    assert_landed_in(&pool, doi, agent, human_group, "spine").await;
}

/// The operator revoked the AGENT's row in the operator's group: the link is
/// live but not acting, the fallback is the agent's own personal group, and
/// its operator does not write that. Refused by name, synchronously, with
/// nothing written. Pre-fix: `queued` plus a `papers` row.
#[sqlx::test(migrations = "../../migrations")]
async fn agent_revoked_in_its_operators_group_is_refused_opl02_synchronously(pool: PgPool) {
    let (human, human_group) = fixture::seed_human_operator(&pool, "human").await;
    let server = app_role_server(&pool, SEED).await;
    let agent = linked_after_own_group(&pool, &server, human).await;
    let revoked = sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() \
          WHERE agent_id = $1 AND group_id = $2 AND revoked_at IS NULL",
    )
    .bind(agent)
    .bind(human_group)
    .execute(&pool)
    .await
    .expect("revoke the agent in the operator's group")
    .rows_affected();
    assert_eq!(
        revoked, 1,
        "CALIBRATION: the link gave the agent one live row"
    );

    let doi = "10.9999/operator-owner-agent-revoked";
    let err = inline(&server, doi)
        .await
        .expect_err("a linked agent revoked in its operator's group must be refused");
    assert!(err.contains("OPL02"), "the refusal must be OPL02: {err}");
    assert_nothing_written(&pool, doi).await;
}

/// The OPERATOR no longer holds its own group (its row there revoked): the
/// agent's link is not acting, though the agent's own row there is still live.
/// Refused `OPL02`, synchronously, nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn operator_without_its_group_is_refused_opl02_synchronously(pool: PgPool) {
    let (human, human_group) = fixture::seed_human_operator(&pool, "human").await;
    let server = app_role_server(&pool, SEED).await;
    let _agent = linked_after_own_group(&pool, &server, human).await;
    let revoked = sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() \
          WHERE agent_id = $1 AND group_id = $2 AND revoked_at IS NULL",
    )
    .bind(human)
    .bind(human_group)
    .execute(&pool)
    .await
    .expect("revoke the operator's own row")
    .rows_affected();
    assert_eq!(revoked, 1, "CALIBRATION: the operator held one live row");

    let doi = "10.9999/operator-owner-operator-revoked";
    let err = inline(&server, doi)
        .await
        .expect_err("a link whose operator no longer holds its group must be refused");
    assert!(err.contains("OPL02"), "the refusal must be OPL02: {err}");
    assert_nothing_written(&pool, doi).await;
}

/// Unlinked, armed: refused `OPL01` by the preflight, before the `papers` row.
/// Pre-fix the preflight passed (the agent's own group is live and writable),
/// the handler answered `queued`, and the background walk died on the
/// trigger's `OPL01`. Same outcome, now reported to the caller.
#[sqlx::test(migrations = "../../migrations")]
async fn unlinked_agent_once_armed_is_refused_opl01_synchronously(pool: PgPool) {
    let server = app_role_server(&pool, SEED).await;
    let agent = server.server_agent_id().await.expect("server agent");
    assert_eq!(
        own_personal_state(&pool, agent).await.as_deref(),
        Some("admin(live)"),
        "CALIBRATION: the own personal group exists, so only the binding can refuse"
    );
    arm(&pool).await;

    let doi = "10.9999/operator-owner-unlinked-armed";
    let err = inline(&server, doi)
        .await
        .expect_err("an unbound agent must be refused once armed");
    assert!(err.contains("OPL01"), "the refusal must be OPL01: {err}");
    assert!(
        err.contains(&agent.to_string()),
        "the refusal names the agent: {err}"
    );
    assert_nothing_written(&pool, doi).await;
}

/// CONTROL: unlinked and unarmed, the owner is still the agent's own personal
/// group, through the handler. This passes before and after the fix.
#[sqlx::test(migrations = "../../migrations")]
async fn unlinked_unarmed_agent_still_ingests_into_its_own_personal_group(pool: PgPool) {
    let server = app_role_server(&pool, SEED).await;
    let agent = server.server_agent_id().await.expect("server agent");
    let own = own_personal_group(&pool, agent)
        .await
        .expect("own personal group");

    let doi = "10.9999/operator-owner-unlinked-unarmed";
    let queued = inline(&server, doi)
        .await
        .expect("an unlinked agent on an unarmed database ingests");
    assert_eq!(queued["status"], "queued", "{queued}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    while processed_by(&pool, doi).await == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no processed_by edge within 90 s; claims: {:?}",
            doc_owners(&pool, doi).await
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_landed_in(&pool, doi, agent, own, "unlinked unarmed").await;
}
