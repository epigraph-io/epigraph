//! A document ingest must be refused — synchronously, with nothing written —
//! when the ingesting agent cannot write its PERSONAL group, even if it can
//! write some other group.
//!
//! # The defect this pins (hard constraint #3)
//!
//! Every row a document ingest writes is owned by the ingesting agent's
//! personal group. The walk's authority check (`begin_author_stamped_tx`) asked
//! only whether the author had SOME writable group; the owner group was then
//! resolved by `ClaimRepository::default_decl_for_author`, which MINTS when the
//! group is not visible — and `ensure_personal_group`'s `ON CONFLICT … DO
//! UPDATE SET revoked_at = NULL, role = 'admin'` revives a revoked admin
//! membership. MEASURED by review on the real binary as `epigraph_app`: server
//! agent revoked in its personal group, live `writer` in a team group,
//! `ingest_document_inline` twice → `personal:admin(revoked)` became
//! `personal:admin(live)` and +3 / +4 claims committed under it.
//!
//! # What this can and cannot observe under `#[sqlx::test]`
//!
//! The test connection is a BYPASSRLS superuser, so the RLS half of the
//! mechanism (the personal group being INVISIBLE to a stamped app session) does
//! not reproduce here: the group reads back, nothing is minted, and the revival
//! itself is a harness-only observation (`scripts/e2e/probe-unit-e.sh`, the
//! PERSONAL-REVOKED arms). What DOES reproduce is the other half — the stamp.
//! The transaction is stamped from the author's viewer, whose writable set holds
//! only the team group, and `IngestTx::owner_decl` asks `personal =
//! ANY(epigraph_writable_groups())` — a GUC read, not an RLS read. Pre-fix, the
//! walk never asked that question and committed rows owned by a group the
//! author could not write; that commit is what these tests catch.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::tools::ingestion::{do_ingest_document, ingest_document_inline};
use epigraph_mcp::types::IngestDocumentInlineParams;
use sqlx::PgPool;
use uuid::Uuid;

fn doc(doi: &str) -> DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {"title": format!("Owner authority {doi}"), "doi": doi,
                   "source_type": "Paper", "authors": []},
        "thesis": format!("Owner authority thesis {doi}"),
        "thesis_derivation": "TopDown",
        "sections": [{"title": "S", "paragraphs": [{
            "text": format!("Owner authority paragraph {doi}"),
            "atoms": [format!("Owner authority atom {doi}")],
            "generality": [3], "confidence": 0.8
        }]}],
        "relationships": []
    }))
    .expect("extraction")
}

/// The server agent (provisioned by `agent_id()`'s PR-09 block), its personal
/// group, and a TEAM group it is a live `writer` of.
async fn agent_with_team_writer(
    pool: &PgPool,
    server: &epigraph_mcp::server::EpiGraphMcpFull,
) -> (Uuid, Uuid) {
    let agent = server.server_agent_id().await.expect("server agent");
    let personal: Uuid = sqlx::query_scalar(
        "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("personal group provisioned by agent_id()");
    let team: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind) \
         VALUES ('owner-authority team', 'did:test:team:' || gen_random_uuid(), \
                 decode(repeat('ab', 32), 'hex'), 'team') RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("team group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, '\\x00', 0, 'writer')",
    )
    .bind(team)
    .bind(agent)
    .execute(pool)
    .await
    .expect("team writer membership");
    (agent, personal)
}

async fn personal_state(pool: &PgPool, agent: Uuid, personal: Uuid) -> String {
    sqlx::query_scalar(
        "SELECT string_agg(role || CASE WHEN revoked_at IS NULL THEN '(live)' ELSE '(revoked)' END, ',') \
         FROM group_memberships WHERE agent_id = $1 AND group_id = $2",
    )
    .bind(agent)
    .bind(personal)
    .fetch_one(pool)
    .await
    .expect("membership state")
}

async fn doc_claims(pool: &PgPool, doi: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE $1 = ANY(labels)")
        .bind(format!("doi:{doi}"))
        .fetch_one(pool)
        .await
        .unwrap()
}

/// CONTROL: the same setup with the personal membership LIVE ingests. Without
/// it the refusal arms below could pass for an unrelated reason.
#[sqlx::test(migrations = "../../migrations")]
async fn control_live_personal_membership_ingests(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_agent, _personal) = agent_with_team_writer(&pool, &server).await;

    let doi = "10.9999/owner-authority-control";
    do_ingest_document(&server, &viewer, &doc(doi), None)
        .await
        .expect("a live personal membership must ingest");
    assert!(doc_claims(&pool, doi).await > 0, "control wrote nothing");
}

/// Personal membership REVOKED, team membership live: the walk must refuse and
/// write nothing, and the revocation must stand.
#[sqlx::test(migrations = "../../migrations")]
async fn revoked_personal_membership_refuses_the_walk(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (agent, personal) = agent_with_team_writer(&pool, &server).await;
    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() WHERE agent_id = $1 AND group_id = $2",
    )
    .bind(agent)
    .bind(personal)
    .execute(&pool)
    .await
    .unwrap();

    let doi = "10.9999/owner-authority-revoked";
    let err = do_ingest_document(&server, &viewer, &doc(doi), None)
        .await
        .expect_err("an author revoked in its personal group must be refused");
    assert!(
        err.message.contains("personal group"),
        "refusal must name the cause, got: {}",
        err.message
    );
    assert_eq!(doc_claims(&pool, doi).await, 0, "refused walk wrote claims");
    assert_eq!(
        personal_state(&pool, agent, personal).await,
        "admin(revoked)",
        "the revocation must stand"
    );
}

/// The detached entry point must refuse SYNCHRONOUSLY — to the caller, before
/// the `papers` row — instead of answering `queued` over a task that writes
/// nothing (or, pre-fix, writes under authority it should not have).
#[sqlx::test(migrations = "../../migrations")]
async fn revoked_personal_membership_is_refused_by_the_preflight(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (agent, personal) = agent_with_team_writer(&pool, &server).await;
    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() WHERE agent_id = $1 AND group_id = $2",
    )
    .bind(agent)
    .bind(personal)
    .execute(&pool)
    .await
    .unwrap();

    let doi = "10.9999/owner-authority-preflight";
    let res = ingest_document_inline(
        &server,
        &viewer,
        IngestDocumentInlineParams {
            extraction: doc(doi),
        },
        None,
    )
    .await;
    assert!(res.is_err(), "the preflight must refuse, got {res:?}");
    // Give a (wrongly) spawned task time to land before asserting it did not.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let papers: i64 = sqlx::query_scalar("SELECT count(*) FROM papers WHERE doi = $1")
        .bind(doi)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(papers, 0, "the refusal must precede the papers row");
    assert_eq!(doc_claims(&pool, doi).await, 0);
    assert_eq!(
        personal_state(&pool, agent, personal).await,
        "admin(revoked)"
    );
}

/// A LIVE but read-only (`reader`) personal membership is refused too: every
/// row would be owned by a group the author cannot write.
#[sqlx::test(migrations = "../../migrations")]
async fn reader_personal_membership_refuses_the_walk(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (agent, personal) = agent_with_team_writer(&pool, &server).await;
    sqlx::query(
        "UPDATE group_memberships SET role = 'reader' WHERE agent_id = $1 AND group_id = $2",
    )
    .bind(agent)
    .bind(personal)
    .execute(&pool)
    .await
    .unwrap();

    let doi = "10.9999/owner-authority-reader";
    do_ingest_document(&server, &viewer, &doc(doi), None)
        .await
        .expect_err("a read-only personal membership must be refused");
    assert_eq!(doc_claims(&pool, doi).await, 0);
    assert_eq!(
        personal_state(&pool, agent, personal).await,
        "reader(live)",
        "must not be promoted"
    );
}
