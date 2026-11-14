#![cfg(feature = "db")]
//! `GET /api/v1/papers` carries each paper's authors, its claim count and
//! its ingestion block, as the CALLER's viewer sees them (backlogs fe75ef36,
//! b7354adc).
//!
//! Every request goes through the full router with a real bearer, on an
//! `AppState` whose pools are both the APPLICATION ROLE, so a row the caller
//! may not read is filtered by the database as well as by the statement.
//!
//! What each test pins:
//!
//! * `authors` are ONE ingest's (the paper's first readable ingest principal,
//!   named in `authors_ingested_by`), in position order; an author that
//!   ingest named without speaking for them is under `pending_authors`, never
//!   `authors`; a retracted authorship and another principal's naming are
//!   not listed;
//! * `claim_count` counts each claim any ingest of the paper asserts once,
//!   only while the assertion is in force and both the assertion and the
//!   claim are readable by the caller;
//! * `ingestions` lists every readable ingest of the paper once, oldest
//!   first, at its EARLIEST record, with the ingester's human at that time,
//!   the prompt snapshot only for the snapshot's audience, and `derived` on a
//!   record the legacy backfill wrote; an ingest whose assertion the caller
//!   cannot read is not listed.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{
    AgentIdentityRepository, AgentRepository, IdentityRegistration, PromptFile,
    PromptSnapshotAudience, ScopedPool, SessionGucMode, PROMPT_SNAPSHOT_AUDIENCE,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{as_role, database_url_for, downgraded_pool};

async fn app_role_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

fn random32() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

async fn named(pool: &PgPool, agent: Uuid, name: &str) {
    sqlx::query("UPDATE agents SET display_name = $2 WHERE id = $1")
        .bind(agent)
        .bind(name)
        .execute(pool)
        .await
        .expect("name the agent");
}

async fn agent(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let (id, group) = viewer_fixture::seed_agent_with_group(pool, name).await;
    named(pool, id, name).await;
    (id, group)
}

async fn human(pool: &PgPool, name: &str) -> Uuid {
    let (id, _) = agent(pool, name).await;
    viewer_fixture::make_human_operator(pool, id).await;
    id
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let out = as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("the maintenance role links the agent");
    assert!(out.link_live, "CALIBRATION: the manual link is live");
}

/// A registered identity (so it has a prompt snapshot) linked to `operator`.
async fn registered_agent(pool: &PgPool, operator: Uuid, name: &str) -> (Uuid, Uuid) {
    let pubkey = random32();
    let reg = IdentityRegistration {
        identity_pubkey: pubkey,
        parent_agent_id: None,
        model: "test-model-9".to_string(),
        prompt_hash: blake3::hash(&pubkey).to_hex().to_string(),
        group_folder: "g-papers".to_string(),
        signing_pubkey: Some(random32()),
        identity_md: PromptFile::Absent,
        global_claude_md: PromptFile::Absent,
        group_claude_md: PromptFile::Stored(b"group rules\n".to_vec()),
        learned_md: PromptFile::Absent,
        in_prompt: json!({"global_claude_md": false, "group_claude_md": true, "learned_md": false}),
        runner_version: Some("runner-test".to_string()),
        host_sha: None,
    };
    let out = as_role(pool, "epigraph_identity_attestor", |mut conn| async move {
        let r = AgentIdentityRepository::register(&mut conn, &reg).await;
        (conn, r)
    })
    .await
    .expect("the attestor registers");
    link(pool, out.agent_id, operator).await;
    named(pool, out.agent_id, name).await;
    (out.agent_id, out.snapshot_id)
}

async fn paper(pool: &PgPool, doi: &str, title: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, $2) RETURNING id")
        .bind(doi)
        .bind(title)
        .fetch_one(pool)
        .await
        .expect("paper")
}

/// `by`'s ingest (under `tool`) asserts `claim` from `paper` and records it.
/// Returns `(asserts edge, record edge)`.
async fn ingest(
    pool: &PgPool,
    tool: &'static str,
    paper: Uuid,
    claim: Uuid,
    by: Uuid,
    created: bool,
) -> (Uuid, Uuid) {
    let mut conn = pool.acquire().await.expect("conn");
    let asserts = epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut conn, None, tool, by, paper, "paper", claim, "claim", "asserts", None,
    )
    .await
    .expect("asserts")
    .0
    .id;
    assert!(epigraph_db::ClaimIngestRepository::record_signed_conn(
        &mut conn,
        None,
        paper,
        claim,
        by,
        created,
        &[],
        tool,
        "test-pipeline",
    )
    .await
    .expect("record"));
    let record: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND target_id = $2 \
           AND relationship = 'ingested_claim' AND properties ->> 'ingested_by' = $3",
    )
    .bind(paper)
    .bind(claim)
    .bind(by.to_string())
    .fetch_one(pool)
    .await
    .expect("record id");
    (asserts, record)
}

/// `author`'s authorship of `paper`, as `by`'s document ingest writes it.
async fn authored(pool: &PgPool, author: Uuid, paper: Uuid, by: Uuid, props: Value) -> Uuid {
    let mut conn = pool.acquire().await.expect("conn");
    epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut conn,
        None,
        "ingest_document",
        by,
        author,
        "agent",
        paper,
        "paper",
        "authored",
        Some(props),
    )
    .await
    .expect("authored edge")
    .0
    .id
}

async fn set_edge_created_at(pool: &PgPool, edge: Uuid, at: &str) {
    sqlx::query("UPDATE edges SET created_at = $2::timestamptz WHERE id = $1")
        .bind(edge)
        .bind(at)
        .execute(pool)
        .await
        .expect("set edge created_at");
}

async fn make_group_private(pool: &PgPool, edge: Uuid, group: Uuid) {
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(edge)
    .bind(group)
    .execute(pool)
    .await
    .expect("make the edge group-private");
}

async fn list(state: &AppState, caller: Uuid, query: &str) -> Value {
    let token = common::mint_token_with_agent(&["claims:read"], caller);
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/v1/papers?{query}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn by_doi(state: &AppState, caller: Uuid, doi: &str) -> Value {
    let body = list(state, caller, &format!("doi={doi}")).await;
    assert_eq!(body["total"], json!(1), "{body}");
    body["items"][0].clone()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_paper_lists_one_ingests_authors_and_counts_only_readable_claims(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (ingester, _) = agent(&pool, "ingester").await;
    let (other, _) = agent(&pool, "other-ingester").await;
    let (stranger, _) = agent(&pool, "stranger").await;
    let (member, group) = agent(&pool, "member").await;
    let (first, _) = agent(&pool, "First Author").await;
    let (second, _) = agent(&pool, "Second Author").await;
    let (person, _) = agent(&pool, "Named Person").await;
    let (gone, _) = agent(&pool, "Retracted Author").await;
    let (intruder, _) = agent(&pool, "Intruder").await;
    let doc = paper(&pool, "10.5555/papers.listing", "Listing Paper").await;

    let c1 = viewer_fixture::seed_public_claim(&pool, ingester, "listing claim 1").await;
    let c2 = viewer_fixture::seed_public_claim(&pool, ingester, "listing claim 2").await;
    let hidden = viewer_fixture::seed_group_claim(&pool, member, group, "listing hidden").await;
    let hidden_public_edge =
        viewer_fixture::seed_group_claim(&pool, member, group, "listing hidden 2").await;
    let retracted = viewer_fixture::seed_public_claim(&pool, ingester, "listing retracted").await;
    let c5 = viewer_fixture::seed_public_claim(&pool, other, "listing other's claim").await;

    let (a1, _) = ingest(&pool, "ingest_document", doc, c1, ingester, true).await;
    ingest(&pool, "ingest_document", doc, c2, ingester, true).await;
    ingest(&pool, "ingest_document", doc, hidden, ingester, false).await;
    let (a4, _) = ingest(
        &pool,
        "ingest_document",
        doc,
        hidden_public_edge,
        ingester,
        false,
    )
    .await;
    // The assertion itself public, the claim not: still not the stranger's.
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(a4)
    .bind(viewer_fixture::world_group(&pool).await)
    .execute(&pool)
    .await
    .expect("make the assertion public");
    let (a5, _) = ingest(&pool, "ingest_document", doc, retracted, ingester, true).await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 hour' WHERE id = $1")
        .bind(a5)
        .execute(&pool)
        .await
        .expect("retract the assertion");
    // A second ingest principal, later: re-asserts c1 and adds c5.
    let (o1, _) = ingest(&pool, "ingest_document", doc, c1, other, false).await;
    let (o5, _) = ingest(&pool, "ingest_document", doc, c5, other, true).await;
    set_edge_created_at(&pool, o1, "2099-01-01T00:00:00Z").await;
    set_edge_created_at(&pool, o5, "2099-01-01T00:00:00Z").await;
    set_edge_created_at(&pool, a1, "2026-01-01T00:00:00Z").await;

    let pos = |p: i64| json!({"position": p, "role": "author", "affiliations": []});
    authored(&pool, second, doc, ingester, pos(1)).await;
    authored(
        &pool,
        first,
        doc,
        ingester,
        json!({"position": 0, "role": "corresponding", "affiliations": ["Fixture Institute"]}),
    )
    .await;
    authored(
        &pool,
        person,
        doc,
        ingester,
        json!({"position": 2, "pending_countersign": true, "ingested_by": ingester.to_string()}),
    )
    .await;
    let g = authored(&pool, gone, doc, ingester, pos(3)).await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 hour' WHERE id = $1")
        .bind(g)
        .execute(&pool)
        .await
        .expect("retract the authorship");
    // The other principal names an author of its own: not on the first
    // ingest's list.
    let i = authored(&pool, intruder, doc, other, pos(0)).await;
    set_edge_created_at(&pool, i, "2099-01-01T00:00:00Z").await;

    let item = by_doi(&state, stranger, "https://doi.org/10.5555/papers.listing").await;
    assert_eq!(item["id"], json!(doc), "{item}");
    assert_eq!(item["title"], json!("Listing Paper"), "{item}");
    assert_eq!(item["authors_ingested_by"], json!(ingester), "{item}");
    assert_eq!(
        item["authors"],
        json!([
            {"id": first, "display_name": "First Author", "position": 0,
             "role": "corresponding", "affiliations": ["Fixture Institute"]},
            {"id": second, "display_name": "Second Author", "position": 1,
             "role": "author", "affiliations": []},
        ]),
        "{item}"
    );
    assert_eq!(
        item["pending_authors"],
        json!([
            {"id": person, "display_name": "Named Person", "position": 2,
             "role": "author", "affiliations": [], "named_by": ingester},
        ]),
        "a pending author is apart, never an author: {item}"
    );
    assert_eq!(item["authors_truncated"], json!(false), "{item}");
    assert_eq!(
        item["claim_count"],
        json!(3),
        "c1 once, c2, c5; not the hidden claims nor the retracted assertion: {item}"
    );

    // The member reads both of its group's claims.
    let theirs = by_doi(&state, member, "10.5555/papers.listing").await;
    assert_eq!(theirs["claim_count"], json!(5), "{theirs}");

    // The full list carries the same blocks.
    let all = list(&state, stranger, "limit=100").await;
    let row = all["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|p| p["id"] == json!(doc))
        .cloned()
        .unwrap_or_else(|| panic!("the paper is listed: {all}"));
    assert_eq!(row["claim_count"], json!(3), "{row}");
    assert_eq!(row["authors"], item["authors"], "{row}");

    // The first ingest's assertion of c1 hidden from the stranger: c1 is
    // still counted, once, through the other ingest's own assertion.
    make_group_private(&pool, a1, group).await;
    let item = by_doi(&state, stranger, "10.5555/papers.listing").await;
    assert_eq!(
        item["claim_count"],
        json!(3),
        "c1 still via the other ingest: {item}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_paper_names_each_ingest_with_its_human_model_and_date(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let operator = human(&pool, "Operator Fixture").await;
    let (stranger, _) = agent(&pool, "stranger").await;
    let (member, group) = agent(&pool, "member").await;
    let (ingester, snapshot) = registered_agent(&pool, operator, "ingest-agent").await;
    let (legacy, _) = agent(&pool, "legacy-principal").await;
    let (private_ingester, _) = agent(&pool, "private-ingester").await;
    let doc = paper(&pool, "10.5555/papers.ingestion", "Ingestion Paper").await;

    let c1 = viewer_fixture::seed_public_claim(&pool, ingester, "ingestion claim 1").await;
    let c2 = viewer_fixture::seed_public_claim(&pool, ingester, "ingestion claim 2").await;
    let (_, r1) = ingest(&pool, "ingest_document", doc, c1, ingester, true).await;
    let (_, r2) = ingest(&pool, "ingest_document", doc, c2, ingester, true).await;
    // Two records of one ingest: the block is at the EARLIEST.
    set_edge_created_at(&pool, r2, "2099-02-01T00:00:00Z").await;
    let first_at: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT created_at FROM edges WHERE id = $1")
            .bind(r1)
            .fetch_one(&pool)
            .await
            .expect("first record time");

    // A record the legacy backfill wrote.
    let (_, rl) = ingest(&pool, "backfill-ingest-markers", doc, c1, legacy, false).await;
    set_edge_created_at(&pool, rl, "2099-03-01T00:00:00Z").await;

    // An ingest whose ASSERTION only the member's group can read (its record
    // stays public): the record counts only beside its own readable
    // assertion.
    let (pa, pr) = ingest(&pool, "ingest_document", doc, c2, private_ingester, false).await;
    make_group_private(&pool, pa, group).await;
    set_edge_created_at(&pool, pr, "2099-04-01T00:00:00Z").await;

    let mine = by_doi(&state, operator, "10.5555/papers.ingestion").await;
    let got = mine["ingestions"]
        .as_array()
        .unwrap_or_else(|| panic!("{mine}"));
    assert_eq!(got.len(), 2, "one entry per readable ingest: {mine}");
    let block = &got[0];
    assert_eq!(
        block["ingested_by"],
        json!({"id": ingester, "display_name": "ingest-agent"}),
        "{mine}"
    );
    assert_eq!(
        block["human"],
        json!({"id": operator, "display_name": "Operator Fixture"}),
        "{mine}"
    );
    let at: chrono::DateTime<chrono::Utc> = serde_json::from_value(block["ingested_at"].clone())
        .unwrap_or_else(|e| panic!("ingested_at {e}: {mine}"));
    assert_eq!(at, first_at, "the earliest record: {mine}");
    assert_eq!(block["tool"], json!("ingest_document"), "{mine}");
    assert_eq!(block["pipeline"], json!("test-pipeline"), "{mine}");
    assert_eq!(block["derived"], json!(false), "{mine}");
    let snap = &block["prompt_snapshot"];
    assert_eq!(snap["snapshot_id"], json!(snapshot), "{mine}");
    assert_eq!(snap["model"], json!("test-model-9"), "{mine}");
    assert!(snap.get("text").is_none(), "no prompt text: {mine}");

    let legacy_block = &got[1];
    assert_eq!(legacy_block["ingested_by"]["id"], json!(legacy), "{mine}");
    assert_eq!(legacy_block["derived"], json!(true), "{mine}");
    assert_eq!(legacy_block["human"], Value::Null, "{mine}");
    assert_eq!(mine["ingestions_truncated"], json!(false), "{mine}");

    let theirs = by_doi(&state, stranger, "10.5555/papers.ingestion").await;
    let tb = &theirs["ingestions"][0];
    assert_eq!(tb["ingested_by"], block["ingested_by"], "{theirs}");
    assert_eq!(tb["human"], block["human"], "every reader sees the human");
    match PROMPT_SNAPSHOT_AUDIENCE {
        PromptSnapshotAudience::OperatorAndAdmins => assert_eq!(
            tb["prompt_snapshot"],
            Value::Null,
            "gated: a stranger does not see the snapshot: {theirs}"
        ),
        PromptSnapshotAudience::ClaimReaders => assert_eq!(&tb["prompt_snapshot"], snap),
    }
    assert_eq!(
        theirs["ingestions"].as_array().map(Vec::len),
        Some(2),
        "the private ingest is not the stranger's: {theirs}"
    );

    let members = by_doi(&state, member, "10.5555/papers.ingestion").await;
    let ids: Vec<Value> = members["ingestions"]
        .as_array()
        .unwrap_or_else(|| panic!("{members}"))
        .iter()
        .map(|b| b["ingested_by"]["id"].clone())
        .collect();
    assert_eq!(
        ids,
        vec![json!(ingester), json!(legacy), json!(private_ingester)],
        "oldest first, the private ingest for its group: {members}"
    );
}
