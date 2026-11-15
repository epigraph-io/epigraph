#![cfg(feature = "db")]
//! `GET /api/v1/claims/:id` carries `authored_by` (backlog 48421526): the
//! agent that filed the claim, the human it acts for, and the prompt snapshot
//! it was running, each under the caller's viewer.
//!
//! Every request goes through the full router with a real bearer, on an
//! `AppState` whose pools are both the APPLICATION ROLE: on the superuser pool
//! `epigraph_bypass()` is true, so every caller would pass the snapshot gate
//! and every edge would be readable, and "a stranger does not see it" could
//! not fail.
//!
//! The snapshot's audience is the ONE constant
//! `epigraph_db::PROMPT_SNAPSHOT_AUDIENCE`. These tests read it and assert
//! whichever setting is live, so the owner's ruling is that one line; the
//! repo-level tests (`epigraph-db/tests/claim_authored_by.rs`) drive both
//! settings explicitly.

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
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
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

/// A registered human with its personal group (so its viewer reads).
async fn human(pool: &PgPool, name: &str) -> Uuid {
    let (id, _) = viewer_fixture::seed_agent_with_group(pool, name).await;
    viewer_fixture::make_human_operator(pool, id).await;
    named(pool, id, name).await;
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

/// A registered EpiClaw identity linked to `operator`: `(agent, snapshot)`.
async fn registered_agent(pool: &PgPool, operator: Uuid) -> (Uuid, Uuid) {
    let pubkey = random32();
    let reg = IdentityRegistration {
        identity_pubkey: pubkey,
        parent_agent_id: None,
        model: "test-model-7".to_string(),
        prompt_hash: blake3::hash(&pubkey).to_hex().to_string(),
        group_folder: "g-authored".to_string(),
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
    named(pool, out.agent_id, "fixture-agent-7").await;
    (out.agent_id, out.snapshot_id)
}

async fn get_claim(state: &AppState, caller: Uuid, claim: Uuid) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(&["claims:read"], caller);
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/v1/claims/{claim}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

async fn authored_by(state: &AppState, caller: Uuid, claim: Uuid) -> Value {
    let (status, body) = get_claim(state, caller, claim).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["authored_by"].clone()
}

/// The agent's human sees the whole block; an admin sees the snapshot; a
/// stranger sees the agent and its human (the binding is shown to every
/// reader), and the snapshot only when the audience setting is every claim
/// reader.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_read_names_the_agent_the_human_and_the_snapshot_by_audience(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let operator = human(&pool, "Operator Fixture").await;
    let custodian = human(&pool, "Custodian Fixture").await;
    viewer_fixture::make_custodian(&pool, custodian).await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "stranger").await;
    let (agent, snapshot) = registered_agent(&pool, operator).await;
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "authored-by fixture claim").await;

    let mine = authored_by(&state, operator, claim).await;
    assert_eq!(
        mine["agent"],
        json!({"id": agent, "display_name": "fixture-agent-7"}),
        "{mine}"
    );
    assert_eq!(
        mine["human"],
        json!({"id": operator, "display_name": "Operator Fixture"}),
        "{mine}"
    );
    let snap = &mine["prompt_snapshot"];
    assert_eq!(snap["snapshot_id"], json!(snapshot), "{mine}");
    assert_eq!(snap["model"], json!("test-model-7"), "{mine}");
    assert_eq!(
        snap["prompt_hash"].as_str().map(str::len),
        Some(64),
        "{mine}"
    );
    assert!(snap["started_at"].is_string(), "{mine}");
    assert!(snap.get("text").is_none(), "no prompt text: {mine}");

    let admin = authored_by(&state, custodian, claim).await;
    assert_eq!(
        &admin["prompt_snapshot"], snap,
        "an admin sees the snapshot"
    );

    let theirs = authored_by(&state, stranger, claim).await;
    assert_eq!(theirs["agent"], mine["agent"]);
    assert_eq!(
        theirs["human"], mine["human"],
        "every reader sees the human"
    );
    match PROMPT_SNAPSHOT_AUDIENCE {
        PromptSnapshotAudience::OperatorAndAdmins => assert_eq!(
            theirs["prompt_snapshot"],
            Value::Null,
            "gated: a stranger does not see the snapshot: {theirs}"
        ),
        PromptSnapshotAudience::ClaimReaders => assert_eq!(
            &theirs["prompt_snapshot"], snap,
            "open: every reader of the claim sees the snapshot"
        ),
    }
    assert_eq!(theirs["source"], json!("agent"), "{theirs}");
    let mut keys: Vec<&str> = theirs
        .as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "agent",
            "corroborated_by",
            "corroborated_by_truncated",
            "human",
            "ingesters",
            "ingesters_truncated",
            "prompt_snapshot",
            "source"
        ],
        "{theirs}"
    );
    assert_eq!(theirs["corroborated_by"], json!([]), "{theirs}");
    assert_eq!(theirs["ingesters"], json!([]), "{theirs}");
}

/// `caller` tries to write an `OPERATED_BY` edge `agent -> target` through
/// `POST /api/v1/edges`, which refuses it (only a recorded link writes one);
/// then the same edge is planted directly, as a row written before that
/// refusal existed would be.
async fn forge_over_http(pool: &PgPool, state: &AppState, caller: Uuid, agent: Uuid, target: Uuid) {
    let token = common::mint_token_with_agent(&["edges:write"], caller);
    let body = json!({
        "source_id": agent, "source_type": "agent",
        "target_id": target, "target_type": "agent",
        "relationship": "OPERATED_BY",
    });
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/edges")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the route refuses a generic OPERATED_BY write: {}",
        String::from_utf8_lossy(&bytes)
    );
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'agent', $2, 'agent', 'OPERATED_BY')",
    )
    .bind(agent)
    .bind(target)
    .execute(pool)
    .await
    .expect("a forged OPERATED_BY row from before the refusal");
}

/// On the wire the human is the agent's binding, for every reader: a stranger
/// sees the human of a link no edge records, and edges the stranger forges
/// through `POST /api/v1/edges`, to a wrong guess and to the right human,
/// leave the block byte for byte as it was. A claim the caller cannot read is
/// the 404 a missing id gets, with no block.
#[sqlx::test(migrations = "../../migrations")]
async fn a_forged_edge_changes_nothing_and_a_hidden_claim_leaks_nothing(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (operator, operator_group) = viewer_fixture::seed_agent_with_group(&pool, "op").await;
    viewer_fixture::make_human_operator(&pool, operator).await;
    named(&pool, operator, "Operator Fixture").await;
    let decoy = human(&pool, "Decoy Fixture").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "stranger").await;
    let (member, group) = viewer_fixture::seed_agent_with_group(&pool, "member").await;
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "agent").await;
    sqlx::query(
        "INSERT INTO operator_links (agent_id, operator_id, operator_group_id) VALUES ($1, $2, $3)",
    )
    .bind(agent)
    .bind(operator)
    .bind(operator_group)
    .execute(&pool)
    .await
    .expect("a link row with no edge");
    let edges = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'OPERATED_BY'",
        )
        .bind(agent)
        .fetch_one(&pool)
        .await
        .expect("count")
    };
    assert_eq!(edges().await, 0, "CALIBRATION: no edge records the link");
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "edgeless link claim").await;

    let before = authored_by(&state, stranger, claim).await;
    assert_eq!(
        before["human"],
        json!({"id": operator, "display_name": "Operator Fixture"}),
        "a stranger sees the binding: {before}"
    );
    forge_over_http(&pool, &state, stranger, agent, decoy).await;
    forge_over_http(&pool, &state, stranger, agent, operator).await;
    assert_eq!(edges().await, 2, "CALIBRATION: both forged rows are stored");
    assert_eq!(
        authored_by(&state, stranger, claim).await,
        before,
        "forged edges change nothing on the wire"
    );

    let private = viewer_fixture::seed_group_claim(&pool, agent, group, "private claim").await;
    let (status, body) = get_claim(&state, member, private).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "CONTROL: the member reads it: {body}"
    );
    let (status, hidden_body) = get_claim(&state, stranger, private).await;
    let (missing_status, missing_body) = get_claim(&state, stranger, Uuid::new_v4()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
    assert!(hidden_body.get("authored_by").is_none(), "{hidden_body}");
    let strip = |mut v: Value| {
        if let Some(o) = v.as_object_mut() {
            o.retain(|k, _| k != "details" && k != "message");
        }
        v
    };
    assert_eq!(
        strip(hidden_body),
        strip(missing_body),
        "the same 404 shape"
    );
}

/// A claim a document's ingest created, on the wire: `source:
/// "literature"`, the document and its authors first (by position, with role
/// and affiliations, a pending author apart), the filer, with its human,
/// apart as `ingested_by`, and every ingester. A reader who cannot see the
/// document's assertion gets the agent block instead.
#[sqlx::test(migrations = "../../migrations")]
async fn a_literature_claim_names_the_document_authors_and_the_ingester_apart(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let operator = human(&pool, "Operator Fixture").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "stranger").await;
    let (member, group) = viewer_fixture::seed_agent_with_group(&pool, "member").await;
    let (ingester, _) = viewer_fixture::seed_agent_with_group(&pool, "ingester").await;
    named(&pool, ingester, "ingest-fixture").await;
    link(&pool, ingester, operator).await;
    let claim = viewer_fixture::seed_public_claim(&pool, ingester, "wire literature claim").await;
    let doc: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (doi, title) VALUES ('10.0000/fixture.wire', 'Wire Paper') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("paper");
    let (second, _) = viewer_fixture::seed_agent_with_group(&pool, "second").await;
    named(&pool, second, "Second Author").await;
    let (first, _) = viewer_fixture::seed_agent_with_group(&pool, "first").await;
    named(&pool, first, "First Author").await;
    let (person, _) = viewer_fixture::seed_agent_with_group(&pool, "person").await;
    named(&pool, person, "Named Person").await;
    let asserts = ingest_record(&pool, doc, claim, ingester, true, &[first, second, person]).await;
    authored_edge(
        &pool,
        second,
        doc,
        ingester,
        json!({"position": 1, "role": "author", "affiliations": []}),
    )
    .await;
    authored_edge(
        &pool,
        first,
        doc,
        ingester,
        json!({"position": 0, "role": "corresponding", "affiliations": ["Fixture Institute"]}),
    )
    .await;
    authored_edge(
        &pool,
        person,
        doc,
        ingester,
        json!({"position": 2, "pending_countersign": true, "ingested_by": ingester.to_string()}),
    )
    .await;

    let block = authored_by(&state, stranger, claim).await;
    assert_eq!(block["source"], json!("literature"), "{block}");
    assert!(block.get("agent").is_none(), "{block}");
    let p = &block["paper"];
    assert_eq!(
        p["paper"],
        json!({"id": doc, "doi": "10.0000/fixture.wire", "title": "Wire Paper"})
    );
    assert_eq!(
        p["authors"],
        json!([
            {"id": first, "display_name": "First Author", "position": 0,
             "role": "corresponding", "affiliations": ["Fixture Institute"],
             "pending_countersign": false, "named_by": null, "added_by": null},
            {"id": second, "display_name": "Second Author", "position": 1,
             "role": "author", "affiliations": [],
             "pending_countersign": false, "named_by": null, "added_by": null},
        ]),
        "{block}"
    );
    assert_eq!(
        p["pending_authors"],
        json!([
            {"id": person, "display_name": "Named Person", "position": 2,
             "role": "author", "affiliations": [],
             "pending_countersign": true,
             "named_by": {"id": ingester, "display_name": "ingest-fixture"},
             "added_by": null},
        ]),
        "a pending author is apart, never primary: {block}"
    );
    assert_eq!(p["added_authors"], json!([]), "{block}");
    assert_eq!(p["authors_truncated"], json!(false));
    assert_eq!(
        block["ingested_by"]["agent"],
        json!({"id": ingester, "display_name": "ingest-fixture"})
    );
    assert_eq!(
        block["ingested_by"]["human"],
        json!({"id": operator, "display_name": "Operator Fixture"})
    );
    assert_eq!(block["ingested_by"]["prompt_snapshot"], Value::Null);
    assert_eq!(block["corroborated_by"], json!([]));
    assert_eq!(block["ingesters"][0]["agent"]["id"], json!(ingester));
    assert_eq!(block["ingesters"][0]["human"]["id"], json!(operator));
    assert_eq!(block["ingesters"][0]["paper_id"], json!(doc));
    assert_eq!(block["ingesters"][0]["created_claim"], json!(true));

    // The document's assertion private to the member's group (an
    // administrative state: no application path writes it): the member
    // still sees the literature block, a stranger the plain agent block.
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(asserts)
    .bind(group)
    .execute(&pool)
    .await
    .expect("make the asserts edge group-private");
    assert_eq!(
        authored_by(&state, member, claim).await["source"],
        json!("literature")
    );
    let plain = authored_by(&state, stranger, claim).await;
    assert_eq!(plain["source"], json!("agent"), "{plain}");
    assert_eq!(plain["agent"]["id"], json!(ingester));
    assert_eq!(plain["human"]["id"], json!(operator));
    assert_eq!(plain["ingesters"], json!([]), "{plain}");
}

/// The grafted claim on the wire. A person's own ingest of a document wrote
/// the person's countersigned authorship; a stranger's ingest of the SAME
/// document key named the person (its own row, pending) and created a claim,
/// recording the person among its authors. GET /claims/:id lists the person
/// as PENDING on the stranger's claim, named by the stranger, never as a
/// primary author, for a third party, the person and the stranger alike; on
/// the person's own claim the stranger, which never recorded it, adds
/// nothing. The rows are the ones the walks write (each principal its own).
#[sqlx::test(migrations = "../../migrations")]
async fn a_strangers_graft_lists_the_named_person_pending_on_the_wire(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (third, _) = viewer_fixture::seed_agent_with_group(&pool, "third").await;
    let (person, _) = viewer_fixture::seed_agent_with_group(&pool, "person").await;
    named(&pool, person, "Cass Orvell").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "stranger").await;
    named(&pool, stranger, "graft-fixture").await;
    let doc: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (doi, title) VALUES ('10.0000/fixture.graft', 'Graft Paper') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("paper");
    let own = viewer_fixture::seed_public_claim(&pool, person, "the person's own claim").await;
    authored_edge(&pool, person, doc, person, json!({"position": 0})).await;
    ingest_record(&pool, doc, own, person, true, &[person]).await;
    let graft = viewer_fixture::seed_public_claim(&pool, stranger, "the stranger's graft").await;
    authored_edge(
        &pool,
        person,
        doc,
        stranger,
        json!({"position": 0, "pending_countersign": true, "ingested_by": stranger.to_string()}),
    )
    .await;
    ingest_record(&pool, doc, graft, stranger, true, &[person]).await;

    for caller in [third, person, stranger] {
        let block = authored_by(&state, caller, graft).await;
        assert_eq!(block["source"], json!("literature"), "{block}");
        assert_eq!(block["ingested_by"]["agent"]["id"], json!(stranger));
        let p = &block["paper"];
        assert_eq!(
            p["authors"],
            json!([]),
            "the stranger's naming is never primary: {block}"
        );
        assert_eq!(
            p["pending_authors"],
            json!([
                {"id": person, "display_name": "Cass Orvell", "position": 0,
                 "role": "author", "affiliations": [],
                 "pending_countersign": true,
                 "named_by": {"id": stranger, "display_name": "graft-fixture"},
                 "added_by": null},
            ]),
            "{block}"
        );
        assert_eq!(p["added_authors"], json!([]), "{block}");

        let mine = authored_by(&state, caller, own).await;
        assert_eq!(mine["paper"]["authors"][0]["id"], json!(person), "{mine}");
        assert_eq!(mine["paper"]["authors"].as_array().map(Vec::len), Some(1));
        assert_eq!(mine["paper"]["pending_authors"], json!([]), "{mine}");
        assert_eq!(mine["paper"]["added_authors"], json!([]), "{mine}");
    }
}

async fn get_papers(state: &AppState, caller: Uuid, query: &str) -> (StatusCode, Value) {
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
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

/// Backlog fe75ef36. `GET /api/v1/papers?doi=` names the paper's authors, in
/// the extraction's order with a pending author marked, and counts its claims,
/// under any spelling of the DOI. The count is the CALLER's: a claim of the
/// paper that is private to a group is counted for a member and not for a
/// stranger, and a paper nobody has ingested lists no author and no claim.
#[sqlx::test(migrations = "../../migrations")]
async fn the_papers_route_lists_authors_and_counts_the_callers_claims(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "stranger").await;
    let (member, group) = viewer_fixture::seed_agent_with_group(&pool, "member").await;
    let (ingester, _) = viewer_fixture::seed_agent_with_group(&pool, "ingester").await;
    let doc: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (doi, title, journal) \
         VALUES ('10.0000/fixture.list', 'Listed Paper', 'Fixture Letters') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("paper");
    sqlx::query("INSERT INTO papers (doi, title) VALUES ('10.0000/fixture.bare', 'Bare Paper')")
        .execute(&pool)
        .await
        .expect("bare paper");

    let (second, _) = viewer_fixture::seed_agent_with_group(&pool, "second").await;
    named(&pool, second, "Second Author").await;
    let (first, _) = viewer_fixture::seed_agent_with_group(&pool, "first").await;
    named(&pool, first, "First Author").await;
    let (person, _) = viewer_fixture::seed_agent_with_group(&pool, "person").await;
    named(&pool, person, "Named Person").await;

    let public_claim =
        viewer_fixture::seed_public_claim(&pool, ingester, "a public claim of the paper").await;
    let private_claim =
        viewer_fixture::seed_group_claim(&pool, member, group, "a group claim of the paper").await;
    ingest_record(
        &pool,
        doc,
        public_claim,
        ingester,
        true,
        &[first, second, person],
    )
    .await;
    ingest_record(&pool, doc, private_claim, ingester, true, &[]).await;
    authored_edge(
        &pool,
        second,
        doc,
        ingester,
        json!({"position": 1, "role": "author", "affiliations": []}),
    )
    .await;
    authored_edge(
        &pool,
        first,
        doc,
        ingester,
        json!({"position": 0, "role": "corresponding", "affiliations": ["Fixture Institute"]}),
    )
    .await;
    authored_edge(
        &pool,
        person,
        doc,
        ingester,
        json!({"position": 2, "pending_countersign": true, "ingested_by": ingester.to_string()}),
    )
    .await;

    // Every spelling of the document key finds the one paper.
    for spelling in [
        "10.0000/fixture.list",
        "doi:10.0000/fixture.list",
        "https://doi.org/10.0000/fixture.list",
    ] {
        let (status, body) = get_papers(&state, stranger, &format!("doi={spelling}")).await;
        assert_eq!(status, StatusCode::OK, "{spelling}: {body}");
        assert_eq!(body["total"], json!(1), "{spelling}: {body}");
        assert_eq!(body["items"][0]["id"], json!(doc), "{spelling}: {body}");
    }

    let (_, body) = get_papers(&state, stranger, "doi=10.0000/fixture.list").await;
    let item = &body["items"][0];
    assert_eq!(item["title"], json!("Listed Paper"));
    assert_eq!(item["journal"], json!("Fixture Letters"));
    assert_eq!(
        item["authors"],
        json!([
            {"agent_id": first, "name": "First Author", "position": 0,
             "role": "corresponding", "affiliations": ["Fixture Institute"],
             "pending_countersign": false},
            {"agent_id": second, "name": "Second Author", "position": 1,
             "role": "author", "affiliations": [],
             "pending_countersign": false},
            {"agent_id": person, "name": "Named Person", "position": 2,
             "role": "author", "affiliations": [],
             "pending_countersign": true},
        ]),
        "{item}"
    );
    assert_eq!(item["authors_truncated"], json!(false));
    assert_eq!(
        item["ingests"]
            .as_array()
            .expect("ingests")
            .iter()
            .map(|i| i["ingested_by"].clone())
            .collect::<Vec<_>>(),
        vec![json!(ingester)],
        "{item}"
    );
    assert_eq!(
        item["claim_count"],
        json!(1),
        "a stranger counts the public claim only: {item}"
    );

    let (_, member_body) = get_papers(&state, member, "doi=10.0000/fixture.list").await;
    assert_eq!(
        member_body["items"][0]["claim_count"],
        json!(2),
        "a member also counts its group's claim: {member_body}"
    );

    // A paper with no ingest: the fields are present and empty.
    let (_, bare) = get_papers(&state, stranger, "doi=10.0000/fixture.bare").await;
    let bare_item = &bare["items"][0];
    assert_eq!(bare_item["authors"], json!([]), "{bare_item}");
    assert_eq!(bare_item["claim_count"], json!(0), "{bare_item}");
    assert_eq!(bare_item["ingests"], json!([]), "{bare_item}");

    // The unfiltered list carries the same fields on every row.
    let (status, all) = get_papers(&state, stranger, "limit=10").await;
    assert_eq!(status, StatusCode::OK, "{all}");
    let listed = all["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|p| p["id"] == json!(doc))
        .expect("the paper is on the list")
        .clone();
    assert_eq!(listed["claim_count"], json!(1), "{listed}");
    assert_eq!(
        listed["authors"].as_array().map(Vec::len),
        Some(3),
        "{listed}"
    );
}

/// The ingest's `asserts` edge and its record (with the authors it resolved),
/// written with the walk's own primitives (ingest-written, by `by`). Returns
/// the asserts edge.
async fn ingest_record(
    pool: &PgPool,
    paper: Uuid,
    claim: Uuid,
    by: Uuid,
    created: bool,
    authors: &[Uuid],
) -> Uuid {
    let mut conn = pool.acquire().await.expect("conn");
    let e = epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut conn,
        None,
        "ingest_document",
        by,
        paper,
        "paper",
        claim,
        "claim",
        "asserts",
        None,
    )
    .await
    .expect("asserts")
    .0
    .id;
    epigraph_db::ClaimIngestRepository::record_signed_conn(
        &mut conn,
        None,
        paper,
        claim,
        by,
        created,
        authors,
        "ingest_document",
        "test-pipeline",
    )
    .await
    .expect("record");
    e
}

/// `author`'s authorship of `paper`, as `by`'s document ingest writes it.
async fn authored_edge(pool: &PgPool, author: Uuid, paper: Uuid, by: Uuid, props: Value) {
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
    .expect("authored edge");
}

/// `caller` POSTs an edge to `/api/v1/edges`: the status.
async fn post_edge(state: &AppState, caller: Uuid, body: Value) -> StatusCode {
    let token = common::mint_token_with_agent(&["edges:write"], caller);
    create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/edges")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response")
        .status()
}

/// A stranger cannot make a document the author of someone's claim, or make
/// an agent assert it, over `POST /api/v1/edges`: a `paper -asserts-> claim`
/// edge, an ingest record and an `authored` edge into a paper are refused
/// (400) for every caller, an agent-sourced `asserts` from an agent the
/// caller neither is nor operates is refused (403), and the claim's block is
/// byte for byte as it was, for a third party and for the filer's human.
#[sqlx::test(migrations = "../../migrations")]
async fn a_forged_document_assertion_is_refused_and_changes_nothing(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let operator = human(&pool, "Operator Fixture").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "stranger").await;
    let (bystander, _) = viewer_fixture::seed_agent_with_group(&pool, "bystander").await;
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "agent").await;
    link(&pool, agent, operator).await;
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "an agent's own claim").await;
    let doc: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (doi, title) VALUES ('10.0000/fixture.forged', 'Forged') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("paper");
    let (author, _) = viewer_fixture::seed_agent_with_group(&pool, "unwitting").await;
    authored_edge(&pool, author, doc, author, json!({"position": 0})).await;

    let before_third = authored_by(&state, bystander, claim).await;
    let before_human = authored_by(&state, operator, claim).await;
    assert_eq!(before_third["source"], json!("agent"), "CALIBRATION");

    let forged_asserts = json!({
        "source_id": doc, "source_type": "paper",
        "target_id": claim, "target_type": "claim", "relationship": "asserts",
    });
    assert_eq!(
        post_edge(&state, stranger, forged_asserts).await,
        StatusCode::BAD_REQUEST,
        "a paper's assertion is the ingest's alone"
    );
    let forged_record = json!({
        "source_id": doc, "source_type": "paper",
        "target_id": claim, "target_type": "claim", "relationship": "ingested_claim",
        "properties": {"ingested_by": agent.to_string(), "created_claim": true},
    });
    assert_eq!(
        post_edge(&state, stranger, forged_record).await,
        StatusCode::BAD_REQUEST,
        "the ingest record is the ingest's alone"
    );
    let forged_authorship = json!({
        "source_id": stranger, "source_type": "agent",
        "target_id": doc, "target_type": "paper", "relationship": "authored",
    });
    assert_eq!(
        post_edge(&state, stranger, forged_authorship).await,
        StatusCode::BAD_REQUEST,
        "an authorship of a paper is the ingest's alone"
    );
    let forged_agent_asserts = json!({
        "source_id": operator, "source_type": "agent",
        "target_id": claim, "target_type": "claim", "relationship": "asserts",
    });
    assert_eq!(
        post_edge(&state, stranger, forged_agent_asserts).await,
        StatusCode::FORBIDDEN,
        "an agent's assertion is that agent's, or its operator's, alone"
    );
    let landed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE target_id = $1 AND relationship IN \
           ('asserts', 'ingested_claim')",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(landed, 0, "nothing was written");
    assert_eq!(authored_by(&state, bystander, claim).await, before_third);
    assert_eq!(authored_by(&state, operator, claim).await, before_human);
}
