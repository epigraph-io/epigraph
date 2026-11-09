#![cfg(feature = "db")]
//! `POST /api/v1/edges` and the provenance relationships a document's
//! authorship is read from, through the full router (bearer middleware, scope
//! check, viewer extractor, the stamped write) with both pools of the
//! `AppState` on the APPLICATION ROLE.
//!
//! * `asserts` or `AUTHORED` from an AGENT source is accepted only when that
//!   agent is the caller itself or an agent the caller operates through a
//!   live binding. Anyone else's would put words in that agent's mouth: the
//!   edge lands world-owned, so neither the agent nor the writer could take
//!   it back.
//! * The same authorship written the other way round (`claim
//!   -attributed_to-> agent` and every other relationship that credits the
//!   TARGET agent with the source's content), and an agent's `generated`,
//!   likewise. The operator link's own `OPERATED_BY` is refused for every
//!   caller.
//! * `paper -asserts-> claim`, a paper's `AUTHORED`, any `authored` edge into
//!   a paper, and the ingest's own `ingested_claim` record are written only
//!   by the document ingest. Refused for every caller, the paper's own
//!   authors included.
//! * `POST /api/v1/claims/:id/provenance` (claim -ATTRIBUTED_TO-> author,
//!   author -AUTHORED-> claim) only by the claim's filer or its operator, and
//!   only for authors the caller is or operates.
//!
//! Every refusal writes nothing (the edge count is measured), and every
//! refusal has an accepted positive control. All names are invented.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
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
    let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(scoped.inner())
        .await
        .expect("epigraph_bypass on the scoped pool");
    assert!(
        !bypass,
        "CALIBRATION: the scoped pool must not be privileged"
    );
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let out = as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("link");
    assert!(out.link_live, "CALIBRATION: the link is live");
}

async fn retire(pool: &PgPool, agent: Uuid) {
    let outcome: String = as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r: String = sqlx::query_scalar(
            "SELECT outcome FROM public.epigraph_retire_operator_link($1, 'edge test', true)",
        )
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("retire the link");
        (conn, r)
    })
    .await;
    assert_eq!(outcome, "retired", "CALIBRATION: the link was live");
}

async fn paper(pool: &PgPool, doi: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, $1) RETURNING id")
        .bind(doi)
        .fetch_one(pool)
        .await
        .expect("paper")
}

async fn edge_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM edges")
        .fetch_one(pool)
        .await
        .expect("count edges")
}

/// `POST /api/v1/edges` as `caller` with `edges:write`.
async fn post_edge(
    state: &AppState,
    caller: Uuid,
    (source, source_type): (Uuid, &str),
    (target, target_type): (Uuid, &str),
    relationship: &str,
) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(&["edges:write"], caller);
    let body = json!({
        "source_id": source, "source_type": source_type,
        "target_id": target, "target_type": target_type,
        "relationship": relationship,
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/edges")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = create_router(state.clone())
        .oneshot(req)
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// An agent-sourced `asserts` or `AUTHORED` edge is the caller's only for
/// itself or an agent it operates (live). A stranger naming a registered
/// human, or the human after the binding is retired, is refused and nothing
/// is written; the self and operated controls are accepted.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_sourced_attribution_is_accepted_only_for_the_caller_or_its_live_agent(
    pool: PgPool,
) {
    let state = app_role_state(&pool).await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "edge-stranger").await;
    let (human, _) = viewer_fixture::seed_human_operator(&pool, "edge-human").await;
    let (bot, _) = viewer_fixture::seed_agent_with_group(&pool, "edge-bot").await;
    link(&pool, bot, human).await;
    let claims: Vec<Uuid> = {
        let mut v = Vec::new();
        for i in 0..8 {
            v.push(
                viewer_fixture::seed_public_claim(&pool, stranger, &format!("edge target {i}"))
                    .await,
            );
        }
        v
    };

    for (n, (source, relationship)) in [(human, "asserts"), (human, "AUTHORED"), (bot, "asserts")]
        .into_iter()
        .enumerate()
    {
        let before = edge_count(&pool).await;
        let (status, body) = post_edge(
            &state,
            stranger,
            (source, "agent"),
            (claims[n], "claim"),
            relationship,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a stranger's {relationship} from {source}: {body}"
        );
        assert!(
            body.to_string().contains("operates"),
            "the refusal says whose edge it may write: {body}"
        );
        assert_eq!(edge_count(&pool).await, before, "nothing written");
    }

    // CONTROLS: the caller itself, and the human for the agent it operates.
    for (n, (caller, source, relationship)) in [
        (stranger, stranger, "asserts"),
        (stranger, stranger, "AUTHORED"),
        (human, bot, "asserts"),
        (human, bot, "AUTHORED"),
        (human, human, "asserts"),
    ]
    .into_iter()
    .enumerate()
    {
        let (status, body) = post_edge(
            &state,
            caller,
            (source, "agent"),
            (claims[3 + n.min(4)], "claim"),
            relationship,
        )
        .await;
        assert!(
            status.is_success(),
            "CONTROL {n}: {caller} writes {relationship} from {source}: {status} {body}"
        );
    }

    // Once the binding is retired the human no longer operates the bot.
    retire(&pool, bot).await;
    let before = edge_count(&pool).await;
    let (status, body) = post_edge(
        &state,
        human,
        (bot, "agent"),
        (claims[7], "claim"),
        "asserts",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "after retirement: {body}");
    assert_eq!(edge_count(&pool).await, before, "nothing written");
}

/// `paper -asserts-> claim`, `authored` into a paper and the ingest record are
/// the document ingest's alone: refused for a stranger AND for an author of the
/// paper, in any spelling, and nothing is written. CONTROL: the same caller's
/// own agent-sourced `asserts` onto the same claim is accepted.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ingest_only_relationships_are_refused_for_every_caller(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "edge-stranger").await;
    let (author, _) = viewer_fixture::seed_human_operator(&pool, "edge-author").await;
    let claim = viewer_fixture::seed_public_claim(&pool, stranger, "a public claim").await;
    let doc = paper(&pool, "10.9999/ingest-only-edges").await;

    for caller in [stranger, author] {
        for (source, target, relationship) in [
            ((doc, "paper"), (claim, "claim"), "asserts"),
            ((doc, "paper"), (claim, "claim"), "ASSERTS"),
            ((doc, "paper"), (claim, "claim"), "AUTHORED"),
            ((doc, "paper"), (claim, "claim"), "ingested_claim"),
            ((caller, "agent"), (doc, "paper"), "AUTHORED"),
            ((caller, "agent"), (doc, "paper"), "authored"),
        ] {
            let before = edge_count(&pool).await;
            let (status, body) = post_edge(&state, caller, source, target, relationship).await;
            // The gate's own refusal, not the relationship list's: several of
            // these spellings are not in that list, which would refuse them
            // with a 400 of its own.
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{caller}: {relationship} {source:?} -> {target:?}: {body}"
            );
            assert!(
                body.to_string().contains("document ingest"),
                "{caller}: {relationship} {source:?} -> {target:?}: the refusal names the \
                 only writer: {body}"
            );
            assert_eq!(
                edge_count(&pool).await,
                before,
                "{relationship} {source:?} -> {target:?}: nothing written"
            );
        }
    }

    let (status, body) = post_edge(
        &state,
        author,
        (author, "agent"),
        (claim, "claim"),
        "asserts",
    )
    .await;
    assert!(
        status.is_success(),
        "CONTROL: the author's own asserts: {status} {body}"
    );
}

/// `PATCH /api/v1/edges/:id` as `caller` with `edges:write`.
async fn patch_edge(state: &AppState, caller: Uuid, id: Uuid, body: Value) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(&["edges:write"], caller);
    let req = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/api/v1/edges/{id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = create_router(state.clone())
        .oneshot(req)
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The ingest record on a GROUP-PRIVATE claim takes the claim's tenancy, so
/// it is owned by that group and its writers may patch it. They still cannot
/// turn a convergence into a creation or rewrite who ingested it: both keys
/// are reserved for the ingest (400, nothing changed). CONTROL: the same
/// writer patches another property of the same record, so the refusal is the
/// keys', not a missing write right.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_writer_cannot_rewrite_its_claims_ingest_record(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (member, group) = viewer_fixture::seed_agent_with_group(&pool, "edge-record-member").await;
    let (other, _) = viewer_fixture::seed_agent_with_group(&pool, "edge-record-other").await;
    let claim = viewer_fixture::seed_group_claim(&pool, member, group, "a group's claim").await;
    let doc = paper(&pool, "10.9999/ingest-record-patch").await;
    let record = {
        let mut conn = pool.acquire().await.expect("conn");
        epigraph_db::EdgeRepository::create_if_absent_including_retracted_signed_conn(
            &mut conn, None, doc, "paper", claim, "claim", "asserts", None, None, None,
        )
        .await
        .expect("asserts");
        assert!(epigraph_db::ClaimIngestRepository::record_signed_conn(
            &mut conn,
            None,
            doc,
            claim,
            other,
            false,
            &[],
            "ingest_document",
            "test-pipeline",
        )
        .await
        .expect("record"));
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM edges WHERE source_id = $1 AND target_id = $2 \
               AND relationship = 'ingested_claim'",
        )
        .bind(doc)
        .bind(claim)
        .fetch_one(&mut *conn)
        .await
        .expect("record id")
    };
    let props = || async {
        sqlx::query_as::<_, (Uuid, Value)>(
            "SELECT owner_group_id, properties FROM edges WHERE id = $1",
        )
        .bind(record)
        .fetch_one(&pool)
        .await
        .expect("record row")
    };
    let (owner, before) = props().await;
    assert_eq!(owner, group, "CALIBRATION: the record is the group's");

    for forged in [
        json!({"created_claim": true}),
        json!({"ingested_by": member.to_string()}),
        json!({"ingest_authors": [member.to_string()]}),
    ] {
        let (status, body) =
            patch_edge(&state, member, record, json!({"properties": forged})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{forged}: {body}");
        assert!(body.to_string().contains("reserved"), "{body}");
        assert_eq!(props().await.1, before, "{forged}: nothing changed");
    }

    let (status, body) = patch_edge(
        &state,
        member,
        record,
        json!({"properties": {"note": "curated"}}),
    )
    .await;
    assert!(
        status.is_success(),
        "CONTROL: the group's writer may patch the record otherwise: {status} {body}"
    );
    let (_, after) = props().await;
    assert_eq!(after["created_claim"], false, "{after}");
    assert_eq!(after["ingested_by"], other.to_string(), "{after}");
}

/// `GET /api/v1/agents/:id/claims` as `caller` with `claims:read`: the total.
async fn attributed_total(state: &AppState, caller: Uuid, agent: Uuid) -> i64 {
    let token = common::mint_token_with_agent(&["claims:read"], caller);
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/v1/agents/{agent}/claims"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let resp = create_router(state.clone())
        .oneshot(req)
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "attributed claims");
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    body["total"].as_i64().expect("total")
}

/// The same authorship written the other way round: an edge ONTO an agent
/// that credits it with the source's content (`claim -attributed_to-> agent`
/// and every other spelling the relationship list accepts), and an agent's
/// `generated`. A stranger is refused for a registered human and for an
/// agent that human operates (403, nothing written), and a third party's
/// `GET /api/v1/agents/:id/claims` lists none of it. The operator link's own
/// `OPERATED_BY` is refused for every caller (400). CONTROLS: the human
/// attributes its own claim to itself, and a claim to the agent it operates.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reverse_attribution_is_accepted_only_for_the_caller_or_its_live_agent(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "rev-stranger").await;
    let (reader, _) = viewer_fixture::seed_agent_with_group(&pool, "rev-reader").await;
    let (human, _) = viewer_fixture::seed_human_operator(&pool, "rev-human").await;
    let (bot, _) = viewer_fixture::seed_agent_with_group(&pool, "rev-bot").await;
    link(&pool, bot, human).await;
    let forged = viewer_fixture::seed_public_claim(&pool, stranger, "a stranger's claim").await;
    let own = viewer_fixture::seed_public_claim(&pool, human, "the human's own claim").await;
    let human_before = attributed_total(&state, reader, human).await;

    for target in [human, bot] {
        for relationship in [
            "attributed_to",
            "ATTRIBUTED_TO",
            "authored_by",
            "ORIGINATED_BY",
            "AMPLIFIED_BY",
            "GENERATED_BY",
            "interpreted_by",
        ] {
            let before = edge_count(&pool).await;
            let (status, body) = post_edge(
                &state,
                stranger,
                (forged, "claim"),
                (target, "agent"),
                relationship,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a stranger's claim -{relationship}-> {target}: {body}"
            );
            assert!(
                body.to_string().contains("operates"),
                "the refusal says whose edge it may write: {body}"
            );
            assert_eq!(edge_count(&pool).await, before, "nothing written");
        }
        let before = edge_count(&pool).await;
        let (status, body) = post_edge(
            &state,
            stranger,
            (target, "agent"),
            (forged, "claim"),
            "generated",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{target} -generated->: {body}"
        );
        assert_eq!(edge_count(&pool).await, before, "nothing written");
    }
    assert_eq!(
        attributed_total(&state, reader, human).await,
        human_before,
        "a third party sees no forged attribution"
    );

    for caller in [stranger, human] {
        for relationship in ["OPERATED_BY", "operated_by"] {
            let before = edge_count(&pool).await;
            let (status, body) = post_edge(
                &state,
                caller,
                (bot, "agent"),
                (caller, "agent"),
                relationship,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{relationship}: {body}");
            assert!(
                body.to_string().contains("operator link"),
                "the refusal names the only writer: {body}"
            );
            assert_eq!(edge_count(&pool).await, before, "nothing written");
        }
    }

    // CONTROLS: the human itself, and the agent it operates.
    let (status, body) = post_edge(
        &state,
        human,
        (own, "claim"),
        (human, "agent"),
        "attributed_to",
    )
    .await;
    assert!(status.is_success(), "CONTROL self: {status} {body}");
    let (status, body) = post_edge(
        &state,
        human,
        (own, "claim"),
        (bot, "agent"),
        "ORIGINATED_BY",
    )
    .await;
    assert!(status.is_success(), "CONTROL operated: {status} {body}");
    assert_eq!(
        attributed_total(&state, reader, human).await,
        human_before + 1,
        "CONTROL: the human's own attribution is listed"
    );
}

/// `POST /api/v1/claims/:id/provenance` as `caller` holding `scopes`.
async fn post_provenance(
    state: &AppState,
    caller: Uuid,
    scopes: &[&str],
    claim: Uuid,
    body: Value,
) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(scopes, caller);
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/claims/{claim}/provenance"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = create_router(state.clone())
        .oneshot(req)
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn agent_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM agents")
        .fetch_one(pool)
        .await
        .expect("count agents")
}

/// The provenance route writes `claim -ATTRIBUTED_TO-> author` and
/// `author -AUTHORED-> claim`, world-owned. A stranger (with or without write
/// scopes) cannot attach authors to someone else's claim; the claim's own
/// filer cannot attach a third party it does not operate (there is no
/// document to record that person's authorship on), nor name another agent as
/// the ingestion agent. Every refusal writes no edge and creates no agent.
/// CONTROL: a human attaches, to its own claim, an author node it operates
/// and itself as the ingestion agent.
#[sqlx::test(migrations = "../../migrations")]
async fn provenance_is_attached_only_by_the_filer_for_authors_it_speaks_for(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "prov-stranger").await;
    let (human, _) = viewer_fixture::seed_human_operator(&pool, "prov-human").await;
    let victim = viewer_fixture::seed_public_claim(&pool, human, "the human's claim").await;
    let write = ["claims:write", "edges:write"];
    let third_party = json!({"authors": [{"name": "Orsolya Quennell"}]});

    for (caller, scopes, claim, body, want, says) in [
        (
            stranger,
            &["claims:read"][..],
            victim,
            third_party.clone(),
            StatusCode::FORBIDDEN,
            "",
        ),
        (
            stranger,
            &write[..],
            victim,
            third_party.clone(),
            StatusCode::FORBIDDEN,
            "filer",
        ),
        (
            human,
            &write[..],
            victim,
            third_party.clone(),
            StatusCode::FORBIDDEN,
            "countersignature",
        ),
        (
            human,
            &write[..],
            victim,
            json!({"authors": [], "ingestion_agent_id": stranger}),
            StatusCode::FORBIDDEN,
            "ingestion agent",
        ),
    ] {
        let (edges, agents) = (edge_count(&pool).await, agent_count(&pool).await);
        let (status, got) = post_provenance(&state, caller, scopes, claim, body.clone()).await;
        assert_eq!(status, want, "{caller} {scopes:?} {body}: {got}");
        assert!(got.to_string().contains(says), "{body}: {got}");
        assert_eq!(edge_count(&pool).await, edges, "{body}: no edge written");
        assert_eq!(agent_count(&pool).await, agents, "{body}: no agent created");
    }

    // CONTROL: the author node a name derives, operated by the human.
    let name = "Tamsin Ferrow";
    let node: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
    )
    .bind(
        epigraph_crypto::did_key::did_key_for_author(None, name)
            .1
            .as_slice(),
    )
    .bind(name)
    .fetch_one(&pool)
    .await
    .expect("author node");
    link(&pool, node, human).await;
    let (status, got) = post_provenance(
        &state,
        human,
        &write,
        victim,
        json!({"authors": [{"name": name, "position": 0}], "ingestion_agent_id": human}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "CONTROL: {got}");
    assert_eq!(got["edges_created"], 3, "{got}");
    let written: Vec<(String, Uuid, Uuid)> = sqlx::query_as(
        "SELECT relationship, source_id, target_id FROM edges \
          WHERE (source_id = $1 OR target_id = $1) \
            AND relationship IN ('ATTRIBUTED_TO', 'AUTHORED', 'WAS_ASSOCIATED_WITH') \
          ORDER BY relationship",
    )
    .bind(victim)
    .fetch_all(&pool)
    .await
    .expect("written edges");
    assert_eq!(
        written,
        vec![
            ("ATTRIBUTED_TO".to_string(), victim, node),
            ("AUTHORED".to_string(), node, victim),
            ("WAS_ASSOCIATED_WITH".to_string(), victim, human),
        ]
    );
}

/// The evidence detail's `agent_id` is the evidence row's own record (its
/// signer, set by the writer that stored it), never the source of an
/// `agent -> evidence` edge. A stranger may post `supports`,
/// `derived_from`, `uses_evidence` or `relates_to` from a registered human
/// onto someone's evidence (none of these credits the agent, so the edge
/// route accepts them); the detail still names the evidence's signer, and
/// names no agent for unsigned evidence.
#[sqlx::test(migrations = "../../migrations")]
async fn a_strangers_edge_onto_evidence_never_names_its_agent(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "ev-stranger").await;
    let (reader, _) = viewer_fixture::seed_agent_with_group(&pool, "ev-reader").await;
    let (signer, _) = viewer_fixture::seed_agent_with_group(&pool, "ev-signer").await;
    let (human, _) = viewer_fixture::seed_human_operator(&pool, "ev-human").await;
    let claim = viewer_fixture::seed_public_claim(&pool, signer, "a claim with evidence").await;
    let mut seeded = Vec::new();
    for signed in [true, false] {
        let ev = Uuid::new_v4();
        let hash: Vec<u8> = ev.as_bytes().iter().copied().cycle().take(32).collect();
        sqlx::query(
            "INSERT INTO evidence (id, raw_content, content_hash, evidence_type, claim_id, \
                                   properties, signature, signer_id) \
             VALUES ($1, 'ev', $2, 'document', $3, '{}'::jsonb, $4, $5)",
        )
        .bind(ev)
        .bind(&hash)
        .bind(claim)
        .bind(signed.then(|| vec![7_u8; 64]))
        .bind(signed.then_some(signer))
        .execute(&pool)
        .await
        .expect("seed evidence");
        seeded.push((ev, signed.then_some(signer)));
    }
    for (ev, expected) in seeded {
        for rel in ["supports", "derived_from", "uses_evidence", "relates_to"] {
            let (status, body) =
                post_edge(&state, stranger, (human, "agent"), (ev, "evidence"), rel).await;
            assert!(
                status.is_success() || status == StatusCode::CONFLICT,
                "CALIBRATION: the route accepts human -{rel}-> evidence: {status} {body}"
            );
        }
        let token = common::mint_token_with_agent(&["claims:read"], reader);
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/api/v1/evidence/{ev}"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request");
        let resp = create_router(state.clone())
            .oneshot(req)
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        let detail: Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(
            detail["agent_id"],
            expected.map_or(Value::Null, |s| json!(s.to_string())),
            "the evidence's agent is its own record, never a stranger's edge: {detail}"
        );
    }
}
