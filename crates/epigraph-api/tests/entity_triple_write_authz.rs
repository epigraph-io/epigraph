//! The entity-mention and triple batch writes are authorized against the
//! CLAIM each item attaches to, not only against the `claims:write` scope
//! (backlog 850dcc61).
//!
//! `POST /api/v1/entity-mentions/batch` and `POST /api/v1/triples/batch`
//! authorize each item against its target claim through the caller's viewer.
//! The rule these tests pin, item by item over the whole batch:
//!
//! * a claim the caller cannot read is `404`, answered exactly like a claim
//!   that does not exist;
//! * a claim the caller can read but whose owning group it cannot write
//!   (`admin` / `writer` membership) is `403 not_owner`, rule
//!   `not_claim_writer`;
//! * one refused item refuses the batch, and nothing from it is written, even
//!   when the refused item comes LAST, after items the caller may write.
//!
//! Driven over HTTP through the real router (`common::spawn_app`). Its DSN is
//! the test superuser, which BYPASSES row security, so every refusal here comes
//! from the handler's own check and none from the database's policies. The
//! application-role half (the owner's write commits under `epigraph_app`, with
//! row security forced) is `entity_triple_write_app_role.rs`.
#![cfg(feature = "db")]

mod common;
mod viewer_fixture;

use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, seed_agent_with_group};

async fn claim_of(pool: &PgPool, agent: Uuid, group: Uuid, visibility: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, $5, $6)",
    )
    .bind(id)
    .bind(format!("850dcc61 claim {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn entity(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO entities (canonical_name, type_top, is_canonical) \
         VALUES ($1, 'Material', true) RETURNING id",
    )
    .bind(format!("850dcc61 entity {}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed entity")
}

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

/// Rows of `table` (`triples` or `entity_mentions`) attached to `claim`, read
/// on the superuser harness connection so nothing is filtered.
async fn rows_on(pool: &PgPool, table: &str, claim: Uuid) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE claim_id = $1"))
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count rows")
}

fn triple(claim: Uuid, subject: Uuid) -> serde_json::Value {
    serde_json::json!({
        "claim_id": claim,
        "subject_id": subject,
        "predicate": "is_a",
        "object_literal": "probe",
        "confidence": 0.9,
        "extractor": "850dcc61-test",
    })
}

fn mention(claim: Uuid, entity: Uuid) -> serde_json::Value {
    serde_json::json!({
        "entity_id": entity,
        "claim_id": claim,
        "surface_form": "probe",
        "mention_role": "subject",
        "confidence": 0.9,
        "extractor": "850dcc61-test",
    })
}

struct App {
    addr: std::net::SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn app(pool: &PgPool) -> App {
    let (addr, _shutdown) = common::spawn_app(&database_url_for(pool).await).await;
    App { addr, _shutdown }
}

async fn post(
    app: &App,
    agent: Uuid,
    path: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = reqwest::Client::new()
        .post(format!("http://{}{path}", app.addr))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)),
    )
}

async fn post_triples(
    app: &App,
    agent: Uuid,
    items: Vec<serde_json::Value>,
) -> (u16, serde_json::Value) {
    post(
        app,
        agent,
        "/api/v1/triples/batch",
        serde_json::json!({ "triples": items }),
    )
    .await
}

async fn post_mentions(
    app: &App,
    agent: Uuid,
    items: Vec<serde_json::Value>,
) -> (u16, serde_json::Value) {
    post(
        app,
        agent,
        "/api/v1/entity-mentions/batch",
        serde_json::json!({ "mentions": items }),
    )
    .await
}

fn assert_not_claim_writer(status: u16, body: &serde_json::Value, claim: Uuid) {
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "not_owner", "{body}");
    assert_eq!(body["rule"], "not_claim_writer", "{body}");
    assert_eq!(body["claim_id"], claim.to_string(), "{body}");
}

/// A `claims:write` caller with no membership in the owning group cannot
/// attach a triple or a mention to that group's private claim: `404`, and
/// nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stranger_cannot_attach_to_another_groups_private_claim(pool: PgPool) {
    let (owner, og) = seed_agent_with_group(&pool, "850-owner").await;
    let (stranger, _) = seed_agent_with_group(&pool, "850-stranger").await;
    let private = claim_of(&pool, owner, og, "group").await;
    let e = entity(&pool).await;
    let app = app(&pool).await;

    let (status, body) = post_triples(&app, stranger, vec![triple(private, e)]).await;
    assert_eq!(status, 404, "triples: {body}");
    assert_eq!(
        rows_on(&pool, "triples", private).await,
        0,
        "a triple was written"
    );

    let (status, body) = post_mentions(&app, stranger, vec![mention(private, e)]).await;
    assert_eq!(status, 404, "mentions: {body}");
    assert_eq!(
        rows_on(&pool, "entity_mentions", private).await,
        0,
        "a mention was written"
    );
}

/// A hidden claim is answered exactly like a missing one: the refusal for a
/// claim the caller cannot read is the refusal for a claim that does not
/// exist, byte for byte once the id is masked, on both batch endpoints.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_claim_is_answered_like_a_missing_one(pool: PgPool) {
    let (owner, og) = seed_agent_with_group(&pool, "850-owner").await;
    let (stranger, _) = seed_agent_with_group(&pool, "850-stranger").await;
    let private = claim_of(&pool, owner, og, "group").await;
    let missing = Uuid::new_v4();
    let e = entity(&pool).await;
    let app = app(&pool).await;

    let (hs, hb) = post_triples(&app, stranger, vec![triple(private, e)]).await;
    let (ms, mb) = post_triples(&app, stranger, vec![triple(missing, e)]).await;
    let h = hb.to_string().replace(&private.to_string(), "<id>");
    let m = mb.to_string().replace(&missing.to_string(), "<id>");
    assert_eq!((hs, &h), (ms, &m), "triples");
    assert_eq!(hs, 404, "triples: {h}");

    let (hs, hb) = post_mentions(&app, stranger, vec![mention(private, e)]).await;
    let (ms, mb) = post_mentions(&app, stranger, vec![mention(missing, e)]).await;
    let h = hb.to_string().replace(&private.to_string(), "<id>");
    let m = mb.to_string().replace(&missing.to_string(), "<id>");
    assert_eq!((hs, &h), (ms, &m), "mentions");
    assert_eq!(hs, 404, "mentions: {h}");
}

/// A PUBLIC claim the caller can read but whose owning group it cannot write
/// is refused by name (`403 not_claim_writer`), for both endpoints.
#[sqlx::test(migrations = "../../migrations")]
async fn a_readable_claim_the_caller_cannot_write_is_refused_by_name(pool: PgPool) {
    let (owner, og) = seed_agent_with_group(&pool, "850-owner").await;
    let (stranger, _) = seed_agent_with_group(&pool, "850-stranger").await;
    let public = claim_of(&pool, owner, og, "public").await;
    let e = entity(&pool).await;
    let app = app(&pool).await;

    let (status, body) = post_triples(&app, stranger, vec![triple(public, e)]).await;
    assert_not_claim_writer(status, &body, public);
    assert_eq!(rows_on(&pool, "triples", public).await, 0);

    let (status, body) = post_mentions(&app, stranger, vec![mention(public, e)]).await;
    assert_not_claim_writer(status, &body, public);
    assert_eq!(rows_on(&pool, "entity_mentions", public).await, 0);
}

/// One refused item refuses the whole batch. The refused item is LAST, after
/// items on the caller's own claims, so this catches a non-atomic batch that
/// commits earlier items before refusing a later one: no row from the batch
/// may remain.
#[sqlx::test(migrations = "../../migrations")]
async fn a_batch_whose_last_item_is_refused_writes_nothing(pool: PgPool) {
    let (owner, og) = seed_agent_with_group(&pool, "850-owner").await;
    let (caller, cg) = seed_agent_with_group(&pool, "850-caller").await;
    let mine = claim_of(&pool, caller, cg, "group").await;
    let mine_public = claim_of(&pool, caller, cg, "public").await;
    let theirs_private = claim_of(&pool, owner, og, "group").await;
    let theirs_public = claim_of(&pool, owner, og, "public").await;
    let e = entity(&pool).await;
    let app = app(&pool).await;

    let (status, body) = post_triples(
        &app,
        caller,
        vec![
            triple(mine, e),
            triple(mine_public, e),
            triple(theirs_private, e),
        ],
    )
    .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(rows_on(&pool, "triples", mine).await, 0, "partial write");
    assert_eq!(
        rows_on(&pool, "triples", mine_public).await,
        0,
        "partial write"
    );

    let (status, body) = post_mentions(
        &app,
        caller,
        vec![
            mention(mine, e),
            mention(mine_public, e),
            mention(theirs_public, e),
        ],
    )
    .await;
    assert_not_claim_writer(status, &body, theirs_public);
    assert_eq!(
        rows_on(&pool, "entity_mentions", mine).await,
        0,
        "partial write"
    );
    assert_eq!(
        rows_on(&pool, "entity_mentions", mine_public).await,
        0,
        "partial write"
    );
}

/// Write authority is MEMBERSHIP of the owning group with a write-capable
/// role, not authorship: a `reader` of the group is refused by name, a
/// `writer` of the same group (who authored nothing) attaches.
#[sqlx::test(migrations = "../../migrations")]
async fn a_writer_of_the_owning_group_attaches_and_a_reader_is_refused(pool: PgPool) {
    let (owner, og) = seed_agent_with_group(&pool, "850-owner").await;
    let (writer, _) = seed_agent_with_group(&pool, "850-writer").await;
    let (reader, _) = seed_agent_with_group(&pool, "850-reader").await;
    add_member(&pool, og, writer, "writer").await;
    add_member(&pool, og, reader, "reader").await;
    let c = claim_of(&pool, owner, og, "group").await;
    let e = entity(&pool).await;
    let app = app(&pool).await;

    let (status, body) = post_triples(&app, reader, vec![triple(c, e)]).await;
    assert_not_claim_writer(status, &body, c);
    assert_eq!(rows_on(&pool, "triples", c).await, 0);

    let (status, body) = post_triples(&app, writer, vec![triple(c, e)]).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["count"], 1, "{body}");
    assert_eq!(rows_on(&pool, "triples", c).await, 1);
}

/// The owner attaches triples and mentions to its own private and public
/// claims in one batch each, and every row lands.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_attaches_to_its_own_claims(pool: PgPool) {
    let (caller, cg) = seed_agent_with_group(&pool, "850-caller").await;
    let private = claim_of(&pool, caller, cg, "group").await;
    let public = claim_of(&pool, caller, cg, "public").await;
    let e = entity(&pool).await;
    let app = app(&pool).await;

    let (status, body) = post_triples(
        &app,
        caller,
        vec![triple(private, e), triple(public, e), triple(private, e)],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["count"], 3, "{body}");
    assert_eq!(rows_on(&pool, "triples", private).await, 2);
    assert_eq!(rows_on(&pool, "triples", public).await, 1);

    let (status, body) =
        post_mentions(&app, caller, vec![mention(private, e), mention(public, e)]).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["count"], 2, "{body}");
    assert_eq!(rows_on(&pool, "entity_mentions", private).await, 1);
    assert_eq!(rows_on(&pool, "entity_mentions", public).await, 1);
}
