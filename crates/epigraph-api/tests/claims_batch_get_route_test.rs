#![cfg(feature = "db")]
//! `POST /api/v1/claims/batch-get`.
//!
//! Hermetic `#[sqlx::test]`: the order, partition and byte-budget assertions
//! only mean anything on a database that holds nothing but this test's
//! fixtures.
//!
//! `AppState` is built with `with_scoped_pool`, so `read_as` has a scoped pool
//! to stamp from (every other constructor makes it refuse, and the handler
//! would answer 500).
//!
//! The tenancy arms compare RAW bodies, not parsed ones: "a private claim is
//! indistinguishable from an absent one" is a statement about the bytes a
//! stranger receives.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::HashSet;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use epigraph_api::routes::claims_batch_get::{MAX_BATCH_GET_BYTES, MAX_BATCH_GET_IDS};
use epigraph_api::{create_router, ApiConfig, AppState};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const PATH: &str = "/api/v1/claims/batch-get";

async fn router(pool: &PgPool) -> Router {
    create_router(AppState::with_scoped_pool(
        fixture::scoped_pool(pool).await,
        ApiConfig::default(),
    ))
}

fn token(agent: Uuid) -> String {
    common::mint_token_with_agent(&["claims:read"], agent)
}

async fn send(
    app: &Router,
    method: Method,
    path: &str,
    body: Option<(&str, &str)>,
    bearer: Option<&str>,
) -> (StatusCode, String) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let body = match body {
        Some((content_type, text)) => {
            if !content_type.is_empty() {
                req = req.header("content-type", content_type);
            }
            Body::from(text.to_string())
        }
        None => Body::empty(),
    };
    let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into())
}

/// POST a raw JSON text; returns the status and the raw body.
async fn post_raw(app: &Router, text: &str, bearer: &str) -> (StatusCode, String) {
    send(
        app,
        Method::POST,
        PATH,
        Some(("application/json", text)),
        Some(bearer),
    )
    .await
}

/// POST `{"ids": ids}`; returns the status, the parsed body and the raw body.
async fn batch(app: &Router, ids: &[String], bearer: &str) -> (StatusCode, Value, String) {
    let text = json!({ "ids": ids }).to_string();
    let (status, raw) = post_raw(app, &text, bearer).await;
    let value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    (status, value, raw)
}

fn strs(ids: &[Uuid]) -> Vec<String> {
    ids.iter().map(Uuid::to_string).collect()
}

fn id_list(body: &Value, key: &str) -> Vec<String> {
    body[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array missing from {body}"))
        .iter()
        .map(|v| v.as_str().expect("id string").to_string())
        .collect()
}

fn claim_ids(body: &Value) -> Vec<String> {
    body["claims"]
        .as_array()
        .unwrap_or_else(|| panic!("claims array missing from {body}"))
        .iter()
        .map(|c| c["id"].as_str().expect("claim id").to_string())
        .collect()
}

fn item(body: &Value, id: Uuid) -> &Value {
    body["claims"]
        .as_array()
        .expect("claims array")
        .iter()
        .find(|c| c["id"] == id.to_string())
        .unwrap_or_else(|| panic!("claim {id} missing from {body}"))
}

fn top_keys(body: &Value) -> Vec<String> {
    let mut keys: Vec<String> = body.as_object().expect("object").keys().cloned().collect();
    keys.sort();
    keys
}

/// `owner`'s personal group, with the `agents` row `groups_created_by_fkey`
/// needs (copied from `claim_ego_route_test.rs`).
async fn personal_group_for(pool: &PgPool, owner: Uuid) -> Uuid {
    let pk: Vec<u8> = owner.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system') ON CONFLICT (id) DO NOTHING",
    )
    .bind(owner)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed the owning agent");
    common::personal_group_of(pool, owner).await
}

/// Stamp a trace group-private to `owner`'s personal group with a privileged
/// harness UPDATE, checking the stamp landed (copied from
/// `claim_ego_route_test.rs`).
async fn make_trace_private(pool: &PgPool, trace_id: Uuid, owner: Uuid) {
    let group = personal_group_for(pool, owner).await;
    let got: Option<(String, Uuid)> = sqlx::query_as(
        "UPDATE reasoning_traces SET visibility = 'group', owner_group_id = $2 \
         WHERE id = $1 RETURNING visibility, owner_group_id",
    )
    .bind(trace_id)
    .bind(group)
    .fetch_optional(pool)
    .await
    .expect("stamp the trace group-private");
    assert_eq!(
        got,
        Some(("group".to_string(), group)),
        "a mis-stamped trace makes every 'a stranger sees nothing' assertion vacuous"
    );
}

/// A `claim_encryption` row for a claim that is already group-private
/// (migration 081 refuses a seal on a public claim).
async fn seal(pool: &PgPool, claim: Uuid, group: Uuid) {
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT DO NOTHING",
    )
    .bind(group)
    .execute(pool)
    .await
    .expect("seed the group key epoch the FK requires");
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                       encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', decode('0badc0de', 'hex'))",
    )
    .bind(claim)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed a claim_encryption row");
}

/// A group-private, sealed claim owned by `owner`; returns `(claim, group)`.
async fn seed_sealed_claim(pool: &PgPool, owner: Uuid, content: &str) -> (Uuid, Uuid) {
    let claim = common::seed_claim_with_agent(pool, content, owner).await;
    common::seed_private_ownership(pool, claim, owner).await;
    let group = common::personal_group_of(pool, owner).await;
    seal(pool, claim, group).await;
    (claim, group)
}

async fn set_labels(pool: &PgPool, claim: Uuid, labels: &[&str]) {
    let labels: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query("UPDATE claims SET labels = $2 WHERE id = $1")
        .bind(claim)
        .bind(&labels)
        .execute(pool)
        .await
        .expect("set labels");
}

async fn retire(pool: &PgPool, claim: Uuid) {
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(claim)
        .execute(pool)
        .await
        .expect("retire the claim");
}

/// A public claim with explicit, whole-second timestamps, so every such item
/// serialises its two timestamps to the same width. `claims_updated_at` is a
/// BEFORE UPDATE trigger, so an INSERT keeps the values given.
async fn seed_fixed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             labels, created_at, updated_at) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[], \
                 '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed fixed claim");
    id
}

/// `n` public claims of about 64 KB each: together they exceed the byte budget.
async fn seed_large_claims(pool: &PgPool, agent: Uuid, n: usize) -> Vec<Uuid> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let content = format!("large claim {i:03} {}", "x".repeat(64 * 1024));
        out.push(seed_fixed_claim(pool, agent, &content).await);
    }
    out
}

/// Byte length of the `claims` array as the handler accounts for it.
fn claims_array_len(body: &Value) -> usize {
    serde_json::to_vec(&body["claims"]).unwrap().len()
}

/// `2 + sum(len_i) + (n - 1)`, from the items one by one.
fn accounted_len(body: &Value) -> usize {
    let items = body["claims"].as_array().expect("claims array");
    if items.is_empty() {
        return 2;
    }
    2 + items
        .iter()
        .map(|i| serde_json::to_vec(i).unwrap().len())
        .sum::<usize>()
        + (items.len() - 1)
}

/// Resubmit `remaining` until it is empty; return every response body.
async fn drain(app: &Router, ids: &[String], bearer: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut next = ids.to_vec();
    for _ in 0..10 {
        let (status, body, _) = batch(app, &next, bearer).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        next = id_list(&body, "remaining");
        out.push(body);
        if next.is_empty() {
            return out;
        }
    }
    panic!("the cursor did not complete in 10 rounds");
}

// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn requires_a_bearer(pool: PgPool) {
    let app = router(&pool).await;
    let (status, _) = send(
        &app,
        Method::POST,
        PATH,
        Some(("application/json", r#"{"ids":[]}"#)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn each_item_is_the_get_body_plus_is_current(pool: PgPool) {
    let owner = Uuid::new_v4();
    let labelled = common::seed_claim_with_agent(&pool, "a labelled claim", owner).await;
    set_labels(&pool, labelled, &["doi:10.1234/x", "topic:atlas"]).await;
    let plain = common::seed_claim_with_agent(&pool, "an unlabelled claim", owner).await;
    let traced = common::seed_claim_with_agent(&pool, "a traced public claim", owner).await;
    let trace = fixture::seed_reasoning_trace(&pool, traced, "deductive").await;
    let retired = common::seed_claim_with_agent(&pool, "a retired claim", owner).await;
    retire(&pool, retired).await;
    let (sealed, group) = seed_sealed_claim(&pool, owner, "a fully private claim").await;

    let app = router(&pool).await;
    let bearer = token(owner);
    let ids = [labelled, plain, traced, retired, sealed];
    let (status, body, _) = batch(&app, &strs(&ids), &bearer).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(claim_ids(&body), strs(&ids));
    assert!(id_list(&body, "not_found").is_empty());
    assert!(id_list(&body, "remaining").is_empty());

    for id in ids {
        let (status, get_raw) = send(
            &app,
            Method::GET,
            &format!("/api/v1/claims/{id}"),
            None,
            Some(&bearer),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "GET {id}: {get_raw}");
        let mut get_body: Value = serde_json::from_str(&get_raw).unwrap();

        let mut batch_item = item(&body, id).clone();
        let is_current = batch_item
            .as_object_mut()
            .unwrap()
            .remove("is_current")
            .expect("is_current is always present");
        assert_eq!(is_current, Value::Bool(id != retired), "is_current of {id}");

        // trace_id is checked on its own: GET and batch-get agree here because
        // the caller can read every trace involved.
        let get_trace = get_body.as_object_mut().unwrap().remove("trace_id");
        let batch_trace = batch_item.as_object_mut().unwrap().remove("trace_id");
        assert_eq!(batch_trace, get_trace, "trace_id of {id}");
        // `authored_by` is GET's alone (several reads per claim); a batch item
        // omits it rather than carry a different block.
        assert!(
            get_body
                .as_object_mut()
                .unwrap()
                .remove("authored_by")
                .is_some(),
            "GET carries authored_by for {id}"
        );
        assert!(
            batch_item.get("authored_by").is_none(),
            "a batch item has no authored_by: {batch_item}"
        );
        assert_eq!(batch_item, get_body, "batch item of {id} vs its GET body");
    }

    assert_eq!(item(&body, traced)["trace_id"], trace.to_string());
    assert_eq!(item(&body, plain)["trace_id"], Value::Null);
    let mut labels: Vec<String> = item(&body, labelled)["labels"]
        .as_array()
        .expect("labels")
        .iter()
        .map(|l| l.as_str().unwrap().to_string())
        .collect();
    labels.sort();
    assert_eq!(labels, vec!["doi:10.1234/x", "topic:atlas"]);
    assert!(
        item(&body, plain).get("labels").is_none(),
        "labels omitted when empty"
    );
    let s = item(&body, sealed);
    assert_eq!(s["privacy_tier"], "fully_private");
    assert_eq!(s["encryption_epoch"], 0);
    assert_eq!(s["group_id"], group.to_string());
    assert_eq!(s["encrypted_content"], "C63A3g==");
    assert!(item(&body, plain).get("privacy_tier").is_none());
    for i in body["claims"].as_array().unwrap() {
        for k in [
            "belief",
            "plausibility",
            "pignistic_prob",
            "supersedes",
            "was_created",
        ] {
            assert!(i.get(k).is_none(), "{k} must not be served: {i}");
        }
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn request_order_is_kept_and_duplicates_collapse(pool: PgPool) {
    let agent = Uuid::new_v4();
    let a = common::seed_claim_with_agent(&pool, "claim a", agent).await;
    let b = common::seed_claim_with_agent(&pool, "claim b", agent).await;
    let absent = Uuid::new_v4();
    let app = router(&pool).await;

    let ids = vec![
        b.to_string(),
        a.to_string(),
        b.to_string().to_uppercase(),
        absent.simple().to_string(),
        b.to_string(),
    ];
    let (status, body, _) = batch(&app, &ids, &token(Uuid::new_v4())).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(claim_ids(&body), strs(&[b, a]));
    assert_eq!(
        id_list(&body, "not_found"),
        vec![absent.to_string()],
        "echoed in canonical form"
    );
    assert!(id_list(&body, "remaining").is_empty());
    assert_eq!(top_keys(&body), vec!["claims", "not_found", "remaining"]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_claim_is_indistinguishable_from_an_absent_one(pool: PgPool) {
    let owner = Uuid::new_v4();
    let p = common::seed_claim_with_agent(&pool, "a public claim", owner).await;
    let (secret, group) = seed_sealed_claim(&pool, owner, "the secret content").await;
    let absent = Uuid::new_v4();

    // A stranger in a group of its own: two viewers, two disjoint group sets.
    let stranger = Uuid::new_v4();
    let stranger_group = personal_group_for(&pool, stranger).await;
    assert_ne!(stranger_group, group);

    let app = router(&pool).await;
    let st = token(stranger);

    let (s1, b1, raw1) = batch(&app, &strs(&[p, secret]), &st).await;
    let (s2, b2, raw2) = batch(&app, &strs(&[p, absent]), &st).await;
    assert_eq!(s1, StatusCode::OK, "body: {raw1}");
    assert_eq!(s2, StatusCode::OK, "body: {raw2}");

    assert_eq!(
        raw1.replace(&secret.to_string(), "<ID>"),
        raw2.replace(&absent.to_string(), "<ID>"),
        "a private id and an absent id must give byte-identical bodies"
    );
    for b in [&b1, &b2] {
        assert_eq!(claim_ids(b), vec![p.to_string()], "only the public claim");
        assert_eq!(top_keys(b), vec!["claims", "not_found", "remaining"]);
    }
    let low = raw1.to_lowercase();
    assert!(!raw1.contains("the secret content"));
    assert!(!low.contains(&group.to_string()));
    assert!(!low.contains(&group.simple().to_string()));
    assert!(!raw1.contains("encrypted_content"));
    assert!(!raw1.contains("privacy_tier"));
    assert_eq!(
        raw1.matches(&secret.to_string()).count(),
        1,
        "the secret id appears once"
    );
    assert_eq!(id_list(&b1, "not_found"), vec![secret.to_string()]);
    assert_eq!(id_list(&b2, "not_found"), vec![absent.to_string()]);

    // Calibration: the owner gets both, with the seal fields.
    let (status, body, _) = batch(&app, &strs(&[p, secret]), &token(owner)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(claim_ids(&body), strs(&[p, secret]));
    let s = item(&body, secret);
    assert_eq!(s["content"], "the secret content");
    assert_eq!(s["group_id"], group.to_string());
    assert_eq!(s["privacy_tier"], "fully_private");
    assert!(s.get("encrypted_content").is_some());
    assert!(id_list(&body, "not_found").is_empty());
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_id_in_the_tail_goes_to_remaining_like_an_absent_one(pool: PgPool) {
    let owner = Uuid::new_v4();
    personal_group_for(&pool, owner).await;
    let large = seed_large_claims(&pool, owner, 40).await;
    let (secret, _) = seed_sealed_claim(&pool, owner, "the secret content").await;
    let absent = Uuid::new_v4();
    let stranger = Uuid::new_v4();
    personal_group_for(&pool, stranger).await;
    let app = router(&pool).await;
    let st = token(stranger);

    let mut ids = strs(&large);
    ids.push(secret.to_string());
    ids.push(absent.to_string());

    let (status, body, _) = batch(&app, &ids, &st).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let remaining = id_list(&body, "remaining");
    let not_found = id_list(&body, "not_found");
    assert!(
        claim_ids(&body).len() < large.len(),
        "the fixture must overflow the budget"
    );
    for hidden in [secret, absent] {
        assert!(
            remaining.contains(&hidden.to_string()),
            "{hidden} in remaining"
        );
        assert!(!not_found.contains(&hidden.to_string()));
    }

    // The tail cut does not depend on whether the last id is hidden or absent.
    let mut with_secret = strs(&large);
    with_secret.push(secret.to_string());
    let mut with_absent = strs(&large);
    with_absent.push(absent.to_string());
    let (_, _, r1) = batch(&app, &with_secret, &st).await;
    let (_, _, r2) = batch(&app, &with_absent, &st).await;
    assert_eq!(
        r1.replace(&secret.to_string(), "<ID>"),
        r2.replace(&absent.to_string(), "<ID>")
    );

    // Resubmitting classifies them: not_found for the stranger ...
    let rounds = drain(&app, &remaining, &st).await;
    let last = rounds.last().unwrap();
    assert_eq!(
        id_list(last, "not_found"),
        strs(&[secret, absent]),
        "both hidden and absent are not_found once classified"
    );
    // ... and the secret claim for its owner.
    let rounds = drain(&app, &ids, &token(owner)).await;
    let got: Vec<String> = rounds.iter().flat_map(claim_ids).collect();
    assert!(got.contains(&secret.to_string()));
    let nf: Vec<String> = rounds
        .iter()
        .flat_map(|b| id_list(b, "not_found"))
        .collect();
    assert_eq!(nf, vec![absent.to_string()]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_byte_budget_is_respected_and_the_cursor_completes(pool: PgPool) {
    let agent = Uuid::new_v4();
    personal_group_for(&pool, agent).await;
    let large = seed_large_claims(&pool, agent, 40).await;
    let absent = Uuid::new_v4();
    let app = router(&pool).await;
    let bearer = token(Uuid::new_v4());

    let mut ids = strs(&large);
    ids.insert(5, absent.to_string());
    let rounds = drain(&app, &ids, &bearer).await;
    assert!(rounds.len() >= 2, "40 x 64 KB must not fit in one response");

    let mut seen_claims: Vec<String> = Vec::new();
    for body in &rounds {
        let n = body["claims"].as_array().unwrap().len();
        let len = claims_array_len(body);
        assert!(
            len <= MAX_BATCH_GET_BYTES || n == 1,
            "claims array is {len} bytes over {n} items"
        );
        assert_eq!(len, accounted_len(body), "brackets and commas are counted");
        // Partition: the three arrays of one response cover its request.
        let c = claim_ids(body);
        let nf = id_list(body, "not_found");
        let r = id_list(body, "remaining");
        let all: HashSet<&String> = c.iter().chain(&nf).chain(&r).collect();
        assert_eq!(all.len(), c.len() + nf.len() + r.len(), "no id twice");
        seen_claims.extend(c);
    }
    let first = &rounds[0];
    assert_eq!(
        id_list(first, "not_found"),
        vec![absent.to_string()],
        "the absent id before the cut is classified in the first round"
    );
    let rest = id_list(first, "remaining");
    assert_eq!(
        claim_ids(first).len() + 1 + rest.len(),
        ids.len(),
        "claims, not_found and remaining partition the request"
    );
    // The first round is cut by bytes: one more item would have broken the cap.
    let next_len = {
        let (_, one, _) = batch(&app, &rest[..1], &bearer).await;
        serde_json::to_vec(&one["claims"][0]).unwrap().len()
    };
    assert!(claims_array_len(first) + 1 + next_len > MAX_BATCH_GET_BYTES);

    // Looping on `remaining` returns every claim exactly once.
    assert_eq!(
        seen_claims,
        strs(&large),
        "every claim once, in request order"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_byte_budget_counts_brackets_and_commas_at_the_boundary(pool: PgPool) {
    let agent = Uuid::new_v4();
    personal_group_for(&pool, agent).await;
    let app = router(&pool).await;
    let bearer = token(Uuid::new_v4());

    // Measure the fixed part of an item: everything but the content. Every
    // fixture here has the same agent, fixed-width ids, no labels, no trace and
    // the same whole-second timestamps, so the item length is base + content.
    let probe_content = "p".repeat(100);
    let probe = seed_fixed_claim(&pool, agent, &probe_content).await;
    let (_, body, _) = batch(&app, &strs(&[probe]), &bearer).await;
    let base = serde_json::to_vec(&body["claims"][0]).unwrap().len() - probe_content.len();

    // n items whose lengths sum to cap - 16: the items alone fit, but the
    // array (sum + n + 1 = cap + 17) does not, so the last one must be cut.
    let n: usize = 32;
    let target_sum = MAX_BATCH_GET_BYTES - 16;
    let each = target_sum / n;
    let mut lens = vec![each; n];
    lens[n - 1] += target_sum - each * n;
    let mut ids = Vec::with_capacity(n);
    for (i, len) in lens.iter().enumerate() {
        let prefix = format!("boundary {i:03} ");
        let content = format!("{prefix}{}", "y".repeat(len - base - prefix.len()));
        ids.push(seed_fixed_claim(&pool, agent, &content).await);
    }

    let (status, body, _) = batch(&app, &strs(&ids), &bearer).await;
    assert_eq!(status, StatusCode::OK);
    let items = body["claims"].as_array().unwrap();
    let item_sum: usize = items
        .iter()
        .map(|i| serde_json::to_vec(i).unwrap().len())
        .sum();
    assert_eq!(items.len(), n - 1, "the last item goes to remaining");
    assert_eq!(id_list(&body, "remaining"), vec![ids[n - 1].to_string()]);
    assert_eq!(
        item_sum + lens[n - 1],
        target_sum,
        "the fixture is sized as planned, so the arm tests the boundary"
    );
    assert!(target_sum <= MAX_BATCH_GET_BYTES);
    assert!(target_sum + n + 1 > MAX_BATCH_GET_BYTES);
    assert!(claims_array_len(&body) <= MAX_BATCH_GET_BYTES);
}

#[sqlx::test(migrations = "../../migrations")]
async fn more_than_100_ids_is_400(pool: PgPool) {
    let app = router(&pool).await;
    let bearer = token(Uuid::new_v4());
    let ids: Vec<String> = (0..=MAX_BATCH_GET_IDS)
        .map(|_| Uuid::new_v4().to_string())
        .collect();
    let (status, body, _) = batch(&app, &ids, &bearer).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "ValidationError");
    assert_eq!(body["details"]["field"], "ids");

    let (status, body, _) = batch(&app, &ids[..MAX_BATCH_GET_IDS], &bearer).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(id_list(&body, "not_found").len(), MAX_BATCH_GET_IDS);
}

#[sqlx::test(migrations = "../../migrations")]
async fn malformed_bodies_are_400(pool: PgPool) {
    let app = router(&pool).await;
    let bearer = token(Uuid::new_v4());

    let (status, body, _) = batch(
        &app,
        &[Uuid::new_v4().to_string(), "not-a-uuid".to_string()],
        &bearer,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "ValidationError");
    assert_eq!(body["details"]["field"], "ids[1]");

    for text in [
        r#"{"ids": [7]}"#,
        r#"{}"#,
        r#"{"ids": "x"}"#,
        r#"{"ids": [], "extra": 1}"#,
        r#"{"ids": [], "include_belief": true}"#,
        "not json",
    ] {
        let (status, raw) = post_raw(&app, text, &bearer).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{text}: {raw}");
        let body: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
        assert_eq!(
            body["error"], "BadRequest",
            "{text}: standard shape, got {raw}"
        );
    }

    // No JSON content type.
    let (status, raw) = send(
        &app,
        Method::POST,
        PATH,
        Some(("", r#"{"ids": []}"#)),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{raw}");
    let body: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    assert_eq!(body["error"], "BadRequest", "{raw}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn empty_ids_is_an_empty_200(pool: PgPool) {
    let app = router(&pool).await;
    let (status, raw) = post_raw(&app, r#"{"ids": []}"#, &token(Uuid::new_v4())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(raw, r#"{"claims":[],"not_found":[],"remaining":[]}"#);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_trace_is_not_named(pool: PgPool) {
    let owner = Uuid::new_v4();
    let p1 = common::seed_claim_with_agent(&pool, "first public claim", owner).await;
    let p2 = common::seed_claim_with_agent(&pool, "second public claim", owner).await;
    let p3 = common::seed_claim_with_agent(&pool, "third public claim", owner).await;
    let t = fixture::seed_reasoning_trace(&pool, p1, "deductive").await;
    make_trace_private(&pool, t, owner).await;
    let t3 = fixture::seed_reasoning_trace(&pool, p3, "inductive").await;
    // One statement after the trace seeding, so the BEFORE UPDATE trigger gives
    // all three the same `updated_at` (now() is per transaction).
    sqlx::query("UPDATE claims SET created_at = '2026-01-01T00:00:00Z' WHERE id = ANY($1)")
        .bind(vec![p1, p2, p3])
        .execute(&pool)
        .await
        .expect("align the timestamps");

    let stranger = Uuid::new_v4();
    personal_group_for(&pool, stranger).await;
    let app = router(&pool).await;
    let st = token(stranger);

    let t_forms = [t.to_string(), t.simple().to_string()];
    let (s1, b1, raw1) = batch(&app, &strs(&[p1]), &st).await;
    let (s2, _, raw2) = batch(&app, &strs(&[p2]), &st).await;
    assert_eq!(s1, StatusCode::OK, "{raw1}");
    assert_eq!(s2, StatusCode::OK, "{raw2}");
    for raw in [&raw1, &raw2] {
        let low = raw.to_lowercase();
        for f in &t_forms {
            assert!(!low.contains(f), "the private trace id leaked: {raw}");
        }
    }
    assert_eq!(item(&b1, p1)["trace_id"], Value::Null);
    assert_eq!(
        raw1.replace(&p1.to_string(), "<ID>")
            .replace("first public claim", "<C>"),
        raw2.replace(&p2.to_string(), "<ID>")
            .replace("second public claim", "<C>"),
        "an unreadable trace gives the same answer as no trace"
    );

    // Selective, not blanket: a readable trace is named.
    let (_, b3, _) = batch(&app, &strs(&[p3]), &st).await;
    assert_eq!(item(&b3, p3)["trace_id"], t3.to_string());

    // Calibration: the owner reads the trace, so it is named for them.
    let (_, ob, _) = batch(&app, &strs(&[p1]), &token(owner)).await;
    assert_eq!(item(&ob, p1)["trace_id"], t.to_string());

    // Bulk: the private trace appears nowhere, the public one once.
    let (status, _, raw) = batch(&app, &strs(&[p1, p2, p3]), &st).await;
    assert_eq!(status, StatusCode::OK, "{raw}");
    let low = raw.to_lowercase();
    for f in &t_forms {
        assert!(!low.contains(f), "the private trace id leaked: {raw}");
    }
    assert_eq!(raw.matches(&t3.to_string()).count(), 1);
}
