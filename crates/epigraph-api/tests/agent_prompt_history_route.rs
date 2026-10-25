#![cfg(feature = "db")]
//! `GET /api/v1/agents/:id/prompt-history` and
//! `GET /api/v1/agents/:id/prompt-history/blobs/:hash` (agent identity lineage
//! design D4): an agent's prompt snapshots and its succession lineage, and the
//! content of one prompt file named in them, readable by the agent's operator
//! and by admins, and by nobody else. The listing names each file by hash and
//! carries no content, so its size does not grow with the files'.
//!
//! Every request goes through the full router (`create_router`) with a real
//! bearer, so route registration, the bearer middleware, the scope check and
//! the viewer extractor are all on the path. Both pools of the `AppState` are
//! the APPLICATION ROLE. That is load-bearing: on the superuser pool
//! `#[sqlx::test]` hands out, `epigraph_bypass()` (which tests `session_user`)
//! is true, so the history definer would treat every caller as an admin and
//! "a stranger is refused" could not fail.
//!
//! The registrations are made through `AgentIdentityRepository::register` on
//! the attestor role, so every file here went through the real hash and
//! compression path and comes back through the real decompression.
//!
//! Every refusal is paired with a positive control in the same test: before
//! the route exists the router answers 404 to everything, and a refusal test
//! without its control would pass on a tree with no route at all.

mod common;
mod viewer_fixture;

#[path = "../../epigraph-passkey/tests/support/soft_authenticator.rs"]
mod support;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{
    AgentIdentityRepository, AgentRepository, IdentityRegistration, PromptFile, ScopedPool,
    SessionGucMode,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{as_role, database_url_for, downgraded_pool};

use std::net::SocketAddr;
use std::sync::Arc;

use epigraph_auth::{AccessTokenBinding, JwtConfig};
use epigraph_db::ScopedPoolOptions;
use epigraph_passkey::{AttestationPolicy, PasskeyConfig, Passkeys};
use support::{ClientUv, SoftAuthenticator, ORIGIN, RP_ID};
use tokio::sync::oneshot;

const ATTESTOR: &str = "epigraph_identity_attestor";

/// An `AppState` whose scoped and raw pools are both the application role.
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
    let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(scoped.inner())
        .await
        .expect("epigraph_bypass on the scoped pool");
    assert!(
        !bypass,
        "CALIBRATION: the scoped pool must not be privileged, or the definer admits every \
         caller as an admin"
    );
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

/// A registered human (who may operate agents and hold a token).
async fn human(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(random32().to_vec())
        .execute(pool)
        .await
        .expect("seed human agent");
    viewer_fixture::make_human_operator(pool, id).await;
    id
}

/// A manual (maintenance) link of `agent` to `operator`.
async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let out = as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("the maintenance role links the agent");
    assert!(out.link_live, "CALIBRATION: the manual link is live");
}

fn identity(group: &str, parent: Option<Uuid>, files: [PromptFile; 4]) -> IdentityRegistration {
    let pubkey = random32();
    let [identity_md, global_claude_md, group_claude_md, learned_md] = files;
    IdentityRegistration {
        identity_pubkey: pubkey,
        parent_agent_id: parent,
        model: "test-model-7".to_string(),
        prompt_hash: blake3::hash(&pubkey).to_hex().to_string(),
        group_folder: group.to_string(),
        signing_pubkey: Some(random32()),
        identity_md,
        global_claude_md,
        group_claude_md,
        learned_md,
        in_prompt: json!({"global_claude_md": false, "group_claude_md": true, "learned_md": true}),
        runner_version: Some("runner-test".to_string()),
        host_sha: None,
    }
}

fn stored(s: &str) -> PromptFile {
    PromptFile::Stored(s.as_bytes().to_vec())
}

async fn register(pool: &PgPool, reg: &IdentityRegistration) -> epigraph_db::IdentityRegistered {
    let reg = reg.clone();
    as_role(pool, ATTESTOR, |mut conn| async move {
        let r = AgentIdentityRepository::register(&mut conn, &reg).await;
        (conn, r)
    })
    .await
    .expect("the attestor registers")
}

/// A parent identity registered in TWO groups (one shared identity, two
/// snapshots), live-linked to `operator`; and a child that succeeds it in the
/// first group, inheriting the link. Returns `(parent, child)`.
struct Family {
    parent: Uuid,
    child: Uuid,
    child_learned: String,
    child_group_claude: String,
}

async fn family(pool: &PgPool, operator: Uuid) -> Family {
    let parent_reg = identity(
        "g-hist-a",
        None,
        [
            PromptFile::Absent,
            PromptFile::Absent,
            stored("group rules v1\n"),
            stored("parent lesson\n"),
        ],
    );
    let p = register(pool, &parent_reg).await;
    let mut in_b = parent_reg.clone();
    in_b.group_folder = "g-hist-b".to_string();
    in_b.group_claude_md = stored("another group's rules\n");
    let p_b = register(pool, &in_b).await;
    assert_eq!(
        p_b.agent_id, p.agent_id,
        "CALIBRATION: one identity in two groups is one agent"
    );
    assert_ne!(
        p_b.snapshot_id, p.snapshot_id,
        "CALIBRATION: with a snapshot per group"
    );
    link(pool, p.agent_id, operator).await;

    // Multi-byte UTF-8 and a long, compressible body, so the round trip is not
    // satisfied by an accidental passthrough of the stored frame.
    let child_learned = "leçon apprise — the child learned this ✓\n".repeat(50);
    let child_group_claude = "group rules v2\n".to_string();
    let c = register(
        pool,
        &identity(
            "g-hist-a",
            Some(p.agent_id),
            [
                PromptFile::Refused,
                PromptFile::Absent,
                stored(&child_group_claude),
                stored(&child_learned),
            ],
        ),
    )
    .await;
    assert!(
        c.link_live && c.operator_id == Some(operator),
        "CALIBRATION: the child inherits its parent's live link ({c:?})"
    );
    Family {
        parent: p.agent_id,
        child: c.agent_id,
        child_learned,
        child_group_claude,
    }
}

/// `GET uri` through the full router as `caller` holding `scopes`:
/// `(status, body)`.
async fn get_json(
    state: &AppState,
    caller: Uuid,
    scopes: &[&str],
    uri: &str,
) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(scopes, caller);
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
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

/// `GET /api/v1/agents/{agent}/prompt-history` as `caller` holding `scopes`.
async fn get_history(
    state: &AppState,
    caller: Uuid,
    scopes: &[&str],
    agent: Uuid,
) -> (StatusCode, Value) {
    get_json(
        state,
        caller,
        scopes,
        &format!("/api/v1/agents/{agent}/prompt-history"),
    )
    .await
}

/// `GET /api/v1/agents/{agent}/prompt-history/blobs/{hash}` as `caller`
/// holding `claims:read`.
async fn get_blob(state: &AppState, caller: Uuid, agent: Uuid, hash: &str) -> (StatusCode, Value) {
    get_json(
        state,
        caller,
        &["claims:read"],
        &format!("/api/v1/agents/{agent}/prompt-history/blobs/{hash}"),
    )
    .await
}

async fn read_blob_ok(state: &AppState, caller: Uuid, agent: Uuid, hash: &str) -> Value {
    let (status, body) = get_blob(state, caller, agent, hash).await;
    assert_eq!(status, StatusCode::OK, "expected a served blob: {body}");
    body
}

/// The listing's reference to one file: its hash, and nothing else.
fn file_hash(file: &Value) -> &str {
    let obj = file
        .as_object()
        .unwrap_or_else(|| panic!("a stored file is an object, got {file}"));
    assert_eq!(
        obj.keys().map(String::as_str).collect::<Vec<_>>(),
        ["blob_hash"],
        "the listing names a file by hash and carries no content: {file}"
    );
    obj["blob_hash"].as_str().expect("hex hash")
}

async fn read_ok(state: &AppState, caller: Uuid, agent: Uuid) -> Value {
    let (status, body) = get_history(state, caller, &["claims:read"], agent).await;
    assert_eq!(status, StatusCode::OK, "expected a served history: {body}");
    body
}

fn arr<'a>(v: &'a Value, what: &str) -> &'a Vec<Value> {
    v.as_array()
        .unwrap_or_else(|| panic!("{what} must be an array, got {v}"))
}

fn blake3_hex(s: &str) -> String {
    blake3::hash(s.as_bytes()).to_hex().to_string()
}

/// The operator reads its agent's history: every stored file comes back as
/// the text that was registered, under the BLAKE3 of its raw bytes; a refused
/// file is named and carries no content; an absent file is neither. The
/// lineage walks up to the parent (one entry, though it has two snapshots)
/// and, read from the parent, down to the child.
#[sqlx::test(migrations = "../../migrations")]
async fn the_operator_reads_its_agents_snapshots_and_lineage(pool: PgPool) {
    let operator = human(&pool).await;
    let f = family(&pool, operator).await;
    let state = app_role_state(&pool).await;

    let body = read_ok(&state, operator, f.child).await;
    assert_eq!(body["agent_id"], json!(f.child));

    let snaps = arr(&body["snapshots"], "snapshots");
    assert_eq!(snaps.len(), 1, "the child ran in one group: {body}");
    let s = &snaps[0];
    assert_eq!(s["group_folder"], json!("g-hist-a"));
    assert_eq!(s["model"], json!("test-model-7"));
    assert_eq!(
        s["prompt_hash"].as_str().map(str::len),
        Some(64),
        "the identity hash is returned: {s}"
    );
    assert_eq!(s["in_prompt"]["group_claude_md"], json!(true));
    let learned_hash = file_hash(&s["files"]["learned_md"]);
    assert_eq!(learned_hash, blake3_hex(&f.child_learned));
    let learned = read_blob_ok(&state, operator, f.child, learned_hash).await;
    assert_eq!(
        learned["text"].as_str(),
        Some(f.child_learned.as_str()),
        "LEARNED.md round-trips byte for byte through compression: {learned}"
    );
    assert_eq!(learned["blob_hash"], json!(learned_hash));
    assert_eq!(learned["raw_size"], json!(f.child_learned.len()));
    assert_eq!(learned["lossy"], json!(false));
    let group_hash = file_hash(&s["files"]["group_claude_md"]);
    assert_eq!(
        read_blob_ok(&state, operator, f.child, group_hash).await["text"].as_str(),
        Some(f.child_group_claude.as_str())
    );
    assert_eq!(
        s["files"]["identity_md"],
        Value::Null,
        "a refused file carries no content"
    );
    assert_eq!(s["files"]["global_claude_md"], Value::Null);
    assert_eq!(
        s["blob_refused"],
        json!(["identity_md"]),
        "the refused file is named; the absent one is not"
    );
    let (first, last) = (
        s["first_seen"].as_str().expect("first_seen"),
        s["last_seen"].as_str().expect("last_seen"),
    );
    assert!(
        chrono::DateTime::parse_from_rfc3339(first).expect("rfc3339")
            <= chrono::DateTime::parse_from_rfc3339(last).expect("rfc3339"),
        "first_seen <= last_seen"
    );

    let up = arr(&body["lineage"]["ancestors"], "ancestors");
    assert_eq!(
        up.len(),
        1,
        "the parent is ONE lineage entry although it has two snapshots: {body}"
    );
    assert_eq!(up[0]["agent_id"], json!(f.parent));
    assert_eq!(up[0]["distance"], json!(1));
    assert_eq!(up[0]["readable"], json!(true));
    let mut groups: Vec<&str> = arr(&up[0]["snapshots"], "parent snapshots")
        .iter()
        .map(|p| p["group_folder"].as_str().expect("group"))
        .collect();
    groups.sort_unstable();
    assert_eq!(groups, ["g-hist-a", "g-hist-b"]);
    assert_eq!(body["lineage"]["descendants"], json!([]));
    // A readable ancestor's file is served through the child's history.
    let parent_learned =
        arr(&up[0]["snapshots"], "parent snapshots")[0]["files"]["learned_md"].clone();
    assert_eq!(
        read_blob_ok(&state, operator, f.child, file_hash(&parent_learned)).await["text"],
        json!("parent lesson\n")
    );

    let parent_view = read_ok(&state, operator, f.parent).await;
    assert_eq!(arr(&parent_view["snapshots"], "snapshots").len(), 2);
    assert_eq!(parent_view["lineage"]["ancestors"], json!([]));
    let down = arr(&parent_view["lineage"]["descendants"], "descendants");
    assert_eq!(down.len(), 1, "{parent_view}");
    assert_eq!(down[0]["agent_id"], json!(f.child));
    assert_eq!(down[0]["distance"], json!(1));
}

/// A caller who neither operates the agent nor is an admin gets exactly the
/// 404 that an agent which does not exist gets: same status, same body but
/// for the id. (Agent ids are public; this pins a uniform refusal, not
/// secrecy about which agents exist.) CONTROL: the operator reads the same
/// agent.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stranger_gets_the_404_an_absent_agent_gets(pool: PgPool) {
    let operator = human(&pool).await;
    let stranger = human(&pool).await;
    let f = family(&pool, operator).await;
    let state = app_role_state(&pool).await;

    let control = read_ok(&state, operator, f.child).await;
    assert_eq!(arr(&control["snapshots"], "snapshots").len(), 1);

    let absent = Uuid::new_v4();
    let (s_real, b_real) = get_history(&state, stranger, &["claims:read"], f.child).await;
    let (s_absent, b_absent) = get_history(&state, stranger, &["claims:read"], absent).await;
    assert_eq!(s_real, StatusCode::NOT_FOUND, "{b_real}");
    assert_eq!(s_absent, StatusCode::NOT_FOUND, "{b_absent}");
    let normalised = |b: &Value, id: Uuid| b.to_string().replace(&id.to_string(), "<id>");
    assert_eq!(
        normalised(&b_real, f.child),
        normalised(&b_absent, absent),
        "the refusal must not differ from the absence"
    );
    assert!(
        !b_real.to_string().contains("AID06"),
        "the refusal's SQLSTATE must not reach the caller: {b_real}"
    );

    // The operator asking for an absent id gets the same 404 as well.
    let (s_op_absent, b_op_absent) = get_history(&state, operator, &["claims:read"], absent).await;
    assert_eq!(s_op_absent, StatusCode::NOT_FOUND, "{b_op_absent}");
    assert_eq!(
        normalised(&b_op_absent, absent),
        normalised(&b_absent, absent)
    );
}

/// An admin (custodian) reads an agent it does not operate, and the admin arm
/// is what admits it: the SAME human is refused before it holds the role. An
/// admin asking for an agent that does not exist still gets 404.
#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_reads_any_agents_history_and_only_as_admin(pool: PgPool) {
    let operator = human(&pool).await;
    let custodian = human(&pool).await;
    let f = family(&pool, operator).await;
    let state = app_role_state(&pool).await;

    let (before, refused) = get_history(&state, custodian, &["claims:read"], f.child).await;
    assert_eq!(
        before,
        StatusCode::NOT_FOUND,
        "CONTROL: not yet an admin, so refused: {refused}"
    );

    viewer_fixture::make_custodian(&pool, custodian).await;
    let body = read_ok(&state, custodian, f.child).await;
    let snaps = arr(&body["snapshots"], "snapshots");
    assert_eq!(snaps.len(), 1, "{body}");
    let hash = file_hash(&snaps[0]["files"]["learned_md"]);
    assert_eq!(
        read_blob_ok(&state, custodian, f.child, hash).await["text"].as_str(),
        Some(f.child_learned.as_str()),
        "the admin gets the content, not a redacted shape"
    );
    assert_eq!(
        arr(&body["lineage"]["ancestors"], "ancestors")[0]["readable"],
        json!(true),
        "an admin reads every lineage member"
    );

    let absent = Uuid::new_v4();
    let (status, body) = get_history(&state, custodian, &["claims:read"], absent).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an admin asking for an agent that does not exist gets 404, not an empty history: {body}"
    );
    // The admin's 404 comes from the existence check after the gate, the
    // stranger's from the gate's refusal: two code paths, one body.
    assert_eq!(
        body.to_string().replace(&absent.to_string(), "<id>"),
        refused.to_string().replace(&f.child.to_string(), "<id>"),
        "the existence check's 404 is the refusal's 404"
    );
}

/// An agent that has never been registered (no snapshot, no succession) is
/// served to its operator as empty arrays, not as a 404 and not as a null
/// snapshot. CONTROL: the same operator's registered agent has a snapshot.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_with_no_snapshots_returns_empty_arrays(pool: PgPool) {
    let operator = human(&pool).await;
    let f = family(&pool, operator).await;
    let bare = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(bare)
        .bind(random32().to_vec())
        .execute(&pool)
        .await
        .expect("seed an unregistered agent");
    link(&pool, bare, operator).await;
    let state = app_role_state(&pool).await;

    let control = read_ok(&state, operator, f.child).await;
    assert_eq!(arr(&control["snapshots"], "snapshots").len(), 1);

    let body = read_ok(&state, operator, bare).await;
    assert_eq!(body["agent_id"], json!(bare));
    assert_eq!(body["snapshots"], json!([]), "{body}");
    assert_eq!(body["lineage"]["ancestors"], json!([]), "{body}");
    assert_eq!(body["lineage"]["descendants"], json!([]), "{body}");
}

/// The route requires `claims:read`: the operator's token without it is
/// refused 403 (and the refusal does not depend on the agent), with it the
/// same caller is served.
#[sqlx::test(migrations = "../../migrations")]
async fn the_route_requires_claims_read(pool: PgPool) {
    let operator = human(&pool).await;
    let f = family(&pool, operator).await;
    let state = app_role_state(&pool).await;

    let (status, body) = get_history(&state, operator, &["claims:write"], f.child).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status_absent, _) = get_history(&state, operator, &["claims:write"], Uuid::new_v4()).await;
    assert_eq!(
        status_absent,
        StatusCode::FORBIDDEN,
        "the scope check runs before any lookup"
    );
    let body = read_ok(&state, operator, f.child).await;
    let hash = file_hash(&body["snapshots"][0]["files"]["learned_md"]).to_string();
    let blob_uri = format!("/api/v1/agents/{}/prompt-history/blobs/{hash}", f.child);
    let (status, body) = get_json(&state, operator, &["claims:write"], &blob_uri).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the blob read needs claims:read too: {body}"
    );
    read_blob_ok(&state, operator, f.child, &hash).await;
}

/// A parent registered unlinked and later linked to `other`, and a child of
/// it (which inherits nothing from an unlinked parent) linked by hand to
/// `operator`: each human operates one of the two. Returns `(parent, child)`.
async fn split_family(pool: &PgPool, operator: Uuid, other: Uuid) -> (Uuid, Uuid) {
    let p = register(
        pool,
        &identity(
            "g-split",
            None,
            [
                PromptFile::Absent,
                PromptFile::Absent,
                stored("split group rules\n"),
                stored(PARENT_PRIVATE),
            ],
        ),
    )
    .await;
    let c = register(
        pool,
        &identity(
            "g-split",
            Some(p.agent_id),
            [
                PromptFile::Absent,
                PromptFile::Absent,
                stored("split group rules\n"),
                stored("the child's own lesson\n"),
            ],
        ),
    )
    .await;
    assert!(
        !c.link_live,
        "CALIBRATION: a child of an unlinked parent inherits no link ({c:?})"
    );
    link(pool, c.agent_id, operator).await;
    link(pool, p.agent_id, other).await;
    (p.agent_id, c.agent_id)
}

const PARENT_PRIVATE: &str = "the parent's lesson, which only its own operator reads\n";

/// The blob endpoint serves a file only when a snapshot the caller may read
/// in that agent's history names it. The parent's file, asked for through the
/// child's history by the child's operator (who does not operate the parent),
/// is the 404 an unknown hash gets; the parent's own operator reads it
/// (CONTROL), and so does an admin through the child. A stranger gets the
/// absent-agent 404 even for a hash the history names; a malformed hash is a
/// 400.
#[sqlx::test(migrations = "../../migrations")]
async fn a_blob_is_served_only_through_a_snapshot_the_caller_may_read(pool: PgPool) {
    let operator = human(&pool).await;
    let other = human(&pool).await;
    let stranger = human(&pool).await;
    let custodian = human(&pool).await;
    let (parent, child) = split_family(&pool, operator, other).await;
    viewer_fixture::make_custodian(&pool, custodian).await;
    let state = app_role_state(&pool).await;
    let private = blake3_hex(PARENT_PRIVATE);

    // CONTROL: the parent's operator reads it, through the parent.
    let body = read_blob_ok(&state, other, parent, &private).await;
    assert_eq!(body["text"], json!(PARENT_PRIVATE));

    let own = blake3_hex("the child's own lesson\n");
    assert_eq!(
        read_blob_ok(&state, operator, child, &own).await["text"],
        json!("the child's own lesson\n"),
        "CONTROL: the child's operator reads the child's file"
    );
    let (status, withheld) = get_blob(&state, operator, child, &private).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a file of a lineage member the caller does not operate is not served: {withheld}"
    );
    let unknown = blake3_hex("no snapshot names this file");
    let (status, nothing) = get_blob(&state, operator, child, &unknown).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{nothing}");
    assert_eq!(
        withheld.to_string().replace(&private, "<hash>"),
        nothing.to_string().replace(&unknown, "<hash>"),
        "an unreadable member's file looks exactly like a file nobody stored"
    );

    // An admin reads every lineage member, so the parent's file too.
    assert_eq!(
        read_blob_ok(&state, custodian, child, &private).await["text"],
        json!(PARENT_PRIVATE)
    );

    // A stranger: the absent-agent 404, whatever the hash.
    let absent = Uuid::new_v4();
    let (s_real, b_real) = get_blob(&state, stranger, child, &own).await;
    let (s_absent, b_absent) = get_blob(&state, stranger, absent, &own).await;
    assert_eq!(s_real, StatusCode::NOT_FOUND, "{b_real}");
    assert_eq!(s_absent, StatusCode::NOT_FOUND, "{b_absent}");
    assert_eq!(
        b_real.to_string().replace(&child.to_string(), "<id>"),
        b_absent.to_string().replace(&absent.to_string(), "<id>")
    );

    let (status, body) = get_blob(&state, operator, child, "not-a-hash").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// A file that is not valid UTF-8 is served with `lossy: true` (its text
/// replaces the invalid bytes) and its exact raw size; a UTF-8 file of the
/// same snapshot is `lossy: false`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_blob_says_when_its_text_is_not_byte_exact(pool: PgPool) {
    let operator = human(&pool).await;
    let raw = vec![b'o', b'k', 0xff, 0xfe];
    let a = register(
        &pool,
        &identity(
            "g-lossy",
            None,
            [
                stored("plain identity\n"),
                PromptFile::Absent,
                PromptFile::Absent,
                PromptFile::Stored(raw.clone()),
            ],
        ),
    )
    .await;
    link(&pool, a.agent_id, operator).await;
    let state = app_role_state(&pool).await;

    let body = read_ok(&state, operator, a.agent_id).await;
    let files = &body["snapshots"][0]["files"];
    let lossy = read_blob_ok(
        &state,
        operator,
        a.agent_id,
        file_hash(&files["learned_md"]),
    )
    .await;
    assert_eq!(lossy["lossy"], json!(true), "{lossy}");
    assert_eq!(lossy["raw_size"], json!(raw.len()));
    assert_eq!(lossy["text"], json!("ok\u{FFFD}\u{FFFD}"));
    assert_eq!(
        lossy["blob_hash"],
        json!(blake3::hash(&raw).to_hex().to_string()),
        "the hash is of the raw bytes, not of the replaced text"
    );
    let exact = read_blob_ok(
        &state,
        operator,
        a.agent_id,
        file_hash(&files["identity_md"]),
    )
    .await;
    assert_eq!(exact["lossy"], json!(false), "{exact}");
    assert_eq!(exact["text"], json!("plain identity\n"));
}

/// A stored blob that no longer decompresses to its key is WITHHELD: the
/// blob endpoint refuses it (500, naming the verification failure) and never
/// serves the bytes it holds, while the other files of the same snapshot are
/// still served and the listing still names it. The corruption swaps in
/// another stored file's valid frame (as the superuser, triggers off), so only
/// the hash check can catch it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_blob_that_fails_verification_is_withheld(pool: PgPool) {
    let operator = human(&pool).await;
    let a = register(
        &pool,
        &identity(
            "g-corrupt",
            None,
            [
                PromptFile::Absent,
                PromptFile::Absent,
                stored("the intact group file\n"),
                stored("the file that will be corrupted\n"),
            ],
        ),
    )
    .await;
    link(&pool, a.agent_id, operator).await;
    let intact = blake3::hash(b"the intact group file\n").as_bytes().to_vec();
    let corrupted = blake3::hash(b"the file that will be corrupted\n")
        .as_bytes()
        .to_vec();
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("SET session_replication_role = replica")
        .execute(&mut *conn)
        .await
        .expect("triggers off");
    let n = sqlx::query(
        "UPDATE agent_prompt_blobs SET content = \
           (SELECT content FROM agent_prompt_blobs WHERE blob_hash = $1) \
          WHERE blob_hash = $2",
    )
    .bind(&intact)
    .bind(&corrupted)
    .execute(&mut *conn)
    .await
    .expect("swap the frame")
    .rows_affected();
    assert_eq!(n, 1, "CALIBRATION: the blob was rewritten");
    sqlx::query("RESET session_replication_role")
        .execute(&mut *conn)
        .await
        .expect("triggers on");
    drop(conn);
    let state = app_role_state(&pool).await;

    let body = read_ok(&state, operator, a.agent_id).await;
    let files = &body["snapshots"][0]["files"];
    let bad = file_hash(&files["learned_md"]).to_string();
    assert_eq!(bad, hex::encode(&corrupted), "the listing still names it");
    let (status, refused) = get_blob(&state, operator, a.agent_id, &bad).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{refused}");
    assert!(
        refused.to_string().contains("failed verification"),
        "the refusal names the verification failure: {refused}"
    );
    assert!(
        !refused.to_string().contains("intact group file"),
        "the frame's actual bytes are never served: {refused}"
    );
    assert_eq!(
        read_blob_ok(
            &state,
            operator,
            a.agent_id,
            file_hash(&files["group_claude_md"])
        )
        .await["text"],
        json!("the intact group file\n"),
        "CONTROL: the snapshot's other file is still served"
    );
}

/// Registers a chain of `n` generations in one group, each succeeding the
/// last, the first live-linked to `operator` (so every later one inherits
/// the link). Returns the agent ids, oldest first.
async fn chain(pool: &PgPool, operator: Uuid, n: usize) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = Vec::with_capacity(n);
    for g in 0..n {
        let r = register(
            pool,
            &identity(
                "g-chain",
                ids.last().copied(),
                [
                    PromptFile::Absent,
                    PromptFile::Absent,
                    PromptFile::Absent,
                    stored(&format!("generation {g}\n")),
                ],
            ),
        )
        .await;
        if g == 0 {
            link(pool, r.agent_id, operator).await;
        } else {
            assert!(
                r.link_live,
                "CALIBRATION: generation {g} inherits the live link ({r:?})"
            );
        }
        ids.push(r.agent_id);
    }
    ids
}

/// The lineage walk stops at the definer's 64 generations each way, and the
/// listing SAYS when it reached that limit, so a cut lineage does not look
/// complete. From the newest of 66 generations, 64 ancestors are listed (the
/// farthest at distance 64) and `ancestors_at_limit` is true; from the
/// oldest, the same holds down the succession. CONTROL: a lineage of one
/// generation each way reaches neither limit.
#[sqlx::test(migrations = "../../migrations")]
async fn the_listing_says_when_the_lineage_walk_reached_its_depth_limit(pool: PgPool) {
    let operator = human(&pool).await;
    let ids = chain(&pool, operator, 66).await;
    let f = family(&pool, operator).await;
    let state = app_role_state(&pool).await;

    let control = read_ok(&state, operator, f.child).await;
    assert_eq!(control["lineage"]["depth_limit"], json!(64), "{control}");
    assert_eq!(control["lineage"]["ancestors_at_limit"], json!(false));
    assert_eq!(control["lineage"]["descendants_at_limit"], json!(false));

    let newest = read_ok(&state, operator, ids[65]).await;
    let up = arr(&newest["lineage"]["ancestors"], "ancestors");
    assert_eq!(up.len(), 64, "65 ancestors exist; the walk lists 64");
    assert_eq!(up[63]["distance"], json!(64));
    assert_eq!(newest["lineage"]["ancestors_at_limit"], json!(true));
    assert_eq!(newest["lineage"]["descendants_at_limit"], json!(false));

    let oldest = read_ok(&state, operator, ids[0]).await;
    let down = arr(&oldest["lineage"]["descendants"], "descendants");
    assert_eq!(down.len(), 64, "65 descendants exist; the walk lists 64");
    assert_eq!(oldest["lineage"]["descendants_at_limit"], json!(true));
    assert_eq!(oldest["lineage"]["ancestors_at_limit"], json!(false));
}

/// From any member of a three-generation chain, the lineage is nearest first
/// in both directions, with each member's true distance: from the youngest,
/// ancestors are [parent (1), grandparent (2)], although the definer returns
/// the grandparent first; from the oldest, descendants are [child (1),
/// grandchild (2)]; from the middle, one of each at distance 1.
#[sqlx::test(migrations = "../../migrations")]
async fn the_lineage_is_listed_nearest_first_both_ways(pool: PgPool) {
    let operator = human(&pool).await;
    let ids = chain(&pool, operator, 3).await;
    let state = app_role_state(&pool).await;
    let order = |v: &Value| -> Vec<(Value, Value)> {
        arr(v, "members")
            .iter()
            .map(|m| (m["agent_id"].clone(), m["distance"].clone()))
            .collect()
    };

    let youngest = read_ok(&state, operator, ids[2]).await;
    assert_eq!(
        order(&youngest["lineage"]["ancestors"]),
        [(json!(ids[1]), json!(1)), (json!(ids[0]), json!(2))],
        "{youngest}"
    );
    assert_eq!(youngest["lineage"]["descendants"], json!([]));

    let oldest = read_ok(&state, operator, ids[0]).await;
    assert_eq!(
        order(&oldest["lineage"]["descendants"]),
        [(json!(ids[1]), json!(1)), (json!(ids[2]), json!(2))],
        "{oldest}"
    );
    assert_eq!(oldest["lineage"]["ancestors"], json!([]));

    let middle = read_ok(&state, operator, ids[1]).await;
    assert_eq!(
        order(&middle["lineage"]["ancestors"]),
        [(json!(ids[0]), json!(1))]
    );
    assert_eq!(
        order(&middle["lineage"]["descendants"]),
        [(json!(ids[2]), json!(1))]
    );
}

/// A lineage member the caller does not operate is listed by id, at its
/// distance, `readable: false`, with no snapshots, in both directions: the
/// child's operator sees the parent so, and the parent's operator sees the
/// child so. CONTROL: an admin reads both members, and each operator reads
/// its own agent's snapshot.
#[sqlx::test(migrations = "../../migrations")]
async fn a_lineage_member_the_caller_does_not_operate_is_listed_by_id_only(pool: PgPool) {
    let operator = human(&pool).await;
    let other = human(&pool).await;
    let custodian = human(&pool).await;
    let (parent, child) = split_family(&pool, operator, other).await;
    viewer_fixture::make_custodian(&pool, custodian).await;
    let state = app_role_state(&pool).await;

    let mine = read_ok(&state, operator, child).await;
    assert_eq!(arr(&mine["snapshots"], "snapshots").len(), 1, "{mine}");
    assert_eq!(
        mine["lineage"]["ancestors"],
        json!([{"agent_id": parent, "distance": 1, "readable": false, "snapshots": []}])
    );

    let theirs = read_ok(&state, other, parent).await;
    assert_eq!(arr(&theirs["snapshots"], "snapshots").len(), 1, "{theirs}");
    assert_eq!(
        theirs["lineage"]["descendants"],
        json!([{"agent_id": child, "distance": 1, "readable": false, "snapshots": []}])
    );

    let admin = read_ok(&state, custodian, child).await;
    let up = arr(&admin["lineage"]["ancestors"], "ancestors");
    assert_eq!(up[0]["agent_id"], json!(parent));
    assert_eq!(up[0]["readable"], json!(true), "{admin}");
    assert_eq!(arr(&up[0]["snapshots"], "snapshots").len(), 1);
}

/// The history outlives a hand-over: an operator whose link to the agent is
/// RETIRED still reads the agent's history (its snapshot and the file's
/// content), and still reads it as a readable ancestor through a successor it
/// operates live. CONTROL: a stranger is still refused.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operator_whose_link_is_retired_still_reads_the_history(pool: PgPool) {
    let operator = human(&pool).await;
    let stranger = human(&pool).await;
    let before = "written before the hand-over\n";
    let r = register(
        &pool,
        &identity(
            "g-retired",
            None,
            [
                PromptFile::Absent,
                PromptFile::Absent,
                PromptFile::Absent,
                stored(before),
            ],
        ),
    )
    .await;
    let out = as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let res = AgentRepository::link_retired_agent(&mut conn, r.agent_id, operator).await;
        (conn, res)
    })
    .await
    .expect("the maintenance role retire-links the agent");
    assert!(out.link_retired, "CALIBRATION: the link is retired");
    let retired: bool =
        sqlx::query_scalar("SELECT retired FROM operator_links WHERE agent_id = $1")
            .bind(r.agent_id)
            .fetch_one(&pool)
            .await
            .expect("the link row");
    assert!(retired, "CALIBRATION: the link record says retired");
    let c = register(
        &pool,
        &identity(
            "g-retired",
            Some(r.agent_id),
            [
                PromptFile::Absent,
                PromptFile::Absent,
                PromptFile::Absent,
                stored("after the hand-over\n"),
            ],
        ),
    )
    .await;
    assert!(
        !c.link_live,
        "CALIBRATION: a retired-linked parent passes on nothing ({c:?})"
    );
    link(&pool, c.agent_id, operator).await;
    let state = app_role_state(&pool).await;

    let body = read_ok(&state, operator, r.agent_id).await;
    let snaps = arr(&body["snapshots"], "snapshots");
    assert_eq!(snaps.len(), 1, "{body}");
    let hash = file_hash(&snaps[0]["files"]["learned_md"]);
    assert_eq!(
        read_blob_ok(&state, operator, r.agent_id, hash).await["text"],
        json!(before)
    );

    let through = read_ok(&state, operator, c.agent_id).await;
    let up = arr(&through["lineage"]["ancestors"], "ancestors");
    assert_eq!(up[0]["agent_id"], json!(r.agent_id));
    assert_eq!(
        up[0]["readable"],
        json!(true),
        "a retired link still reads the ancestor: {through}"
    );
    assert_eq!(arr(&up[0]["snapshots"], "snapshots").len(), 1);

    let (status, refused) = get_history(&state, stranger, &["claims:read"], r.agent_id).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{refused}");
}

// =====================================================================
// Armed admin scopes: the admin arm needs an ELEVATED session
// =====================================================================

/// The authenticator model the test authenticator claims (synthetic).
const MODEL: Uuid = Uuid::from_u128(0x6a1e_7e57_0000_4a11_8c0d_0000_0000_0161);

fn software() -> Passkeys {
    Passkeys::new(PasskeyConfig {
        rp_id: RP_ID.into(),
        origin: ORIGIN.parse().expect("origin"),
        policy: AttestationPolicy::SoftwareAllowed,
    })
    .expect("relying party")
}

/// The REST router on an application-role pool that declares the per-access
/// recorder (an elevated request on any other pool is refused before it is
/// served), with the passkey relying party, on a real listener.
struct Recording {
    addr: SocketAddr,
    jwt: Arc<JwtConfig>,
    http: reqwest::Client,
    _stop: oneshot::Sender<()>,
}

impl Recording {
    async fn start(pool: &PgPool) -> Self {
        let scoped = ScopedPool::connect_with_access_recorder_for_tests(
            &database_url_for(pool).await,
            SessionGucMode::Session,
            ScopedPoolOptions::default(),
            Some("epigraph_app"),
        )
        .await
        .expect("app-role recording pool");
        let state = AppState::with_scoped_pool(scoped, ApiConfig::default())
            .with_passkeys(Some(Arc::new(software())));
        let jwt = state.jwt_config.clone();
        let app = create_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .expect("serve");
        });
        Self {
            addr,
            jwt,
            http: reqwest::Client::new(),
            _stop: tx,
        }
    }

    async fn post(&self, path: &str, token: Option<&str>, body: &Value) -> (u16, Value) {
        let mut req = self
            .http
            .post(format!("http://{}{path}", self.addr))
            .json(body);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.expect("POST");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn get(&self, path: &str, token: &str) -> (u16, Value) {
        let resp = self
            .http
            .get(format!("http://{}{path}", self.addr))
            .bearer_auth(token)
            .send()
            .await
            .expect("GET");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    /// A token for `principal` on `client` and `family` (each as given),
    /// naming `elv`, with `claims:read`.
    fn token(
        &self,
        principal: Uuid,
        client: Uuid,
        family: Option<Uuid>,
        elv: Option<Uuid>,
    ) -> String {
        self.jwt
            .issue_access_token(
                client,
                vec!["claims:read".to_string()],
                "human",
                None,
                Some(principal),
                chrono::Duration::minutes(30),
                AccessTokenBinding {
                    family_id: family,
                    elevation_id: elv,
                    delegated_by: None,
                },
            )
            .expect("mint")
            .0
    }
}

/// A platform custodian: a registered human with its human client (holding
/// `claims:read`), a live refresh family, the custodian role and a passkey
/// on `auth`, enrolled through the real enrollment ceremony.
struct Custodian {
    person: Uuid,
    client: Uuid,
    client_id: String,
    family: Uuid,
}

async fn custodian_with_passkey(
    pool: &PgPool,
    s: &Recording,
    auth: &mut SoftAuthenticator,
) -> Custodian {
    let (person, _group) =
        viewer_fixture::seed_human_operator(pool, "prompt-history-custodian").await;
    let (client, client_id): (Uuid, String) = sqlx::query_as(
        "SELECT id, client_id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human'",
    )
    .bind(person)
    .fetch_one(pool)
    .await
    .expect("the human's client");
    sqlx::query(
        "UPDATE oauth_clients SET granted_scopes = ARRAY['claims:read'], \
                allowed_scopes = ARRAY['claims:read'] WHERE id = $1",
    )
    .bind(client)
    .execute(pool)
    .await
    .expect("scopes");
    let family: Uuid = sqlx::query_scalar(
        "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
         VALUES ($1, $2, ARRAY['claims:read'], now() + interval '1 day') RETURNING id",
    )
    .bind(random32().to_vec())
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("a refresh family");
    viewer_fixture::make_custodian(pool, person).await;

    let enrollment = as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let id: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'prompt history', 'key')",
        )
        .bind(person)
        .fetch_one(&mut *conn)
        .await
        .expect("open the enrollment");
        (conn, id)
    })
    .await;
    let base = format!("/elevate/enroll/{enrollment}");
    let (status, options) = s.post(&format!("{base}/challenge"), None, &json!({})).await;
    assert_eq!(status, 200, "enrollment challenge: {options}");
    let response = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let (status, body) = s.post(&format!("{base}/finish"), None, &response).await;
    assert_eq!(status, 200, "enrollment finish: {body}");
    Custodian {
        person,
        client,
        client_id,
        family,
    }
}

/// Elevate `c` the CLI way (a grant-mode ticket, the passkey ceremony, the
/// elevate grant): `(the elevation session, the elevated token)`.
async fn sudo(
    pool: &PgPool,
    s: &Recording,
    c: &Custodian,
    auth: &mut SoftAuthenticator,
) -> (Uuid, String) {
    let plain = s.token(c.person, c.client, Some(c.family), None);
    let (status, body) = s
        .post(
            "/api/v1/elevation/tickets",
            Some(&plain),
            &json!({"reason": "audit an agent's prompt history"}),
        )
        .await;
    assert_eq!(status, 201, "ticket: {body}");
    let ticket: Uuid = body["ticket_id"]
        .as_str()
        .expect("id")
        .parse()
        .expect("uuid");
    let secret = body["redeem_secret"].as_str().expect("secret").to_string();
    let (status, options) = s
        .post(&format!("/elevate/{ticket}/challenge"), None, &json!({}))
        .await;
    assert_eq!(status, 200, "challenge: {options}");
    let response = auth.authenticate(ORIGIN, options).await;
    let (status, body) = s
        .post(&format!("/elevate/{ticket}/assert"), None, &response)
        .await;
    assert_eq!(status, 200, "ceremony: {body}");
    assert_eq!(body["outcome"], "confirmed", "{body}");
    let (status, body) = s
        .post(
            "/oauth/token",
            None,
            &json!({"grant_type": "urn:epigraph:grant:elevate", "ticket_id": ticket,
                    "redeem_secret": secret, "client_id": c.client_id}),
        )
        .await;
    assert_eq!(status, 200, "elevate grant: {body}");
    let session: Uuid =
        sqlx::query_scalar("SELECT session_id FROM elevation_tickets WHERE id = $1")
            .bind(ticket)
            .fetch_one(pool)
            .await
            .expect("the session");
    (
        session,
        body["access_token"].as_str().expect("token").to_string(),
    )
}

/// With the admin-scope switch ARMED, the definer's admin arm needs an
/// ELEVATED session. The operator still reads (its arm does not depend on
/// the switch); the custodian's ordinary token, which reads while the switch
/// is off (CONTROL), is refused once it is armed, the listing and the file
/// alike; the same custodian ELEVATED reads both, and each elevated read is
/// recorded against the elevation session.
#[sqlx::test(migrations = "../../migrations")]
async fn armed_only_an_elevated_custodian_reads_and_each_read_is_recorded(pool: PgPool) {
    let operator = human(&pool).await;
    let f = family(&pool, operator).await;
    let s = Recording::start(&pool).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let c = custodian_with_passkey(&pool, &s, &mut auth).await;
    let listing = format!("/api/v1/agents/{}/prompt-history", f.child);
    let hash = blake3_hex(&f.child_learned);
    let file = format!("{listing}/blobs/{hash}");
    let plain = s.token(c.person, c.client, Some(c.family), None);

    let (status, body) = s.get(&listing, &plain).await;
    assert_eq!(
        status, 200,
        "CONTROL: unarmed, the custodian's ordinary token reads: {body}"
    );

    sqlx::query(
        "SELECT * FROM public.epigraph_set_admin_scope_enforcement(true, 'prompt history')",
    )
    .execute(&pool)
    .await
    .expect("arm");
    let armed: bool = sqlx::query_scalar("SELECT public.epigraph_admin_scopes_armed()")
        .fetch_one(&pool)
        .await
        .expect("armed read");
    assert!(armed, "CALIBRATION: the switch is armed");

    let op = s.token(operator, Uuid::new_v4(), None, None);
    let (status, body) = s.get(&listing, &op).await;
    assert_eq!(status, 200, "armed, the operator still reads: {body}");

    let (status, body) = s.get(&listing, &plain).await;
    assert_eq!(
        status, 404,
        "armed, an unelevated custodian is refused: {body}"
    );
    let (status, body) = s.get(&file, &plain).await;
    assert_eq!(status, 404, "and refused the file too: {body}");

    let (session, elevated) = sudo(&pool, &s, &c, &mut auth).await;
    let (status, body) = s.get(&listing, &elevated).await;
    assert_eq!(status, 200, "elevated, the custodian reads: {body}");
    assert_eq!(arr(&body["snapshots"], "snapshots").len(), 1, "{body}");
    assert_eq!(
        body["lineage"]["ancestors"][0]["readable"],
        json!(true),
        "elevated, every lineage member is readable: {body}"
    );
    let (status, body) = s.get(&file, &elevated).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["text"].as_str(), Some(f.child_learned.as_str()));

    let mut surfaces: Vec<String> =
        sqlx::query_scalar("SELECT surface FROM elevated_access WHERE elevation_id = $1")
            .bind(session)
            .fetch_all(&pool)
            .await
            .expect("the access log");
    surfaces.sort();
    assert_eq!(
        surfaces,
        [
            "GET /api/v1/agents/:id/prompt-history",
            "GET /api/v1/agents/:id/prompt-history/blobs/:hash",
        ],
        "each elevated read is recorded against the session"
    );
}
