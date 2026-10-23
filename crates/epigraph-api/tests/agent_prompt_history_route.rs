#![cfg(feature = "db")]
//! `GET /api/v1/agents/:id/prompt-history` (agent identity lineage design D4):
//! an agent's prompt snapshots and its succession lineage, readable by the
//! agent's operator and by admins, and by nobody else.
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

/// `GET /api/v1/agents/{agent}/prompt-history` through the full router as
/// `caller` holding `scopes`: `(status, body)`.
async fn get_history(
    state: &AppState,
    caller: Uuid,
    scopes: &[&str],
    agent: Uuid,
) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(scopes, caller);
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/v1/agents/{agent}/prompt-history"))
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
    let learned = &s["files"]["learned_md"];
    assert_eq!(
        learned["text"].as_str(),
        Some(f.child_learned.as_str()),
        "LEARNED.md round-trips byte for byte through compression: {learned}"
    );
    assert_eq!(learned["blob_hash"], json!(blake3_hex(&f.child_learned)));
    assert_eq!(
        s["files"]["group_claude_md"]["text"].as_str(),
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
    assert_eq!(s["withheld_files"], json!([]));
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
/// for the id. So the route is not an oracle for which agent ids exist.
/// CONTROL: the operator reads the same agent.
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
    let (s_op_absent, b_op_absent) =
        get_history(&state, operator, &["claims:read"], absent).await;
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

    let (before, body) = get_history(&state, custodian, &["claims:read"], f.child).await;
    assert_eq!(
        before,
        StatusCode::NOT_FOUND,
        "CONTROL: not yet an admin, so refused: {body}"
    );

    viewer_fixture::make_custodian(&pool, custodian).await;
    let body = read_ok(&state, custodian, f.child).await;
    let snaps = arr(&body["snapshots"], "snapshots");
    assert_eq!(snaps.len(), 1, "{body}");
    assert_eq!(
        snaps[0]["files"]["learned_md"]["text"].as_str(),
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
    let (status_absent, _) =
        get_history(&state, operator, &["claims:write"], Uuid::new_v4()).await;
    assert_eq!(
        status_absent,
        StatusCode::FORBIDDEN,
        "the scope check runs before any lookup"
    );

    read_ok(&state, operator, f.child).await;
}
