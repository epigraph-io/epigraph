//! `plan_label_dedup`, `apply_label_dedup` and `probe_label_dedup`.
//!
//! Every fixture is neutral: a synthetic `tracked-item` family, synthetic
//! organisations and `ACME-` ids. Every refusal asserts its specific code and
//! carries a positive control (the same call without the refused condition
//! succeeds, and for apply, writes), so a tool that refuses everything cannot
//! pass.
//!
//! Two server shapes:
//!
//! * the superuser-backed test server, for the HTTP ownership gates and the
//!   profile loader;
//! * an APPLICATION-ROLE server (both of its pools downgraded to
//!   `epigraph_app`), so row security decides what the plan reads and what
//!   apply may write. That is the only shape in which a plan reading on the
//!   unstamped pool would lose the caller's own group-private rows, and in
//!   which a write into a group the caller cannot write is refused by the
//!   database rather than by an application gate.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_engine::label_dedup::{profile_hash, revert_writes, AppliedLabelChange};
use epigraph_mcp::errors::McpError;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::label_dedup::{
    apply_label_dedup, plan_label_dedup, probe_label_dedup, LabelDedupConfig,
};
use epigraph_mcp::types::{
    ApplyLabelDedupParams, LabelDedupCandidateParam, PlanLabelDedupParams, ProbeLabelDedupParams,
    UpdateLabelsParams,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

// ── Fixtures ────────────────────────────────────────────────────────────────

const FAMILY: &str = "tracked-item";
const RUN_TAG: &str = "item-dedup-2026-10-15";
const AS_OF: &str = "2026-10-15";

fn profile_value() -> Value {
    json!({
        "schema": "label-dedup-profile/v1",
        "family_label": FAMILY,
        "closed_label": "resolved",
        "retired_labels": ["tracked-item-duplicate"],
        "hygiene_write": {"add": ["{run_tag}"], "remove": ["{family}"]},
        "fields": {
            "entity": {"pipe_position": 1},
            "deadline": {"keys": ["due:"], "carry_label": "due"}
        },
        "ids": {
            "reject": ["iso_date", "us_date", "bare_year", "year_range", "fiscal_year",
                       "clock_time", "money", "percent"],
            "carry_label_prefix": "also-id:"
        },
        "merge": {
            "loser_add": ["tracked-item-duplicate", "duplicate-of:{survivor}", "{run_tag}"],
            "loser_remove": ["{family}"],
            "survivor_add": ["{run_tag}"],
            "carry_ids": true,
            "carry_later_dates": ["deadline"]
        },
        "closeout": {"date_field": "deadline", "add": ["resolved", "closed-past-due", "{run_tag}"]}
    })
}

fn profile_bytes() -> Vec<u8> {
    serde_json::to_vec(&profile_value()).expect("profile json")
}

/// The same profile, spelled with different whitespace: the same rules,
/// different bytes, a different hash.
fn profile_bytes_respaced() -> Vec<u8> {
    serde_json::to_vec_pretty(&profile_value()).expect("profile json")
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_string()).collect()
}

/// A fresh directory under the system temp dir, holding `profile.json`.
fn profile_root(bytes: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("label-dedup-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("profile root");
    std::fs::write(dir.join("profile.json"), bytes).expect("write profile");
    dir
}

fn config(root: Option<&Path>, pin: Option<&str>, cap: usize) -> LabelDedupConfig {
    LabelDedupConfig {
        profile_root: root.map(Path::to_path_buf),
        profile_pin: pin.map(str::to_string),
        max_claims_cap: cap,
    }
}

fn plan_params_path(path: &str, hash: &str, sections: &[&str]) -> PlanLabelDedupParams {
    PlanLabelDedupParams {
        profile_path: Some(path.to_string()),
        profile_json: None,
        profile_claim_id: None,
        profile_hash: hash.to_string(),
        run_tag: RUN_TAG.to_string(),
        as_of: Some(AS_OF.to_string()),
        sections: s(sections),
        max_claims: None,
    }
}

fn plan_params_json(bytes: &[u8], sections: &[&str]) -> PlanLabelDedupParams {
    PlanLabelDedupParams {
        profile_path: None,
        profile_json: Some(String::from_utf8(bytes.to_vec()).expect("utf8")),
        profile_claim_id: None,
        profile_hash: profile_hash(bytes),
        run_tag: RUN_TAG.to_string(),
        as_of: Some(AS_OF.to_string()),
        sections: s(sections),
        max_claims: None,
    }
}

fn apply_params(p: &PlanLabelDedupParams, plan_hash: &str) -> ApplyLabelDedupParams {
    ApplyLabelDedupParams {
        profile_path: p.profile_path.clone(),
        profile_json: p.profile_json.clone(),
        profile_claim_id: p.profile_claim_id.clone(),
        profile_hash: p.profile_hash.clone(),
        run_tag: p.run_tag.clone(),
        as_of: p.as_of.clone(),
        sections: p.sections.clone(),
        max_claims: p.max_claims,
        plan_hash: plan_hash.to_string(),
    }
}

const DEDUP: &[&str] = &["hygiene", "dedup"];
const ALL: &[&str] = &["hygiene", "dedup", "closeout"];

/// Insert a claim with explicit author, owner group, visibility, labels and
/// creation time, on the superuser pool.
async fn seed(
    pool: &PgPool,
    agent: Uuid,
    group: Uuid,
    visibility: &str,
    content: &str,
    labels: &[&str],
    created: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = blake3::hash(format!("{id}{content}").as_bytes())
        .as_bytes()
        .to_vec();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             labels, visibility, owner_group_id, created_at) \
         VALUES ($1, $2, $3, 0.6, $4, true, $5, $6, $7, $8::timestamptz)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .bind(s(labels))
    .bind(visibility)
    .bind(group)
    .bind(created)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn labels_of(pool: &PgPool, id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT COALESCE(labels, ARRAY[]::text[]) FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("labels")
}

async fn snapshot(pool: &PgPool, ids: &[Uuid]) -> BTreeMap<Uuid, Vec<String>> {
    let mut out = BTreeMap::new();
    for id in ids {
        out.insert(*id, labels_of(pool, *id).await);
    }
    out
}

fn code(e: &McpError) -> String {
    e.data
        .as_ref()
        .and_then(|d| d.get("code"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

async fn plan_ok(
    server: &EpiGraphMcpFull,
    viewer: &Viewer,
    p: PlanLabelDedupParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Value {
    first_text(
        &plan_label_dedup(server, viewer, p, auth)
            .await
            .expect("plan"),
    )
}

async fn apply_ok(
    server: &EpiGraphMcpFull,
    viewer: &Viewer,
    p: ApplyLabelDedupParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Value {
    first_text(
        &apply_label_dedup(server, viewer, p, auth)
            .await
            .expect("apply"),
    )
}

fn plan_hash(plan: &Value) -> String {
    plan["plan_hash"].as_str().expect("plan_hash").to_string()
}

fn unit_writes(plan: &Value) -> Vec<Value> {
    plan["write_units"].as_array().expect("write_units").clone()
}

/// The plan's per-unit prediction for `unit`.
fn unit_check<'a>(plan: &'a Value, unit: &str) -> &'a Value {
    plan["unit_check"]
        .as_array()
        .and_then(|a| a.iter().find(|u| u["unit"] == unit))
        .unwrap_or_else(|| panic!("no unit_check for {unit}: {plan}"))
}

/// Whether `unit_check` names `id` as a member the write identity does not own.
fn names_foreign_member(check: &Value, id: Uuid) -> bool {
    check["members"].as_array().is_some_and(|ms| {
        ms.iter()
            .any(|m| m["claim_id"] == id.to_string() && m["owned"] == false)
    })
}

fn result_for<'a>(apply: &'a Value, unit: &str) -> &'a Value {
    apply["results"]
        .as_array()
        .expect("results")
        .iter()
        .find(|r| r["unit"] == unit)
        .unwrap_or_else(|| panic!("no result for {unit}: {apply}"))
}

/// An application-role server: both pools downgraded, so row security
/// decides every read and write. Returns the server, its agent, the agent's
/// personal group and its viewer.
async fn app_role_server(
    pool: &PgPool,
    cfg: LabelDedupConfig,
) -> (EpiGraphMcpFull, Uuid, Uuid, Viewer) {
    app_role_server_with_signer(pool, cfg, Signer::Declared).await
}

/// Which signer the stdio server runs under.
#[derive(Debug, Clone, Copy)]
enum Signer {
    /// A fixed key: ownership is decided against the server's own agent.
    Declared,
    /// `main::select_signer`'s no-key rung: another agent's claim takes the
    /// `UndeclaredSigner` arm of the ownership check.
    Generated,
}

async fn app_role_server_with_signer(
    pool: &PgPool,
    cfg: LabelDedupConfig,
    signer: Signer,
) -> (EpiGraphMcpFull, Uuid, Uuid, Viewer) {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let server = match signer {
        Signer::Declared => build_scoped_test_server(plain, scoped),
        Signer::Generated => build_scoped_test_server_generated_signer(plain, scoped),
    }
    .with_label_dedup_config(cfg);
    let agent = server.server_agent_id().await.expect("server agent");
    let group = personal_group_of(pool, agent).await;
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    (server, agent, group, viewer)
}

async fn superuser_server(pool: &PgPool, cfg: LabelDedupConfig) -> EpiGraphMcpFull {
    build_scoped_test_server(pool.clone(), fixture::scoped_pool(pool).await)
        .with_label_dedup_config(cfg)
}

// Content in the pipe layout the profile parses: title | entity | due | ref.
const PUMP_A: &str =
    "Pump station rehab | Acme Water Authority | due: 2026-11-20 | ref ACME-123456";
const PUMP_B: &str =
    "Pump station rehabilitation | Acme Water Authority | due: 2026-12-05 | ref ACME-123456 ACME-777001";
const PUMP_C: &str =
    "Pump station rehab works | Acme Water Authority | due: 2026-11-20 | ref ACME-123456";
const FENCE: &str =
    "Yard fence replacement | Acme Parks Office | due: 2026-09-01 | ref ACME-555001";
const GATE: &str = "Gate motor swap | Acme Parks Office | due: 2026-09-03 | ref ACME-555002";
const ROOF: &str = "Library roof survey | Acme Library Board | due: 2026-12-20 | ref ACME-888001";
const ROOF_B: &str =
    "Library roof survey works | Acme Library Board | due: 2026-12-20 | ref ACME-888001";
/// PUMP_A's item under a different strong id: it joins PUMP_A only through a
/// revision label (the label overrides the strong-id veto).
const PUMP_REVISED: &str =
    "Pump station rehab | Acme Water Authority | due: 2026-11-20 | ref ACME-424242";

// ── Profile loading ─────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn stdio_plans_from_a_path_profile_and_refuses_inline_json(pool: PgPool) {
    let bytes = profile_bytes();
    let root = profile_root(&bytes);
    let server = superuser_server(&pool, config(Some(&root), None, 5000)).await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("viewer");

    let plan = plan_ok(
        &server,
        &viewer,
        plan_params_path("profile.json", &profile_hash(&bytes), DEDUP),
        None,
    )
    .await;
    assert_eq!(
        plan["profile_hash"],
        profile_hash(&bytes),
        "control: the path profile loads"
    );
    assert!(
        plan["plan_hash"].as_str().is_some_and(|h| h.len() == 64),
        "{plan}"
    );
    // The absolute spelling under the root is the same file.
    let abs = root.join("profile.json");
    plan_ok(
        &server,
        &viewer,
        plan_params_path(abs.to_str().expect("utf8"), &profile_hash(&bytes), DEDUP),
        None,
    )
    .await;

    let err = plan_label_dedup(&server, &viewer, plan_params_json(&bytes, DEDUP), None)
        .await
        .expect_err("stdio refuses inline profile json");
    assert_eq!(code(&err), "PROFILE_JSON_REFUSED", "{err:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_stdio_profile_hash_must_equal_the_bytes_and_the_pin(pool: PgPool) {
    let bytes = profile_bytes();
    let other = profile_bytes_respaced();
    let root = profile_root(&bytes);
    std::fs::write(root.join("other.json"), &other).expect("second profile");
    let pinned = superuser_server(
        &pool,
        config(Some(&root), Some(&profile_hash(&bytes)), 5000),
    )
    .await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&pinned, None)
        .await
        .expect("viewer");

    // Control: the pinned profile, its own hash (upper-cased: the pin is
    // compared canonically).
    plan_ok(
        &pinned,
        &viewer,
        plan_params_path("profile.json", &profile_hash(&bytes).to_uppercase(), DEDUP),
        None,
    )
    .await;

    // A different profile, correctly hashed, is still not the pin.
    let err = plan_label_dedup(
        &pinned,
        &viewer,
        plan_params_path("other.json", &profile_hash(&other), DEDUP),
        None,
    )
    .await
    .expect_err("a hash other than the pin");
    assert_eq!(code(&err), "PROFILE_HASH_MISMATCH", "{err:?}");

    // Without a pin, the other profile loads under its own hash...
    let unpinned = superuser_server(&pool, config(Some(&root), None, 5000)).await;
    plan_ok(
        &unpinned,
        &viewer,
        plan_params_path("other.json", &profile_hash(&other), DEDUP),
        None,
    )
    .await;
    // ...but never under a hash its bytes do not have.
    let err = plan_label_dedup(
        &unpinned,
        &viewer,
        plan_params_path("other.json", &profile_hash(&bytes), DEDUP),
        None,
    )
    .await
    .expect_err("bytes that do not hash to the argument");
    assert_eq!(code(&err), "PROFILE_HASH_MISMATCH", "{err:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn profile_path_is_refused_without_a_root_outside_it_through_a_symlink_or_off_a_regular_file(
    pool: PgPool,
) {
    let bytes = profile_bytes();
    let hash = profile_hash(&bytes);
    let root = profile_root(&bytes);
    let outside = profile_root(&bytes); // a sibling directory, same bytes
    std::os::unix::fs::symlink(root.join("profile.json"), root.join("link.json")).expect("symlink");
    std::fs::create_dir_all(root.join("real-dir")).expect("dir");
    std::fs::write(root.join("real-dir").join("p.json"), &bytes).expect("nested profile");
    std::os::unix::fs::symlink(root.join("real-dir"), root.join("dir-link")).expect("dir symlink");

    let server = superuser_server(&pool, config(Some(&root), None, 5000)).await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("viewer");

    // Controls: the plain file and the nested file load.
    plan_ok(
        &server,
        &viewer,
        plan_params_path("profile.json", &hash, DEDUP),
        None,
    )
    .await;
    plan_ok(
        &server,
        &viewer,
        plan_params_path("real-dir/p.json", &hash, DEDUP),
        None,
    )
    .await;

    let outside_abs = outside.join("profile.json");
    let cases: Vec<(String, &str)> = vec![
        (
            "../".to_string() + outside.file_name().unwrap().to_str().unwrap() + "/profile.json",
            "dot-dot",
        ),
        (
            outside_abs.to_str().unwrap().to_string(),
            "absolute outside",
        ),
        ("link.json".to_string(), "symlinked file"),
        ("dir-link/p.json".to_string(), "symlinked directory"),
        ("real-dir".to_string(), "a directory"),
    ];
    for (path, why) in cases {
        let err = plan_label_dedup(
            &server,
            &viewer,
            plan_params_path(&path, &hash, DEDUP),
            None,
        )
        .await
        .expect_err(why);
        assert_eq!(code(&err), "PROFILE_PATH_REFUSED", "{why}: {err:?}");
    }

    // A FIFO must be refused, not opened (an open would block forever).
    let fifo = root.join("pipe.json");
    if std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .is_ok_and(|st| st.success())
    {
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            plan_label_dedup(
                &server,
                &viewer,
                plan_params_path("pipe.json", &hash, DEDUP),
                None,
            ),
        )
        .await
        .expect("a FIFO profile must not hang the call");
        let err = res.expect_err("a FIFO is not a regular file");
        assert_eq!(code(&err), "PROFILE_PATH_REFUSED", "{err:?}");
    }

    // No root configured: path mode is off.
    let rootless = superuser_server(&pool, config(None, None, 5000)).await;
    let err = plan_label_dedup(
        &rootless,
        &viewer,
        plan_params_path("profile.json", &hash, DEDUP),
        None,
    )
    .await
    .expect_err("no root");
    assert_eq!(code(&err), "PROFILE_PATH_REFUSED", "{err:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_profile_reads_as_not_found(pool: PgPool) {
    use std::os::unix::fs::PermissionsExt;
    let bytes = profile_bytes();
    let hash = profile_hash(&bytes);
    let root = profile_root(&bytes);
    std::fs::write(root.join("locked.json"), &bytes).expect("locked profile");
    let server = superuser_server(&pool, config(Some(&root), None, 5000)).await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("viewer");

    // Control: readable, it loads.
    plan_ok(
        &server,
        &viewer,
        plan_params_path("locked.json", &hash, DEDUP),
        None,
    )
    .await;

    let missing = plan_label_dedup(
        &server,
        &viewer,
        plan_params_path("absent.json", &hash, DEDUP),
        None,
    )
    .await
    .expect_err("missing");
    assert_eq!(code(&missing), "PROFILE_NOT_FOUND", "{missing:?}");

    std::fs::set_permissions(
        root.join("locked.json"),
        std::fs::Permissions::from_mode(0o000),
    )
    .expect("chmod 000");
    if std::fs::read(root.join("locked.json")).is_ok() {
        // A process that reads a mode-000 file (root) cannot construct the
        // unreadable case; the missing-file half above still ran.
        eprintln!("skipping the unreadable half: this process can read a mode-000 file");
        return;
    }
    let locked = plan_label_dedup(
        &server,
        &viewer,
        plan_params_path("locked.json", &hash, DEDUP),
        None,
    )
    .await
    .expect_err("unreadable");
    assert_eq!(code(&locked), "PROFILE_NOT_FOUND", "{locked:?}");
    assert_eq!(
        locked.message.replace("locked.json", "X"),
        missing.message.replace("absent.json", "X"),
        "an unreadable profile is indistinguishable from a missing one"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn http_refuses_profile_path_and_reads_inline_json(pool: PgPool) {
    let bytes = profile_bytes();
    let root = profile_root(&bytes);
    let server = superuser_server(&pool, config(Some(&root), None, 5000)).await;
    let (_caller, auth, viewer) = seed_caller(&pool, &["claims:read"]).await;

    let plan = plan_ok(
        &server,
        &viewer,
        plan_params_json(&bytes, DEDUP),
        Some(&auth),
    )
    .await;
    assert_eq!(
        plan["profile_hash"],
        profile_hash(&bytes),
        "control: inline json over HTTP"
    );

    let err = plan_label_dedup(
        &server,
        &viewer,
        plan_params_path("profile.json", &profile_hash(&bytes), DEDUP),
        Some(&auth),
    )
    .await
    .expect_err("HTTP refuses path mode, even with a root configured");
    assert_eq!(code(&err), "PROFILE_PATH_REFUSED", "{err:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_profile_claim_id_is_refused_as_deferred(pool: PgPool) {
    let bytes = profile_bytes();
    let server = superuser_server(&pool, config(None, None, 5000)).await;
    let (_caller, auth, viewer) = seed_caller(&pool, &["claims:read"]).await;
    let mut p = plan_params_json(&bytes, DEDUP);
    plan_ok(&server, &viewer, p.clone(), Some(&auth)).await;
    p.profile_claim_id = Some(Uuid::new_v4().to_string());
    let err = plan_label_dedup(&server, &viewer, p, Some(&auth))
        .await
        .expect_err("deferred");
    assert_eq!(code(&err), "PROFILE_CLAIM_DEFERRED", "{err:?}");
}

// ── Visibility ──────────────────────────────────────────────────────────────

/// On an application-role server: the server agent's own GROUP-PRIVATE
/// family row is planned (only a stamped read can see it), and a stranger's
/// private row with the same id is invisible, nowhere in the output.
#[sqlx::test(migrations = "../../migrations")]
async fn the_plan_reads_the_callers_private_rows_and_never_a_strangers(pool: PgPool) {
    let bytes = profile_bytes();
    let root = profile_root(&bytes);
    let (server, agent, group, viewer) =
        app_role_server(&pool, config(Some(&root), None, 5000)).await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "item-stranger").await;

    let mine_public = seed(
        &pool,
        agent,
        group,
        "public",
        PUMP_A,
        &[FAMILY],
        "2026-10-01T00:00:00Z",
    )
    .await;
    let mine_private = seed(
        &pool,
        agent,
        group,
        "group",
        PUMP_B,
        &[FAMILY],
        "2026-09-01T00:00:00Z",
    )
    .await;
    let theirs = seed(
        &pool,
        stranger,
        stranger_group,
        "group",
        PUMP_C,
        &[FAMILY],
        "2026-08-01T00:00:00Z",
    )
    .await;

    let plan = plan_ok(
        &server,
        &viewer,
        plan_params_path("profile.json", &profile_hash(&bytes), DEDUP),
        None,
    )
    .await;
    assert_eq!(plan["coverage"]["members"], 2, "{plan}");
    let text = plan.to_string();
    assert!(
        text.contains(&mine_private.to_string()),
        "the caller's private row is planned: {plan}"
    );
    assert!(text.contains(&mine_public.to_string()), "{plan}");
    assert!(
        !text.contains(&theirs.to_string()),
        "a stranger's private row is invisible: {plan}"
    );
    let cluster = &plan["clusters"][0];
    assert_eq!(cluster["survivor"], mine_public.to_string(), "{plan}");

    // Control: the stranger's own viewer over HTTP reads its row.
    let stranger_viewer = Viewer::resolve(&pool, stranger).await.expect("viewer");
    let auth = epigraph_auth::AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(stranger),
        owner_id: None,
        client_type: epigraph_auth::ClientType::Agent,
        scopes: s(&["claims:read"]),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
    };
    let theirs_plan = plan_ok(
        &server,
        &stranger_viewer,
        plan_params_json(&bytes, DEDUP),
        Some(&auth),
    )
    .await;
    assert!(
        theirs_plan.to_string().contains(&theirs.to_string()),
        "{theirs_plan}"
    );
}

// ── max_claims ──────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn max_claims_above_the_cap_is_clamped_reported_and_enforced(pool: PgPool) {
    let bytes = profile_bytes();
    let (agent, group) = fixture::seed_agent_with_group(&pool, "item-cap").await;
    for (c, t) in [
        (PUMP_A, "2026-10-01T00:00:00Z"),
        (PUMP_B, "2026-09-01T00:00:00Z"),
        (ROOF, "2026-09-02T00:00:00Z"),
    ] {
        seed(&pool, agent, group, "public", c, &[FAMILY], t).await;
    }
    let (_caller, auth, viewer) = seed_caller(&pool, &["claims:read"]).await;

    let capped = superuser_server(&pool, config(None, None, 2)).await;
    let mut p = plan_params_json(&bytes, DEDUP);
    p.max_claims = Some(1000);
    let plan = plan_ok(&capped, &viewer, p.clone(), Some(&auth)).await;
    assert_eq!(plan["max_claims"]["requested"], 1000, "{plan}");
    assert_eq!(plan["max_claims"]["effective"], 2, "{plan}");
    assert_eq!(plan["max_claims"]["clamped"], true, "{plan}");
    assert_eq!(plan["coverage"]["members"], 2, "{plan}");
    assert_eq!(
        plan["coverage"]["truncated"], true,
        "the clamp is enforced: {plan}"
    );

    // Control: under a larger cap the same request is not clamped.
    let roomy = superuser_server(&pool, config(None, None, 5000)).await;
    let plan = plan_ok(&roomy, &viewer, p, Some(&auth)).await;
    assert_eq!(plan["max_claims"]["effective"], 1000, "{plan}");
    assert_eq!(plan["max_claims"]["clamped"], false, "{plan}");
    assert_eq!(plan["coverage"]["members"], 3, "{plan}");
    assert_eq!(plan["coverage"]["truncated"], false, "{plan}");
}

// ── Apply refusals ──────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn a_truncated_plan_refuses_apply_and_writes_nothing(pool: PgPool) {
    let bytes = profile_bytes();
    let root = profile_root(&bytes);
    let (server, agent, group, viewer) =
        app_role_server(&pool, config(Some(&root), None, 5000)).await;
    let a = seed(
        &pool,
        agent,
        group,
        "public",
        PUMP_A,
        &[FAMILY],
        "2026-10-01T00:00:00Z",
    )
    .await;
    let b = seed(
        &pool,
        agent,
        group,
        "public",
        PUMP_B,
        &[FAMILY],
        "2026-09-01T00:00:00Z",
    )
    .await;
    let c = seed(
        &pool,
        agent,
        group,
        "public",
        PUMP_C,
        &[FAMILY],
        "2026-08-01T00:00:00Z",
    )
    .await;
    let ids = [a, b, c];
    let before = snapshot(&pool, &ids).await;

    let mut p = plan_params_path("profile.json", &profile_hash(&bytes), DEDUP);
    p.max_claims = Some(2);
    let plan = plan_ok(&server, &viewer, p.clone(), None).await;
    assert_eq!(plan["coverage"]["truncated"], true, "{plan}");
    assert!(
        !unit_writes(&plan).is_empty(),
        "the prefix alone has writes: {plan}"
    );
    let out = apply_ok(&server, &viewer, apply_params(&p, &plan_hash(&plan)), None).await;
    assert_eq!(out["status"], "refused", "{out}");
    assert_eq!(out["refusal"]["code"], "TRUNCATED", "{out}");
    assert_eq!(snapshot(&pool, &ids).await, before, "nothing written");

    // Control: the whole family read, the same apply writes.
    p.max_claims = Some(10);
    let plan = plan_ok(&server, &viewer, p.clone(), None).await;
    let out = apply_ok(&server, &viewer, apply_params(&p, &plan_hash(&plan)), None).await;
    assert_eq!(out["status"], "applied", "{out}");
    assert_ne!(snapshot(&pool, &ids).await, before);
}

#[sqlx::test(migrations = "../../migrations")]
async fn plan_drift_refuses_apply_writes_nothing_and_returns_the_fresh_plan(pool: PgPool) {
    let bytes = profile_bytes();
    let root = profile_root(&bytes);
    let (server, agent, group, viewer) =
        app_role_server(&pool, config(Some(&root), None, 5000)).await;
    let a = seed(
        &pool,
        agent,
        group,
        "public",
        PUMP_A,
        &[FAMILY],
        "2026-10-01T00:00:00Z",
    )
    .await;
    let b = seed(
        &pool,
        agent,
        group,
        "public",
        PUMP_B,
        &[FAMILY],
        "2026-09-01T00:00:00Z",
    )
    .await;
    let p = plan_params_path("profile.json", &profile_hash(&bytes), DEDUP);
    let stale = plan_ok(&server, &viewer, p.clone(), None).await;

    // A third member joins the cluster: the writes change.
    let c = seed(
        &pool,
        agent,
        group,
        "public",
        PUMP_C,
        &[FAMILY],
        "2026-08-01T00:00:00Z",
    )
    .await;
    let ids = [a, b, c];
    let before = snapshot(&pool, &ids).await;
    let out = apply_ok(&server, &viewer, apply_params(&p, &plan_hash(&stale)), None).await;
    assert_eq!(out["status"], "refused", "{out}");
    assert_eq!(out["refusal"]["code"], "PLAN_DRIFT", "{out}");
    let fresh = &out["plan"];
    assert_ne!(fresh["plan_hash"], stale["plan_hash"], "{out}");
    assert!(
        fresh.to_string().contains(&c.to_string()),
        "the fresh plan names the new member: {out}"
    );
    assert_eq!(snapshot(&pool, &ids).await, before, "nothing written");

    // Control: applying the fresh hash writes.
    let out = apply_ok(&server, &viewer, apply_params(&p, &plan_hash(fresh)), None).await;
    assert_eq!(out["status"], "applied", "{out}");
    assert_ne!(snapshot(&pool, &ids).await, before);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_read_only_server_refuses_apply(pool: PgPool) {
    let bytes = profile_bytes();
    let root = profile_root(&bytes);
    let scoped = fixture::scoped_pool(&pool).await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0xA7u8; 32]).expect("signer");
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    let read_only = EpiGraphMcpFull::new(pool.clone(), signer, embedder, true)
        .with_scoped_pool(scoped)
        .with_label_dedup_config(config(Some(&root), None, 5000));
    let writable = superuser_server(&pool, config(Some(&root), None, 5000)).await;
    let agent = writable.server_agent_id().await.expect("agent");
    let group = personal_group_of(&pool, agent).await;
    let viewer = Viewer::resolve(&pool, agent).await.expect("viewer");
    let a = seed(
        &pool,
        agent,
        group,
        "public",
        PUMP_A,
        &[FAMILY],
        "2026-10-01T00:00:00Z",
    )
    .await;
    let b = seed(
        &pool,
        agent,
        group,
        "public",
        PUMP_B,
        &[FAMILY],
        "2026-09-01T00:00:00Z",
    )
    .await;
    let before = snapshot(&pool, &[a, b]).await;

    let p = plan_params_path("profile.json", &profile_hash(&bytes), DEDUP);
    let plan = plan_ok(&read_only, &viewer, p.clone(), None).await;
    let err = apply_label_dedup(
        &read_only,
        &viewer,
        apply_params(&p, &plan_hash(&plan)),
        None,
    )
    .await
    .expect_err("read-only");
    assert!(err.message.contains("read-only"), "{err:?}");
    assert_eq!(snapshot(&pool, &[a, b]).await, before);

    // Control: the writable twin applies the same plan.
    let out = apply_ok(
        &writable,
        &viewer,
        apply_params(&p, &plan_hash(&plan)),
        None,
    )
    .await;
    assert_eq!(out["status"], "applied", "{out}");
    assert_ne!(snapshot(&pool, &[a, b]).await, before);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_plan_hash_covers_the_profile_hash(pool: PgPool) {
    let a_bytes = profile_bytes();
    let b_bytes = profile_bytes_respaced();
    assert_ne!(
        profile_hash(&a_bytes),
        profile_hash(&b_bytes),
        "precondition"
    );
    let (agent, group) = fixture::seed_agent_with_group(&pool, "item-hash").await;
    seed(
        &pool,
        agent,
        group,
        "public",
        PUMP_A,
        &[FAMILY],
        "2026-10-01T00:00:00Z",
    )
    .await;
    seed(
        &pool,
        agent,
        group,
        "public",
        PUMP_B,
        &[FAMILY],
        "2026-09-01T00:00:00Z",
    )
    .await;
    let server = superuser_server(&pool, config(None, None, 5000)).await;
    let (_caller, auth, viewer) = seed_caller(&pool, &["claims:write"]).await;

    let pa = plan_params_json(&a_bytes, DEDUP);
    let pb = plan_params_json(&b_bytes, DEDUP);
    let plan_a = plan_ok(&server, &viewer, pa.clone(), Some(&auth)).await;
    let plan_b = plan_ok(&server, &viewer, pb.clone(), Some(&auth)).await;
    assert_eq!(
        unit_writes(&plan_a),
        unit_writes(&plan_b),
        "same rules, same writes"
    );
    assert!(!unit_writes(&plan_a).is_empty());
    assert_ne!(
        plan_a["plan_hash"], plan_b["plan_hash"],
        "the profile hash is covered"
    );

    // Applying A's hash under profile B is drift: nothing is written.
    let out = apply_ok(
        &server,
        &viewer,
        apply_params(&pb, &plan_hash(&plan_a)),
        Some(&auth),
    )
    .await;
    assert_eq!(out["status"], "refused", "{out}");
    assert_eq!(out["refusal"]["code"], "PLAN_DRIFT", "{out}");
}

// ── Unit atomicity ──────────────────────────────────────────────────────────

/// Over HTTP: the caller owns the survivor and one loser; a stranger owns the
/// other loser. The cluster unit fails as a whole (the survivor gets no carry
/// labels, the owned loser is not retired), the plan's write_check predicted
/// the refusal, and a later unit (a close-out) still commits.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cluster_with_one_unwritable_loser_writes_nothing_and_later_units_continue(pool: PgPool) {
    let bytes = profile_bytes();
    let server = superuser_server(&pool, config(None, None, 5000)).await;
    let (caller, auth, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let caller_group = personal_group_of(&pool, caller).await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "item-other").await;

    let survivor = seed(
        &pool,
        caller,
        caller_group,
        "public",
        PUMP_A,
        &[FAMILY],
        "2026-10-01T00:00:00Z",
    )
    .await;
    let owned_loser = seed(
        &pool,
        caller,
        caller_group,
        "public",
        PUMP_B,
        &[FAMILY],
        "2026-09-01T00:00:00Z",
    )
    .await;
    let foreign_loser = seed(
        &pool,
        stranger,
        stranger_group,
        "public",
        PUMP_C,
        &[FAMILY],
        "2026-08-01T00:00:00Z",
    )
    .await;
    let fence = seed(
        &pool,
        caller,
        caller_group,
        "public",
        FENCE,
        &[FAMILY],
        "2026-07-01T00:00:00Z",
    )
    .await;
    let cluster_ids = [survivor, owned_loser, foreign_loser];
    let before = snapshot(&pool, &cluster_ids).await;

    let p = plan_params_json(&bytes, ALL);
    let plan = plan_ok(&server, &viewer, p.clone(), Some(&auth)).await;
    assert_eq!(
        plan["clusters"][0]["survivor"],
        survivor.to_string(),
        "{plan}"
    );
    let check = |id: Uuid| {
        plan["write_check"]
            .as_array()
            .expect("write_check")
            .iter()
            .find(|c| c["claim_id"] == id.to_string())
            .cloned()
            .unwrap_or_else(|| panic!("no write_check for {id}: {plan}"))
    };
    assert_eq!(check(foreign_loser)["writable"], false, "predicted: {plan}");
    assert_eq!(check(owned_loser)["writable"], true, "{plan}");
    assert_eq!(check(fence)["writable"], true, "{plan}");

    let out = apply_ok(
        &server,
        &viewer,
        apply_params(&p, &plan_hash(&plan)),
        Some(&auth),
    )
    .await;
    assert_eq!(out["status"], "applied", "{out}");
    let cluster = result_for(&out, &format!("cluster:{survivor}"));
    assert_eq!(cluster["ok"], false, "{out}");
    assert!(
        cluster["error"].as_str().is_some_and(|e| !e.is_empty()),
        "{out}"
    );
    assert_eq!(
        snapshot(&pool, &cluster_ids).await,
        before,
        "the whole cluster unit rolled back"
    );
    assert!(
        !out["applied_units"]
            .to_string()
            .contains(&survivor.to_string()),
        "a rolled-back unit is not in applied_units: {out}"
    );

    assert_eq!(
        result_for(&out, &format!("closeout:{fence}"))["ok"],
        true,
        "{out}"
    );
    assert!(
        labels_of(&pool, fence)
            .await
            .contains(&"resolved".to_string()),
        "the later unit committed"
    );
    assert_eq!(out["counts"]["failed"], 1, "{out}");
}

/// On an application-role server over stdio: the database refuses the write
/// into a group the server agent cannot write. That close-out unit fails
/// alone; the agent's own close-out commits.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unwritable_closeout_target_fails_only_its_own_unit(pool: PgPool) {
    let bytes = profile_bytes();
    let root = profile_root(&bytes);
    let (server, agent, group, viewer) =
        app_role_server(&pool, config(Some(&root), None, 5000)).await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "item-closeout").await;
    let mine = seed(
        &pool,
        agent,
        group,
        "public",
        FENCE,
        &[FAMILY],
        "2026-07-01T00:00:00Z",
    )
    .await;
    let theirs = seed(
        &pool,
        stranger,
        stranger_group,
        "public",
        GATE,
        &[FAMILY],
        "2026-07-02T00:00:00Z",
    )
    .await;
    let theirs_before = labels_of(&pool, theirs).await;

    let p = plan_params_path("profile.json", &profile_hash(&bytes), &["closeout"]);
    let plan = plan_ok(&server, &viewer, p.clone(), None).await;
    assert_eq!(plan["past_due"].as_array().map(Vec::len), Some(2), "{plan}");
    let out = apply_ok(&server, &viewer, apply_params(&p, &plan_hash(&plan)), None).await;
    assert_eq!(
        result_for(&out, &format!("closeout:{mine}"))["ok"],
        true,
        "{out}"
    );
    assert_eq!(
        result_for(&out, &format!("closeout:{theirs}"))["ok"],
        false,
        "{out}"
    );
    assert!(labels_of(&pool, mine)
        .await
        .contains(&"resolved".to_string()));
    assert_eq!(labels_of(&pool, theirs).await, theirs_before);
}

// ── Apply, idempotency and revert ───────────────────────────────────────────

/// On an application-role server over stdio, every claim the server agent's
/// own: apply hygiene, a cluster (with a replaced carried date) and a
/// close-out (the retirement label, gated), check the re-plan is empty, then
/// revert from `applied_units` through `update_labels`, newest first.
///
/// Byte-for-byte for every claim whose stored labels were already sorted and
/// distinct. The write path stores labels sorted and distinct, so a claim
/// stored in another order comes back with the same SET in sorted order: that
/// limit is pinned on `fence` below, not hidden by pre-sorted fixtures.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_then_revert_from_applied_units_restores_every_label_set(pool: PgPool) {
    let bytes = profile_bytes();
    let root = profile_root(&bytes);
    let (server, agent, group, viewer) =
        app_role_server(&pool, config(Some(&root), None, 5000)).await;

    let survivor = seed(
        &pool,
        agent,
        group,
        "public",
        PUMP_A,
        &["due-carried:2026-11-01", FAMILY],
        "2026-10-01T00:00:00Z",
    )
    .await;
    let loser = seed(
        &pool,
        agent,
        group,
        "public",
        PUMP_B,
        &["src-b", FAMILY],
        "2026-09-01T00:00:00Z",
    )
    .await;
    let partial = seed(
        &pool,
        agent,
        group,
        "public",
        ROOF,
        &[FAMILY, "tracked-item-duplicate"],
        "2026-09-05T00:00:00Z",
    )
    .await;
    // Stored out of order on purpose.
    let fence = seed(
        &pool,
        agent,
        group,
        "public",
        FENCE,
        &[FAMILY, "zeta", "alpha"],
        "2026-07-01T00:00:00Z",
    )
    .await;
    let ids = [survivor, loser, partial, fence];
    let before = snapshot(&pool, &ids).await;

    let p = plan_params_path("profile.json", &profile_hash(&bytes), ALL);
    let plan = plan_ok(&server, &viewer, p.clone(), None).await;
    let out = apply_ok(&server, &viewer, apply_params(&p, &plan_hash(&plan)), None).await;
    assert_eq!(out["status"], "applied", "{out}");
    assert_eq!(out["counts"]["failed"], 0, "{out}");
    assert_eq!(out["applied_plan_hash"], plan["plan_hash"], "{out}");
    let applied: Vec<AppliedLabelChange> =
        serde_json::from_value(out["applied_units"].clone()).expect("applied_units");

    // Preconditions: the apply replaced a carried date (a removal the revert
    // must add back) and retired a claim with the gated label.
    assert!(
        applied.iter().any(|c| c.claim_id == survivor
            && c.labels_removed
                .contains(&"due-carried:2026-11-01".to_string())
            && c.labels_added
                .contains(&"due-carried:2026-12-05".to_string())),
        "{applied:?}"
    );
    assert!(
        applied
            .iter()
            .any(|c| c.claim_id == fence && c.labels_added.contains(&"resolved".to_string())),
        "{applied:?}"
    );
    assert!(
        applied
            .iter()
            .any(|c| c.claim_id == partial && c.labels_removed == s(&[FAMILY])),
        "{applied:?}"
    );
    // Each record is exactly the change on the stored row.
    let after = snapshot(&pool, &ids).await;
    for id in ids {
        let mut expect: Vec<String> = sorted(before[&id].clone());
        for c in applied.iter().filter(|c| c.claim_id == id) {
            expect.retain(|l| !c.labels_removed.contains(l));
            expect.extend(c.labels_added.iter().cloned());
        }
        assert_eq!(
            sorted(expect),
            after[&id],
            "applied_units is exact for {id}"
        );
    }

    // Idempotent: the applied family re-plans empty, and a second apply has
    // nothing to do.
    let again = plan_ok(&server, &viewer, p.clone(), None).await;
    assert!(unit_writes(&again).is_empty(), "{again}");
    let out2 = apply_ok(&server, &viewer, apply_params(&p, &plan_hash(&again)), None).await;
    assert_eq!(out2["status"], "nothing_to_do", "{out2}");

    // THE REVERT PROCEDURE: the inverse of applied_units, newest first, each
    // through update_labels under the same identity.
    for w in revert_writes(&applied) {
        epigraph_mcp::tools::claims::update_labels(
            &server,
            &viewer,
            UpdateLabelsParams {
                claim_id: w.claim_id.to_string(),
                add: w.add,
                remove: w.remove,
            },
            None,
        )
        .await
        .expect("revert write");
    }
    let restored = snapshot(&pool, &ids).await;
    for id in [survivor, loser, partial] {
        assert_eq!(restored[&id], before[&id], "byte-for-byte for {id}");
    }
    assert_eq!(
        restored[&fence],
        sorted(before[&fence].clone()),
        "the set comes back..."
    );
    assert_ne!(
        restored[&fence], before[&fence],
        "...in sorted order, not the stored order"
    );

    // And the restored family plans exactly as before.
    let replanned = plan_ok(&server, &viewer, p, None).await;
    assert_eq!(replanned["plan_hash"], plan["plan_hash"]);
}

// ── Probe ───────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn probe_matches_a_live_member_and_refuses_a_truncated_index(pool: PgPool) {
    let bytes = profile_bytes();
    let root = profile_root(&bytes);
    let (server, agent, group, viewer) =
        app_role_server(&pool, config(Some(&root), None, 5000)).await;
    let member = seed(
        &pool,
        agent,
        group,
        "group",
        PUMP_A,
        &[FAMILY],
        "2026-10-01T00:00:00Z",
    )
    .await;
    seed(
        &pool,
        agent,
        group,
        "public",
        ROOF,
        &[FAMILY],
        "2026-09-01T00:00:00Z",
    )
    .await;

    let params = |max: Option<i64>| ProbeLabelDedupParams {
        profile_path: Some("profile.json".into()),
        profile_json: None,
        profile_claim_id: None,
        profile_hash: profile_hash(&bytes),
        candidates: vec![
            LabelDedupCandidateParam {
                key: "same".into(),
                content: PUMP_C.into(),
                labels: s(&[FAMILY]),
            },
            LabelDedupCandidateParam {
                key: "fresh".into(),
                content:
                    "Bridge deck coating | Acme Roads Unit | due: 2026-12-01 | ref ACME-990001"
                        .into(),
                labels: s(&[FAMILY]),
            },
        ],
        include_closed_signals: false,
        max_claims: max,
    };
    let out = first_text(
        &probe_label_dedup(&server, &viewer, params(None), None)
            .await
            .expect("probe"),
    );
    let verdict = |key: &str| {
        out["verdicts"]
            .as_array()
            .expect("verdicts")
            .iter()
            .find(|v| v["key"] == key)
            .cloned()
            .unwrap_or_else(|| panic!("no verdict for {key}: {out}"))
    };
    assert_eq!(verdict("same")["verdict"], "match", "{out}");
    assert_eq!(
        verdict("same")["matched_id"],
        member.to_string(),
        "a private member, read stamped: {out}"
    );
    assert_eq!(verdict("fresh")["verdict"], "new", "{out}");

    let err = probe_label_dedup(&server, &viewer, params(Some(1)), None)
        .await
        .expect_err("a truncated index is refused, never answered new");
    assert_eq!(code(&err), "TRUNCATED", "{err:?}");
}

/// Another author's PUBLIC claim carrying the family label is a member the
/// caller can read, but it cannot answer `match` for the caller: a generator
/// would skip filing its own item on a claim it neither owns nor can merge.
/// The verdict is `review` and keeps `matched_id` for the human. Control: a
/// candidate matching the caller's own member is still `match`.
#[sqlx::test(migrations = "../../migrations")]
async fn probe_answers_review_not_match_for_another_authors_member(pool: PgPool) {
    let bytes = profile_bytes();
    let root = profile_root(&bytes);
    let (server, agent, group, viewer) =
        app_role_server(&pool, config(Some(&root), None, 5000)).await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "item-public").await;
    let foreign = seed(
        &pool,
        stranger,
        stranger_group,
        "public",
        PUMP_A,
        &[FAMILY],
        "2026-10-01T00:00:00Z",
    )
    .await;
    let mine = seed(
        &pool,
        agent,
        group,
        "public",
        ROOF,
        &[FAMILY],
        "2026-09-01T00:00:00Z",
    )
    .await;

    let out = first_text(
        &probe_label_dedup(
            &server,
            &viewer,
            ProbeLabelDedupParams {
                profile_path: Some("profile.json".into()),
                profile_json: None,
                profile_claim_id: None,
                profile_hash: profile_hash(&bytes),
                candidates: vec![
                    LabelDedupCandidateParam {
                        key: "foreign".into(),
                        content: PUMP_C.into(),
                        labels: s(&[FAMILY]),
                    },
                    LabelDedupCandidateParam {
                        key: "mine".into(),
                        content: "Library roof survey works | Acme Library Board | due: \
                                  2026-12-20 | ref ACME-888001"
                            .into(),
                        labels: s(&[FAMILY]),
                    },
                ],
                include_closed_signals: false,
                max_claims: None,
            },
            None,
        )
        .await
        .expect("probe"),
    );
    let verdict = |key: &str| {
        out["verdicts"]
            .as_array()
            .expect("verdicts")
            .iter()
            .find(|v| v["key"] == key)
            .cloned()
            .unwrap_or_else(|| panic!("no verdict for {key}: {out}"))
    };
    assert_eq!(
        verdict("foreign")["verdict"],
        "review",
        "a foreign member never answers match: {out}"
    );
    assert_eq!(
        verdict("foreign")["matched_id"],
        foreign.to_string(),
        "the human still sees which claim it resembles: {out}"
    );
    assert_eq!(verdict("mine")["verdict"], "match", "control: {out}");
    assert_eq!(verdict("mine")["matched_id"], mine.to_string(), "{out}");
}

/// The profile's own closed label is a retirement label: on stdio a free
/// label is ungated, but closing another author's claim with the profile's
/// closed label takes the same ownership gate as `resolved`. The server's
/// own past-due claim closes (control); a stranger's fails its unit.
#[sqlx::test(migrations = "../../migrations")]
async fn the_profiles_closed_label_takes_the_retirement_gate(pool: PgPool) {
    let mut v = profile_value();
    v["closed_label"] = json!("done");
    v["closeout"] = json!({"date_field": "deadline", "add": ["done", "{run_tag}"]});
    let bytes = serde_json::to_vec(&v).expect("profile");
    let root = profile_root(&bytes);
    let server = superuser_server(&pool, config(Some(&root), None, 5000)).await;
    let agent = server.server_agent_id().await.expect("agent");
    let group = personal_group_of(&pool, agent).await;
    let viewer = Viewer::resolve(&pool, agent).await.expect("viewer");
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "item-closer").await;
    // Both owned by the server agent's group, so only authorship differs.
    let mine = seed(
        &pool,
        agent,
        group,
        "public",
        FENCE,
        &[FAMILY],
        "2026-07-01T00:00:00Z",
    )
    .await;
    let theirs = seed(
        &pool,
        stranger,
        group,
        "public",
        GATE,
        &[FAMILY],
        "2026-07-02T00:00:00Z",
    )
    .await;

    let p = plan_params_path("profile.json", &profile_hash(&bytes), &["closeout"]);
    let plan = plan_ok(&server, &viewer, p.clone(), None).await;
    assert_eq!(plan["past_due"].as_array().map(Vec::len), Some(2), "{plan}");
    let out = apply_ok(&server, &viewer, apply_params(&p, &plan_hash(&plan)), None).await;
    assert_eq!(
        result_for(&out, &format!("closeout:{mine}"))["ok"],
        true,
        "{out}"
    );
    assert_eq!(
        result_for(&out, &format!("closeout:{theirs}"))["ok"],
        false,
        "{out}"
    );
    assert!(labels_of(&pool, mine).await.contains(&"done".to_string()));
    assert!(!labels_of(&pool, theirs).await.contains(&"done".to_string()));
}

// ── Cluster ownership ───────────────────────────────────────────────────────
//
// A cluster unit retires its losers toward its survivor, so every member of
// it, survivor included, must be the write identity's own (author, the
// author's operator, or an admin over HTTP), whatever the transport and
// whether or not the member itself is written. Row security alone does not
// decide this: the foreign claims below sit in groups the write identity can
// write, or are never written at all.

/// How the foreign claim joins the caller's cluster.
#[derive(Debug, Clone, Copy)]
enum Join {
    /// It shares the strong id.
    SharedId,
    /// A revision label naming the other claim, across a conflicting strong id.
    RevisionLabel,
}

fn profile_for(join: Join) -> Value {
    let mut v = profile_value();
    if matches!(join, Join::RevisionLabel) {
        v["revision_label_prefix"] = json!("revises:");
    }
    v
}

/// On an application-role server over stdio: the caller's survivor, a loser
/// AUTHORED BY A STRANGER but owned by the server agent's own group (so row
/// security admits the write and only an application check can refuse it),
/// and, as the control, a second cluster whose members are all the agent's
/// own. The foreign cluster is refused with nothing written and was predicted
/// by `unit_check`; the self-authored cluster applies.
async fn a_cross_author_cluster_is_refused_on_stdio(pool: PgPool, signer: Signer, join: Join) {
    let bytes = serde_json::to_vec(&profile_for(join)).expect("profile");
    let root = profile_root(&bytes);
    let (server, agent, group, viewer) =
        app_role_server_with_signer(&pool, config(Some(&root), None, 5000), signer).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "item-foreign-author").await;

    let survivor = seed(
        &pool,
        agent,
        group,
        "public",
        PUMP_A,
        &[FAMILY],
        "2026-10-01T00:00:00Z",
    )
    .await;
    let mut cluster_ids = vec![survivor];
    let foreign = match join {
        Join::SharedId => {
            cluster_ids.push(
                seed(
                    &pool,
                    agent,
                    group,
                    "public",
                    PUMP_B,
                    &[FAMILY],
                    "2026-09-01T00:00:00Z",
                )
                .await,
            );
            seed(
                &pool,
                stranger,
                group,
                "public",
                PUMP_C,
                &[FAMILY],
                "2026-08-01T00:00:00Z",
            )
            .await
        }
        Join::RevisionLabel => {
            let label = format!("revises:{survivor}");
            seed(
                &pool,
                stranger,
                group,
                "public",
                PUMP_REVISED,
                &[FAMILY, &label],
                "2026-08-01T00:00:00Z",
            )
            .await
        }
    };
    cluster_ids.push(foreign);
    let roof_old = seed(
        &pool,
        agent,
        group,
        "public",
        ROOF,
        &[FAMILY],
        "2026-09-02T00:00:00Z",
    )
    .await;
    let roof_new = seed(
        &pool,
        agent,
        group,
        "public",
        ROOF_B,
        &[FAMILY],
        "2026-09-03T00:00:00Z",
    )
    .await;
    let before = snapshot(&pool, &cluster_ids).await;

    let p = plan_params_path("profile.json", &profile_hash(&bytes), DEDUP);
    let plan = plan_ok(&server, &viewer, p.clone(), None).await;
    // Precondition: the foreign claim is a loser of the caller's cluster.
    let cluster = plan["clusters"]
        .as_array()
        .expect("clusters")
        .iter()
        .find(|c| c["survivor"] == survivor.to_string())
        .unwrap_or_else(|| panic!("no cluster for the survivor: {plan}"));
    let member = cluster["members"]
        .as_array()
        .expect("members")
        .iter()
        .find(|m| m["id"] == foreign.to_string())
        .unwrap_or_else(|| panic!("the foreign claim is not in the cluster: {plan}"));
    if matches!(join, Join::RevisionLabel) {
        assert_eq!(member["tier"], "revision_label", "{plan}");
    }

    let out = apply_ok(&server, &viewer, apply_params(&p, &plan_hash(&plan)), None).await;
    let unit = format!("cluster:{survivor}");
    let refused = result_for(&out, &unit);
    assert_eq!(
        refused["ok"], false,
        "a cluster joining another author's claim must not apply ({signer:?}, {join:?}): {out}"
    );
    assert_eq!(
        snapshot(&pool, &cluster_ids).await,
        before,
        "nothing of the unit lands, the foreign claim least of all"
    );
    assert!(
        refused["error"]
            .as_str()
            .is_some_and(|e| e.contains("CROSS_OWNER_MEMBER")),
        "{out}"
    );
    let check = unit_check(&plan, &unit);
    assert_eq!(check["applies"], false, "predicted: {plan}");
    assert!(names_foreign_member(check, foreign), "{plan}");

    // Control: the self-authored cluster in the same apply commits.
    let control = format!("cluster:{roof_new}");
    assert_eq!(result_for(&out, &control)["ok"], true, "{out}");
    assert!(
        labels_of(&pool, roof_old)
            .await
            .contains(&format!("duplicate-of:{roof_new}")),
        "the control cluster applied"
    );
    assert_eq!(unit_check(&plan, &control)["applies"], true, "{plan}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_cross_author_cluster_joined_by_a_shared_id_is_refused_under_a_declared_signer(
    pool: PgPool,
) {
    a_cross_author_cluster_is_refused_on_stdio(pool, Signer::Declared, Join::SharedId).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_cross_author_cluster_joined_by_a_revision_label_is_refused_under_a_declared_signer(
    pool: PgPool,
) {
    a_cross_author_cluster_is_refused_on_stdio(pool, Signer::Declared, Join::RevisionLabel).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_cross_author_cluster_joined_by_a_shared_id_is_refused_under_a_generated_signer(
    pool: PgPool,
) {
    a_cross_author_cluster_is_refused_on_stdio(pool, Signer::Generated, Join::SharedId).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_cross_author_cluster_joined_by_a_revision_label_is_refused_under_a_generated_signer(
    pool: PgPool,
) {
    a_cross_author_cluster_is_refused_on_stdio(pool, Signer::Generated, Join::RevisionLabel).await;
}

/// Over HTTP: a stranger files a NEWER public claim that joins the caller's
/// family, so it ranks survivor. With `merge.survivor_add` empty and nothing
/// to carry, the survivor has no write of its own: every write of the unit
/// targets the caller's claims, which the caller owns, so no per-write gate
/// sees the stranger. The unit must still refuse, because its survivor is
/// not the caller's, and leave the caller's labels byte-identical.
async fn a_foreign_survivor_never_absorbs_the_callers_claims(pool: PgPool, join: Join) {
    let mut v = profile_for(join);
    v["merge"]["survivor_add"] = json!([]);
    if matches!(join, Join::RevisionLabel) {
        // The stranger's claim carries none of the caller's ids, so nothing
        // may be carried onto it either.
        v["merge"]["carry_ids"] = json!(false);
        v["merge"]["carry_later_dates"] = json!([]);
    }
    let bytes = serde_json::to_vec(&v).expect("profile");
    let server = superuser_server(&pool, config(None, None, 5000)).await;
    let (caller, auth, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let caller_group = personal_group_of(&pool, caller).await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "item-newer").await;

    let a = seed(
        &pool,
        caller,
        caller_group,
        "public",
        PUMP_A,
        &[FAMILY],
        "2026-09-01T00:00:00Z",
    )
    .await;
    let mut mine = vec![a];
    let theirs = match join {
        // Every id and the latest date already on the stranger's claim.
        Join::SharedId => {
            mine.push(
                seed(
                    &pool,
                    caller,
                    caller_group,
                    "public",
                    PUMP_C,
                    &[FAMILY],
                    "2026-08-01T00:00:00Z",
                )
                .await,
            );
            seed(
                &pool,
                stranger,
                stranger_group,
                "public",
                PUMP_B,
                &[FAMILY],
                "2026-10-01T00:00:00Z",
            )
            .await
        }
        // A one-sided revision label on the stranger's own claim, across a
        // conflicting strong id.
        Join::RevisionLabel => {
            let label = format!("revises:{a}");
            seed(
                &pool,
                stranger,
                stranger_group,
                "public",
                PUMP_REVISED,
                &[FAMILY, &label],
                "2026-10-01T00:00:00Z",
            )
            .await
        }
    };
    let before = snapshot(&pool, &mine).await;

    let p = plan_params_json(&bytes, DEDUP);
    let plan = plan_ok(&server, &viewer, p.clone(), Some(&auth)).await;
    // Preconditions: the stranger's claim is the survivor, and the unit writes
    // only the caller's claims.
    assert_eq!(
        plan["clusters"][0]["survivor"],
        theirs.to_string(),
        "{plan}"
    );
    let unit = format!("cluster:{theirs}");
    let writes = unit_writes(&plan)
        .into_iter()
        .find(|u| u["unit"] == unit)
        .unwrap_or_else(|| panic!("no write unit {unit}: {plan}"));
    let targets: Vec<String> = writes["writes"]
        .as_array()
        .expect("writes")
        .iter()
        .map(|w| w["claim_id"].as_str().expect("claim_id").to_string())
        .collect();
    assert!(!targets.contains(&theirs.to_string()), "{plan}");
    assert!(targets.contains(&a.to_string()), "{plan}");

    let out = apply_ok(
        &server,
        &viewer,
        apply_params(&p, &plan_hash(&plan)),
        Some(&auth),
    )
    .await;
    let refused = result_for(&out, &unit);
    assert_eq!(
        refused["ok"], false,
        "the caller's claims are never retired toward a stranger's ({join:?}): {out}"
    );
    assert_eq!(
        snapshot(&pool, &mine).await,
        before,
        "the caller's labels are byte-identical"
    );
    assert!(
        refused["error"]
            .as_str()
            .is_some_and(|e| e.contains("CROSS_OWNER_MEMBER")),
        "{out}"
    );
    let check = unit_check(&plan, &unit);
    assert_eq!(check["applies"], false, "predicted: {plan}");
    assert!(names_foreign_member(check, theirs), "{plan}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_foreign_survivor_with_no_write_of_its_own_is_refused_over_http(pool: PgPool) {
    a_foreign_survivor_never_absorbs_the_callers_claims(pool, Join::SharedId).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_one_sided_revision_label_cannot_make_a_stranger_the_survivor(pool: PgPool) {
    a_foreign_survivor_never_absorbs_the_callers_claims(pool, Join::RevisionLabel).await;
}
