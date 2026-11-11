//! `submit_bug_report` and `list_my_bug_reports` (migration 207's intake) end
//! to end through the tool functions, on a server whose pools are downgraded
//! to `epigraph_app`, on a database armed for operator binding.
//!
//! Pinned at the tool layer (the definer's own guarantees are pinned in
//! `epigraph-db/tests/bug_report_intake.rs`):
//! * the answer is exactly `{claim_id, submitted_at}`, the same shape for a
//!   report that repeats an earlier one;
//! * the reporter cannot read the report back through `get_claim`,
//!   `query_claims`, `query_claims_by_label` or `recall` (each answers as for
//!   a claim that does not exist), and `submit_claim` of the same text never
//!   hands back the report's id; a member of the intake group reads it
//!   through the same tools (calibration, on a superuser server where only
//!   the tools' own viewer predicate filters);
//! * `list_my_bug_reports` lists only the caller's reports, and nothing on a
//!   principal-less listener;
//! * an unconfigured intake is refused by name, as the caller's error;
//! * oversized input is refused before anything is written;
//! * a call the intake refuses for who the caller is or for its limit
//!   (unconfigured, system agent, unbound, a role's agent its holder does not
//!   cover, over the limit) makes no embedding-provider call; an admitted one
//!   makes exactly one.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_crypto::AgentSigner;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools;
use epigraph_mcp::types::{ListMyBugReportsParams, SubmitBugReportParams};
use rmcp::model::ErrorCode;
use sqlx::PgPool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    build_scoped_test_server(plain, scoped)
}

/// A server on the harness's superuser pools: row security does not apply,
/// so only each tool's own viewer predicate decides what a caller reads.
async fn superuser_server(pool: &PgPool) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(pool).await;
    build_scoped_test_server(pool.clone(), scoped)
}

fn token(agent: Uuid, scopes: &[&str]) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
}

async fn team_group(pool: &PgPool, admin: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, 'intake', 'did:test:team:' || $1::text, $2, 'team', $3)",
    )
    .bind(id)
    .bind(&key)
    .bind(admin)
    .execute(pool)
    .await
    .expect("team group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(id)
    .bind(admin)
    .execute(pool)
    .await
    .expect("admin membership");
    id
}

async fn linked_agent(pool: &PgPool, human: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("live link");
    agent
}

struct World {
    ops: Uuid,
    intake: Uuid,
    reporter: Uuid,
    other: Uuid,
}

/// An intake group run by `ops`, two reporters linked to two other humans,
/// optionally configured, then armed.
async fn world(pool: &PgPool, configured: bool) -> World {
    let (ops, _) = fixture::seed_human_operator(pool, "brim-ops").await;
    let intake = team_group(pool, ops).await;
    let (h1, _) = fixture::seed_human_operator(pool, "brim-h1").await;
    let (h2, _) = fixture::seed_human_operator(pool, "brim-h2").await;
    let reporter = linked_agent(pool, h1, "brim-reporter").await;
    let other = linked_agent(pool, h2, "brim-other").await;
    if configured {
        sqlx::query("INSERT INTO bug_report_intake_settings (intake_group_id) VALUES ($1)")
            .bind(intake)
            .execute(pool)
            .await
            .expect("configure");
    }
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(pool)
        .await
        .expect("arm");
    World {
        ops,
        intake,
        reporter,
        other,
    }
}

fn params(title: &str) -> SubmitBugReportParams {
    serde_json::from_value(serde_json::json!({
        "title": title,
        "description": "the recall tool returns a stale vector for zebra-quartz queries",
        "severity": "minor",
        "component": "recall",
    }))
    .expect("params")
}

async fn submit(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    agent: Uuid,
    p: SubmitBugReportParams,
) -> Result<serde_json::Value, epigraph_mcp::errors::McpError> {
    tools::bug_report::submit_bug_report(
        server,
        &viewer(pool, agent).await,
        p,
        Some(&token(agent, &["claims:write"])),
    )
    .await
    .map(|r| first_text(&r))
}

async fn list(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    agent: Uuid,
) -> Result<serde_json::Value, epigraph_mcp::errors::McpError> {
    tools::bug_report::list_my_bug_reports(
        server,
        &viewer(pool, agent).await,
        ListMyBugReportsParams { limit: None },
        Some(&token(agent, &["claims:read"])),
    )
    .await
    .map(|r| first_text(&r))
}

fn keys(v: &serde_json::Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().expect("object").keys().cloned().collect();
    k.sort();
    k
}

/// `get_claim`'s answer as one comparable string, with `id` replaced, so a
/// hidden claim and a random id can be compared.
async fn get_claim_text(server: &EpiGraphMcpFull, v: &Viewer, id: Uuid) -> String {
    let p = serde_json::from_value(serde_json::json!({"claim_id": id.to_string()})).unwrap();
    match tools::claims::get_claim(server, v, p).await {
        Ok(r) => format!("OK {}", first_text(&r)),
        Err(e) => format!(
            "ERR {:?} {}",
            e.code,
            e.message.replace(&id.to_string(), "<id>")
        ),
    }
}

/// Every read tool's answer, as text, for `v`.
async fn reads(server: &EpiGraphMcpFull, v: &Viewer) -> Vec<(&'static str, String)> {
    let by_label = tools::paper_queries::query_claims_by_label(
        server,
        v,
        serde_json::from_value(serde_json::json!({"labels": ["bug-report"], "limit": 100}))
            .unwrap(),
    )
    .await
    .map(|r| first_text(&r).to_string())
    .unwrap_or_else(|e| format!("ERR {}", e.message));
    let query = tools::claims::query_claims(
        server,
        v,
        serde_json::from_value(serde_json::json!({"min_truth": 0.0, "limit": 100})).unwrap(),
    )
    .await
    .map(|r| first_text(&r).to_string())
    .unwrap_or_else(|e| format!("ERR {}", e.message));
    let recall = tools::memory::recall(
        server,
        v,
        serde_json::from_value(
            serde_json::json!({"query": "zebra-quartz stale vector", "min_truth": 0.0}),
        )
        .unwrap(),
    )
    .await
    .map(|r| first_text(&r).to_string())
    .unwrap_or_else(|e| format!("ERR {}", e.message));
    vec![
        ("query_claims_by_label", by_label),
        ("query_claims", query),
        ("recall", recall),
    ]
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_answer_is_a_receipt_and_the_reporter_reads_nothing_back(pool: PgPool) {
    let w = world(&pool, true).await;
    let server = app_role_server(&pool).await;

    let first = submit(&pool, &server, w.reporter, params("stale recall vector"))
        .await
        .expect("filed");
    let again = submit(&pool, &server, w.reporter, params("stale recall vector"))
        .await
        .expect("filed again");
    assert_eq!(keys(&first), vec!["claim_id", "submitted_at"]);
    assert_eq!(keys(&again), keys(&first), "the same shape for a repeat");
    let id: Uuid = first["claim_id"].as_str().unwrap().parse().unwrap();
    assert_ne!(
        first["claim_id"], again["claim_id"],
        "a repeat is a new row"
    );

    let super_server = superuser_server(&pool).await;
    let reporter = viewer(&pool, w.reporter).await;
    let ops = viewer(&pool, w.ops).await;
    let random = Uuid::new_v4();

    // CALIBRATION: a member of the intake group reads it through every tool.
    assert!(
        get_claim_text(&super_server, &ops, id)
            .await
            .starts_with("OK"),
        "a member reads the report"
    );
    for (tool, text) in reads(&super_server, &ops).await {
        assert!(
            text.contains(&id.to_string()),
            "{tool}: a member finds the report: {text}"
        );
    }

    // The reporter: on the application-role server and on the superuser one.
    for (which, s) in [("app role", &server), ("superuser", &super_server)] {
        assert_eq!(
            get_claim_text(s, &reporter, id).await,
            get_claim_text(s, &reporter, random).await,
            "{which}: get_claim answers as for an id that does not exist"
        );
        for (tool, text) in reads(s, &reporter).await {
            assert!(
                !text.contains(&id.to_string()),
                "{which}: {tool} must not return the report: {text}"
            );
        }
    }

    // submit_claim of the report's exact content never answers with its id.
    let content = format!(
        "stale recall vector\n\n{}",
        "the recall tool returns a stale vector for zebra-quartz queries"
    );
    let r = tools::claims::submit_claim(
        &server,
        &reporter,
        serde_json::from_value(serde_json::json!({
            "content": content, "methodology": "direct_observation", "evidence_data": "x",
            "evidence_type": "empirical", "confidence": 0.5,
        }))
        .unwrap(),
        Some(&token(w.reporter, &["claims:write"])),
    )
    .await
    .expect("an ordinary claim with the same text");
    let text = first_text(&r).to_string();
    assert!(
        !text.contains(&id.to_string()) && !text.contains(again["claim_id"].as_str().unwrap()),
        "submit_claim must not hand back an intake report: {text}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_list_is_the_callers_own_reports(pool: PgPool) {
    let w = world(&pool, true).await;
    let server = app_role_server(&pool).await;
    let mine = submit(&pool, &server, w.reporter, params("mine"))
        .await
        .expect("mine");
    let theirs = submit(&pool, &server, w.other, params("theirs"))
        .await
        .expect("theirs");

    let listed = list(&pool, &server, w.reporter).await.expect("list");
    assert_eq!(listed["count"], 1, "{listed}");
    let row = &listed["reports"][0];
    assert_eq!(row["claim_id"], mine["claim_id"]);
    assert_eq!(row["title"], "mine");
    assert_eq!(row["resolved"], false);
    assert_eq!(
        row["labels"],
        serde_json::json!([
            "backlog",
            "bug-report",
            "intake",
            "severity:minor",
            "component:recall"
        ])
    );
    assert!(!listed
        .to_string()
        .contains(theirs["claim_id"].as_str().unwrap()));

    // A principal-less listener reads as its own agent; it lists nothing,
    // even when that agent has filed a report itself.
    let listener = server.server_agent_id().await.expect("server agent");
    let (h, _) = fixture::seed_human_operator(&pool, "brim-listener-human").await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, listener, h)
        .await
        .expect("the listener's agent is bound");
    drop(conn);
    submit(&pool, &server, listener, params("the listener's own"))
        .await
        .expect("the listener's agent files one");
    let anon = epigraph_mcp::auth::unauthenticated_context(
        Some(listener),
        epigraph_mcp::auth::UnauthenticatedWrites::Refused,
    );
    let e = tools::bug_report::list_my_bug_reports(
        &server,
        &viewer(&pool, listener).await,
        ListMyBugReportsParams { limit: None },
        Some(&anon),
    )
    .await
    .expect_err("a principal-less listener lists nothing");
    assert_eq!(e.code, ErrorCode::INVALID_REQUEST);
    assert!(e.message.contains("principal-less"), "{}", e.message);
    // CALIBRATION: the same agent with a real token does see its report.
    let own = list(&pool, &server, listener).await.expect("its own list");
    assert_eq!(own["count"], 1, "{own}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unconfigured_intake_is_refused_by_name(pool: PgPool) {
    let w = world(&pool, false).await;
    let server = app_role_server(&pool).await;
    let e = submit(&pool, &server, w.reporter, params("nowhere"))
        .await
        .expect_err("refused");
    assert_eq!(
        e.code,
        ErrorCode::INVALID_REQUEST,
        "the caller's error: {e:?}"
    );
    assert!(
        e.message.contains("bug intake is not configured"),
        "{}",
        e.message
    );
    let e = list(&pool, &server, w.reporter).await.expect_err("refused");
    assert_eq!(e.code, ErrorCode::INVALID_REQUEST);
    assert!(
        e.message.contains("bug intake is not configured"),
        "{}",
        e.message
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE agent_id = $1")
        .bind(w.reporter)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn oversized_input_is_refused_before_anything_is_written(pool: PgPool) {
    let w = world(&pool, true).await;
    let server = app_role_server(&pool).await;
    let mut p = params(&"t".repeat(201));
    let e = submit(&pool, &server, w.reporter, p)
        .await
        .expect_err("long title");
    assert_eq!(e.code, ErrorCode::INVALID_PARAMS);
    assert!(e.message.starts_with("BUG04:"), "{}", e.message);
    p = params("ok");
    p.evidence = Some("e".repeat(51_201));
    let e = submit(&pool, &server, w.reporter, p)
        .await
        .expect_err("long evidence");
    assert!(e.message.starts_with("BUG04:"), "{}", e.message);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE agent_id = $1")
        .bind(w.reporter)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

/// [`app_role_server`] whose embedder counts its calls and answers a fixed
/// vector: no request leaves the process.
async fn counting_server(pool: &PgPool) -> (EpiGraphMcpFull, Arc<AtomicUsize>) {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let embedder = McpEmbedder::new(plain.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(Arc::new(move |_text: &str| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(vec![0.01_f32; 1536])
        }));
    let server = EpiGraphMcpFull::new(
        plain,
        AgentSigner::from_bytes(&[0xA7u8; 32]).expect("signer"),
        embedder,
        false,
    )
    .with_scoped_pool(scoped);
    (server, calls)
}

/// The rate limit caps provider spend: a call the intake refuses for who the
/// caller is or for its limit makes no embedding call. The admitted call
/// (CALIBRATION) makes exactly one, and its vector is stored.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_report_costs_no_embedding_call(pool: PgPool) {
    let w = world(&pool, false).await;
    let (server, calls) = counting_server(&pool).await;
    let calls_now = || calls.load(Ordering::SeqCst);

    let e = submit(&pool, &server, w.reporter, params("unconfigured"))
        .await
        .expect_err("not configured");
    assert!(e.message.contains("BUG03:"), "{}", e.message);
    assert_eq!(calls_now(), 0, "BUG03 (unconfigured) embedded");

    sqlx::query(
        "INSERT INTO bug_report_intake_settings (intake_group_id, per_hour) VALUES ($1, 1)",
    )
    .bind(w.intake)
    .execute(&pool)
    .await
    .expect("configure, one per hour");

    let ok = submit(&pool, &server, w.reporter, params("admitted"))
        .await
        .expect("CALIBRATION: an admitted report");
    assert_eq!(calls_now(), 1, "an admitted report embeds once");
    let id: Uuid = ok["claim_id"].as_str().unwrap().parse().unwrap();
    let stored: bool = sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("the report");
    assert!(stored, "the counted vector reached the definer");

    let e = submit(&pool, &server, w.reporter, params("over the limit"))
        .await
        .expect_err("over the limit");
    assert!(e.message.contains("BUG08:"), "{}", e.message);
    assert_eq!(calls_now(), 1, "BUG08 (over the limit) embedded");

    let (h, _) = fixture::seed_human_operator(&pool, "brim-system-human").await;
    let system = linked_agent(&pool, h, "brim-system").await;
    assert!(fixture::register_system_agent(&pool, system).await);
    let e = submit(&pool, &server, system, params("from a system agent"))
        .await
        .expect_err("a system agent");
    assert!(e.message.contains("BUG06:"), "{}", e.message);
    assert_eq!(calls_now(), 1, "BUG06 (system agent) embedded");

    let (unbound, _) = fixture::seed_agent_with_group(&pool, "brim-unbound").await;
    let e = submit(&pool, &server, unbound, params("from nobody's agent"))
        .await
        .expect_err("an unbound agent");
    assert!(e.message.contains("BUG07:"), "{}", e.message);
    assert_eq!(calls_now(), 1, "BUG07 (unbound) embedded");

    // A role's agent (166) whose role has no holder: the write refuses it
    // ROL01, so the preflight does too, before the embed.
    seed_role(&pool, "role:brim-curator").await;
    attach(&pool, "role:brim-curator", w.other).await;
    let e = submit(&pool, &server, w.other, params("from a role's agent"))
        .await
        .expect_err("a role's agent with no holder");
    assert!(e.message.contains("ROL01"), "{}", e.message);
    assert_eq!(calls_now(), 1, "ROL01 (role agent, no holder) embedded");
}

/// A synthetic catalog role, with the role node 123 requires for every role.
async fn seed_role(pool: &PgPool, key: &str) {
    let node = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type, role, labels) \
         VALUES ($1, uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()), $2, 'role', \
                 'custom', ARRAY['role'])",
    )
    .bind(node)
    .bind(key)
    .execute(pool)
    .await
    .expect("role node");
    sqlx::query(
        "INSERT INTO platform_roles (key, elevates, reads_audit, role_node_id, description) \
         VALUES ($1, false, false, $2, 'test role')",
    )
    .bind(key)
    .bind(node)
    .execute(pool)
    .await
    .expect("platform role");
}

/// Attach `agent` to `role` through the maintenance definer.
async fn attach(pool: &PgPool, role: &str, agent: Uuid) {
    let role = role.to_string();
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let _: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_attach_agent_to_role($1, $2, now() - interval '5 seconds', \
                                                         NULL, 'test attach')",
        )
        .bind(&role)
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("the maintenance role attaches");
        (conn, ())
    })
    .await;
}
