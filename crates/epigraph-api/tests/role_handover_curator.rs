//! A role handover with a role-attached curator agent (backlog 6a1825ef).
//!
//! The question: when a role changes hands, does the curator agent that works
//! FOR the role keep publishing its workflow lineage, and does authority over
//! the role's claims move from the old holder to the new one?
//!
//! The world, on a fresh database, armed (migration 122):
//!
//! * a role `R` bound to a keyless team group `G` at `writer`, in migration
//!   179's `attached_agents` mode (165's `group_role_bindings`). `G` is
//!   administered by a third human, so no explicit roster row of either
//!   holder can stand in for the role;
//! * holder `H1`, a registered human with a live assignment of `R`
//!   (`role_assignments`);
//! * the curator `C`: a stdio agent live-linked to `H1` (107) and attached to
//!   `R` (166's `role_agents`);
//! * `H2`, a second registered human, not yet holding `R`.
//!
//! The steps, in order:
//!
//! 1. `C` publishes generation 0 of a workflow private to `G`, and generation
//!    0 of a workflow public in `G`; `C` is the recorded submitter of both.
//! 2. Hand over: end `H1`'s assignment, then grant `R` to `H2`.
//! 3. `C` publishes generation 1 of the private workflow: accepted, with the
//!    same recorded submitter.
//! 4. `H1` can no longer act on the role's claims: its add-step to each of
//!    `C`'s two workflows is refused.
//! 5. `H2` can: its add-step to the private workflow lands.
//!
//! MEASURED (this file's first run): step 3 FAILS. An attached agent is a
//! member of `G` only while its OWN human holds the role (179), and it may
//! write nothing while it is attached and its human does not hold the role
//! (166's `ROL01`). The curator's human is `H1` for good: an agent is linked to
//! ONE operator, ever (161's `epigraph_link_operator` refuses a second), and
//! no verb moves a curator to the new holder. So a handover cuts the curator
//! off: the ingest refuses its declaration of `G`, and a new workflow
//! declaring no group is refused `ROL01`. Step 4 holds for the private workflow only: on the
//! PUBLIC one `H1` keeps acting through the lineage gate's upward arm (it is
//! still the submitter's operator; the step lands in `H1`'s own group). Step
//! 5 holds.
//!
//! [`a_role_handover_keeps_the_curator_publishing_and_moves_authority`] is the
//! whole target and is `#[ignore]`d with the failing steps named.
//! [`a_role_handover_today`] runs every step and pins what each one does now,
//! so the ignored test cannot silently rot: when a transfer verb lands, the
//! pin goes red and the ignored test should be un-ignored.
#![cfg(feature = "db")]

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{RunTokens, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const ROLE: &str = "role:test-handover-curator";
const PRIVATE_WF: &str = "handover-curator-private";
const PUBLIC_WF: &str = "handover-curator-public";
const WRITE_SCOPES: &[&str] = &["claims:read", "claims:write", "edges:write"];

// ─────────────────────────────────────────────────────────────────────────────
// Production-shaped servers
// ─────────────────────────────────────────────────────────────────────────────

async fn app_scoped(pool: &PgPool) -> ScopedPool {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every step is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

/// An app-role MCP server whose own (stdio) agent is keyed by `seed`.
async fn mcp_server(pool: &PgPool, seed: u8) -> epigraph_mcp::server::EpiGraphMcpFull {
    let scoped = app_scoped(pool).await;
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder = epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|_text: &str| Ok(vec![0.5_f32; 1536])));
    epigraph_mcp::server::EpiGraphMcpFull::new(plain, signer, embedder, false)
        .with_scoped_pool(scoped)
        .with_run_tokens(RunTokens::On)
}

/// The stdio server's own agent, created by its first viewer resolution.
async fn stdio_agent(
    pool: &PgPool,
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    seed: u8,
) -> Uuid {
    epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("the stdio viewer");
    let key = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32])
        .expect("signer")
        .public_key();
    sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_one(pool)
        .await
        .expect("the stdio server's agent row")
}

fn rest_token(state: &AppState, agent: Uuid) -> String {
    state
        .jwt_config
        .issue_access_token(
            Uuid::new_v4(),
            WRITE_SCOPES.iter().map(|s| (*s).to_string()).collect(),
            "agent",
            None,
            Some(agent),
            chrono::Duration::minutes(15),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("mint")
        .0
}

fn tool_json(out: &rmcp::model::CallToolResult) -> Result<Value, String> {
    if out.is_error == Some(true) {
        return Err(format!("the tool reported an error: {out:?}"));
    }
    let text = out
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .ok_or_else(|| "no text result".to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("not JSON: {e}: {text}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Payloads and reads
// ─────────────────────────────────────────────────────────────────────────────

fn extraction(name: &str, generation: u32) -> Value {
    let steps: Vec<Value> = (0..2)
        .map(|i| {
            json!({"compound": format!("{name} gen {generation} step {i}"),
                   "rationale": "ordered",
                   "operations": [format!("{name} gen {generation} operation {i}")],
                   "generality": [], "confidence": 0.8})
        })
        .collect();
    json!({
        "source": {"canonical_name": name,
                   "goal": format!("workflow goal for {name}"),
                   "generation": generation, "metadata": {}},
        "thesis_derivation": "TopDown",
        "phases": [{"title": "Body", "summary": format!("{name} phase"), "steps": steps}],
        "relationships": []
    })
}

/// `(visibility, owner group, recorded submitter)` of generation `generation`
/// of `name`, if it exists.
async fn workflow_gen(
    pool: &PgPool,
    name: &str,
    generation: i32,
) -> Option<(String, Uuid, Option<String>)> {
    sqlx::query_as(
        "SELECT visibility::text, owner_group_id, metadata->>'epigraph_submitted_by' \
           FROM workflows WHERE canonical_name = $1 AND generation = $2",
    )
    .bind(name)
    .bind(generation)
    .fetch_optional(pool)
    .await
    .expect("workflow row")
}

/// One claim's `(author, owner group)`.
async fn claim_owner(pool: &PgPool, id: Uuid) -> (Uuid, Uuid) {
    sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("claim row")
}

async fn writes(pool: &PgPool, agent: Uuid, group: Uuid) -> bool {
    epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve")
        .writable_groups()
        .contains(&group)
}

// ─────────────────────────────────────────────────────────────────────────────
// Maintenance verbs, as the operator CLI calls them
// ─────────────────────────────────────────────────────────────────────────────

async fn maintenance<T>(
    pool: &PgPool,
    what: &'static str,
    sql: &'static str,
    binds: Vec<String>,
) -> T
where
    T: for<'r> sqlx::Decode<'r, sqlx::Postgres>
        + sqlx::Type<sqlx::Postgres>
        + Send
        + Unpin
        + 'static,
{
    fixture::as_role(pool, "epigraph_maintenance", move |mut conn| async move {
        let mut q = sqlx::query_scalar::<_, T>(sql);
        for b in binds {
            q = q.bind(b);
        }
        let out = q
            .fetch_one(&mut *conn)
            .await
            .unwrap_or_else(|e| panic!("{what}: {e}"));
        (conn, out)
    })
    .await
}

/// Define `ROLE` and bind it to `group` at `writer`, attached agents only
/// (179's mode-taking overload of 165's verb).
async fn bind_attached(pool: &PgPool, group: Uuid) -> Uuid {
    maintenance(
        pool,
        "define the role, bound in attached_agents mode",
        "SELECT public.epigraph_define_group_role($1, $2, $3::uuid, $4, $5::text, $6)",
        vec![
            ROLE.into(),
            "synthetic curated role".into(),
            group.to_string(),
            "writer".into(),
            "attached_agents".into(),
            "role handover test".into(),
        ],
    )
    .await
}

/// Grant `ROLE` to `holder`, live from a few seconds ago (123's verb).
async fn grant(pool: &PgPool, holder: Uuid) -> Uuid {
    maintenance(
        pool,
        "grant the role",
        "SELECT public.epigraph_grant_role($1, $2::uuid, now() - interval '5 seconds', NULL, \
                NULL, 'role handover test')",
        vec![ROLE.into(), holder.to_string()],
    )
    .await
}

async fn end_assignment(pool: &PgPool, assignment: Uuid) {
    let ended: bool = maintenance(
        pool,
        "end the assignment",
        "SELECT public.epigraph_end_role_assignment($1::uuid, 'role handover test')",
        vec![assignment.to_string()],
    )
    .await;
    assert!(ended, "PREMISE: the assignment was live");
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    fixture::as_role(pool, "epigraph_maintenance", move |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_link_operator($1, $2)")
            .bind(agent)
            .bind(operator)
            .execute(&mut *conn)
            .await
            .unwrap_or_else(|e| panic!("link {agent} to {operator}: {e}"));
        (conn, ())
    })
    .await;
}

/// 166's attach verb, live from a few seconds ago, open-ended.
async fn attach(pool: &PgPool, agent: Uuid) -> Uuid {
    maintenance(
        pool,
        "attach the curator to the role",
        "SELECT public.epigraph_attach_agent_to_role($1, $2::uuid, now() - interval '5 seconds', \
                NULL, 'role handover test')",
        vec![ROLE.into(), agent.to_string()],
    )
    .await
}

async fn arm(pool: &PgPool) {
    let armed: bool = maintenance(
        pool,
        "arm the operator binding",
        "SELECT armed_now FROM public.epigraph_arm_operator_binding()",
        Vec::new(),
    )
    .await;
    assert!(armed, "the database arms");
}

// ─────────────────────────────────────────────────────────────────────────────
// The acts
// ─────────────────────────────────────────────────────────────────────────────

/// The curator publishes generation `generation` of `name` over MCP stdio.
async fn publish(
    curator: &epigraph_mcp::server::EpiGraphMcpFull,
    name: &str,
    generation: u32,
    tenancy: Value,
) -> Result<Value, String> {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(curator, None)
        .await
        .map_err(|e| format!("the curator's stdio viewer: {}", e.message))?;
    let params = serde_json::from_value(json!({
        "extraction": extraction(name, generation),
        "tenancy": tenancy,
    }))
    .expect("ingest params");
    let out = epigraph_mcp::tools::workflow_ingest::ingest_workflow(curator, &viewer, params, None)
        .await
        .map_err(|e| e.message.to_string())?;
    tool_json(&out)
}

/// `POST /api/v1/workflows/steps` as `agent`: the new step's claim id.
async fn add_step(
    router: &axum::Router,
    token: &str,
    name: &str,
    text: &str,
) -> Result<Uuid, String> {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/workflows/steps")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"canonical_name": name, "step_text": text}).to_string(),
        ))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("router");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    if status != StatusCode::OK {
        return Err(format!("{status}: {body}"));
    }
    body["step_claim_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| format!("no step_claim_id: {body}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// The handover, step by step
// ─────────────────────────────────────────────────────────────────────────────

/// What each step did, in order: `Ok` when it did what the target says, `Err`
/// with the observation when it did not.
type Outcomes = Vec<(&'static str, Result<(), String>)>;

/// The outcomes, and the curator's server for a probe after them.
struct Handover {
    outcomes: Outcomes,
    curator: epigraph_mcp::server::EpiGraphMcpFull,
    curator_id: Uuid,
}

async fn run_handover(pool: &PgPool) -> Handover {
    let mut out: Outcomes = Vec::new();

    // The world.
    let (h1, _) = fixture::seed_human_operator(pool, "handover-h1").await;
    let (h2, _) = fixture::seed_human_operator(pool, "handover-h2").await;
    let (admin, _) = fixture::seed_human_operator(pool, "handover-group-admin").await;
    let g = fixture::verb_team_group(pool, "Synthetic Curated Team", admin).await;
    bind_attached(pool, g).await;
    let curator_server = mcp_server(pool, 0xC1).await;
    let c = stdio_agent(pool, &curator_server, 0xC1).await;
    link(pool, c, h1).await;
    attach(pool, c).await;
    let a1 = grant(pool, h1).await;
    arm(pool).await;
    let state = AppState::with_scoped_pool(app_scoped(pool).await, ApiConfig::default())
        .with_run_tokens(RunTokens::On);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    let router = epigraph_api::routes::create_router(state.clone());

    // Premises.
    assert!(writes(pool, h1, g).await, "PREMISE: H1 writes G through R");
    assert!(
        writes(pool, c, g).await,
        "PREMISE: the curator writes G through R"
    );
    assert!(
        !writes(pool, h2, g).await,
        "PREMISE: H2 does not write G yet"
    );

    // Step 1: generation 0 of both workflows, the curator's.
    let private = json!({"visibility": "group", "owner_group_id": g});
    let public = json!({"visibility": "public", "owner_group_id": g});
    let mut step1 = Ok(());
    for (name, tenancy, visibility) in [
        (PRIVATE_WF, private.clone(), "group"),
        (PUBLIC_WF, public, "public"),
    ] {
        let r = publish(&curator_server, name, 0, tenancy).await;
        let row = workflow_gen(pool, name, 0).await;
        if let Err(e) = r {
            step1 = Err(format!("{name} gen 0 refused: {e}"));
            break;
        }
        if row != Some((visibility.to_string(), g, Some(c.to_string()))) {
            step1 = Err(format!("{name} gen 0 row: {row:?}"));
            break;
        }
    }
    let step1_ok = step1.is_ok();
    out.push(("1: the curator publishes generation 0", step1));
    if !step1_ok {
        return Handover {
            outcomes: out,
            curator: curator_server,
            curator_id: c,
        };
    }

    // Step 2: the handover.
    end_assignment(pool, a1).await;
    grant(pool, h2).await;
    let step2 = if writes(pool, h2, g).await && !writes(pool, h1, g).await {
        Ok(())
    } else {
        Err("G's writers did not follow the role".to_string())
    };
    out.push(("2: the role passes from H1 to H2", step2));

    // Step 3: generation 1, accepted, the same recorded submitter.
    let step3 = match publish(&curator_server, PRIVATE_WF, 1, private).await {
        Err(e) => Err(format!("refused: {e}")),
        Ok(_) => match workflow_gen(pool, PRIVATE_WF, 1).await {
            Some((_, _, Some(s))) if s == c.to_string() => Ok(()),
            row => Err(format!("gen 1 row: {row:?}")),
        },
    };
    out.push((
        "3: the curator publishes generation 1 after the handover",
        step3,
    ));

    // Step 4: H1 acts on neither of the curator's workflows.
    let h1_token = rest_token(&state, h1);
    for (label, name) in [
        ("4a: H1 is refused on the private workflow", PRIVATE_WF),
        ("4b: H1 is refused on the public workflow", PUBLIC_WF),
    ] {
        let r = add_step(&router, &h1_token, name, &format!("H1 step on {name}")).await;
        let step = match r {
            Err(_) => Ok(()),
            Ok(id) => {
                let (author, owner) = claim_owner(pool, id).await;
                Err(format!(
                    "admitted: step {id} by {author} owned by {owner} (G = {g}, H1 = {h1})"
                ))
            }
        };
        out.push((label, step));
    }

    // Step 5: H2 acts on the private workflow.
    let h2_token = rest_token(&state, h2);
    let step5 = add_step(&router, &h2_token, PRIVATE_WF, "H2 step")
        .await
        .map(|_| ());
    out.push(("5: H2 adds a step to the private workflow", step5));

    Handover {
        outcomes: out,
        curator: curator_server,
        curator_id: c,
    }
}

/// `epigraph_role_agent_may_run(agent)` on an application session stamped as
/// `agent` (since 248 it answers a session about its own principal only):
/// `(may_run, reason)`.
async fn may_run(pool: &PgPool, agent: Uuid) -> (bool, String) {
    fixture::as_role(pool, "epigraph_app", move |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(agent.to_string())
            .execute(&mut *conn)
            .await
            .expect("stamp the principal");
        let r: (bool, String) =
            sqlx::query_as("SELECT may_run, reason FROM public.epigraph_role_agent_may_run($1)")
                .bind(agent)
                .fetch_one(&mut *conn)
                .await
                .expect("may_run");
        sqlx::query("SELECT set_config('epigraph.principal_id', '', false)")
            .execute(&mut *conn)
            .await
            .expect("unstamp");
        (conn, r)
    })
    .await
}

/// THE TARGET: every step does what the handover needs.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "fails at step 3 (the curator publishes generation 1 after the handover: refused, \
            its linked human is the previous holder and no verb moves it) and at step 4b (the \
            previous holder adds a step to the curator's PUBLIC workflow through the upward \
            operator arm); see a_role_handover_today"]
async fn a_role_handover_keeps_the_curator_publishing_and_moves_authority(pool: PgPool) {
    let outcomes = run_handover(&pool).await.outcomes;
    let failed: Vec<_> = outcomes.iter().filter(|(_, r)| r.is_err()).collect();
    assert!(failed.is_empty(), "failed steps: {failed:#?}");
    assert_eq!(outcomes.len(), 6, "every step ran: {outcomes:#?}");
}

/// THE PIN: what each step does today. Steps 1, 2, 4a and 5 hold. Step 3 is
/// refused: after the handover the curator no longer derives `G` (179: an
/// attached agent is a member only while its OWN human holds the role), so
/// the ingest refuses its declaration of `G` before anything is written; and
/// the database refuses the curator any write at all (166's `ROL01`), which
/// the probe after the steps shows on a new workflow that declares no group. Step 4b is admitted: the previous holder is still the curator's
/// operator, and the lineage gate's upward arm admits it on a workflow it can
/// read (the step lands in its own group, not in `G`).
#[sqlx::test(migrations = "../../migrations")]
async fn a_role_handover_today(pool: PgPool) {
    let Handover {
        outcomes,
        curator,
        curator_id,
    } = run_handover(&pool).await;
    let shape: Vec<(&str, bool)> = outcomes.iter().map(|(s, r)| (*s, r.is_ok())).collect();
    assert_eq!(
        shape,
        vec![
            ("1: the curator publishes generation 0", true),
            ("2: the role passes from H1 to H2", true),
            (
                "3: the curator publishes generation 1 after the handover",
                false
            ),
            ("4a: H1 is refused on the private workflow", true),
            ("4b: H1 is refused on the public workflow", false),
            ("5: H2 adds a step to the private workflow", true),
        ],
        "today's outcomes changed; update the pin and the ignored target: {outcomes:#?}"
    );
    let step3 = outcomes[2].1.as_ref().expect_err("step 3 is refused");
    assert!(
        step3.contains("holds no live writer or admin membership of group"),
        "step 3 is refused because the curator no longer derives G: {step3}"
    );
    // The probe. The curator cannot even read its own lineage now (generation
    // 0 is private to `G`, which it no longer derives), so the gate refuses a
    // generation 1 declaring no group before any write. A NEW workflow
    // declaring no group (it would land in the curator's default group)
    // reaches the database, whose role-agent rule (166's `ROL01`) refuses the
    // row: the tool answers an opaque internal error, so the rule's own verdict
    // is read from `epigraph_role_agent_may_run`. No tenancy choice lets the
    // curator go on publishing.
    const PROBE: &str = "handover-curator-probe";
    let fresh = publish(&curator, PROBE, 0, Value::Null).await;
    assert!(
        fresh.is_err(),
        "the curator writes nothing after the handover: {fresh:?}"
    );
    assert_eq!(
        workflow_gen(&pool, PROBE, 0).await,
        None,
        "the refused probe wrote no workflow row"
    );
    let (may, reason) = may_run(&pool, curator_id).await;
    assert!(
        !may,
        "the role-agent rule refuses the curator after the handover: {reason}"
    );
}
