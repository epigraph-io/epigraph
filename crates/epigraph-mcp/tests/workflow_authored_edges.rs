//! Authorship of the claims a workflow mutation creates, as a graph edge
//! (operator rulings, 2026-10-13): "the agents writing workflow claims should
//! be connected to their authorship of those claims ... through a graph
//! relationship rather than as a parameter of the claim".
//!
//! Every claim a workflow mutation CREATES (`add_step`'s step claim; an
//! ingest's thesis, phase, step and operation claims) gets one `AUTHORED` edge
//! (`source_type = 'agent'` -> `target_type = 'claim'`, the convention of the
//! submit path) from the ACTING agent — the token's agent over HTTP, this
//! server's pinned agent on stdio — on the write's own transaction. The claim
//! itself stays authored and stamped by the workflow-ingest system agent
//! (`claims.agent_id` unchanged).
//!
//! A claim the call did NOT create (a deduplicated operation atom shared with
//! another workflow, a re-ingest, a step already present) gets no edge from
//! this call: authorship is of the creation, and the creator already holds its
//! edge. Re-running is idempotent. A refused call writes no edge. The edge's
//! tenancy is the trigger's (`epigraph_edges_tenancy`), never bound here.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, seed_caller};
use epigraph_auth::{AuthContext, ClientType};
use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::tools;
use epigraph_mcp::tools::step_ops::AddStepParams;
use epigraph_mcp::types::{ImproveWorkflowHierarchyParams, IngestWorkflowParams};
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

/// A one-phase, one-step extraction whose step carries `ops`.
fn extraction(canonical: &str, summary: &str, ops: &[&str]) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: format!("authored-edge workflow {canonical}"),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: None,
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Body".to_string(),
            summary: summary.to_string(),
            steps: vec![Step {
                compound: format!("{summary}: the step of {canonical}"),
                rationale: "because".to_string(),
                operations: ops.iter().map(|o| (*o).to_string()).collect(),
                generality: vec![1],
                confidence: 0.7,
                evidence_type: None,
            }],
        }],
        relationships: vec![],
    }
}

fn add(canonical: &str, text: &str) -> AddStepParams {
    AddStepParams {
        canonical_name: canonical.to_string(),
        step_text: text.to_string(),
        position: None,
    }
}

fn token(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: None,
        client_type: ClientType::Human,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

async fn http_viewer(
    server: &EpiGraphMcpFull,
    auth: &AuthContext,
) -> epigraph_db::visibility::Viewer {
    tools::viewer::request_viewer(server, Some(auth))
        .await
        .expect("HTTP viewer")
}

/// Every `AUTHORED` source naming `claim`, as `(source_id, source_type,
/// target_type)`.
async fn authored(pool: &PgPool, claim: Uuid) -> Vec<(Uuid, String, String)> {
    sqlx::query_as(
        "SELECT source_id, source_type, target_type FROM edges \
          WHERE relationship = 'AUTHORED' AND target_id = $1 ORDER BY created_at, id",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read AUTHORED edges")
}

async fn authored_total(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM edges WHERE relationship = 'AUTHORED'")
        .fetch_one(pool)
        .await
        .expect("count AUTHORED")
}

async fn claim_author(pool: &PgPool, claim: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim author")
}

/// The ids of every claim, for a before/after diff of what a call created.
async fn all_claims(pool: &PgPool) -> std::collections::HashSet<Uuid> {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM claims")
        .fetch_all(pool)
        .await
        .expect("claim ids")
        .into_iter()
        .collect()
}

/// The claims a workflow row `executes`.
async fn executed(pool: &PgPool, canonical: &str, generation: i32) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT e.target_id FROM edges e JOIN workflows w ON w.id = e.source_id \
          WHERE w.canonical_name = $1 AND w.generation = $2 AND e.relationship = 'executes'",
    )
    .bind(canonical)
    .bind(generation)
    .fetch_all(pool)
    .await
    .expect("executed claims")
}

fn step_id(res: &rmcp::model::CallToolResult) -> Uuid {
    common::first_text(res)["step_claim_id"]
        .as_str()
        .expect("step id")
        .parse()
        .expect("uuid")
}

/// Ingest `canonical` as `submitter` over HTTP (a brand-new lineage records
/// the caller as its submitter).
async fn ingest_as(server: &EpiGraphMcpFull, auth: &AuthContext, canonical: &str, ops: &[&str]) {
    tools::workflow_ingest::ingest_workflow(
        server,
        &http_viewer(server, auth).await,
        IngestWorkflowParams {
            extraction: extraction(canonical, "gen0", ops),
            tenancy: None,
            embed: None,
        },
        Some(auth),
    )
    .await
    .expect("ingest");
}

/// stdio `add_step`: exactly one `AUTHORED` edge, from this server's pinned
/// agent, to the new step claim, which the system agent still authors.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stdio_add_step_records_the_pinned_agent_as_author(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (h, _) = fixture::seed_human_operator(&pool, "h").await;
    ingest_as(&server, &token(h), "ae-stdio", &["ae-stdio op"]).await;
    let viewer = tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");
    let pinned = viewer.principal().expect("the server's pinned agent");

    let res = tools::step_ops::add_step(&server, &viewer, add("ae-stdio", "a stdio step"), None)
        .await
        .expect("stdio add_step");
    let step = step_id(&res);
    assert_eq!(
        authored(&pool, step).await,
        vec![(pinned, "agent".to_string(), "claim".to_string())],
        "one AUTHORED edge from the pinned stdio agent"
    );
    let author = claim_author(&pool, step).await;
    assert_ne!(author, pinned, "claims.agent_id stays the system agent");
    assert_ne!(author, h);
}

/// HTTP `add_step` by the submitting human: one edge from that principal; the
/// edge's tenancy is the trigger's (an agent endpoint and a public claim:
/// `('public', world)`, migration 120), not the caller's.
#[sqlx::test(migrations = "../../migrations")]
async fn an_http_add_step_records_the_principal_as_author(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (h, _) = fixture::seed_human_operator(&pool, "h").await;
    let auth = token(h);
    ingest_as(&server, &auth, "ae-http", &["ae-http op"]).await;

    let res = tools::step_ops::add_step(
        &server,
        &http_viewer(&server, &auth).await,
        add("ae-http", "H's step"),
        Some(&auth),
    )
    .await
    .expect("the submitter adds a step");
    let step = step_id(&res);
    assert_eq!(
        authored(&pool, step).await,
        vec![(h, "agent".to_string(), "claim".to_string())]
    );
    assert_ne!(
        claim_author(&pool, step).await,
        h,
        "the system agent authors it"
    );
    let (vis, owner): (String, Uuid) = sqlx::query_as(
        "SELECT visibility::text, owner_group_id FROM edges \
          WHERE relationship = 'AUTHORED' AND target_id = $1",
    )
    .bind(step)
    .fetch_one(&pool)
    .await
    .expect("edge tenancy");
    assert_eq!(
        (vis.as_str(), owner),
        ("public", fixture::world_group(&pool).await),
        "the trigger's tenancy for an agent -> public-claim edge"
    );

    // Re-adding the same text creates nothing, and writes no second edge.
    let before = authored_total(&pool).await;
    tools::step_ops::add_step(
        &server,
        &http_viewer(&server, &auth).await,
        add("ae-http", "H's step"),
        Some(&auth),
    )
    .await
    .expect("idempotent add_step");
    assert_eq!(
        authored_total(&pool).await,
        before,
        "no duplicate AUTHORED edge"
    );
    assert_eq!(authored(&pool, step).await.len(), 1);
}

/// A new generation writes one edge per claim it CREATED, from the acting
/// agent; an operation atom it shares with generation 0 (deduplicated, created
/// by gen 0's ingester) gets none from it; a re-run writes nothing new.
#[sqlx::test(migrations = "../../migrations")]
async fn a_new_generation_records_one_author_edge_per_created_claim(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (h, _) = fixture::seed_human_operator(&pool, "h").await;
    let auth = token(h);
    ingest_as(&server, &auth, "ae-gen", &["ae shared op", "ae gen0 op"]).await;
    let gen0_claims = executed(&pool, "ae-gen", 0).await;
    for c in &gen0_claims {
        assert_eq!(
            authored(&pool, *c).await,
            vec![(h, "agent".to_string(), "claim".to_string())],
            "gen 0's ingest authored {c}"
        );
    }

    let before = all_claims(&pool).await;
    let improve = || ImproveWorkflowHierarchyParams {
        parent_canonical_name: "ae-gen".to_string(),
        extraction: extraction("ignored", "gen1", &["ae shared op", "ae gen1 op"]),
    };
    tools::workflow_ingest::improve_workflow_hierarchy(
        &server,
        &http_viewer(&server, &auth).await,
        improve(),
        Some(&auth),
    )
    .await
    .expect("the submitter adds a generation");
    let created: Vec<Uuid> = all_claims(&pool)
        .await
        .difference(&before)
        .copied()
        .collect();
    assert!(
        created.len() >= 3,
        "thesis/phase/step/op created: {created:?}"
    );
    for c in &created {
        assert_eq!(
            authored(&pool, *c).await,
            vec![(h, "agent".to_string(), "claim".to_string())],
            "created claim {c} has exactly one AUTHORED edge, from the actor"
        );
        assert_ne!(claim_author(&pool, *c).await, h, "system agent authors {c}");
    }
    let gen1_claims = executed(&pool, "ae-gen", 1).await;
    let reused: Vec<Uuid> = gen1_claims
        .iter()
        .filter(|c| !created.contains(c))
        .copied()
        .collect();
    assert!(
        !reused.is_empty(),
        "calibration: gen 1 reuses at least the shared operation atom"
    );
    for c in &reused {
        assert_eq!(
            authored(&pool, *c).await.len(),
            1,
            "a reused claim {c} keeps only its creator's edge"
        );
    }

    // Re-ingesting the existing generation creates nothing and writes nothing.
    let total = authored_total(&pool).await;
    let mut again = extraction("ae-gen", "gen1", &["ae shared op", "ae gen1 op"]);
    again.source.generation = 1;
    again.source.parent_canonical_name = Some("ae-gen".to_string());
    tools::workflow_ingest::ingest_workflow(
        &server,
        &http_viewer(&server, &auth).await,
        IngestWorkflowParams {
            extraction: again,
            tenancy: None,
            embed: None,
        },
        Some(&auth),
    )
    .await
    .expect("re-ingest");
    assert_eq!(
        authored_total(&pool).await,
        total,
        "re-ingest is idempotent"
    );
}

/// The operation atom another agent created stays attributed to that agent:
/// a second lineage by a DIFFERENT actor that reuses it writes no edge from
/// the second actor onto it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deduplicated_claim_keeps_its_creators_edge_only(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (first, _) = fixture::seed_human_operator(&pool, "first").await;
    let (second, _) = fixture::seed_human_operator(&pool, "second").await;
    ingest_as(
        &server,
        &token(first),
        "ae-dedup-a",
        &["ae globally shared op"],
    )
    .await;
    let atom: Uuid =
        sqlx::query_scalar("SELECT id FROM claims WHERE content = 'ae globally shared op'")
            .fetch_one(&pool)
            .await
            .expect("the shared atom");
    ingest_as(
        &server,
        &token(second),
        "ae-dedup-b",
        &["ae globally shared op"],
    )
    .await;
    assert!(
        executed(&pool, "ae-dedup-b", 0).await.contains(&atom),
        "calibration: the second lineage executes the same atom"
    );
    assert_eq!(
        authored(&pool, atom).await,
        vec![(first, "agent".to_string(), "claim".to_string())],
        "only its creator authored it"
    );
}

/// A refused call writes no edge.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_write_records_no_author_edge(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (h, _) = fixture::seed_human_operator(&pool, "h").await;
    ingest_as(&server, &token(h), "ae-refused", &["ae-refused op"]).await;
    let (_stranger, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let before = authored_total(&pool).await;
    tools::step_ops::add_step(
        &server,
        &stranger_viewer,
        add("ae-refused", "a stranger's step"),
        Some(&stranger_token),
    )
    .await
    .expect_err("a stranger is refused");
    tools::workflow_ingest::improve_workflow_hierarchy(
        &server,
        &stranger_viewer,
        ImproveWorkflowHierarchyParams {
            parent_canonical_name: "ae-refused".to_string(),
            extraction: extraction("ignored", "stranger gen", &["ae stranger op"]),
        },
        Some(&stranger_token),
    )
    .await
    .expect_err("a stranger's generation is refused");
    assert_eq!(
        authored_total(&pool).await,
        before,
        "no AUTHORED edge written"
    );
}

/// Row security admits the AUTHORED edge on the system-stamped transaction:
/// an HTTP `add_step` on a server whose every connection is the APPLICATION
/// ROLE.
#[sqlx::test(migrations = "../../migrations")]
async fn the_author_edge_is_admitted_on_the_application_role(pool: PgPool) {
    let seed_server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (h, _) = fixture::seed_human_operator(&pool, "h").await;
    let auth = token(h);
    ingest_as(&seed_server, &auth, "ae-app-role", &["ae-app-role op"]).await;
    let url = fixture::database_url_for(&pool).await;
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &url,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let server = build_scoped_test_server(plain, scoped);
    let res = tools::step_ops::add_step(
        &server,
        &http_viewer(&server, &auth).await,
        add("ae-app-role", "a step on the application role"),
        Some(&auth),
    )
    .await
    .expect("admitted on the application role");
    assert_eq!(
        authored(&pool, step_id(&res)).await,
        vec![(h, "agent".to_string(), "claim".to_string())]
    );
}
