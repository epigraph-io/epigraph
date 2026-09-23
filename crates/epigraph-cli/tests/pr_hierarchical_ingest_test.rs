//! End-to-end contracts the PR-hierarchical `ingest_git --pr-ingest` path depends on.
//!
//! `run_pr_ingest` talks HTTP to epigraph-api. Rather than spawn a server (or import
//! the bin's private helpers, which are unreachable from an integration test), this
//! exercises the exact JSON bodies the CLI emits against the *real* epigraph-api
//! handlers via `tower::ServiceExt::oneshot`, on `epigraph_db_repo_test`.
//!
//! It asserts the three contracts the CLI relies on:
//!   1. submit-packet idempotency: a stable `idempotency_key` returns the same claim_id;
//!   2. a datestamped `RESOLVED_BY` edge (`backlog -> PR`) is accepted with `valid_from`;
//!   3. `content_contains` search finds a backlog claim citing "PR #<n>".
//!
//! A second test runs the REAL `ingest_git` binary over loopback HTTP against the
//! same handlers with packet-signature enforcement ON
//! (`EPIGRAPH_REQUIRE_SIGNATURES=true`). The binary signs its packets, and this is
//! the only place that proves it: the unit tests check the signing primitive,
//! this checks the wiring.
//!
//! Scaffolding (`ensure_system_agent`, `seed_claim`) is copied verbatim from
//! `epigraph-api`'s `routes::edges` `db_tests`.
#![cfg(feature = "db")]

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post},
    Router,
};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

mod viewer_fixture;

use epigraph_api::routes;
use epigraph_api::state::{ApiConfig, AppState};

/// Router mirroring the four routes the CLI hits (submit + edges + claim read + query).
///
/// # Why the state is built from a `ScopedPool` and the fn is `async`
///
/// PR-28 converted `routes::claims_query::list_claims_query` onto
/// `AppState::read_as`, which REFUSES rather than falling back when the state
/// carries no `ScopedPool` — deliberately, because an unstamped connection makes
/// the RLS policy and the in-query predicate disagree. `AppState::with_db` leaves
/// `scoped` at `None`, so step 4 below would answer 500 instead of 200.
///
/// `with_scoped_pool` and not a hand-set `state.scoped`: it is the constructor
/// `bin/server.rs` uses, and it sets `db_pool = scoped.inner()` over the same
/// `#[sqlx::test]` database, so the three other mounted routes and the seeding
/// done on `pool` are unaffected.
async fn app(pool: PgPool) -> Router {
    app_with_config(pool, ApiConfig::default()).await
}

/// [`app`] with an explicit config, plus the agent-registration route the CLI
/// calls before it submits (`POST /agents`).
async fn app_with_config(pool: PgPool, config: ApiConfig) -> Router {
    let state = AppState::with_scoped_pool(viewer_fixture::scoped_pool(&pool).await, config);
    Router::new()
        .route("/agents", post(routes::agents::create_agent))
        .route("/api/v1/submit/packet", post(routes::submit::submit_packet))
        .route("/api/v1/edges", post(routes::edges::create_edge))
        .route("/api/v1/claims/:id", get(routes::claims::get_claim))
        .route(
            "/api/v1/claims",
            get(routes::claims_query::list_claims_query),
        )
        // PR-06: these handlers take `ViewerExtractor`, which requires an
        // `AuthContext` on the request. In production the bearer middleware
        // installs it; a bare test router carries none, so every request 401s
        // before reaching the handler.
        .layer(axum::Extension({
            let principal = Uuid::new_v4();
            epigraph_api::middleware::bearer::AuthContext {
                client_id: principal,
                agent_id: Some(principal),
                owner_id: Some(principal),
                client_type: epigraph_api::middleware::bearer::ClientType::Service,
                scopes: vec![
                    "agents:write".to_string(),
                    "epigraph:write".to_string(),
                    "epigraph:read".to_string(),
                    "claims:read".to_string(),
                    "claims:write".to_string(),
                    "edges:write".to_string(),
                    "graph:read".to_string(),
                ],
                jti: Uuid::new_v4(),
            }
        }))
        .with_state(state)
}

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&b).unwrap()
}

/// Insert a system agent (mirrors `policies.rs::ensure_system_agent`) and return its
/// id. Each call uses a fresh random pubkey so tests don't collide on the unique
/// constraint. Copied from `epigraph-api` `routes::edges` `db_tests`.
async fn ensure_system_agent(pool: &PgPool) -> Uuid {
    let mut pub_key = vec![0u8; 32];
    for b in pub_key.iter_mut() {
        *b = rand::random();
    }
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
    )
    .bind(&pub_key)
    .bind("cli-pr-ingest-test")
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Insert a plain claim and return its id. Copied from `epigraph-api`
/// `routes::edges` `db_tests`.
async fn seed_claim(pool: &PgPool, agent_id: Uuid, content: &str) -> Uuid {
    let content_hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties) \
         VALUES ($1, $2, $3, 0.5, ARRAY[]::text[], '{}'::jsonb) RETURNING id",
    )
    .bind(content)
    .bind(content_hash.as_slice())
    .bind(agent_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn pr_ingest_builds_hierarchy_and_resolution_edge(pool: PgPool) {
    // Seed an agent + a backlog claim whose content cites "PR #999" (the PR-number
    // resolution path the CLI uses to find claims to link), plus a decoy claim that
    // does NOT mention PR #999 so step 4 proves the filter discriminates rather than
    // returning everything.
    let agent = ensure_system_agent(&pool).await;
    let backlog = seed_claim(&pool, agent, "Backlog X. Fixed by PR #999.").await;
    let decoy = seed_claim(&pool, agent, "Unrelated backlog item about PR #123.").await;

    let router = app(pool.clone()).await;

    // 1) submit the PR node (stable idempotency_key pr:org/repo#999).
    let pr_body = serde_json::json!({
        "claim": {
            "content": "[PR #999] fix(api): thing",
            "initial_truth": 0.8,
            "agent_id": agent,
            "idempotency_key": "pr:org/repo#999",
            "properties": { "source": "git-history", "node": "pr", "pr_number": 999 }
        },
        "evidence": [],
        "reasoning_trace": {
            "methodology": "heuristic",
            "inputs": [],
            "confidence": 0.8,
            "explanation": "x"
        },
        "signature": "0".repeat(128)
    });
    let r = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/submit/packet")
                .header("content-type", "application/json")
                .body(Body::from(pr_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "first PR submit accepted (got {})",
        r.status()
    );
    let pr_id: Uuid = json(r).await["claim_id"].as_str().unwrap().parse().unwrap();

    // 2) re-submit the same PR -> same claim_id (idempotent find-or-create).
    let r2 = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/submit/packet")
                .header("content-type", "application/json")
                .body(Body::from(pr_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(r2.status().is_success(), "re-submit accepted");
    let r2_json = json(r2).await;
    let pr_id2: Uuid = r2_json["claim_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        pr_id, pr_id2,
        "stable idempotency_key returns the same claim"
    );
    assert_eq!(
        r2_json["was_duplicate"], true,
        "re-submit flagged as duplicate"
    );

    // 3) datestamped RESOLVED_BY edge backlog -> PR (the resolution link).
    let edge = serde_json::json!({
        "source_id": backlog,
        "target_id": pr_id,
        "source_type": "claim",
        "target_type": "claim",
        "relationship": "RESOLVED_BY",
        "valid_from": "2026-06-02T15:10:01Z",
        "if_not_exists": true,
        "properties": { "source": "git-history" }
    });
    let re = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/edges")
                .header("content-type", "application/json")
                .body(Body::from(edge.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        re.status().is_success(),
        "RESOLVED_BY edge accepted (got {})",
        re.status()
    );
    let edge_json = json(re).await;
    assert_eq!(edge_json["relationship"], "RESOLVED_BY");
    // valid_from round-trips to the same instant (chrono may render +00:00 vs Z).
    let returned_vf = edge_json["valid_from"]
        .as_str()
        .expect("edge carries valid_from");
    let want: chrono::DateTime<chrono::Utc> = "2026-06-02T15:10:01Z".parse().unwrap();
    let got: chrono::DateTime<chrono::Utc> = returned_vf.parse().unwrap();
    assert_eq!(got, want, "edge is datestamped at merge time");

    // 4) content_contains finds the backlog claim citing "PR #999".
    let q = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/claims?content_contains=PR%20%23999&is_current=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(q.status(), StatusCode::OK, "claim query ok");
    let found = json(q).await;
    let ids: Vec<String> = found["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        ids.contains(&backlog.to_string()),
        "PR-number search finds the backlog claim (found ids: {ids:?})"
    );
    assert!(
        !ids.contains(&decoy.to_string()),
        "PR-number search excludes the non-matching decoy (filter discriminates, \
         found ids: {ids:?})"
    );
}

/// Run `git` in `dir` with the user's global/system config masked, so a global
/// `commit.gpgsign` or hook cannot change what the test commits.
fn git(dir: &std::path::Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn commit_as(dir: &std::path::Path, name: &str, email: &str, file: &str, message: &str) {
    std::fs::write(dir.join(file), format!("{file}\n")).unwrap();
    git(dir, &["add", file]);
    git(
        dir,
        &[
            "-c",
            &format!("user.name={name}"),
            "-c",
            &format!("user.email={email}"),
            "commit",
            "-q",
            "-m",
            message,
        ],
    );
}

/// Run `ingest_git --pr-ingest` against `endpoint` and return (success, stderr).
async fn run_ingest_git(
    repo: &std::path::Path,
    endpoint: &str,
    orchestrator_id: Uuid,
    orchestrator_key: Option<&str>,
    pr_number: u64,
    merge_sha: &str,
) -> (bool, String) {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_ingest_git"));
    cmd.args([
        "--pr-ingest",
        "--endpoint",
        endpoint,
        "--repo-slug",
        "sig-test/repo",
        "--pr-number",
        &pr_number.to_string(),
        "--pr-title",
        "feat(core): add the widget",
        "--pr-body",
        "Adds the widget.",
        "--merge-sha",
        merge_sha,
        "--merged-at",
        "2026-09-22T12:00:00Z",
        "--pr-author",
        "tester",
        "--rev-range",
        "base..HEAD",
        "--orchestrator-id",
        &orchestrator_id.to_string(),
    ])
    .arg("--repo")
    .arg(repo)
    // Run from the temp repo so the binary's `dotenv()` finds no project `.env`,
    // and give it only the orchestrator key this test chooses.
    .current_dir(repo)
    .env_remove("EPIGRAPH_ORCHESTRATOR_KEY")
    .env_remove("EPIGRAPH_DEFAULT_ORCHESTRATOR_ID")
    .env_remove("EPIGRAPH_TOKEN")
    .env("GIT_CONFIG_GLOBAL", "/dev/null")
    .env("GIT_CONFIG_SYSTEM", "/dev/null");
    if let Some(key) = orchestrator_key {
        cmd.env("EPIGRAPH_ORCHESTRATOR_KEY", key);
    }
    let out = cmd.output().await.expect("ingest_git runs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn pr_ingest_binary_is_accepted_with_signature_enforcement_on(pool: PgPool) {
    use base64::{engine::general_purpose::STANDARD, Engine};

    // The orchestrator is a pre-registered Ed25519 agent whose key the ingester
    // is given through EPIGRAPH_ORCHESTRATOR_KEY.
    let seed: [u8; 32] = rand::random();
    let orchestrator = epigraph_crypto::AgentSigner::from_bytes(&seed).unwrap();
    let orchestrator_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
    )
    .bind(orchestrator.public_key().as_slice())
    .bind("sig-test-orchestrator")
    .fetch_one(&pool)
    .await
    .unwrap();

    // A PR with two commits by two authors, so two per-author agents sign.
    let repo = std::env::temp_dir().join(format!("ingest-git-sig-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    commit_as(&repo, "Base", "base@example.com", "base.txt", "chore: base");
    git(&repo, &["tag", "base"]);
    commit_as(
        &repo,
        "Alice",
        "alice@example.com",
        "widget.rs",
        "feat(core): add the widget\n\nEvidence:\n- the spec asks for a widget\n\n\
         Reasoning:\n- smallest change\n\nVerification:\n- widget test passes",
    );
    commit_as(
        &repo,
        "Bob",
        "bob@example.com",
        "widget_test.rs",
        "test(core): cover the widget\n\nEvidence:\n- widget had no test",
    );
    let head = git(&repo, &["rev-parse", "HEAD"]);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let router = app_with_config(
        pool.clone(),
        ApiConfig {
            require_packet_signatures: true,
            ..ApiConfig::default()
        },
    )
    .await;
    let server = tokio::spawn(async move { axum::serve(listener, router).await });

    // 1) Without the orchestrator key, the signed repo-root packet is accepted
    //    and the unsigned PR packet is refused with 401. The run names the
    //    missing key in the hint it adds to exactly that failure.
    let (ok, stderr) = run_ingest_git(&repo, &endpoint, orchestrator_id, None, 4241, &head).await;
    assert!(
        !ok,
        "an unsigned PR packet must be refused under enforcement"
    );
    assert!(
        stderr.contains("submit 401")
            && stderr.contains(&format!(
                "hint: the PR claim is authored by orchestrator {orchestrator_id}"
            )),
        "the PR packet, not an earlier one, is what was refused: {stderr}"
    );
    let repo_roots: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM claims WHERE 'node:repo' = ANY(labels) \
         AND 'repo:sig-test/repo' = ANY(labels)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(repo_roots, 1, "the signed repo-root packet was accepted");

    // 2) With it, the whole repo -> PR -> commit run is accepted.
    let key = STANDARD.encode(seed);
    let (ok, stderr) =
        run_ingest_git(&repo, &endpoint, orchestrator_id, Some(&key), 4242, &head).await;
    assert!(
        ok,
        "ingest_git --pr-ingest must succeed with enforcement on: {stderr}"
    );

    // The PR node is attributed to the orchestrator, and both commits landed
    // under their authors.
    let pr_author: Uuid = sqlx::query_scalar(
        "SELECT agent_id FROM claims WHERE content = '[PR #4242] feat(core): add the widget'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pr_author, orchestrator_id);
    let commit_claims: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM claims WHERE 'node:commit' = ANY(labels) \
         AND 'repo:sig-test/repo' = ANY(labels)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(commit_claims, 2, "both commits were ingested");

    server.abort();
    let _ = std::fs::remove_dir_all(&repo);
}
