//! REST `POST /api/v1/workflows` matches a reworded goal to the existing
//! hierarchical workflow instead of minting a new generation-0 lineage
//! (backlog 51d599a9), as MCP `store_workflow` does since backlog 5e54282f
//! (`epigraph-mcp/tests/store_workflow_matches_existing.rs`). Both transports
//! now ask `epigraph_ingest_executor::matching_workflow_conn`.
//!
//! # How the paraphrase is made similar in a test process
//!
//! The router's embedding service is [`WordSetEmbedder`], which derives the
//! vector from the goal's lower-cased words with a few stop words removed and
//! the rest sorted, so two wordings of one goal embed to the SAME vector
//! (cosine 1.0, the geometry a real embedder gives a close paraphrase), and an
//! unrelated goal to a pseudo-random one (cosine near 0). The similarity is
//! computed by pgvector over the stored `workflows.goal_embedding`, through
//! the real handler, on the application role.
//!
//! # Verified to fail
//!
//! On the code before this change the paraphrase minted a second
//! generation-0 lineage (two rows, `matched_existing` absent).
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_embeddings::{EmbeddingError, EmbeddingService, TokenUsage};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DIM: usize = 1536;
const STOP_WORDS: [&str; 6] = ["the", "a", "an", "to", "on", "of"];
const GOAL: &str = "Deploy the Rust binary to the Windows server";
const REWORDED: &str = "Deploy Rust binary to Windows server";
const UNRELATED: &str = "Summarize the weekly grant pipeline";

/// A deterministic vector for `text` that depends only on its set of
/// non-stop words. FNV-1a over the sorted words seeds an xorshift64 stream;
/// each component is the stream's top 16 bits, centred.
fn goal_vector(text: &str) -> Vec<f32> {
    let lower = text.to_lowercase();
    let mut words: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty() && !STOP_WORDS.contains(w))
        .collect();
    words.sort_unstable();
    words.dedup();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in words.join(" ").bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    let mut out = Vec::with_capacity(DIM);
    for _ in 0..DIM {
        h ^= h << 13;
        h ^= h >> 7;
        h ^= h << 17;
        let top = u16::try_from(h >> 48).expect("the top 16 bits fit a u16");
        out.push(f32::from(top) - 32_768.0);
    }
    out
}

/// The embedding service the router is built with: [`goal_vector`].
struct WordSetEmbedder;

#[async_trait::async_trait]
impl EmbeddingService for WordSetEmbedder {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        Ok(goal_vector(text))
    }
    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        Ok(texts.iter().map(|t| goal_vector(t)).collect())
    }
    fn dimension(&self) -> usize {
        DIM
    }
    fn token_usage(&self) -> TokenUsage {
        TokenUsage::default()
    }
    fn reset_token_usage(&self) {}
    async fn health_check(&self) -> Result<(), EmbeddingError> {
        Ok(())
    }
}

/// The router over an `epigraph_app` `ScopedPool` (as `bin/server.rs` builds
/// it), with [`WordSetEmbedder`] as its embedding service.
async fn app(pool: &PgPool) -> axum::Router {
    app_with_provider(pool, None).await
}

/// [`app`], declaring which provider the embedding service is (`None`: not
/// declared, which may store, as a process that never says).
async fn app_with_provider(
    pool: &PgPool,
    provider: Option<epigraph_api::embedding_restore::EmbeddingProviderKind>,
) -> axum::Router {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let mut state = AppState::with_scoped_pool(scoped, ApiConfig::default())
        .with_embedding_service(std::sync::Arc::new(WordSetEmbedder));
    if let Some(p) = provider {
        state = state.with_embedding_provider(p);
    }
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    epigraph_api::routes::create_router(state)
}

async fn store(router: &axum::Router, agent: Uuid, body: &Value) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/workflows")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("router");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, value)
}

fn request(goal: &str) -> Value {
    json!({"goal": goal, "steps": [format!("first step of {goal}"), format!("second step of {goal}")]})
}

async fn count(pool: &PgPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(pool)
        .await
        .expect("count")
}

async fn rows_named(pool: &PgPool, canonical: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflows WHERE canonical_name = $1")
        .bind(canonical)
        .fetch_one(pool)
        .await
        .expect("count rows")
}

/// A reworded goal is answered with the existing workflow and stores nothing;
/// `force_new` mints anyway; an unrelated goal mints; the identical goal is
/// the ingest's own idempotent no-op, never a match.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reworded_goal_returns_the_existing_workflow_and_mints_nothing(pool: PgPool) {
    let (caller, _) = fixture::seed_agent_with_group(&pool, "store-match-caller").await;
    let router = app(&pool).await;

    let (status, first) = store(&router, caller, &request(GOAL)).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let original = first["workflow_id"]
        .as_str()
        .expect("workflow_id")
        .to_string();
    let canonical = first["canonical_name"].as_str().expect("name").to_string();

    let workflows_before = count(&pool, "SELECT count(*) FROM workflows").await;
    let claims_before = count(&pool, "SELECT count(*) FROM claims").await;
    let events_before = count(&pool, "SELECT count(*) FROM events").await;

    let (status, matched) = store(&router, caller, &request(REWORDED)).await;
    assert_eq!(status, StatusCode::OK, "{matched}");
    assert_eq!(matched["matched_existing"], true, "{matched}");
    assert_eq!(matched["workflow_id"], original, "{matched}");
    assert_eq!(matched["canonical_name"], canonical, "{matched}");
    assert_eq!(matched["claims_ingested"], 0, "{matched}");
    assert!(
        matched["similarity"].as_f64().expect("similarity") >= 0.90,
        "{matched}"
    );
    assert!(
        matched["hint"]
            .as_str()
            .expect("hint")
            .contains("improve_workflow_hierarchy"),
        "{matched}"
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM workflows").await,
        workflows_before,
        "no workflow row was minted"
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM claims").await,
        claims_before,
        "no claim was written"
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM events").await,
        events_before,
        "nothing was announced"
    );
    let reworded_name = "deploy-rust-binary-to-windows-server";
    assert_eq!(rows_named(&pool, reworded_name).await, 0);

    // force_new mints the reworded lineage.
    let mut forced = request(REWORDED);
    forced["force_new"] = json!(true);
    let (status, minted) = store(&router, caller, &forced).await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    assert_eq!(minted["matched_existing"], false, "{minted}");
    assert_ne!(minted["workflow_id"], original, "{minted}");
    assert_eq!(rows_named(&pool, reworded_name).await, 1);

    // An unrelated goal is not a match.
    let (status, other) = store(&router, caller, &request(UNRELATED)).await;
    assert_eq!(status, StatusCode::OK, "{other}");
    assert_eq!(other["matched_existing"], false, "{other}");
    assert_ne!(other["workflow_id"], original, "{other}");

    // The identical goal stays the ingest's idempotent no-op.
    let (status, again) = store(&router, caller, &request(GOAL)).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["already_ingested"], true, "{again}");
    assert_eq!(again["matched_existing"], false, "{again}");
    assert_eq!(rows_named(&pool, &canonical).await, 1);
}

/// Only a workflow in exactly the tenancy this store would use is matched: a
/// store declared public is not redirected onto the caller's private plan.
#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_in_another_tenancy_is_not_matched(pool: PgPool) {
    let (caller, own) = fixture::seed_agent_with_group(&pool, "store-match-tenancy").await;
    let router = app(&pool).await;

    let (status, first) = store(&router, caller, &request(GOAL)).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let original = first["workflow_id"].clone();

    let mut public = request(REWORDED);
    public["tenancy"] = json!({"visibility": "public", "owner_group_id": own});
    let (status, minted) = store(&router, caller, &public).await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    assert_eq!(minted["matched_existing"], false, "{minted}");
    assert_ne!(minted["workflow_id"], original, "{minted}");
    assert_eq!(
        rows_named(&pool, "deploy-rust-binary-to-windows-server").await,
        1
    );
}

async fn tenancy_of(pool: &PgPool, wf: &Value) -> (String, Uuid) {
    let id: Uuid = wf.as_str().expect("workflow_id").parse().expect("uuid");
    sqlx::query_as("SELECT visibility::text, owner_group_id FROM workflows WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("tenancy")
}

/// The HTTP twin of MCP's `matching_never_discloses_a_plan_the_caller_cannot_read`:
/// the match reads on the caller's own stamp and viewer, and only a plan in
/// exactly the tenancy the store would use is matched. A stranger that
/// declares nothing (a new lineage is private to its own group):
///
/// * a paraphrase of another agent's group-private plan it cannot read mints
///   a new lineage, and the answer never carries the private goal;
/// * a paraphrase of that agent's PUBLIC plan, which it reads, is not matched
///   either (its outcome reports would land on another group's plan); the new
///   lineage keeps the stranger's private tenancy;
/// * a paraphrase of its own earlier plan IS matched (the positive control).
///
/// Old code had no match to disclose with; VERIFIED TO FAIL with the
/// helper's tenancy comparison removed (the public plan was matched).
#[sqlx::test(migrations = "../../migrations")]
async fn matching_never_discloses_a_plan_the_caller_cannot_read(pool: PgPool) {
    let (owner, owner_g) = fixture::seed_agent_with_group(&pool, "store-match-owner").await;
    let (stranger, stranger_g) =
        fixture::seed_agent_with_group(&pool, "store-match-stranger").await;
    let router = app(&pool).await;
    let tag = Uuid::new_v4().simple().to_string();
    let private_goal = format!("Rotate the private signing keys of the vault {tag}");
    let public_goal = format!("Publish the weekly release notes to the wiki {tag}");
    let own_goal = format!("Compact the audit log archive on the replica {tag}");

    let (status, private) = store(&router, owner, &request(&private_goal)).await;
    assert_eq!(status, StatusCode::OK, "{private}");
    let mut public_req = request(&public_goal);
    public_req["tenancy"] = json!({"visibility": "public", "owner_group_id": owner_g});
    let (status, public) = store(&router, owner, &public_req).await;
    assert_eq!(status, StatusCode::OK, "{public}");
    let (status, own) = store(&router, stranger, &request(&own_goal)).await;
    assert_eq!(status, StatusCode::OK, "{own}");

    let (status, r) = store(
        &router,
        stranger,
        &request(&format!("Rotate private signing keys of vault {tag}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["matched_existing"], false, "{r}");
    assert_ne!(r["workflow_id"], private["workflow_id"], "{r}");
    assert!(
        !r.to_string().contains(&private_goal),
        "the private plan's goal left the database: {r}"
    );

    let (status, r) = store(
        &router,
        stranger,
        &request(&format!("Publish weekly release notes to wiki {tag}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(
        r["matched_existing"], false,
        "a private-by-default store was redirected onto another group's public plan: {r}"
    );
    assert_ne!(r["workflow_id"], public["workflow_id"], "{r}");
    assert_eq!(
        tenancy_of(&pool, &r["workflow_id"]).await,
        ("group".to_string(), stranger_g),
        "the new lineage keeps the store's own private tenancy"
    );

    let (status, r) = store(
        &router,
        stranger,
        &request(&format!("Compact audit log archive on replica {tag}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["matched_existing"], true, "the positive control: {r}");
    assert_eq!(r["workflow_id"], own["workflow_id"], "{r}");
}

/// The match compares the goal with `workflows.goal_embedding`, which only
/// the STORING embedding service writes, so it embeds with that service: a
/// provider declared as not owning the column (another vector space) matches
/// nothing, even against a stored vector equal to its own output, and the
/// store mints as it did before matching existed.
///
/// VERIFIED TO FAIL when the match embedded with the query service: the
/// reworded goal was matched across vector spaces.
#[sqlx::test(migrations = "../../migrations")]
async fn a_provider_that_does_not_own_the_goal_column_matches_nothing(pool: PgPool) {
    let (caller, _) = fixture::seed_agent_with_group(&pool, "store-match-jina").await;
    let router = app_with_provider(
        &pool,
        Some(epigraph_api::embedding_restore::EmbeddingProviderKind::Jina),
    )
    .await;
    let (status, first) = store(&router, caller, &request(GOAL)).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    // Seed the row with the reworded goal's vector in this provider's space:
    // a match embedded with the query service would now score 1.0.
    let id: Uuid = first["workflow_id"]
        .as_str()
        .expect("workflow_id")
        .parse()
        .expect("uuid");
    sqlx::query("UPDATE workflows SET goal_embedding = $1::vector WHERE id = $2")
        .bind(epigraph_db::pgvector_literal(&goal_vector(REWORDED)))
        .bind(id)
        .execute(&pool)
        .await
        .expect("seed the goal embedding");

    let (status, r) = store(&router, caller, &request(REWORDED)).await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["matched_existing"], false, "{r}");
    assert_ne!(r["workflow_id"], first["workflow_id"], "{r}");
}

/// An embedding service of another dimension than the stored goal vectors.
struct OtherDimensionEmbedder;

#[async_trait::async_trait]
impl EmbeddingService for OtherDimensionEmbedder {
    async fn generate(&self, _text: &str) -> Result<Vec<f32>, EmbeddingError> {
        Ok(vec![1.0; 8])
    }
    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        Ok(texts.iter().map(|_| vec![1.0; 8]).collect())
    }
    fn dimension(&self) -> usize {
        8
    }
    fn token_usage(&self) -> TokenUsage {
        TokenUsage::default()
    }
    fn reset_token_usage(&self) {}
    async fn health_check(&self) -> Result<(), EmbeddingError> {
        Ok(())
    }
}

/// A failed match READ matches nothing and the store goes on, the answer MCP
/// `store_workflow` gives the same input (review of 51d599a9: one input, one
/// answer on either transport). The failure is real: pgvector refuses to
/// compare the 8-dimension query with the first store's 1536-dimension goal
/// embedding.
///
/// VERIFIED TO FAIL with the match error returned instead of logged.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_match_read_stores_as_without_matching(pool: PgPool) {
    let (caller, _) = fixture::seed_agent_with_group(&pool, "store-match-fail").await;
    let router = app(&pool).await;
    let (status, first) = store(&router, caller, &request(GOAL)).await;
    assert_eq!(status, StatusCode::OK, "{first}");

    let url = fixture::database_url_for(&pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default())
        .with_embedding_service(std::sync::Arc::new(OtherDimensionEmbedder));
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    let other = epigraph_api::routes::create_router(state);

    let (status, r) = store(&other, caller, &request(REWORDED)).await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["matched_existing"], false, "{r}");
    assert_ne!(r["workflow_id"], first["workflow_id"], "{r}");
}
