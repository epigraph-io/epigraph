#![cfg(feature = "db")]
//! Plan §2.6 redaction sweep: every read the Explorer renders claim text from
//! must apply the same partition check `GET /claims/:id` applies, using the
//! authenticated requester (`agent_id`, falling back to `client_id`).
//!
//! Each test is a DISCRIMINATING TRIPLE over one route:
//!   - a non-owner (anonymous, or a stranger token where the router demands a
//!     bearer) sees `"[REDACTED]"` for the private claim,
//!   - the owner's token sees the real text,
//!   - a public claim in the same response is unchanged for everyone.
//!
//! Without the owner half a handler that redacts unconditionally would pass;
//! without the public half one that redacts everything would.
//!
//! Tests go through `spawn_app` → `build_app_for_tests` → `create_router`, so
//! the production middleware layering (optional vs required bearer) is what
//! produces the `AuthContext` the handlers read.

mod common;

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async fn pool_and_app() -> (
    sqlx::PgPool,
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let (addr, shutdown) = common::spawn_app(&url).await;
    (pool, addr, shutdown)
}

/// The deterministic query vector `semantic_search` falls back to when no
/// embedding service is configured — `build_app_for_tests` configures none, so
/// this is exactly what the handler will compare against. Mirrors
/// `routes::search::generate_mock_embedding_with_dim` (private to that module).
/// Seeding a claim's `embedding` with it pins that claim at similarity 1.0,
/// i.e. the top of the result list on the shared test DB.
fn mock_query_embedding(text: &str, dim: usize) -> String {
    let mut embedding = vec![0.0f32; dim];
    for (i, byte) in text.as_bytes().iter().enumerate() {
        embedding[i % dim] += (*byte as f32) / 255.0;
    }
    let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
    if magnitude > 0.0 {
        for val in embedding.iter_mut() {
            *val /= magnitude;
        }
    }
    format!(
        "[{}]",
        embedding
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

async fn ensure_agent(pool: &sqlx::PgPool, agent_id: Uuid) {
    let pk: Vec<u8> = agent_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system') ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed agent");
}

/// Insert a claim, optionally with an embedding, a theme and explicit labels.
/// `seed_claim_with_agent` in `common` covers none of those, and every route
/// under test needs at least one of them to surface the row.
async fn seed_claim_full(
    pool: &sqlx::PgPool,
    content: &str,
    agent_id: Uuid,
    embedding: Option<&str>,
    theme_id: Option<Uuid>,
    labels: &[&str],
) -> Uuid {
    ensure_agent(pool, agent_id).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    let labels_owned: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query(
        "INSERT INTO claims \
             (id, content, content_hash, truth_value, agent_id, is_current, labels, \
              pignistic_prob, theme_id, embedding) \
         VALUES ($1, $2, $3, 0.5, $4, true, $5, 0.5, $6, $7::vector)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent_id)
    .bind(&labels_owned)
    .bind(theme_id)
    .bind(embedding)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// Wipe the cluster-run fixtures so the run this test inserts is the latest
/// one — every graph route under test resolves "the latest run" and 404s on
/// anything outside it. Matches `common::seed_one_cluster` and
/// `graph_neighborhoods_test`, which wipe the same tables for the same reason.
async fn wipe_cluster_run_fixtures(pool: &sqlx::PgPool) {
    for stmt in [
        "DELETE FROM neighborhood_edges",
        "DELETE FROM claim_neighborhood_membership",
        "DELETE FROM graph_neighborhoods",
        "DELETE FROM cluster_edges",
        "DELETE FROM claim_cluster_membership",
        "DELETE FROM graph_clusters",
        "DELETE FROM graph_cluster_runs",
    ] {
        sqlx::query(stmt).execute(pool).await.expect(stmt);
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

/// Pull `field` out of the first array element whose `id_field` equals `id`.
fn field_for(body: &Value, array: &str, id_field: &str, id: Uuid, field: &str) -> String {
    body.get(array)
        .and_then(|a| a.as_array())
        .unwrap_or_else(|| panic!("response has no `{array}` array: {body}"))
        .iter()
        .find(|row| row.get(id_field).and_then(|v| v.as_str()) == Some(id.to_string().as_str()))
        .unwrap_or_else(|| panic!("{id} not present in `{array}`: {body}"))
        .get(field)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("`{field}` missing or not a string"))
        .to_string()
}

const PRIVATE_BODY: &str = "SWEEP private secret body";
const PUBLIC_BODY: &str = "SWEEP public body";

// ---------------------------------------------------------------------------
// POST /api/v1/search/semantic — flat path
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn semantic_search_flat_redacts_private_for_non_owner_only() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let query = format!("sweep flat probe {}", Uuid::new_v4());
    let vec_literal = mock_query_embedding(&query, 1536);

    let private_id =
        seed_claim_full(&pool, PRIVATE_BODY, owner, Some(&vec_literal), None, &[]).await;
    common::seed_private_ownership(&pool, private_id, owner).await;
    let public_id = seed_claim_full(&pool, PUBLIC_BODY, owner, Some(&vec_literal), None, &[]).await;

    let body = serde_json::json!({ "query": query, "limit": 100 });
    let statement_of =
        |body: &Value, id: Uuid| field_for(body, "results", "claim_id", id, "statement");

    // Anonymous: private redacted, public untouched.
    let resp = client()
        .post(format!("http://{addr}/api/v1/search/semantic"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let anon: Value = resp.json().await.unwrap();
    assert_eq!(
        statement_of(&anon, private_id),
        "[REDACTED]",
        "anonymous semantic search must not return private claim text"
    );
    assert_eq!(
        statement_of(&anon, public_id),
        PUBLIC_BODY,
        "public claim text must survive the sweep"
    );

    // Stranger token: still redacted (the check is on the authenticated agent).
    let stranger = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let resp = client()
        .post(format!("http://{addr}/api/v1/search/semantic"))
        .bearer_auth(&stranger)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let other: Value = resp.json().await.unwrap();
    assert_eq!(statement_of(&other, private_id), "[REDACTED]");

    // Owner token: full text.
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let resp = client()
        .post(format!("http://{addr}/api/v1/search/semantic"))
        .bearer_auth(&owner_token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let owned: Value = resp.json().await.unwrap();
    assert_eq!(
        statement_of(&owned, private_id),
        PRIVATE_BODY,
        "the owner must still see their own claim text"
    );
}

// ---------------------------------------------------------------------------
// POST /api/v1/search/semantic — diverse path (results + graph_neighbors)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn semantic_search_diverse_redacts_results_and_graph_neighbors() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let query = format!("sweep diverse probe {}", Uuid::new_v4());
    let vec_literal = mock_query_embedding(&query, 1536);

    // A theme whose centroid IS the query vector, so `max_themes=1` selects it
    // and nothing else — the candidate pool is then exactly this theme's claims.
    let theme_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claim_themes (id, label, description, claim_count, centroid) \
         VALUES ($1, 'sweep-diverse', '', 0, $2::vector)",
    )
    .bind(theme_id)
    .bind(&vec_literal)
    .execute(&pool)
    .await
    .expect("seed theme");

    let private_id = seed_claim_full(
        &pool,
        PRIVATE_BODY,
        owner,
        Some(&vec_literal),
        Some(theme_id),
        &[],
    )
    .await;
    common::seed_private_ownership(&pool, private_id, owner).await;
    let public_id = seed_claim_full(
        &pool,
        PUBLIC_BODY,
        owner,
        Some(&vec_literal),
        Some(theme_id),
        &[],
    )
    .await;
    // Makes the private claim a graph neighbour of the public one, so the same
    // text is reachable through the nested `graph_neighbors[].statement` too.
    common::insert_edge(&pool, public_id, private_id, "claim", "claim", "supports").await;

    let body = serde_json::json!({
        "query": query,
        "limit": 10,
        "diverse": true,
        "max_themes": 1,
        "centroid_dim": 1536
    });

    let neighbor_statement = |body: &Value| -> String {
        let results = body["results"].as_array().expect("results array");
        let parent = results
            .iter()
            .find(|r| r["claim_id"].as_str() == Some(public_id.to_string().as_str()))
            .expect("public claim selected in diverse mode");
        let neighbors = parent["graph_neighbors"]
            .as_array()
            .unwrap_or_else(|| panic!("public claim has no graph_neighbors: {parent}"));
        neighbors
            .iter()
            .find(|n| n["claim_id"].as_str() == Some(private_id.to_string().as_str()))
            .expect("private claim present as a graph neighbour")["statement"]
            .as_str()
            .expect("neighbour statement is a string")
            .to_string()
    };

    let resp = client()
        .post(format!("http://{addr}/api/v1/search/semantic"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let anon: Value = resp.json().await.unwrap();
    assert_eq!(
        anon["centroid_dim_used"].as_u64(),
        Some(1536),
        "the diverse path must have run, otherwise this test proves nothing"
    );
    assert_eq!(
        field_for(&anon, "results", "claim_id", private_id, "statement"),
        "[REDACTED]",
        "anonymous diverse search must not return private claim text"
    );
    assert_eq!(
        field_for(&anon, "results", "claim_id", public_id, "statement"),
        PUBLIC_BODY
    );
    assert_eq!(
        neighbor_statement(&anon),
        "[REDACTED]",
        "private claim text must not leak through graph_neighbors either"
    );

    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let resp = client()
        .post(format!("http://{addr}/api/v1/search/semantic"))
        .bearer_auth(&owner_token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let owned: Value = resp.json().await.unwrap();
    assert_eq!(
        field_for(&owned, "results", "claim_id", private_id, "statement"),
        PRIVATE_BODY
    );
    assert_eq!(neighbor_statement(&owned), PRIVATE_BODY);
}

// ---------------------------------------------------------------------------
// GET /api/v1/claims/by-labels
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn claims_by_labels_redacts_private_for_non_owner_only() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    // A label unique to this run, so the page holds exactly the two seeds.
    let label = format!("sweep-{}", Uuid::new_v4().simple());

    let private_id = seed_claim_full(&pool, PRIVATE_BODY, owner, None, None, &[&label]).await;
    common::seed_private_ownership(&pool, private_id, owner).await;
    let public_id = seed_claim_full(&pool, PUBLIC_BODY, owner, None, None, &[&label]).await;

    let url = format!("http://{addr}/api/v1/claims/by-labels?labels={label}&limit=100");
    let content_of = |body: &Value, id: Uuid| {
        let rows = body.as_array().expect("bare array of claims");
        let wrapped = serde_json::json!({ "items": rows });
        field_for(&wrapped, "items", "id", id, "content")
    };

    let anon: Value = client()
        .get(&url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        content_of(&anon, private_id),
        "[REDACTED]",
        "anonymous by-labels must not return private claim content"
    );
    assert_eq!(content_of(&anon, public_id), PUBLIC_BODY);

    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let owned: Value = client()
        .get(&url)
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(content_of(&owned, private_id), PRIVATE_BODY);
}

// ---------------------------------------------------------------------------
// GET /api/v1/claims/:id/history
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn claim_history_redacts_private_version_for_non_owner_only() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();

    // v1 public, v2 private: each version carries its own ownership row, so the
    // response must be redacted per version, not per requested claim.
    let v1 = seed_claim_full(&pool, PUBLIC_BODY, owner, None, None, &[]).await;
    let v2 = seed_claim_full(&pool, PRIVATE_BODY, owner, None, None, &[]).await;
    sqlx::query("UPDATE claims SET supersedes = $1, is_current = true WHERE id = $2")
        .bind(v1)
        .bind(v2)
        .execute(&pool)
        .await
        .expect("link v2 -> v1");
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(v1)
        .execute(&pool)
        .await
        .expect("retire v1");
    common::seed_private_ownership(&pool, v2, owner).await;

    let url = format!("http://{addr}/api/v1/claims/{v2}/history");
    let content_of =
        |body: &Value, id: Uuid| field_for(body, "versions", "claim_id", id, "content");

    let anon: Value = client()
        .get(&url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        content_of(&anon, v2),
        "[REDACTED]",
        "anonymous history must not return the private version's content"
    );
    assert_eq!(
        content_of(&anon, v1),
        PUBLIC_BODY,
        "the public version in the same chain must be untouched"
    );

    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let owned: Value = client()
        .get(&url)
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(content_of(&owned, v2), PRIVATE_BODY);

    // Leave no supersedes chain behind for the cycle-guard tests that share
    // this database.
    sqlx::query("UPDATE claims SET supersedes = NULL WHERE id = $1")
        .bind(v2)
        .execute(&pool)
        .await
        .expect("unlink v2");
}

// ---------------------------------------------------------------------------
// GET /api/v1/agents/:id/claims
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn agent_claims_redacts_private_for_non_owner_only() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    // A fresh attribution target, so the page holds exactly the two seeds.
    let subject = Uuid::new_v4();
    ensure_agent(&pool, subject).await;

    let private_id = seed_claim_full(&pool, PRIVATE_BODY, owner, None, None, &[]).await;
    common::seed_private_ownership(&pool, private_id, owner).await;
    let public_id = seed_claim_full(&pool, PUBLIC_BODY, owner, None, None, &[]).await;
    for claim in [private_id, public_id] {
        common::insert_edge(&pool, claim, subject, "claim", "agent", "ATTRIBUTED_TO").await;
    }

    // `AttributedClaimResponse` flattens `ClaimResponse`, so `id`/`content` sit
    // on the item itself rather than under a `claim` key.
    let url = format!("http://{addr}/api/v1/agents/{subject}/claims?limit=100");
    let content_of = |body: &Value, id: Uuid| field_for(body, "items", "id", id, "content");

    let anon: Value = client()
        .get(&url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        content_of(&anon, private_id),
        "[REDACTED]",
        "anonymous agent-claims must not return private claim content"
    );
    assert_eq!(content_of(&anon, public_id), PUBLIC_BODY);

    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let owned: Value = client()
        .get(&url)
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(content_of(&owned, private_id), PRIVATE_BODY);
}

// ---------------------------------------------------------------------------
// GET /api/v1/frames/:id/claims
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn frame_claims_keeps_public_content_after_batching() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    common::ensure_frame_properties_column(&pool).await;
    let owner = Uuid::new_v4();

    let private_id = seed_claim_full(&pool, PRIVATE_BODY, owner, None, None, &[]).await;
    let public_id = seed_claim_full(&pool, PUBLIC_BODY, owner, None, None, &[]).await;
    let frame_id = common::seed_frame_with_claim(&pool, private_id).await;
    sqlx::query("INSERT INTO claim_frames (claim_id, frame_id) VALUES ($1, $2)")
        .bind(public_id)
        .bind(frame_id)
        .execute(&pool)
        .await
        .expect("assign public claim to frame");
    common::seed_private_ownership(&pool, private_id, owner).await;

    let url = format!("http://{addr}/api/v1/frames/{frame_id}/claims?limit=100");
    let content_of = |body: &Value, id: Uuid| {
        let wrapped = serde_json::json!({ "items": body.as_array().expect("bare array") });
        field_for(&wrapped, "items", "claim_id", id, "content")
    };

    let anon: Value = client()
        .get(&url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(content_of(&anon, private_id), "[REDACTED]");
    assert_eq!(
        content_of(&anon, public_id),
        PUBLIC_BODY,
        "batching the per-row check must not over-redact the public row"
    );

    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let owned: Value = client()
        .get(&url)
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(content_of(&owned, private_id), PRIVATE_BODY);
}

// ---------------------------------------------------------------------------
// GET /api/v1/graph/communities/:id/expand
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn communities_expand_redacts_node_label_for_non_owner_only() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    wipe_cluster_run_fixtures(&pool).await;
    let owner = Uuid::new_v4();

    let private_id = seed_claim_full(&pool, PRIVATE_BODY, owner, None, None, &[]).await;
    common::seed_private_ownership(&pool, private_id, owner).await;
    let public_id = seed_claim_full(&pool, PUBLIC_BODY, owner, None, None, &[]).await;

    let run_id = Uuid::new_v4();
    let cluster_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 1, FALSE)",
    )
    .bind(run_id)
    .execute(&pool)
    .await
    .expect("seed run");
    sqlx::query(
        "INSERT INTO graph_clusters \
             (id, run_id, label, size, mean_betp, dominant_type, dominant_frame_id, degraded) \
         VALUES ($1, $2, 'sweep', 2, 0.5, 'claim', NULL, FALSE)",
    )
    .bind(cluster_id)
    .bind(run_id)
    .execute(&pool)
    .await
    .expect("seed cluster");
    for claim in [private_id, public_id] {
        sqlx::query(
            "INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id) \
             VALUES ($1, $2, $3)",
        )
        .bind(claim)
        .bind(cluster_id)
        .bind(run_id)
        .execute(&pool)
        .await
        .expect("seed membership");
    }

    let url = format!("http://{addr}/api/v1/graph/communities/{cluster_id}/expand");
    let label_of = |body: &Value, id: Uuid| field_for(body, "nodes", "id", id, "label");

    // Protected router: no bearer is a hard 401, so the discriminating
    // non-owner here is a stranger token rather than an anonymous call.
    let resp = client().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 401, "expand is on the protected router");

    let stranger = common::mint_token_with_agent(&["graph:read"], Uuid::new_v4());
    let body: Value = client()
        .get(&url)
        .bearer_auth(&stranger)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        label_of(&body, private_id),
        "[REDACTED]",
        "a stranger must not read private claim text through a cluster node label"
    );
    assert_eq!(label_of(&body, public_id), PUBLIC_BODY);

    let owner_token = common::mint_token_with_agent(&["graph:read"], owner);
    let owned: Value = client()
        .get(&url)
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(label_of(&owned, private_id), PRIVATE_BODY);
}

// ---------------------------------------------------------------------------
// GET /api/v1/graph/neighborhoods/:id/expand — compound and atomic
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn neighborhoods_expand_redacts_labels_in_both_modes() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    wipe_cluster_run_fixtures(&pool).await;
    let owner = Uuid::new_v4();

    let run_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 0, FALSE)",
    )
    .bind(run_id)
    .execute(&pool)
    .await
    .expect("seed run");
    let theme_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claim_themes (id, label, description, claim_count) \
         VALUES ($1, 'sweep-neighborhood', '', 0)",
    )
    .bind(theme_id)
    .execute(&pool)
    .await
    .expect("seed theme");

    // A private compound parent over one private and one public atom, plus a
    // public standalone. Compound mode renders {parent, standalone}; atomic
    // mode renders {atoms..., standalone} plus the parent as a compound group.
    let parent = seed_claim_full(&pool, PRIVATE_BODY, owner, None, None, &[]).await;
    common::seed_private_ownership(&pool, parent, owner).await;
    let atom_private = seed_claim_full(&pool, PRIVATE_BODY, owner, None, None, &[]).await;
    common::seed_private_ownership(&pool, atom_private, owner).await;
    let atom_public = seed_claim_full(&pool, PUBLIC_BODY, owner, None, None, &[]).await;
    let standalone = seed_claim_full(&pool, PUBLIC_BODY, owner, None, None, &[]).await;
    for atom in [atom_private, atom_public] {
        common::insert_edge(&pool, parent, atom, "claim", "claim", "decomposes_to").await;
    }

    let nbr = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_neighborhoods \
             (id, run_id, theme_id, label, size, mean_betp, dominant_frame_id) \
         VALUES ($1, $2, $3, 'sweep', 3, NULL, NULL)",
    )
    .bind(nbr)
    .bind(run_id)
    .bind(theme_id)
    .execute(&pool)
    .await
    .expect("seed neighborhood");
    for claim in [atom_private, atom_public, standalone] {
        sqlx::query(
            "INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) \
             VALUES ($1, $2, $3)",
        )
        .bind(run_id)
        .bind(claim)
        .bind(nbr)
        .execute(&pool)
        .await
        .expect("seed membership");
    }

    let base = format!("http://{addr}/api/v1/graph/neighborhoods/{nbr}/expand");
    let stranger = common::mint_token_with_agent(&["graph:read"], Uuid::new_v4());
    let owner_token = common::mint_token_with_agent(&["graph:read"], owner);
    let get = |url: String, token: String| async move {
        let body: Value = client()
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        body
    };

    // Compound mode.
    let compound_url = format!("{base}?mode=compound");
    let body = get(compound_url.clone(), stranger.clone()).await;
    assert_eq!(
        field_for(&body, "nodes", "id", parent, "label"),
        "[REDACTED]",
        "a stranger must not read the private compound's text through its label"
    );
    assert_eq!(
        field_for(&body, "nodes", "id", standalone, "label"),
        PUBLIC_BODY
    );
    let owned = get(compound_url, owner_token.clone()).await;
    assert_eq!(
        field_for(&owned, "nodes", "id", parent, "label"),
        PRIVATE_BODY
    );

    // Atomic mode: node labels AND compound_groups[].label are claim content.
    let atomic_url = format!("{base}?mode=atomic");
    let body = get(atomic_url.clone(), stranger).await;
    assert_eq!(
        field_for(&body, "nodes", "id", atom_private, "label"),
        "[REDACTED]"
    );
    assert_eq!(
        field_for(&body, "nodes", "id", atom_public, "label"),
        PUBLIC_BODY
    );
    assert_eq!(
        field_for(&body, "compound_groups", "compound_id", parent, "label"),
        "[REDACTED]",
        "private claim text must not leak through a compound group label"
    );
    let owned = get(atomic_url, owner_token).await;
    assert_eq!(
        field_for(&owned, "nodes", "id", atom_private, "label"),
        PRIVATE_BODY
    );
    assert_eq!(
        field_for(&owned, "compound_groups", "compound_id", parent, "label"),
        PRIVATE_BODY
    );
}

// ---------------------------------------------------------------------------
// GET /api/v1/claims/:id/compound_neighborhood
//
// The sweep's blind spot: this route is on the PUBLIC router, so the
// non-owner half of the triple is a genuinely anonymous caller — and every
// `label` it emits, the centre's included, is raw `claims.content`.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn claim_compound_neighborhood_redacts_labels_for_non_owner_only() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();

    // A private centre with no `decomposes_to` children, so it is its own
    // atom, reached through `supports` (forward_strength 0.7 > 0, which is
    // what `epistemic_edges` requires).
    let center = seed_claim_full(&pool, PRIVATE_BODY, owner, None, None, &[]).await;
    common::seed_private_ownership(&pool, center, owner).await;
    let private_neighbour = seed_claim_full(&pool, PRIVATE_BODY, owner, None, None, &[]).await;
    common::seed_private_ownership(&pool, private_neighbour, owner).await;
    let public_neighbour = seed_claim_full(&pool, PUBLIC_BODY, owner, None, None, &[]).await;
    for neighbour in [private_neighbour, public_neighbour] {
        common::insert_edge(&pool, center, neighbour, "claim", "claim", "supports").await;
    }

    let url = format!("http://{addr}/api/v1/claims/{center}/compound_neighborhood");
    let label_of = |body: &Value, id: Uuid| field_for(body, "nodes", "id", id, "label");

    // Anonymous: both private labels redacted, the public one untouched.
    let resp = client().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let anon: Value = resp.json().await.unwrap();
    assert_eq!(
        label_of(&anon, private_neighbour),
        "[REDACTED]",
        "an anonymous caller must not read private claim text through a \
         compound-neighbourhood node label"
    );
    assert_eq!(
        label_of(&anon, center),
        "[REDACTED]",
        "the centre's label is `claims.content` too and is redacted the same way"
    );
    assert_eq!(
        label_of(&anon, public_neighbour),
        PUBLIC_BODY,
        "public claim text must survive the sweep"
    );

    // A stranger's token buys nothing: the check is on the authenticated agent.
    let stranger = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let other: Value = client()
        .get(&url)
        .bearer_auth(&stranger)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(label_of(&other, private_neighbour), "[REDACTED]");
    assert_eq!(label_of(&other, center), "[REDACTED]");

    // Owner token: the real text, so this cannot pass by redacting everything.
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let owned: Value = client()
        .get(&url)
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(label_of(&owned, private_neighbour), PRIVATE_BODY);
    assert_eq!(label_of(&owned, center), PRIVATE_BODY);
    assert_eq!(label_of(&owned, public_neighbour), PUBLIC_BODY);
}
