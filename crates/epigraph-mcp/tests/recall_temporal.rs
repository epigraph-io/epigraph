//! Temporal recall (backlog claim `03bb1479-ec73-43fb-b5f3-2b991d3efa91`):
//! `created_at` on every recall hit, plus an optional `since:` window that
//! narrows the CANDIDATE POOL — not the returned page — on every surface that
//! can put a row into the top-level `results` array.
//!
//! ## Why every params struct here is built from `serde_json::from_value`
//!
//! This whole file must COMPILE against `origin/main`, where `since` does not
//! exist. `RecallParams`/`RecallWithContextParams` do not use
//! `deny_unknown_fields`, so a `since` key deserialises fine on both sides —
//! it is simply *ignored* on main. That makes every assertion below a
//! behavioural one: on main these tests fail on an assertion (the pre-window
//! claim comes back), not on a compile error. A compile error would prove
//! nothing about behaviour, so struct literals are deliberately avoided.
//!
//! ## The seven candidate-producing surfaces
//!
//! A window is only real if it is honoured everywhere a row can reach
//! `results`. Each `no_leak_s*` test pins one:
//!
//! | Test | Surface |
//! |---|---|
//! | `no_leak_s1_s2_hybrid_dense_and_lexical` | `search_hybrid_scoped` dense + lex CTEs |
//! | `no_leak_s3_lexical_when_embedder_down`  | `search_lexical_scoped` (degrade path) |
//! | `no_leak_s4_workflows`                   | `WorkflowRepository::search_by_goal_embedding` |
//! | `no_leak_s5_context_flat_ann`            | `search_by_embedding` (level=2 flat ANN) |
//! | `no_leak_s6_diverse_themes`              | `claims_in_themes_at_dim` via `run_diverse_pipeline` |
//! | `no_leak_s7_graph_expansion`             | `apply_graph_expansion` / `graph_expand_seeds` |
//!
//! Each asserts the disjunction the criterion allows: EITHER every top-level
//! hit satisfies `created_at >= since`, OR the call was rejected with an error
//! naming `since` and the incompatible option. What neither branch permits is
//! a successful call that silently ignores the window — the failure mode the
//! existing `paper_doi_filter`-on-diverse `TODO(diverse-recall)` already
//! exhibits, which this feature must not repeat.

#[path = "viewer_fixture.rs"]
mod fixture;

#[rustfmt::skip]
use epigraph_mcp::tools::memory::__test_only::recall_with_pgvec;
#[rustfmt::skip]
use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

// ── Fixture epochs ────────────────────────────────────────────────────────
//
// Three fixed instants, so "old", "since" and "recent" are unambiguous and
// the tests do not depend on wall-clock time.

fn epoch_old() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap()
}

fn epoch_cut() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap()
}

fn epoch_recent() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 10, 9, 30, 0).unwrap()
}

// ── Vector fixtures ───────────────────────────────────────────────────────

const DIM: usize = 1536;
const N_BUCKETS: usize = 8;
const STRIDE: usize = DIM / N_BUCKETS;

fn vec_to_pgvec(v: &[f32]) -> String {
    let inner: Vec<String> = v.iter().map(std::string::ToString::to_string).collect();
    format!("[{}]", inner.join(","))
}

/// Unit-ish vector concentrated in `bucket`. Same-bucket vectors are highly
/// cosine-similar; different-bucket vectors are orthogonal.
fn cluster_pgvec(bucket: usize) -> String {
    let mut v = vec![0.0f32; DIM];
    for slot in v
        .iter_mut()
        .take((bucket + 1) * STRIDE)
        .skip(bucket * STRIDE)
    {
        *slot = 1.0;
    }
    vec_to_pgvec(&v)
}

/// Vector in the query's bucket (0) with `drift` bled into bucket 7.
/// `cos = 1 / sqrt(1 + drift²)` — strictly decreasing in `drift`, so this is
/// how a seed is given a deliberately WEAKER similarity than another. Scaling
/// magnitude alone would not work: cosine is direction-only.
fn drifted_pgvec(drift: f32) -> String {
    let mut v = vec![0.0f32; DIM];
    for slot in v.iter_mut().take(STRIDE) {
        *slot = 1.0;
    }
    for slot in v.iter_mut().take(8 * STRIDE).skip(7 * STRIDE) {
        *slot = drift;
    }
    vec_to_pgvec(&v)
}

// ── Seeding ───────────────────────────────────────────────────────────────

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'recall-temporal', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

fn hash_for(id: Uuid) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[..16].copy_from_slice(id.as_bytes());
    h
}

/// A plain (non-paragraph) current claim with an embedding — reachable by
/// `recall`'s dense leg AND, when `content` matches the tsquery, its lex leg.
async fn seed_claim_at(
    pool: &PgPool,
    agent: Uuid,
    id: Uuid,
    content: &str,
    pgvec: &str,
    created_at: DateTime<Utc>,
) -> Uuid {
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             labels, embedding, created_at) \
         VALUES ($1, $2, $3, $4, 0.8, true, ARRAY['temporalfixture'], $5::vector, $6)",
    )
    .bind(id)
    .bind(content)
    .bind(hash_for(id))
    .bind(agent)
    .bind(pgvec)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn seed_paper(pool: &PgPool, doi: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO papers (id, doi, title) VALUES (gen_random_uuid(), $1, 'temporal fixture') \
         RETURNING id",
    )
    .bind(doi)
    .fetch_one(pool)
    .await
    .expect("seed paper")
}

/// A level=2 paragraph claim — the unit `recall_with_context` retrieves.
/// The `asserts` paper edge is required or the enrichment pipeline drops it.
#[allow(clippy::too_many_arguments)]
async fn seed_paragraph_at(
    pool: &PgPool,
    agent: Uuid,
    paper: Uuid,
    id: Uuid,
    content: &str,
    pgvec: &str,
    created_at: DateTime<Utc>,
    theme_id: Option<Uuid>,
) -> Uuid {
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             properties, embedding, created_at, theme_id) \
         VALUES ($1, $2, $3, $4, 0.8, true, jsonb_build_object('level', 2::int), \
                 $5::vector, $6, $7)",
    )
    .bind(id)
    .bind(content)
    .bind(hash_for(id))
    .bind(agent)
    .bind(pgvec)
    .bind(created_at)
    .bind(theme_id)
    .execute(pool)
    .await
    .expect("seed paragraph");

    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(paper)
    .bind(id)
    .execute(pool)
    .await
    .expect("seed paper edge");
    id
}

async fn seed_edge(pool: &PgPool, from: Uuid, to: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3)",
    )
    .bind(from)
    .bind(to)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
}

async fn seed_theme(pool: &PgPool, label: &str, pgvec: &str) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ($1, 'temporal fixture') \
         RETURNING id",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .expect("seed theme");
    sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
        .bind(id)
        .bind(pgvec)
        .execute(pool)
        .await
        .expect("set centroid");
    id
}

async fn seed_workflow_at(
    pool: &PgPool,
    goal: &str,
    pgvec: &str,
    created_at: DateTime<Utc>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, metadata, truth_value, \
                                goal_embedding, created_at) \
         VALUES ($1, $2, 0, $3, '{}'::jsonb, 1.0, $4::vector, $5)",
    )
    .bind(id)
    .bind(format!("wf-{id}"))
    .bind(goal)
    .bind(pgvec)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

fn build_test_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    // Mock embedder (no API key in CI) — tests drive the pgvec seams directly.
    EpiGraphMcpFull::new(
        pool.clone(),
        signer,
        McpEmbedder::new(pool, None),
        /*read_only=*/ false,
    )
}

// ── Result plumbing ───────────────────────────────────────────────────────

fn envelope(result: &rmcp::model::CallToolResult) -> Value {
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    serde_json::from_str(&text).expect("parse envelope")
}

fn results_of(result: &rmcp::model::CallToolResult) -> Vec<Value> {
    envelope(result)["results"]
        .as_array()
        .expect("results array")
        .clone()
}

/// Either the tool returned a page, or it refused the combination outright.
/// Both are permitted by the no-leak criterion; silently ignoring the window
/// is not.
enum Outcome {
    Page(Vec<Value>),
    Gated(String),
}

fn outcome<E: std::fmt::Debug>(r: Result<rmcp::model::CallToolResult, E>) -> Outcome {
    match r {
        Ok(ok) => Outcome::Page(results_of(&ok)),
        Err(e) => Outcome::Gated(format!("{e:?}")),
    }
}

fn created_at_of(hit: &Value, surface: &str) -> DateTime<Utc> {
    let raw = hit["created_at"].as_str().unwrap_or_else(|| {
        panic!(
            "{surface}: a hit came back with no `created_at` string ({hit}). \
             A windowed recall must not return rows whose creation time is \
             unknown — \"unknown\" is not \"in range\"."
        )
    });
    DateTime::parse_from_rfc3339(raw)
        .unwrap_or_else(|e| panic!("{surface}: created_at {raw:?} is not RFC3339: {e}"))
        .with_timezone(&Utc)
}

/// The universal property: EVERY top-level hit satisfies the window.
///
/// `incompatible` is the option name a REFUSAL would have to name alongside
/// `since` (e.g. `"diverse"`, `"graph_expansion_depth"`). The current
/// implementation filters rather than gates, so the `Gated` arm never fires in
/// this suite — it exists so a future implementation that legitimately takes
/// the pre-registered "documented and gated" branch is still held to a bar.
/// That bar is deliberately more than `msg.contains("since")`: an unrelated
/// internal error whose Debug text happens to mention `since` must not pass
/// for a deliberate refusal, so the message must ALSO name the incompatible
/// option and carry the `invalid_params` code that distinguishes "you asked
/// for something I do not support" from "I broke".
fn assert_window_honoured(surface: &str, o: &Outcome, since: DateTime<Utc>, incompatible: &str) {
    match o {
        Outcome::Gated(msg) => {
            assert!(
                msg.contains("since") && msg.contains(incompatible),
                "{surface}: the call was refused, which is allowed ONLY if the \
                 error names BOTH `since` and the incompatible option \
                 `{incompatible}`. Got: {msg}"
            );
            assert!(
                msg.contains("invalid_params") || msg.contains("InvalidParams"),
                "{surface}: a refusal must be an `invalid_params` error — an \
                 internal error that merely mentions `since` is a failure, not \
                 a documented gate. Got: {msg}"
            );
        }
        Outcome::Page(hits) => {
            for hit in hits {
                let ts = created_at_of(hit, surface);
                assert!(
                    ts >= since,
                    "{surface}: top-level hit created {ts} predates since={since}. \
                     The window leaked on this surface."
                );
            }
        }
    }
}

/// Guard against a vacuously-green no-leak test: a surface that returns
/// nothing satisfies "every hit is in-window" for free.
fn assert_contains(surface: &str, o: &Outcome, id: Uuid, id_field: &str) {
    if let Outcome::Page(hits) = o {
        let ids: Vec<&str> = hits.iter().filter_map(|h| h[id_field].as_str()).collect();
        assert!(
            ids.contains(&id.to_string().as_str()),
            "{surface}: the in-window seed {id} is missing from {ids:?}. \
             The window must narrow the candidate pool, not empty the answer."
        );
    }
}

fn assert_excludes(surface: &str, o: &Outcome, id: Uuid, id_field: &str) {
    if let Outcome::Page(hits) = o {
        let ids: Vec<&str> = hits.iter().filter_map(|h| h[id_field].as_str()).collect();
        assert!(
            !ids.contains(&id.to_string().as_str()),
            "{surface}: pre-window claim {id} leaked into top-level results {ids:?}"
        );
    }
}

fn recall_params(extra: Value) -> epigraph_mcp::types::RecallParams {
    let mut base = json!({
        "query": "grendlewick",
        "min_truth": 0.0,
        "limit": 50,
        "tags": ["temporalfixture"],
    });
    merge(&mut base, extra);
    serde_json::from_value(base).expect("RecallParams")
}

fn context_params(extra: Value) -> epigraph_mcp::tools::recall::RecallWithContextParams {
    let mut base = json!({
        "query": "grendlewick",
        "min_truth": 0.0,
        "limit": 20,
        "centroid_dim": 1536,
    });
    merge(&mut base, extra);
    serde_json::from_value(base).expect("RecallWithContextParams")
}

fn merge(base: &mut Value, extra: Value) {
    let (Value::Object(b), Value::Object(e)) = (base, extra) else {
        panic!("merge expects objects");
    };
    for (k, v) in e {
        b.insert(k, v);
    }
}

// ── G4: the decider — red on origin/main, green on the branch ─────────────

/// Seeds one pre-window and one in-window claim that BOTH match the query on
/// both retrieval legs, sets `since` strictly between them, and requires the
/// old one to be gone and the survivor to report a real creation time.
///
/// On `origin/main` `since` is an unknown key that serde drops, so both
/// claims come back and `created_at` is absent — this fails on assertions,
/// not on compilation, which is what makes it evidence rather than noise.
#[sqlx::test(migrations = "../../migrations")]
async fn since_excludes_older_claims_and_reports_created_at(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let old = seed_claim_at(
        &pool,
        agent,
        Uuid::from_u128(0x0100),
        "grendlewick assay, first pass",
        &cluster_pgvec(0),
        epoch_old(),
    )
    .await;
    let recent = seed_claim_at(
        &pool,
        agent,
        Uuid::from_u128(0x0101),
        "grendlewick assay, revised",
        &cluster_pgvec(0),
        epoch_recent(),
    )
    .await;
    // Sits EXACTLY on the cut. The documented semantic is "at or after this
    // instant" (`created_at >= since`); without a fixture on the boundary,
    // flipping the predicate to `>` passes the whole file, so the schemars
    // description would be the only thing pinning inclusivity. Same cluster
    // vector and same query terms as the other two, so it matches on both the
    // dense and the lexical leg and cannot fail for an unrelated reason.
    let boundary = seed_claim_at(
        &pool,
        agent,
        Uuid::from_u128(0x0102),
        "grendlewick assay, boundary pass",
        &cluster_pgvec(0),
        epoch_cut(),
    )
    .await;

    let server = build_test_server(pool);
    let out = recall_with_pgvec(
        &server, &viewer,
        recall_params(json!({ "since": epoch_cut().to_rfc3339() })),
        Some(cluster_pgvec(0)),
    )
    .await
    .expect("recall ok");
    let hits = results_of(&out);

    let ids: Vec<&str> = hits.iter().filter_map(|h| h["claim_id"].as_str()).collect();
    assert!(
        ids.contains(&recent.to_string().as_str()),
        "the in-window claim must survive the window; got {ids:?}"
    );
    assert!(
        !ids.contains(&old.to_string().as_str()),
        "the pre-window claim must be excluded; got {ids:?}"
    );
    assert!(
        ids.contains(&boundary.to_string().as_str()),
        "`since` is INCLUSIVE — a claim created at exactly since={} must be \
         returned (`created_at >= since`, \"at or after this instant\"); got {ids:?}",
        epoch_cut()
    );

    let hit = hits
        .iter()
        .find(|h| h["claim_id"] == recent.to_string())
        .expect("recent hit");
    assert_eq!(
        created_at_of(hit, "recall"),
        epoch_recent(),
        "created_at must be the claim's real creation instant"
    );
}

// ── G1: absent `since` is exactly today's behaviour ───────────────────────

/// Deterministic ids and strictly-distinct similarities (so `ORDER BY
/// rrf_score DESC`, which has no tiebreak, is stable), then the id list and
/// ORDER are pinned. The expected vector was captured by running this same
/// file against an `origin/main` worktree — it is the base behaviour, not a
/// re-derivation of the new implementation.
#[sqlx::test(migrations = "../../migrations")]
async fn since_absent_is_baseline_behaviour(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    // Distinct drifts ⇒ strictly decreasing cosine ⇒ no rrf ties.
    let a = seed_claim_at(
        &pool,
        agent,
        Uuid::from_u128(0x0201),
        "grendlewick alpha",
        &drifted_pgvec(0.0),
        epoch_old(),
    )
    .await;
    let b = seed_claim_at(
        &pool,
        agent,
        Uuid::from_u128(0x0202),
        "grendlewick beta",
        &drifted_pgvec(0.5),
        epoch_recent(),
    )
    .await;
    let c = seed_claim_at(
        &pool,
        agent,
        Uuid::from_u128(0x0203),
        "grendlewick gamma",
        &drifted_pgvec(1.5),
        epoch_old(),
    )
    .await;

    let server = build_test_server(pool);
    let out = recall_with_pgvec(&server, &viewer, recall_params(json!({})), Some(cluster_pgvec(0)))
        .await
        .expect("recall ok");
    let hits = results_of(&out);
    let ids: Vec<String> = hits
        .iter()
        .map(|h| h["claim_id"].as_str().unwrap().to_string())
        .collect();

    // Pinned baseline: dense rank follows cosine (a > b > c), and every claim
    // matches the lexical leg equally, so RRF preserves the dense order.
    assert_eq!(
        ids,
        vec![a.to_string(), b.to_string(), c.to_string()],
        "with `since` absent the id list AND order must match origin/main exactly"
    );

    // `RecallResult::created_at` documents itself as "surfaced on every hit
    // whether or not `since` was supplied" — the whole point being that a
    // caller can arbitrate between a stale and a current memory WITHOUT
    // asking for a window. Asserting it only on windowed pages would let an
    // implementation tie the field's presence to `since` and stay green.
    let seen: Vec<DateTime<Utc>> = hits
        .iter()
        .map(|h| created_at_of(h, "recall (no since)"))
        .collect();
    assert_eq!(
        seen,
        vec![epoch_old(), epoch_recent(), epoch_old()],
        "every unwindowed hit must carry its own real creation instant"
    );
}

// ── G3 / BCH-J02: created_at is creation, not last-touch ──────────────────

/// `batch_update_truth_values` ends with `..., updated_at = NOW() WHERE id IN
/// (...)` — a nightly `recompute_beliefs` therefore rewrites `updated_at`
/// corpus-wide without changing any content. An implementation that reads or
/// filters on `updated_at` would report the whole corpus as newly created.
#[sqlx::test(migrations = "../../migrations")]
async fn created_at_is_creation_not_update(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    use epigraph_core::{ClaimId, TruthValue};

    let agent = seed_agent(&pool).await;
    let id = seed_claim_at(
        &pool,
        agent,
        Uuid::from_u128(0x0301),
        "grendlewick provenance",
        &cluster_pgvec(0),
        epoch_old(),
    )
    .await;

    // Belief recomputation: bumps updated_at to NOW(), content untouched.
    epigraph_db::ClaimRepository::batch_update_truth_values(
        &pool,
        &[(ClaimId::from_uuid(id), TruthValue::new(0.9).unwrap())],
    )
    .await
    .expect("batch_update_truth_values");

    let (created, updated): (DateTime<Utc>, DateTime<Utc>) =
        sqlx::query_as("SELECT created_at, updated_at FROM claims WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("read timestamps");
    assert!(
        updated > created,
        "fixture precondition: the recompute must have moved updated_at ({updated}) \
         past created_at ({created})"
    );

    let server = build_test_server(pool);

    // (a) The reported timestamp is still the creation instant.
    let out = recall_with_pgvec(&server, &viewer, recall_params(json!({})), Some(cluster_pgvec(0)))
        .await
        .expect("recall ok");
    let hits = results_of(&out);
    let hit = hits
        .iter()
        .find(|h| h["claim_id"] == id.to_string())
        .expect("claim recalled");
    assert_eq!(
        created_at_of(hit, "recall"),
        epoch_old(),
        "created_at tracked updated_at — a recomputed belief must not look newly created"
    );

    // (b) The FILTER column is `created_at`, decided on its own rather than
    //     by accident. The discriminating fixture is
    //     `created_at < since <= updated_at`: the claim was created in 2024,
    //     the recompute above moved `updated_at` to now, and the cut sits at
    //     2025-06-01 — strictly between them. Under `created_at >= since` the
    //     claim is excluded; under `updated_at >= since` it is admitted. Any
    //     `since` at `Utc::now()+1s` would be past BOTH columns and therefore
    //     could not tell the two predicates apart.
    let cut = epoch_cut();
    assert!(
        created < cut && cut <= updated,
        "fixture precondition: the cut {cut} must sit strictly between \
         created_at ({created}) and updated_at ({updated}), or part (b) cannot \
         discriminate the two columns"
    );
    let out = recall_with_pgvec(
        &server, &viewer,
        recall_params(json!({ "since": cut.to_rfc3339() })),
        Some(cluster_pgvec(0)),
    )
    .await
    .expect("recall ok");
    let ids: Vec<String> = results_of(&out)
        .iter()
        .filter_map(|h| h["claim_id"].as_str())
        .map(str::to_owned)
        .collect();
    assert!(
        !ids.contains(&id.to_string()),
        "a claim whose updated_at is inside the window but whose created_at is \
         not must be excluded; filtering on updated_at returns {ids:?}"
    );
}

// ── G5 / BCH-J01: the window must precede the candidate LIMIT ─────────────

/// `HYBRID_CANDIDATE_POOL` is 50 per leg. This seeds 60 pre-window claims that
/// dominate BOTH legs (higher cosine AND higher `ts_rank_cd`, the latter via
/// term repetition) plus one in-window claim that is a weaker but real match
/// on both.
///
/// A post-filter over the returned `Vec<HybridHit>` gives `[]` here: the pool
/// is consumed entirely by pre-window rows and then discarded. Empty reads to
/// the caller as "nothing changed" — the exact inversion of the truth, which
/// is why this is the deciding test rather than a nice-to-have.
#[sqlx::test(migrations = "../../migrations")]
async fn since_survives_candidate_pool_saturation(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // 60 > HYBRID_CANDIDATE_POOL (50), so each leg saturates on old rows.
    for i in 0..60u128 {
        seed_claim_at(
            &pool,
            agent,
            Uuid::from_u128(0x0400 + i),
            // Repeated term ⇒ higher ts_rank_cd than the single-mention
            // recent claim, so the LEXICAL leg saturates too. Filtering only
            // the dense CTE would still let the lex leg answer, and the test
            // would pass over a half-done implementation.
            "grendlewick grendlewick grendlewick grendlewick saturation filler",
            &cluster_pgvec(0),
            epoch_old(),
        )
        .await;
    }

    let recent = seed_claim_at(
        &pool,
        agent,
        Uuid::from_u128(0x04FF),
        "grendlewick, weaker but current",
        &drifted_pgvec(1.2), // strictly lower cosine than the 60 above
        epoch_recent(),
    )
    .await;

    let server = build_test_server(pool);
    let out = recall_with_pgvec(
        &server, &viewer,
        recall_params(json!({ "since": epoch_cut().to_rfc3339(), "limit": 10 })),
        Some(cluster_pgvec(0)),
    )
    .await
    .expect("recall ok");
    let hits = results_of(&out);
    let ids: Vec<&str> = hits.iter().filter_map(|h| h["claim_id"].as_str()).collect();

    assert!(
        ids.contains(&recent.to_string().as_str()),
        "the only in-window claim was not returned (got {ids:?}). A candidate \
         pool of 50 per leg was saturated by 60 pre-window claims, so the \
         window was applied AFTER the LIMIT instead of inside it — the caller \
         is told nothing changed when something did."
    );
    assert_eq!(ids.len(), 1, "exactly one claim is in-window; got {ids:?}");
}

// ── G6: no leak, surface by surface ───────────────────────────────────────

/// S1 (dense CTE) + S2 (lex CTE) of `search_hybrid_scoped`.
#[sqlx::test(migrations = "../../migrations")]
async fn no_leak_s1_s2_hybrid_dense_and_lexical(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    // Dense-only match (no query term in content): reachable via S1 alone.
    let old_dense = seed_claim_at(
        &pool,
        agent,
        Uuid::from_u128(0x0501),
        "vector-only neighbour, no shared term",
        &cluster_pgvec(0),
        epoch_old(),
    )
    .await;
    // Lexical-only match (no embedding): reachable via S2 alone.
    let old_lex = Uuid::from_u128(0x0502);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             labels, created_at) \
         VALUES ($1, 'grendlewick lexical only', $2, $3, 0.8, true, \
                 ARRAY['temporalfixture'], $4)",
    )
    .bind(old_lex)
    .bind(hash_for(old_lex))
    .bind(agent)
    .bind(epoch_old())
    .execute(&pool)
    .await
    .expect("seed lexical-only claim");

    let recent = seed_claim_at(
        &pool,
        agent,
        Uuid::from_u128(0x0503),
        "grendlewick current entry",
        &cluster_pgvec(0),
        epoch_recent(),
    )
    .await;

    let server = build_test_server(pool);
    let o = outcome(
        recall_with_pgvec(
            &server, &viewer,
            recall_params(json!({ "since": epoch_cut().to_rfc3339() })),
            Some(cluster_pgvec(0)),
        )
        .await,
    );

    assert_window_honoured("S1+S2 hybrid", &o, epoch_cut(), "query");
    assert_contains("S1+S2 hybrid", &o, recent, "claim_id");
    assert_excludes("S1+S2 hybrid", &o, old_dense, "claim_id");
    assert_excludes("S1+S2 hybrid", &o, old_lex, "claim_id");
}

/// S3: the embedder-down degrade path (`search_lexical_scoped`). Driven by
/// passing `None` for the pgvector, exactly as `recall` does when
/// `embedder.generate` fails.
#[sqlx::test(migrations = "../../migrations")]
async fn no_leak_s3_lexical_when_embedder_down(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let old = seed_claim_at(
        &pool,
        agent,
        Uuid::from_u128(0x0601),
        "grendlewick legacy note",
        &cluster_pgvec(0),
        epoch_old(),
    )
    .await;
    let recent = seed_claim_at(
        &pool,
        agent,
        Uuid::from_u128(0x0602),
        "grendlewick current note",
        &cluster_pgvec(0),
        epoch_recent(),
    )
    .await;

    let server = build_test_server(pool);
    let o = outcome(
        recall_with_pgvec(
            &server, &viewer,
            recall_params(json!({ "since": epoch_cut().to_rfc3339() })),
            None, // embedder down ⇒ lexical-only
        )
        .await,
    );

    assert_window_honoured("S3 lexical degrade", &o, epoch_cut(), "query");
    assert_contains("S3 lexical degrade", &o, recent, "claim_id");
    assert_excludes("S3 lexical degrade", &o, old, "claim_id");
}

/// S4: `include_workflows=true` merges `workflows` rows into the SAME results
/// array. They are not claims, so they have no `claims.created_at` — the
/// naive fix is `created_at: Utc::now()`, which makes every workflow the
/// newest thing in the corpus. This pins the genuine `workflows.created_at`
/// and requires the window to apply to that leg too.
#[sqlx::test(migrations = "../../migrations")]
async fn no_leak_s4_workflows(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let claim = seed_claim_at(
        &pool,
        agent,
        Uuid::from_u128(0x0701),
        "grendlewick claim leg",
        &cluster_pgvec(0),
        epoch_recent(),
    )
    .await;
    let old_wf = seed_workflow_at(&pool, "archival routine", &cluster_pgvec(0), epoch_old()).await;
    let new_wf =
        seed_workflow_at(&pool, "current routine", &cluster_pgvec(0), epoch_recent()).await;

    let server = build_test_server(pool);
    let o = outcome(
        recall_with_pgvec(
            &server, &viewer,
            recall_params(json!({
                "since": epoch_cut().to_rfc3339(),
                "include_workflows": true,
            })),
            Some(cluster_pgvec(0)),
        )
        .await,
    );

    assert_window_honoured("S4 workflows", &o, epoch_cut(), "include_workflows");
    assert_contains("S4 workflows", &o, claim, "claim_id");
    assert_excludes("S4 workflows", &o, old_wf, "claim_id");

    // The surviving workflow must report its OWN stored timestamp — not the
    // request time, not the Unix epoch.
    if let Outcome::Page(hits) = &o {
        let wf = hits
            .iter()
            .find(|h| h["claim_id"] == new_wf.to_string())
            .expect("in-window workflow returned");
        assert_eq!(
            wf["result_type"], "workflow",
            "fixture precondition: this hit came from the workflows leg"
        );
        assert_eq!(
            created_at_of(wf, "S4 workflows"),
            epoch_recent(),
            "a workflow hit must carry the real workflows.created_at, never a \
             fabricated timestamp"
        );
    }
}

/// S5: `recall_with_context`'s flat level=2 ANN (`search_by_embedding`).
#[sqlx::test(migrations = "../../migrations")]
async fn no_leak_s5_context_flat_ann(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let paper = seed_paper(&pool, "10.temporal/s5").await;
    let old = seed_paragraph_at(
        &pool,
        agent,
        paper,
        Uuid::from_u128(0x0801),
        "grendlewick paragraph, superseded reading",
        &cluster_pgvec(0),
        epoch_old(),
        None,
    )
    .await;
    let recent = seed_paragraph_at(
        &pool,
        agent,
        paper,
        Uuid::from_u128(0x0802),
        "grendlewick paragraph, current reading",
        &cluster_pgvec(0),
        epoch_recent(),
        None,
    )
    .await;

    let server = build_test_server(pool);
    let o = outcome(
        recall_with_context_with_pgvec(
            &server, &viewer,
            context_params(json!({ "since": epoch_cut().to_rfc3339() })),
            1536,
            &cluster_pgvec(0),
        )
        .await,
    );

    assert_window_honoured("S5 flat ANN", &o, epoch_cut(), "query");
    assert_contains("S5 flat ANN", &o, recent, "paragraph_id");
    assert_excludes("S5 flat ANN", &o, old, "paragraph_id");
}

/// S6: the diverse pipeline pulls candidates from themes via
/// `claims_in_themes_at_dim`, bypassing `search_by_embedding` entirely — the
/// surface a "just filter the ANN SELECT" fix silently misses.
#[sqlx::test(migrations = "../../migrations")]
async fn no_leak_s6_diverse_themes(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let paper = seed_paper(&pool, "10.temporal/s6").await;
    let theme = seed_theme(&pool, "temporal-theme", &cluster_pgvec(0)).await;

    let old = seed_paragraph_at(
        &pool,
        agent,
        paper,
        Uuid::from_u128(0x0901),
        "grendlewick themed paragraph, archival",
        &cluster_pgvec(0),
        epoch_old(),
        Some(theme),
    )
    .await;
    let recent = seed_paragraph_at(
        &pool,
        agent,
        paper,
        Uuid::from_u128(0x0902),
        "grendlewick themed paragraph, current",
        &cluster_pgvec(0),
        epoch_recent(),
        Some(theme),
    )
    .await;

    let server = build_test_server(pool);
    let o = outcome(
        recall_with_context_with_pgvec(
            &server, &viewer,
            context_params(json!({
                "since": epoch_cut().to_rfc3339(),
                "diverse": true,
                "max_themes": 5,
            })),
            1536,
            &cluster_pgvec(0),
        )
        .await,
    );

    assert_window_honoured("S6 diverse", &o, epoch_cut(), "diverse");
    assert_contains("S6 diverse", &o, recent, "paragraph_id");
    assert_excludes("S6 diverse", &o, old, "paragraph_id");
}

/// S7 / BCH-J03: graph expansion folds edge-reachable claims into `raw_hits`,
/// i.e. into the top-level results. A pre-window claim reachable by a
/// `supports` edge from an in-window seed must NOT surface as a hit.
#[sqlx::test(migrations = "../../migrations")]
async fn no_leak_s7_graph_expansion(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let paper = seed_paper(&pool, "10.temporal/s7").await;

    // Seed: in-window, cosine-close to the query.
    let seed = seed_paragraph_at(
        &pool,
        agent,
        paper,
        Uuid::from_u128(0x0A01),
        "grendlewick seed paragraph",
        &cluster_pgvec(0),
        epoch_recent(),
        None,
    )
    .await;
    // Reachable in one hop, but created long before the window. Embedded in
    // an ORTHOGONAL bucket so the ONLY way it can reach the results array is
    // graph expansion — if it appears, expansion is the leak.
    let old_neighbour = seed_paragraph_at(
        &pool,
        agent,
        paper,
        Uuid::from_u128(0x0A02),
        "orthogonal archival paragraph",
        &cluster_pgvec(4),
        epoch_old(),
        None,
    )
    .await;
    seed_edge(&pool, seed, old_neighbour, "supports").await;

    let server = build_test_server(pool);

    // Precondition: without a window, expansion really does surface it —
    // otherwise the assertion below would pass for the wrong reason.
    let baseline = outcome(
        recall_with_context_with_pgvec(
            &server, &viewer,
            context_params(json!({ "graph_expansion_depth": 2, "limit": 10 })),
            1536,
            &cluster_pgvec(0),
        )
        .await,
    );
    assert_contains(
        "S7 precondition (no window)",
        &baseline,
        old_neighbour,
        "paragraph_id",
    );
    // `RecallHit::created_at` claims to be "surfaced on every hit whether or
    // not `since` was supplied". This is the only unwindowed
    // `recall_with_context` call in the file, so without this block an
    // implementation that emitted `created_at` only when `since` is set —
    // `params.since.map(|_| core.created_at)` — passes the entire suite.
    // Both hits are checked (the ANN seed and the expansion-reached
    // neighbour), because they are populated on different code paths.
    if let Outcome::Page(hits) = &baseline {
        for (id, expected) in [(seed, epoch_recent()), (old_neighbour, epoch_old())] {
            let hit = hits
                .iter()
                .find(|h| h["paragraph_id"] == id.to_string())
                .unwrap_or_else(|| panic!("S7 precondition: {id} missing from the page"));
            assert_eq!(
                created_at_of(hit, "S7 precondition (no window)"),
                expected,
                "an unwindowed recall_with_context hit must still report its \
                 real creation instant"
            );
        }
    }

    let o = outcome(
        recall_with_context_with_pgvec(
            &server, &viewer,
            context_params(json!({
                "since": epoch_cut().to_rfc3339(),
                "graph_expansion_depth": 2,
                "limit": 10,
            })),
            1536,
            &cluster_pgvec(0),
        )
        .await,
    );

    assert_window_honoured(
        "S7 graph expansion",
        &o,
        epoch_cut(),
        "graph_expansion_depth",
    );
    assert_contains("S7 graph expansion", &o, seed, "paragraph_id");
    assert_excludes("S7 graph expansion", &o, old_neighbour, "paragraph_id");
}

// ── G7: context enrichment is exempt, on purpose ──────────────────────────

/// The window constrains HITS, not the context hanging off them. A two-year-old
/// supporting paragraph is exactly what a caller needs in order to see why a
/// claim created yesterday is believed; filtering it would remove information
/// rather than offer it.
#[sqlx::test(migrations = "../../migrations")]
async fn context_is_exempt_from_since(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let paper = seed_paper(&pool, "10.temporal/g7").await;

    let recent = seed_paragraph_at(
        &pool,
        agent,
        paper,
        Uuid::from_u128(0x0B01),
        "grendlewick current finding",
        &cluster_pgvec(0),
        epoch_recent(),
        None,
    )
    .await;
    // Same section ⇒ a SIBLING of `recent`, and far older than the window.
    let old_sibling = seed_paragraph_at(
        &pool,
        agent,
        paper,
        Uuid::from_u128(0x0B02),
        "older supporting passage",
        &cluster_pgvec(5),
        epoch_old(),
        None,
    )
    .await;
    // A level=1 section parent linking the two.
    let section = Uuid::from_u128(0x0B03);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             properties, created_at) \
         VALUES ($1, 'section', $2, $3, 0.8, true, jsonb_build_object('level', 1::int), $4)",
    )
    .bind(section)
    .bind(hash_for(section))
    .bind(agent)
    .bind(epoch_old())
    .execute(&pool)
    .await
    .expect("seed section");
    seed_edge(&pool, section, recent, "decomposes_to").await;
    seed_edge(&pool, section, old_sibling, "decomposes_to").await;

    let server = build_test_server(pool);
    let out = recall_with_context_with_pgvec(
        &server, &viewer,
        context_params(json!({ "since": epoch_cut().to_rfc3339() })),
        1536,
        &cluster_pgvec(0),
    )
    .await
    .expect("recall_with_context ok");
    let hits = results_of(&out);

    let hit = hits
        .iter()
        .find(|h| h["paragraph_id"] == recent.to_string())
        .expect("the in-window paragraph is a hit");

    // The pre-window sibling is NOT a top-level hit …
    assert!(
        !hits
            .iter()
            .any(|h| h["paragraph_id"] == old_sibling.to_string()),
        "the pre-window sibling must not be a top-level hit"
    );
    // … but it IS still visible as context on the hit that cites it.
    let sibling_ids: Vec<&str> = hit["siblings"]
        .as_array()
        .expect("siblings array")
        .iter()
        .filter_map(|s| s["paragraph_id"].as_str())
        .collect();
    assert!(
        sibling_ids.contains(&old_sibling.to_string().as_str()),
        "context must be EXEMPT from the window: the older sibling disappeared \
         from `siblings` ({sibling_ids:?}), which deletes the caller's ability \
         to see why the recent hit is believed"
    );
}
