//! Regression tests for the write-side semantic novelty gate (backlog
//! `1bcaed94`, Task 6.4) as wired into `submit_claim` / `memorize`.
//!
//! # The gate fires here, through the real server
//!
//! The gate-driven tests below build `EpiGraphMcpFull` with
//! `McpEmbedder::with_provider` (the `test-support` feature, which this crate
//! enables for its own tests through a dev-dependency on itself) around
//! [`ScriptedProvider`]: a deterministic `EmbeddingService` that answers each
//! scripted text with a hand-built unit vector and counts its calls. That makes
//! `novelty_gate::decide` produce a REAL decision — Postgres/pgvector computes
//! the cosine distance against rows `submit_claim`/`memorize` themselves wrote —
//! so the glue that ACTS on a decision is exercised end-to-end, for both tools:
//!
//!   - `ReturnExisting`: the early-return response carries the existing claim's
//!     id (another agent's), `embedded: false`, and nothing is inserted — no
//!     row, no Evidence, and the caller's labels do not land on the other
//!     agent's claim.
//!   - `InsertFlagged`: the claim is inserted with the `near-duplicate` label
//!     (and memorize reports it in `tags`), and the gate's already-generated
//!     vector is what lands in `claims.embedding` — ONE provider call per
//!     submission, which is what proves the pending-vector reuse rather than a
//!     second, coincidentally identical, `embed_and_store`.
//!   - `novelty_threshold = 0.0` never suppresses, but still flags.
//!   - The gate's ANN lookup is viewer-scoped: a group-private claim the caller
//!     cannot read is neither returned (its id would leak through the
//!     `ReturnExisting` response) nor counted as a near neighbour.
//!
//! `ScriptedProvider` rather than `epigraph_embeddings::MockProvider` because
//! the flag band needs two DIFFERENT texts at an EXACT distance (0.10), and
//! MockProvider hashes text, so two distinct strings land wherever the hash
//! puts them. Every gate test is a `#[sqlx::test]` with its own database: fixed
//! vectors left `is_current` in a shared database by an earlier run would be
//! the nearest neighbour of the next run and turn a flag-band case into
//! `ReturnExisting`.
//!
//! # The content-hash pre-check is load-bearing, and tested as such
//!
//! `submit_claim`/`memorize` run a read-only content-hash lookup
//! (`is_exact_resubmit`) BEFORE the gate, so a same-agent exact resubmit takes
//! `create_claim_idempotent`'s dedup path — recording the resubmission's
//! Evidence and applying its labels — instead of the gate. With the gate live,
//! removing that guard is observable: the resubmit would make a provider call,
//! `ReturnExisting` would drop its labels and Evidence, and at
//! `novelty_threshold = 0.0` `InsertFlagged` would stamp `near-duplicate` onto
//! the original claim. `exact_resubmit_takes_the_hash_path_not_the_gate_*`
//! asserts all three are absent.
//!
//! # The degrade path
//!
//! The remaining tests build the server with `McpEmbedder::new(pool, None)` (no
//! key, no provider), which is also the production condition on an embedder
//! outage: `decide` returns `None`, and every write must insert exactly as it
//! did before the gate existed, at ANY `novelty_threshold`.
//!
//! The decision function itself (`classify`, every boundary) and `decide`
//! against `MockProvider` are unit-tested in `src/tools/novelty_gate.rs`; the
//! ANN query is covered by `crates/epigraph-db/tests/claim_nearest_by_embedding.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use async_trait::async_trait;
use common::drop_unique_constraint;
use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimRepository;
use epigraph_embeddings::service::{SimilarClaim, TokenUsage};
use epigraph_embeddings::{EmbeddingError, EmbeddingService};
use epigraph_mcp::types::{MemorizeParams, SubmitClaimParams};
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

// ── servers ──────────────────────────────────────────────────────────────────

/// A server with no embedding source at all (no key, no provider): the gate
/// can never fire, which is the degrade path.
fn build_test_server(pool: PgPool, signer_seed: [u8; 32]) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&signer_seed).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None); // no key, no provider
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

/// A server whose embedder generates through `provider`, so the gate fires.
/// Two servers built from the same `provider` share its call counter.
fn build_gated_server(
    pool: PgPool,
    signer_seed: [u8; 32],
    provider: &Arc<ScriptedProvider>,
) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&signer_seed).expect("signer");
    let provider: Arc<dyn EmbeddingService> = provider.clone();
    let embedder = McpEmbedder::with_provider(pool.clone(), provider);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

const AGENT_A: [u8; 32] = [0x71u8; 32];
const AGENT_B: [u8; 32] = [0x72u8; 32];

// ── the scripted embedder ────────────────────────────────────────────────────

/// Width of `claims.embedding`.
const DIM: usize = 1536;

/// The unit vector along dimension `i`.
fn axis(i: usize) -> Vec<f32> {
    let mut v = vec![0.0f32; DIM];
    v[i] = 1.0;
    v
}

/// A unit vector at cosine distance `dist` from `axis(0)`, tilted toward
/// `axis(1)`: cos = 1 - dist on dimension 0, the remainder on dimension 1.
fn near_axis0(dist: f32) -> Vec<f32> {
    let cos = 1.0 - dist;
    let mut v = vec![0.0f32; DIM];
    v[0] = cos;
    v[1] = (1.0 - cos * cos).sqrt();
    v
}

/// Inside `DEFAULT_NOVELTY_THRESHOLD` (0.05): a semantic duplicate.
const DUPLICATE_DIST: f32 = 0.01;
/// Inside the fixed near-duplicate band [0.05, 0.15): flagged, not suppressed.
const FLAG_BAND_DIST: f32 = 0.10;

/// Deterministic `EmbeddingService`: each scripted text maps to a fixed
/// vector, every `generate` is counted, and an unscripted text panics so a
/// test can never pass on a vector it did not choose.
struct ScriptedProvider {
    script: HashMap<String, Vec<f32>>,
    calls: AtomicUsize,
}

impl ScriptedProvider {
    fn new(script: &[(&str, Vec<f32>)]) -> Arc<Self> {
        Arc::new(Self {
            script: script
                .iter()
                .map(|(text, v)| ((*text).to_string(), v.clone()))
                .collect(),
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl EmbeddingService for ScriptedProvider {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.script.get(text) {
            Some(v) => Ok(v.clone()),
            None => panic!("ScriptedProvider: unscripted text {text:?}"),
        }
    }

    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        let mut out = Vec::with_capacity(texts.len());
        for text in texts {
            out.push(self.generate(text).await?);
        }
        Ok(out)
    }

    async fn store(&self, _claim_id: Uuid, _embedding: &[f32]) -> Result<(), EmbeddingError> {
        Err(EmbeddingError::DatabaseError(
            "ScriptedProvider does not store; McpEmbedder writes claims.embedding itself"
                .to_string(),
        ))
    }

    async fn get(&self, claim_id: Uuid) -> Result<Vec<f32>, EmbeddingError> {
        Err(EmbeddingError::NotFound { claim_id })
    }

    async fn similar(
        &self,
        _embedding: &[f32],
        _k: usize,
        _min_similarity: f32,
    ) -> Result<Vec<SimilarClaim>, EmbeddingError> {
        Ok(Vec::new())
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

// ── writing through either tool ──────────────────────────────────────────────

/// The two MCP write tools the gate is wired into.
#[derive(Clone, Copy, Debug)]
enum Tool {
    SubmitClaim,
    Memorize,
}

/// Write `content` through `tool` and return the parsed JSON response.
/// `evidence` feeds `submit_claim`'s `evidence_data` (memorize has none);
/// `labels` are `submit_claim`'s labels or memorize's tags.
async fn write(
    server: &EpiGraphMcpFull,
    viewer: &Viewer,
    tool: Tool,
    content: &str,
    evidence: &str,
    novelty_threshold: Option<f64>,
    labels: &[&str],
) -> Value {
    let labels: Vec<String> = labels.iter().map(|l| (*l).to_string()).collect();
    let result = match tool {
        Tool::SubmitClaim => {
            let mut params = submit_params(content, evidence, novelty_threshold);
            params.labels = labels;
            tools::claims::submit_claim(server, viewer, params).await
        }
        Tool::Memorize => {
            let params = MemorizeParams {
                content: content.to_string(),
                confidence: Some(0.7),
                tags: (!labels.is_empty()).then_some(labels),
                novelty_threshold,
            };
            tools::memory::memorize(server, viewer, params).await
        }
    }
    .unwrap_or_else(|e| panic!("{tool:?} of {content:?} failed: {e:?}"));
    first_text_json(&result)
}

fn claim_id(response: &Value) -> Uuid {
    let id = response
        .get("claim_id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("claim_id present in {response}"));
    Uuid::parse_str(id).expect("claim_id is a uuid")
}

fn embedded(response: &Value) -> bool {
    response
        .get("embedded")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("embedded present in {response}"))
}

// ── reading state back ───────────────────────────────────────────────────────

async fn claims_with_content_hash_count(pool: &PgPool, content: &str) -> i64 {
    let hash = ContentHasher::hash(content.as_bytes());
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM claims WHERE content_hash = $1")
        .bind(hash.as_slice())
        .fetch_one(pool)
        .await
        .expect("count claims by content_hash")
}

async fn labels_of(pool: &PgPool, claim: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("fetch labels")
}

async fn evidence_count(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM evidence WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count evidence")
}

/// `claims.embedding` for `claim`, parsed back out of pgvector's text form.
async fn embedding_of(pool: &PgPool, claim: Uuid) -> Option<Vec<f32>> {
    let text: Option<String> =
        sqlx::query_scalar("SELECT embedding::text FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(pool)
            .await
            .expect("fetch embedding");
    text.map(|t| {
        t.trim_matches(|c| c == '[' || c == ']')
            .split(',')
            .map(|x| x.trim().parse::<f32>().expect("pgvector component"))
            .collect()
    })
}

fn assert_same_vector(actual: &[f32], expected: &[f32], what: &str) {
    assert_eq!(actual.len(), expected.len(), "{what}: width");
    let worst = actual
        .iter()
        .zip(expected)
        .map(|(a, e)| (a - e).abs())
        .fold(0.0f32, f32::max);
    assert!(worst < 1e-6, "{what}: differs by up to {worst}");
}

// ── gate fires: ReturnExisting ───────────────────────────────────────────────

/// Agent B writes a paraphrase (cosine distance 0.01) of a claim agent A
/// already wrote. The gate must suppress B's insert and hand back A's claim,
/// with nothing of B's recorded against it.
async fn semantic_duplicate_returns_the_existing_claim(pool: PgPool, tool: Tool) {
    let original = "Novelty gate: the reactor runs at 300 kelvin";
    let paraphrase = "Novelty gate: the reactor operates at 300 K";
    let provider = ScriptedProvider::new(&[
        (original, axis(0)),
        (paraphrase, near_axis0(DUPLICATE_DIST)),
    ]);
    let server_a = build_gated_server(pool.clone(), AGENT_A, &provider);
    let server_b = build_gated_server(pool.clone(), AGENT_B, &provider);
    let viewer = fixture::public_viewer(&pool).await;

    let first = write(&server_a, &viewer, tool, original, "ev-a", None, &[]).await;
    let a_id = claim_id(&first);
    let evidence_before = evidence_count(&pool, a_id).await;
    let calls_before = provider.calls();

    let second = write(
        &server_b,
        &viewer,
        tool,
        paraphrase,
        "ev-b",
        None,
        &["b-label"],
    )
    .await;

    assert_eq!(
        claim_id(&second),
        a_id,
        "{tool:?}: a semantic duplicate must return the existing claim's id"
    );
    assert!(
        !embedded(&second),
        "{tool:?}: nothing was inserted, so nothing was embedded"
    );
    assert_eq!(
        provider.calls(),
        calls_before + 1,
        "{tool:?}: the gate embeds the incoming text exactly once"
    );
    assert_eq!(
        claims_with_content_hash_count(&pool, paraphrase).await,
        0,
        "{tool:?}: the suppressed paraphrase must not be inserted"
    );
    assert_eq!(
        evidence_count(&pool, a_id).await,
        evidence_before,
        "{tool:?}: the suppressed write records no Evidence against the existing claim"
    );
    assert!(
        !labels_of(&pool, a_id).await.iter().any(|l| l == "b-label"),
        "{tool:?}: the suppressed caller's labels must not land on another agent's claim"
    );
    if let Tool::SubmitClaim = tool {
        assert_eq!(
            second.get("content_hash").and_then(Value::as_str),
            Some(ContentHasher::to_hex(&ContentHasher::hash(original.as_bytes())).as_str()),
            "submit_claim: the response reports the EXISTING claim's content hash"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_semantic_duplicate_returns_the_existing_claim(pool: PgPool) {
    semantic_duplicate_returns_the_existing_claim(pool, Tool::SubmitClaim).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn memorize_semantic_duplicate_returns_the_existing_claim(pool: PgPool) {
    semantic_duplicate_returns_the_existing_claim(pool, Tool::Memorize).await;
}

// ── gate fires: InsertFlagged + pending-vector reuse ─────────────────────────

/// A write at cosine distance 0.10 from an existing claim is inserted, flagged
/// `near-duplicate`, and stored with the vector the gate already generated.
async fn near_duplicate_is_flagged_and_stores_the_gate_vector(pool: PgPool, tool: Tool) {
    let original = "Novelty gate: the pump draws 40 watts at idle";
    let neighbour = "Novelty gate: the pump draws 45 watts under load";
    let neighbour_vector = near_axis0(FLAG_BAND_DIST);
    let provider =
        ScriptedProvider::new(&[(original, axis(0)), (neighbour, neighbour_vector.clone())]);
    let server = build_gated_server(pool.clone(), AGENT_A, &provider);
    let viewer = fixture::public_viewer(&pool).await;

    let first = write(&server, &viewer, tool, original, "ev-1", None, &[]).await;
    let original_id = claim_id(&first);
    let calls_before = provider.calls();

    let second = write(
        &server,
        &viewer,
        tool,
        neighbour,
        "ev-2",
        None,
        &["caller-label"],
    )
    .await;
    let neighbour_id = claim_id(&second);

    assert_ne!(
        neighbour_id, original_id,
        "{tool:?}: a flag-band write is inserted, not suppressed"
    );
    assert_eq!(
        claims_with_content_hash_count(&pool, neighbour).await,
        1,
        "{tool:?}: exactly one row for the flagged write"
    );
    let labels = labels_of(&pool, neighbour_id).await;
    assert!(
        labels.iter().any(|l| l == "near-duplicate"),
        "{tool:?}: flag-band write must carry `near-duplicate`, got {labels:?}"
    );
    assert!(
        labels.iter().any(|l| l == "caller-label"),
        "{tool:?}: the caller's own labels are kept alongside the flag, got {labels:?}"
    );
    assert!(
        !labels_of(&pool, original_id)
            .await
            .iter()
            .any(|l| l == "near-duplicate"),
        "{tool:?}: the flag goes on the new claim, not its neighbour"
    );
    if let Tool::Memorize = tool {
        let tags: Vec<&str> = second["tags"]
            .as_array()
            .expect("memorize reports tags")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            tags.contains(&"near-duplicate"),
            "memorize: the response's tags report the flag, got {tags:?}"
        );
    }

    // Pending-vector reuse: the gate's vector is the one stored, and it cost
    // ONE provider call. Without the reuse, `embed_and_store` would generate a
    // second time (same vector — the provider is deterministic — so the call
    // count is what tells the two apart).
    assert!(
        embedded(&second),
        "{tool:?}: the inserted claim is embedded"
    );
    let stored = embedding_of(&pool, neighbour_id)
        .await
        .unwrap_or_else(|| panic!("{tool:?}: claims.embedding must be written"));
    assert_same_vector(&stored, &neighbour_vector, "stored embedding");
    assert_eq!(
        provider.calls(),
        calls_before + 1,
        "{tool:?}: one provider call — the gate's vector is reused for storage"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_near_duplicate_is_flagged_and_stores_the_gate_vector(pool: PgPool) {
    near_duplicate_is_flagged_and_stores_the_gate_vector(pool, Tool::SubmitClaim).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn memorize_near_duplicate_is_flagged_and_stores_the_gate_vector(pool: PgPool) {
    near_duplicate_is_flagged_and_stores_the_gate_vector(pool, Tool::Memorize).await;
}

// ── gate fires: the escape hatch ─────────────────────────────────────────────

/// `novelty_threshold = 0.0` never suppresses: the same paraphrase that
/// `semantic_duplicate_returns_the_existing_claim` sees suppressed is inserted
/// here — and still flagged, because 0.01 is inside the fixed 0.15 band.
async fn zero_threshold_inserts_a_semantic_duplicate(pool: PgPool, tool: Tool) {
    let original = "Novelty gate: the valve opens at 2 bar";
    let paraphrase = "Novelty gate: the valve opens at two bar";
    let provider = ScriptedProvider::new(&[
        (original, axis(0)),
        (paraphrase, near_axis0(DUPLICATE_DIST)),
    ]);
    let server_a = build_gated_server(pool.clone(), AGENT_A, &provider);
    let server_b = build_gated_server(pool.clone(), AGENT_B, &provider);
    let viewer = fixture::public_viewer(&pool).await;

    let a_id = claim_id(&write(&server_a, &viewer, tool, original, "ev-a", None, &[]).await);
    let second = write(&server_b, &viewer, tool, paraphrase, "ev-b", Some(0.0), &[]).await;
    let b_id = claim_id(&second);

    assert_ne!(
        b_id, a_id,
        "{tool:?}: novelty_threshold=0.0 must never suppress"
    );
    assert_eq!(
        claims_with_content_hash_count(&pool, paraphrase).await,
        1,
        "{tool:?}: the paraphrase is inserted"
    );
    assert!(
        labels_of(&pool, b_id)
            .await
            .iter()
            .any(|l| l == "near-duplicate"),
        "{tool:?}: the escape hatch disables suppression, not the soft flag"
    );
    assert!(
        embedded(&second),
        "{tool:?}: the inserted claim is embedded"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_zero_threshold_inserts_a_semantic_duplicate(pool: PgPool) {
    zero_threshold_inserts_a_semantic_duplicate(pool, Tool::SubmitClaim).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn memorize_zero_threshold_inserts_a_semantic_duplicate(pool: PgPool) {
    zero_threshold_inserts_a_semantic_duplicate(pool, Tool::Memorize).await;
}

// ── gate is viewer-scoped ────────────────────────────────────────────────────

/// A group-private claim the caller cannot read sits at distance 0.01 from
/// the caller's text. The gate must not see it: returning it would leak its id
/// through the `ReturnExisting` response, and flagging against it would leak
/// its existence through the `near-duplicate` label.
async fn gate_ignores_a_claim_the_viewer_cannot_read(pool: PgPool, tool: Tool) {
    let paraphrase = "Novelty gate: the private dataset has 12 subjects";
    let provider = ScriptedProvider::new(&[(paraphrase, near_axis0(DUPLICATE_DIST))]);

    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "novelty-private-owner").await;
    let private_id =
        fixture::seed_group_claim(&pool, owner, owner_group, "Novelty gate: private neighbour")
            .await;
    let axis0 = epigraph_mcp::embed::format_pgvector(&axis(0));
    fixture::set_claim_embedding(&pool, private_id, &axis0).await;

    // Not vacuous: the private claim IS the gate's duplicate for a viewer
    // that may read it.
    let owner_viewer = Viewer::resolve(&pool, owner).await.expect("owner viewer");
    let paraphrase_pgvec = epigraph_mcp::embed::format_pgvector(&near_axis0(DUPLICATE_DIST));
    let owner_hits =
        ClaimRepository::nearest_by_embedding(&pool, &owner_viewer, &paraphrase_pgvec, 5)
            .await
            .expect("owner ANN");
    assert!(
        matches!(owner_hits.first(), Some(h) if h.claim_id == private_id && h.distance < 0.05),
        "fixture: the owner's viewer must see the private claim as a duplicate, got {owner_hits:?}"
    );

    // Another tenant — a principal with its own group, not the owner's.
    let (other, _) = fixture::seed_agent_with_group(&pool, "novelty-other-tenant").await;
    let other_viewer = Viewer::resolve(&pool, other).await.expect("other viewer");
    let server = build_gated_server(pool.clone(), AGENT_B, &provider);

    let response = write(&server, &other_viewer, tool, paraphrase, "ev", None, &[]).await;
    let new_id = claim_id(&response);

    assert_ne!(
        new_id, private_id,
        "{tool:?}: the gate must not return a claim the viewer cannot read"
    );
    assert!(
        !response.to_string().contains(&private_id.to_string()),
        "{tool:?}: the private claim's id must not appear anywhere in the response"
    );
    assert_eq!(
        claims_with_content_hash_count(&pool, paraphrase).await,
        1,
        "{tool:?}: with nothing visible nearby, the write inserts"
    );
    assert!(
        !labels_of(&pool, new_id)
            .await
            .iter()
            .any(|l| l == "near-duplicate"),
        "{tool:?}: an unreadable neighbour must not trigger the near-duplicate flag"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_gate_ignores_a_claim_the_viewer_cannot_read(pool: PgPool) {
    gate_ignores_a_claim_the_viewer_cannot_read(pool, Tool::SubmitClaim).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn memorize_gate_ignores_a_claim_the_viewer_cannot_read(pool: PgPool) {
    gate_ignores_a_claim_the_viewer_cannot_read(pool, Tool::Memorize).await;
}

// ── the content-hash pre-check runs before the gate ──────────────────────────

/// A same-agent, byte-identical resubmit must take the content-hash path with
/// the gate LIVE. Each assertion below fails if `is_exact_resubmit` is removed
/// or moved after the gate — see the module docs.
async fn exact_resubmit_takes_the_hash_path_not_the_gate(pool: PgPool, tool: Tool) {
    let content = "Novelty gate: the exact-resubmit guard runs first";
    let provider = ScriptedProvider::new(&[(content, axis(0))]);
    let server = build_gated_server(pool.clone(), AGENT_A, &provider);
    let viewer = fixture::public_viewer(&pool).await;

    let first_id = claim_id(&write(&server, &viewer, tool, content, "ev-0", None, &[]).await);
    let calls_after_first = provider.calls();
    let evidence_after_first = evidence_count(&pool, first_id).await;

    // Default threshold: without the guard the gate would see distance 0 and
    // take `ReturnExisting`, dropping this call's label and Evidence.
    let again = write(
        &server,
        &viewer,
        tool,
        content,
        "ev-1",
        None,
        &["resubmit-default"],
    )
    .await;
    assert_eq!(claim_id(&again), first_id, "{tool:?}: same claim id");

    // Escape hatch: without the guard the gate would take `InsertFlagged` and
    // stamp `near-duplicate` onto the original claim.
    let again = write(
        &server,
        &viewer,
        tool,
        content,
        "ev-2",
        Some(0.0),
        &["resubmit-escape"],
    )
    .await;
    assert_eq!(claim_id(&again), first_id, "{tool:?}: same claim id");

    assert_eq!(
        provider.calls(),
        calls_after_first,
        "{tool:?}: an exact resubmit must not reach the embedder at all"
    );
    let labels = labels_of(&pool, first_id).await;
    assert!(
        labels.iter().any(|l| l == "resubmit-default")
            && labels.iter().any(|l| l == "resubmit-escape"),
        "{tool:?}: the hash path applies each resubmission's labels, got {labels:?}"
    );
    assert!(
        !labels.iter().any(|l| l == "near-duplicate"),
        "{tool:?}: a claim must never be flagged as a near-duplicate of itself, got {labels:?}"
    );
    assert_eq!(
        claims_with_content_hash_count(&pool, content).await,
        1,
        "{tool:?}: still one row"
    );
    if let Tool::SubmitClaim = tool {
        assert_eq!(
            evidence_count(&pool, first_id).await,
            evidence_after_first + 2,
            "submit_claim: the hash path records each resubmission's Evidence"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn exact_resubmit_takes_the_hash_path_not_the_gate_submit_claim(pool: PgPool) {
    exact_resubmit_takes_the_hash_path_not_the_gate(pool, Tool::SubmitClaim).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn exact_resubmit_takes_the_hash_path_not_the_gate_memorize(pool: PgPool) {
    exact_resubmit_takes_the_hash_path_not_the_gate(pool, Tool::Memorize).await;
}

// ── degrade path: no embedding source ────────────────────────────────────────

/// `evidence_data` must be unique per (claim, evidence-text) — the schema's
/// `evidence_content_hash_claim_unique` constraint is `(content_hash,
/// claim_id)` — so callers that resubmit the SAME content (same claim id)
/// must vary `evidence_data` across calls, matching the pattern in
/// `tool_resubmit_tests.rs::submit_claim_resubmit_creates_evidence_trace_via_edges`.
fn submit_params(
    content: &str,
    evidence_data: &str,
    novelty_threshold: Option<f64>,
) -> SubmitClaimParams {
    SubmitClaimParams {
        content: content.to_string(),
        methodology: "deductive_logic".to_string(),
        evidence_data: evidence_data.to_string(),
        evidence_type: "logical".to_string(),
        confidence: 0.7,
        source_url: None,
        reasoning: None,
        labels: vec![],
        novelty_threshold,
    }
}

/// `submit_claim` carries a `novelty_threshold` param and a read-only
/// content-hash existence check (`is_exact_resubmit` in claims.rs) ahead of
/// `create_claim_idempotent`. With no embedding source, this proves the param
/// is wire-compatible with the pre-existing exact-content dedup: a
/// byte-identical resubmit still returns the same claim id, and the row count
/// for that content_hash never exceeds 1, for any `novelty_threshold` value.
/// (That the pre-check is load-bearing once the gate is live is asserted by
/// `exact_resubmit_takes_the_hash_path_not_the_gate_*`.)
#[sqlx::test(migrations = "../../migrations")]
async fn exact_resubmit_still_dedups_with_novelty_threshold_param_present(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    drop_unique_constraint(&pool).await;
    let server = build_test_server(pool.clone(), [0x61u8; 32]);

    let content = format!("novelty-gate exact-resubmit test {}", Uuid::new_v4());

    let first =
        tools::claims::submit_claim(&server, &viewer, submit_params(&content, "ev-0", None))
            .await
            .expect("first submit_claim");
    let first_id = first_text_claim_id(&first);

    // Resubmit the SAME content with a variety of novelty_threshold values,
    // including 0.0 (the escape hatch) — none of these should matter,
    // because the exact-hash pre-check must fire before the gate is ever
    // consulted. Evidence text varies per call (schema requires distinct
    // (content_hash, claim_id) on evidence — unrelated to the gate).
    for (i, threshold) in [None, Some(0.05), Some(0.0), Some(1.0)]
        .into_iter()
        .enumerate()
    {
        let evidence = format!("ev-{}", i + 1);
        let again = tools::claims::submit_claim(
            &server,
            &viewer,
            submit_params(&content, &evidence, threshold),
        )
        .await
        .unwrap_or_else(|e| panic!("resubmit with threshold {threshold:?} failed: {e:?}"));
        let again_id = first_text_claim_id(&again);
        assert_eq!(
            again_id, first_id,
            "resubmit (threshold={threshold:?}) must return the SAME claim id as the first submit"
        );
    }

    let row_count = claims_with_content_hash_count(&pool, &content).await;
    assert_eq!(
        row_count, 1,
        "exact-content resubmits must never grow the claims table beyond 1 row for this content_hash"
    );
}

/// When the embedder cannot produce a vector (no key and no provider; also
/// the production degrade-path on an embedder outage), `novelty_gate::decide`
/// returns `None` and submit_claim must fall back to inserting exactly as it
/// did before this feature existed — for genuinely new (non-duplicate)
/// content, at ANY `novelty_threshold` value, including the nominal "always
/// suppress near-dupes" default. The gate must never turn an embedder outage
/// into a blocked write.
#[sqlx::test(migrations = "../../migrations")]
async fn distinct_content_inserts_normally_when_embedder_unavailable(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    drop_unique_constraint(&pool).await;
    let server = build_test_server(pool.clone(), [0x62u8; 32]);

    for (i, threshold) in [None, Some(0.05), Some(0.0)].into_iter().enumerate() {
        let content = format!("novelty-gate distinct content {i} {}", Uuid::new_v4());
        let result =
            tools::claims::submit_claim(&server, &viewer, submit_params(&content, "ev", threshold))
                .await
                .unwrap_or_else(|e| panic!("submit_claim (threshold={threshold:?}) failed: {e:?}"));
        let claim_id = first_text_claim_id(&result);

        let row_count = claims_with_content_hash_count(&pool, &content).await;
        assert_eq!(
            row_count, 1,
            "distinct content must insert exactly one row (threshold={threshold:?})"
        );

        // Confirm the returned id really is a freshly-inserted row, not a
        // stale/foreign one, and it is NOT flagged near-duplicate (nothing
        // in the corpus is close to this random UUID-suffixed content).
        let labels: Vec<String> = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
            .bind(Uuid::parse_str(&claim_id).expect("claim_id is a uuid"))
            .fetch_one(&pool)
            .await
            .expect("fetch labels");
        assert!(
            !labels.iter().any(|l| l == "near-duplicate"),
            "unrelated content must not be flagged near-duplicate, got {labels:?}"
        );
    }
}

/// Same guarantee as above, through `memorize` instead of `submit_claim` —
/// Step 4 of the backlog task ("apply the same gate to memorize").
#[sqlx::test(migrations = "../../migrations")]
async fn memorize_distinct_content_inserts_normally_when_embedder_unavailable(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    drop_unique_constraint(&pool).await;
    let server = build_test_server(pool.clone(), [0x63u8; 32]);

    let content = format!("novelty-gate memorize distinct {}", Uuid::new_v4());
    let params = MemorizeParams {
        content: content.clone(),
        confidence: Some(0.7),
        tags: None,
        novelty_threshold: Some(0.05),
    };
    tools::memory::memorize(&server, &viewer, params)
        .await
        .expect("memorize");

    let row_count = claims_with_content_hash_count(&pool, &content).await;
    assert_eq!(
        row_count, 1,
        "memorize of distinct content must insert one row"
    );
}

/// The JSON body of a `submit_claim`/`memorize` `CallToolResult`.
fn first_text_json(result: &rmcp::model::CallToolResult) -> Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .expect("result has text content");
    serde_json::from_str(text).expect("valid json")
}

/// Pull `claim_id` out of a `submit_claim`/`memorize` `CallToolResult`.
/// Mirrors `extract_submit_claim_id` in `src/tools/claims.rs` (not reused
/// directly since that helper is private to the crate's src tree, not
/// exported to integration tests).
fn first_text_claim_id(result: &rmcp::model::CallToolResult) -> String {
    first_text_json(result)
        .get("claim_id")
        .and_then(|v| v.as_str())
        .expect("claim_id present")
        .to_string()
}
