//! Integration test for perspective-lens reads (spec
//! `docs/superpowers/specs/2026-06-03-perspective-lens-reads-design.md`).
//!
//! Threads an optional `(frame_id, perspective_id)` lens into the four
//! context-delivery read tools (`get_claim`, `get_belief`, `recall`,
//! `recall_with_context`) and attaches an additive `lensed_belief` computed via
//! `epigraph_engine::belief_query::get_perspective_belief`.
//!
//! The DISCRIMINATING proof is lifted from the engine fixture
//! `crates/epigraph-engine/tests/perspective_frame_function.rs::get_perspective_belief_diverges_by_observer`:
//! two observers (a SKEPTIC that down-weights `practitioner_interview` and a
//! neutral BELIEVER) reach DIFFERENT lensed beliefs over the SAME stored
//! evidence. Asserting `skeptic < believer` proves the lens actually flows
//! through the tool — it is NOT a comparison against the stored `truth_value`
//! (which is a constant 0.5, not the DS-computed global belief, so that would
//! be a hollow baseline). The reduce-to-global leg (unmapped perspective ≈
//! global within 1e-9) and the back-compat leg (no lens → key absent) round it
//! out, plus the validation errors (only-one-of, unknown id).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use epigraph_db::{FrameRepository, MassFunctionRepository, PerspectiveRepository, PgPool};
use epigraph_ds::{FocalElement, FrameOfDiscernment, MassFunction};
use epigraph_mcp::tools::claims::get_claim;
use epigraph_mcp::tools::ds::get_belief;
use epigraph_mcp::tools::memory::recall;
use epigraph_mcp::tools::perspectives::list_perspectives;
use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;
use epigraph_mcp::tools::recall::RecallWithContextParams;
use epigraph_mcp::types::{GetBeliefParams, GetClaimParams, ListPerspectivesParams, RecallParams};
use rmcp::model::CallToolResult;
use serde_json::Value;
use uuid::Uuid;

mod common;
use common::build_test_server;

// ── seeding helpers (mirror perspective_frame_function.rs + get_claim.rs) ─────

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at) \
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

/// Seed a level-2 paragraph claim WITH an embedding and a paper-attribution
/// edge, so the SAME claim is both lens-computable (it carries BBAs) and
/// recallable via `recall_with_context` (the pipeline requires level=2 +
/// paper). `truth_value` is a fixed 0.5 — deliberately NOT the DS belief.
async fn insert_paragraph_claim(pool: &PgPool, agent: Uuid, embedding_pgvec: &str) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("lens claim {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, properties, embedding) \
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, true, jsonb_build_object('level', 2::int), $4::vector)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .bind(embedding_pgvec)
    .execute(pool)
    .await
    .expect("paragraph claim");

    let paper = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, $3)")
        .bind(paper)
        .bind(format!("10.test/{id}"))
        .bind("lens test paper")
        .execute(pool)
        .await
        .expect("paper");
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(paper)
    .bind(id)
    .execute(pool)
    .await
    .expect("paper-attribution edge");
    id
}

/// Store a supporting BBA (mass on H0, rest on Θ) tagged with `evidence_type`.
/// Copied from `perspective_frame_function.rs::store_bba`.
async fn store_bba(
    pool: &PgPool,
    claim_id: Uuid,
    frame_id: Uuid,
    agent: Uuid,
    frame: &FrameOfDiscernment,
    evidence_type: &str,
    mass: f64,
) {
    let mut bba = BTreeMap::new();
    bba.insert(FocalElement::positive(BTreeSet::from([0])), mass);
    bba.insert(FocalElement::theta(frame), 1.0 - mass);
    let mf = MassFunction::new(frame.clone(), bba).unwrap();
    MassFunctionRepository::store_with_perspective(
        pool,
        claim_id,
        frame_id,
        Some(agent),
        None,
        &mf.masses_to_json(),
        None,
        Some("discount"),
        Some(1.0),
        Some(evidence_type),
        "unknown",
        None,
    )
    .await
    .expect("store bba");
}

/// The shared fixture: one claim with two differing-evidence-type BBAs on a
/// binary frame, a SKEPTIC perspective that halves trust in
/// `practitioner_interview`, and a BELIEVER (all-α=1.0) that is neutral and so
/// reduces to the global belief.
struct Fixture {
    claim_id: Uuid,
    frame_id: Uuid,
    skeptic_id: Uuid,
    believer_id: Uuid,
}

async fn seed_fixture(pool: &PgPool, embedding_pgvec: &str) -> Fixture {
    let agent = insert_agent(pool).await;
    let claim_id = insert_paragraph_claim(pool, agent, embedding_pgvec).await;
    let frame_row = FrameRepository::create(
        pool,
        "ff_binary",
        None,
        &["H0".to_string(), "H1".to_string()],
    )
    .await
    .expect("frame");
    let frame =
        FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone()).unwrap();

    store_bba(
        pool,
        claim_id,
        frame_row.id,
        agent,
        &frame,
        "western_clinical",
        0.6,
    )
    .await;
    store_bba(
        pool,
        claim_id,
        frame_row.id,
        agent,
        &frame,
        "practitioner_interview",
        0.7,
    )
    .await;

    let skeptic = PerspectiveRepository::create(
        pool,
        "skeptic",
        None,
        None,
        Some("analytical"),
        &[],
        None,
        None,
    )
    .await
    .expect("skeptic");
    let believer = PerspectiveRepository::create(
        pool,
        "believer",
        None,
        None,
        Some("analytical"),
        &[],
        None,
        None,
    )
    .await
    .expect("believer");
    PerspectiveRepository::set_source_reliability(
        pool,
        skeptic.id,
        &HashMap::from([
            ("western_clinical".to_string(), 1.0),
            ("practitioner_interview".to_string(), 0.3),
        ]),
    )
    .await
    .expect("skeptic map");
    PerspectiveRepository::set_source_reliability(
        pool,
        believer.id,
        &HashMap::from([
            ("western_clinical".to_string(), 1.0),
            ("practitioner_interview".to_string(), 1.0),
        ]),
    )
    .await
    .expect("believer map");

    Fixture {
        claim_id,
        frame_id: frame_row.id,
        skeptic_id: skeptic.id,
        believer_id: believer.id,
    }
}

fn parse_json(result: &CallToolResult) -> Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block");
    serde_json::from_str(&text).expect("response is JSON")
}

/// dim=1536 pgvector with all mass in slot 0 — every seeded paragraph shares it,
/// so the flat-ANN recall is cosine-similar to the same query vector.
fn unit_pgvec() -> String {
    let mut v = vec!["0.0"; 1536];
    v[0] = "1.0";
    format!("[{}]", v.join(","))
}

fn rwc_params(
    query: &str,
    frame_id: Option<Uuid>,
    perspective_id: Option<Uuid>,
) -> RecallWithContextParams {
    RecallWithContextParams {
        query: query.to_string(),
        limit: Some(10),
        min_truth: Some(0.0),
        centroid_dim: Some(1536),
        paper_doi_filter: None,
        siblings_limit: None,
        corroborates_limit: None,
        neighbor_paragraphs_limit: None,
        diverse: None,
        max_themes: None,
        diversity_weight: None,
        candidate_pool: None,
        rerank: None,
        rerank_pool_factor: None,
        groundedness_gate: None,
        frame_id: frame_id.map(|f| f.to_string()),
        perspective_id: perspective_id.map(|p| p.to_string()),
        graph_expansion_depth: None,
    }
}

// ── get_claim ─────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn get_claim_lens_diverges_by_perspective_and_is_absent_without_lens(pool: PgPool) {
    let fx = seed_fixture(&pool, &unit_pgvec()).await;
    let server = build_test_server(pool.clone());

    // WITHOUT a lens → key absent (byte-identical back-compat).
    let plain = get_claim(
        &server,
        GetClaimParams {
            claim_id: fx.claim_id.to_string(),
            frame_id: None,
            perspective_id: None,
        },
        None,
    )
    .await
    .expect("get_claim plain");
    let body = parse_json(&plain);
    assert!(
        body.get("lensed_belief").is_none(),
        "no lens → lensed_belief key must be ABSENT (not null): {body}"
    );

    // WITH the skeptic lens → lensed_belief present, carrying the three fields.
    let skeptic = get_claim(
        &server,
        GetClaimParams {
            claim_id: fx.claim_id.to_string(),
            frame_id: Some(fx.frame_id.to_string()),
            perspective_id: Some(fx.skeptic_id.to_string()),
        },
        None,
    )
    .await
    .expect("get_claim skeptic lens");
    let s_body = parse_json(&skeptic);
    let s_lens = &s_body["lensed_belief"];
    assert_eq!(
        s_lens["frame_id"].as_str().unwrap(),
        fx.frame_id.to_string()
    );
    assert_eq!(
        s_lens["perspective_id"].as_str().unwrap(),
        fx.skeptic_id.to_string()
    );
    let skeptic_belief = s_lens["belief"].as_f64().expect("belief f64");

    // WITH the believer lens → different belief from the SAME evidence.
    let believer = get_claim(
        &server,
        GetClaimParams {
            claim_id: fx.claim_id.to_string(),
            frame_id: Some(fx.frame_id.to_string()),
            perspective_id: Some(fx.believer_id.to_string()),
        },
        None,
    )
    .await
    .expect("get_claim believer lens");
    let believer_belief = parse_json(&believer)["lensed_belief"]["belief"]
        .as_f64()
        .expect("believer belief f64");

    // Discriminating assert: skeptic trusts the practitioner interview LESS, so
    // believes H0 less than the neutral believer. Proves the lens flows.
    assert!(
        skeptic_belief < believer_belief,
        "skeptic lensed belief ({skeptic_belief}) must be < believer ({believer_belief})"
    );

    // The top-level global truth_value is UNCHANGED by the lens (additive).
    assert!(
        (s_body["truth_value"].as_f64().unwrap() - 0.5).abs() < 1e-9,
        "lens must not overwrite the global truth_value"
    );
}

// ── get_belief ────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn get_belief_lens_diverges_and_preserves_global(pool: PgPool) {
    let fx = seed_fixture(&pool, &unit_pgvec()).await;
    let server = build_test_server(pool.clone());

    // frame_id alone (no perspective) → framed-but-unlensed; no lensed_belief.
    let framed = get_belief(
        &server,
        GetBeliefParams {
            claim_id: fx.claim_id.to_string(),
            frame_id: Some(fx.frame_id.to_string()),
            perspective_id: None,
        },
    )
    .await
    .expect("get_belief framed-unlensed");
    let framed_body = parse_json(&framed);
    assert!(
        framed_body.get("lensed_belief").is_none(),
        "frame alone (unlensed) → lensed_belief key absent: {framed_body}"
    );
    let global_belief = framed_body["belief"].as_f64().expect("global belief");

    // skeptic lens → lensed_belief present and != the global framed belief.
    let skeptic = get_belief(
        &server,
        GetBeliefParams {
            claim_id: fx.claim_id.to_string(),
            frame_id: Some(fx.frame_id.to_string()),
            perspective_id: Some(fx.skeptic_id.to_string()),
        },
    )
    .await
    .expect("get_belief skeptic lens");
    let s_body = parse_json(&skeptic);
    // Top-level belief stays GLOBAL even under the lens.
    assert!(
        (s_body["belief"].as_f64().unwrap() - global_belief).abs() < 1e-9,
        "top-level belief must remain the global framed value under a lens"
    );
    let skeptic_lensed = s_body["lensed_belief"]["belief"]
        .as_f64()
        .expect("skeptic lensed");
    assert!(
        skeptic_lensed < global_belief,
        "skeptic lensed belief ({skeptic_lensed}) must fall below global ({global_belief})"
    );

    // believer (neutral) lens → reduces to global within 1e-9.
    let believer = get_belief(
        &server,
        GetBeliefParams {
            claim_id: fx.claim_id.to_string(),
            frame_id: Some(fx.frame_id.to_string()),
            perspective_id: Some(fx.believer_id.to_string()),
        },
    )
    .await
    .expect("get_belief believer lens");
    let believer_lensed = parse_json(&believer)["lensed_belief"]["belief"]
        .as_f64()
        .expect("believer lensed");
    assert!(
        (believer_lensed - global_belief).abs() < 1e-9,
        "neutral believer lens ({believer_lensed}) must reduce to global ({global_belief})"
    );
}

// ── recall_with_context ──────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_lens_attaches_diverging_belief(pool: PgPool) {
    let pgvec = unit_pgvec();
    let fx = seed_fixture(&pool, &pgvec).await;
    let server = build_test_server(pool.clone());

    // No lens → the recalled hit has NO lensed_belief key.
    let plain = recall_with_context_with_pgvec(&server, rwc_params("q", None, None), 1536, &pgvec)
        .await
        .expect("recall plain");
    let p_body = parse_json(&plain);
    let p_hit = p_body["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["paragraph_id"].as_str() == Some(&fx.claim_id.to_string()))
        .expect("seeded claim recalled");
    assert!(
        p_hit.get("lensed_belief").is_none(),
        "no lens → recall hit lensed_belief key absent: {p_hit}"
    );

    // skeptic lens → hit carries a lensed_belief.
    let skeptic = recall_with_context_with_pgvec(
        &server,
        rwc_params("q", Some(fx.frame_id), Some(fx.skeptic_id)),
        1536,
        &pgvec,
    )
    .await
    .expect("recall skeptic lens");
    let s_belief = lensed_belief_for(&parse_json(&skeptic), fx.claim_id);

    // believer lens → different belief for the SAME recalled claim.
    let believer = recall_with_context_with_pgvec(
        &server,
        rwc_params("q", Some(fx.frame_id), Some(fx.believer_id)),
        1536,
        &pgvec,
    )
    .await
    .expect("recall believer lens");
    let b_belief = lensed_belief_for(&parse_json(&believer), fx.claim_id);

    assert!(
        s_belief < b_belief,
        "recall: skeptic lensed belief ({s_belief}) must be < believer ({b_belief})"
    );
}

fn lensed_belief_for(body: &Value, claim_id: Uuid) -> f64 {
    let hit = body["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["paragraph_id"].as_str() == Some(&claim_id.to_string()))
        .expect("seeded claim recalled");
    hit["lensed_belief"]["belief"]
        .as_f64()
        .expect("lensed_belief.belief present on lensed recall hit")
}

// ── reduce-to-global (unmapped perspective) ──────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn unmapped_perspective_lens_equals_global(pool: PgPool) {
    let fx = seed_fixture(&pool, &unit_pgvec()).await;
    let server = build_test_server(pool.clone());

    // A perspective with NO source_reliability map expresses no opinion → its
    // lensed belief must reproduce the global framed belief exactly.
    let plain_persp = PerspectiveRepository::create(
        &pool,
        "plain",
        None,
        None,
        Some("analytical"),
        &[],
        None,
        None,
    )
    .await
    .expect("plain perspective");

    let global = parse_json(
        &get_belief(
            &server,
            GetBeliefParams {
                claim_id: fx.claim_id.to_string(),
                frame_id: Some(fx.frame_id.to_string()),
                perspective_id: None,
            },
        )
        .await
        .expect("global"),
    )["belief"]
        .as_f64()
        .unwrap();

    let lensed = parse_json(
        &get_belief(
            &server,
            GetBeliefParams {
                claim_id: fx.claim_id.to_string(),
                frame_id: Some(fx.frame_id.to_string()),
                perspective_id: Some(plain_persp.id.to_string()),
            },
        )
        .await
        .expect("plain-perspective lens"),
    )["lensed_belief"]["belief"]
        .as_f64()
        .unwrap();

    assert!(
        (lensed - global).abs() < 1e-9,
        "unmapped perspective lens ({lensed}) must equal global ({global})"
    );
}

// ── validation ────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn lens_validation_rejects_only_one_of_and_unknown_ids(pool: PgPool) {
    let fx = seed_fixture(&pool, &unit_pgvec()).await;
    let server = build_test_server(pool.clone());

    // Only frame_id (no perspective) on get_claim → both-or-neither error.
    let only_frame = get_claim(
        &server,
        GetClaimParams {
            claim_id: fx.claim_id.to_string(),
            frame_id: Some(fx.frame_id.to_string()),
            perspective_id: None,
        },
        None,
    )
    .await;
    assert!(only_frame.is_err(), "only frame_id must be rejected");

    // Only perspective_id (no frame) on get_claim → error.
    let only_persp = get_claim(
        &server,
        GetClaimParams {
            claim_id: fx.claim_id.to_string(),
            frame_id: None,
            perspective_id: Some(fx.skeptic_id.to_string()),
        },
        None,
    )
    .await;
    assert!(only_persp.is_err(), "only perspective_id must be rejected");

    // Unknown perspective UUID → not-found error (engine would silently reduce
    // to global, so the tool MUST surface it).
    let unknown_persp = get_claim(
        &server,
        GetClaimParams {
            claim_id: fx.claim_id.to_string(),
            frame_id: Some(fx.frame_id.to_string()),
            perspective_id: Some(Uuid::new_v4().to_string()),
        },
        None,
    )
    .await;
    assert!(
        unknown_persp.is_err(),
        "unknown perspective_id must be rejected"
    );

    // Unknown frame UUID → not-found error.
    let unknown_frame = get_claim(
        &server,
        GetClaimParams {
            claim_id: fx.claim_id.to_string(),
            frame_id: Some(Uuid::new_v4().to_string()),
            perspective_id: Some(fx.skeptic_id.to_string()),
        },
        None,
    )
    .await;
    assert!(unknown_frame.is_err(), "unknown frame_id must be rejected");

    // get_belief: perspective_id without frame_id → error (one-sided rule).
    let gb_only_persp = get_belief(
        &server,
        GetBeliefParams {
            claim_id: fx.claim_id.to_string(),
            frame_id: None,
            perspective_id: Some(fx.skeptic_id.to_string()),
        },
    )
    .await;
    assert!(
        gb_only_persp.is_err(),
        "get_belief perspective_id without frame_id must be rejected"
    );
}

// ── plain recall (memory.rs, lexical leg — no embedder) ──────────────────────

/// Spec §9 names `recall` in the discriminating test. With the mock embedder
/// (no API key) the hybrid dense leg errors and `recall` falls back to the
/// lexical `websearch_to_tsquery` leg, which needs no key — so the plain
/// `recall` lens path IS exercisable. Seed content contains the word "lens"; we
/// query it and assert the per-claim lensed_belief diverges skeptic-vs-believer.
#[sqlx::test(migrations = "../../migrations")]
async fn plain_recall_lens_attaches_diverging_belief(pool: PgPool) {
    let fx = seed_fixture(&pool, &unit_pgvec()).await;
    let server = build_test_server(pool.clone());

    let recall_one = |frame: Option<Uuid>, perspective: Option<Uuid>| {
        recall(
            &server,
            RecallParams {
                query: "lens".to_string(),
                min_truth: Some(0.0),
                limit: Some(20),
                tags: vec![],
                agent_id: None,
                frame_id: frame.map(|f| f.to_string()),
                perspective_id: perspective.map(|p| p.to_string()),
            },
        )
    };

    // No lens → the recalled claim has NO lensed_belief key (back-compat).
    let plain = recall_one(None, None).await.expect("recall plain");
    let plain_arr = parse_json(&plain);
    let p_hit = plain_arr
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["claim_id"].as_str() == Some(&fx.claim_id.to_string()))
        .expect("seeded claim recalled via lexical leg");
    assert!(
        p_hit.get("lensed_belief").is_none(),
        "no lens → recall result lensed_belief key absent: {p_hit}"
    );

    let recall_belief = |body: &Value| -> f64 {
        body.as_array()
            .unwrap()
            .iter()
            .find(|h| h["claim_id"].as_str() == Some(&fx.claim_id.to_string()))
            .expect("seeded claim recalled")["lensed_belief"]["belief"]
            .as_f64()
            .expect("lensed_belief.belief on lensed recall result")
    };

    let skeptic = recall_one(Some(fx.frame_id), Some(fx.skeptic_id))
        .await
        .expect("recall skeptic lens");
    let believer = recall_one(Some(fx.frame_id), Some(fx.believer_id))
        .await
        .expect("recall believer lens");

    let s = recall_belief(&parse_json(&skeptic));
    let b = recall_belief(&parse_json(&believer));
    assert!(
        s < b,
        "plain recall: skeptic lensed belief ({s}) must be < believer ({b})"
    );
}

// ── plain recall (memory.rs) per-claim degrade-not-fail ─────────────────────

/// Mirror of `recall_lens_degrades_one_bad_claim_without_failing_page` for the
/// PLAIN `recall` (memory.rs lexical leg) path — which has its OWN lens
/// post-pass loop, so the degrade-not-fail guarantee (spec §8/§9) must be pinned
/// here too, not only on `recall_with_context`. Two lexically-recallable claims
/// share a frame; one claim's stored `masses` is corrupted so
/// `get_perspective_belief` returns `ParseMasses` for it only. `recall` with a
/// lens must return `Ok` with the healthy claim carrying `lensed_belief` and the
/// corrupted one omitting the key (page still served, not aborted).
#[sqlx::test(migrations = "../../migrations")]
async fn plain_recall_lens_degrades_one_bad_claim_without_failing_page(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let frame_row = FrameRepository::create(
        &pool,
        "ff_deg_plain",
        None,
        &["H0".to_string(), "H1".to_string()],
    )
    .await
    .expect("frame");
    let frame =
        FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone()).unwrap();
    let pgvec = unit_pgvec();

    let good = insert_paragraph_claim(&pool, agent, &pgvec).await;
    let bad = insert_paragraph_claim(&pool, agent, &pgvec).await;
    store_bba(
        &pool,
        good,
        frame_row.id,
        agent,
        &frame,
        "western_clinical",
        0.6,
    )
    .await;
    store_bba(
        &pool,
        bad,
        frame_row.id,
        agent,
        &frame,
        "western_clinical",
        0.6,
    )
    .await;

    // Corrupt ONLY the bad claim's stored masses → from_json_masses fails →
    // get_perspective_belief returns ParseMasses for this claim only.
    sqlx::query("UPDATE mass_functions SET masses = '[1,2,3]'::jsonb WHERE claim_id = $1")
        .bind(bad)
        .execute(&pool)
        .await
        .expect("corrupt bad claim masses");

    let persp = PerspectiveRepository::create(
        &pool,
        "deg-persp-plain",
        None,
        None,
        Some("analytical"),
        &[],
        None,
        None,
    )
    .await
    .expect("perspective");

    let server = build_test_server(pool.clone());
    let result = recall(
        &server,
        RecallParams {
            query: "lens".to_string(),
            min_truth: Some(0.0),
            limit: Some(20),
            tags: vec![],
            agent_id: None,
            frame_id: Some(frame_row.id.to_string()),
            perspective_id: Some(persp.id.to_string()),
        },
    )
    .await
    .expect("recall must return Ok — one bad claim must not abort the whole page");

    let arr = parse_json(&result);
    let hits = arr.as_array().expect("recall returns an array");
    let find = |id: Uuid| {
        hits.iter()
            .find(|h| h["claim_id"].as_str() == Some(&id.to_string()))
    };

    let good_hit = find(good).expect("healthy claim recalled via lexical leg");
    assert!(
        good_hit
            .get("lensed_belief")
            .and_then(|v| v.get("belief"))
            .and_then(|b| b.as_f64())
            .is_some(),
        "healthy claim must carry a lensed_belief: {good_hit}"
    );

    let bad_hit = find(bad).expect("corrupted claim still recalled (page served, not aborted)");
    assert!(
        bad_hit.get("lensed_belief").is_none(),
        "corrupted claim must omit lensed_belief (degraded to null) while the page is served: {bad_hit}"
    );
}

// ── per-claim degrade-not-fail (spec §8/§9) ──────────────────────────────────

/// Spec §8/§9: a lensed-compute error for ONE claim in a recall page must
/// degrade to a null lens for THAT claim (warn-logged) while the rest of the
/// page is served — it must NOT abort the whole call. We seed two recallable
/// claims with valid BBAs on a shared frame, then CORRUPT one claim's stored
/// `masses` (a JSON array instead of a `{focal: mass}` object) so
/// `from_json_masses` returns `ParseMasses` for it only. recall_with_context
/// with a lens must return `Ok`, the healthy claim carrying a `lensed_belief`
/// and the corrupted one omitting the key.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_lens_degrades_one_bad_claim_without_failing_page(pool: PgPool) {
    let pgvec = unit_pgvec();
    let agent = insert_agent(&pool).await;
    let frame_row =
        FrameRepository::create(&pool, "ff_deg", None, &["H0".to_string(), "H1".to_string()])
            .await
            .expect("frame");
    let frame =
        FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone()).unwrap();

    let good = insert_paragraph_claim(&pool, agent, &pgvec).await;
    let bad = insert_paragraph_claim(&pool, agent, &pgvec).await;
    store_bba(
        &pool,
        good,
        frame_row.id,
        agent,
        &frame,
        "western_clinical",
        0.6,
    )
    .await;
    store_bba(
        &pool,
        bad,
        frame_row.id,
        agent,
        &frame,
        "western_clinical",
        0.6,
    )
    .await;

    // Corrupt ONLY the bad claim's stored masses → from_json_masses fails →
    // get_perspective_belief returns ParseMasses for this claim only.
    sqlx::query("UPDATE mass_functions SET masses = '[1,2,3]'::jsonb WHERE claim_id = $1")
        .bind(bad)
        .execute(&pool)
        .await
        .expect("corrupt bad claim masses");

    let persp = PerspectiveRepository::create(
        &pool,
        "deg-persp",
        None,
        None,
        Some("analytical"),
        &[],
        None,
        None,
    )
    .await
    .expect("perspective");

    let server = build_test_server(pool.clone());
    let result = recall_with_context_with_pgvec(
        &server,
        rwc_params("q", Some(frame_row.id), Some(persp.id)),
        1536,
        &pgvec,
    )
    .await
    .expect("recall must NOT fail despite one corrupt claim");
    let body = parse_json(&result);
    let hits = body["results"].as_array().expect("results array");

    let good_hit = hits
        .iter()
        .find(|h| h["paragraph_id"].as_str() == Some(&good.to_string()))
        .expect("healthy claim recalled");
    assert!(
        good_hit["lensed_belief"]["belief"].as_f64().is_some(),
        "healthy claim must carry a lensed_belief: {good_hit}"
    );

    let bad_hit = hits
        .iter()
        .find(|h| h["paragraph_id"].as_str() == Some(&bad.to_string()))
        .expect("corrupt claim still recalled (lens failure must not drop it)");
    assert!(
        bad_hit.get("lensed_belief").is_none(),
        "corrupt claim must degrade to absent lensed_belief, not abort the page: {bad_hit}"
    );
}

// ── list_perspectives discovery enrichment ───────────────────────────────────

/// Spec §9 "Discovery": `list_perspectives` must surface the
/// `source_reliability` / `locality_reliability` maps so an agent can SEE what a
/// perspective up/down-weights before choosing it as a lens. Asserts the mapped
/// perspective surfaces its values and an unmapped one is `null` — exercising
/// both branches of `PerspectiveRow::source_reliability()`.
#[sqlx::test(migrations = "../../migrations")]
async fn list_perspectives_surfaces_reliability_maps(pool: PgPool) {
    // skeptic carries a source_reliability map; we add a second WITHOUT one.
    let fx = seed_fixture(&pool, &unit_pgvec()).await;
    let plain = PerspectiveRepository::create(
        &pool,
        "no-map",
        None,
        None,
        Some("analytical"),
        &[],
        None,
        None,
    )
    .await
    .expect("plain perspective");
    let server = build_test_server(pool.clone());

    let result = list_perspectives(&server, ListPerspectivesParams { limit: Some(100) })
        .await
        .expect("list_perspectives");
    let body = parse_json(&result);
    let rows = body.as_array().expect("array of perspectives");

    let skeptic_row = rows
        .iter()
        .find(|r| r["perspective_id"].as_str() == Some(&fx.skeptic_id.to_string()))
        .expect("skeptic in listing");
    // The mapped perspective surfaces its source_reliability values.
    assert_eq!(
        skeptic_row["source_reliability"]["practitioner_interview"]
            .as_f64()
            .expect("skeptic practitioner_interview reliability"),
        0.3,
        "list_perspectives must surface the source_reliability map"
    );
    assert!(
        skeptic_row.get("name").and_then(|n| n.as_str()) == Some("skeptic"),
        "list_perspectives must carry the name for lens choice"
    );

    let plain_row = rows
        .iter()
        .find(|r| r["perspective_id"].as_str() == Some(&plain.id.to_string()))
        .expect("no-map perspective in listing");
    // An unmapped perspective surfaces null (Option<HashMap> → null), so an
    // agent sees it imposes no override.
    assert!(
        plain_row["source_reliability"].is_null(),
        "unmapped perspective source_reliability must be null: {plain_row}"
    );
    assert!(
        plain_row["locality_reliability"].is_null(),
        "unmapped perspective locality_reliability must be null: {plain_row}"
    );
}
