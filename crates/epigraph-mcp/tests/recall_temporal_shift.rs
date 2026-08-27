//! Reproduction fixture for backlog 52eff3ab — `shifted_to` typed edge for
//! temporal succession, plus recall re-ranking of the SOURCE end.
//!
//! ## The fork this file settles
//!
//! `shifted_to` must **RE-RANK ONLY, never move belief**. "The throughput
//! ceiling shifted from 400/s to 900/s" is not evidence that 400/s was ever
//! false — it was true of an earlier world. Wiring it as a `Negative`
//! restriction (the `contradicts` treatment) would retroactively falsify a
//! correct historical measurement, which is precisely why the item exists
//! separately from `contradicts`. What temporal succession DOES license is a
//! retrieval preference: when both ends of a `shifted_to` edge are live and
//! both match a query, the successor is the answer the caller wants first.
//!
//! `shifted_to_moves_no_belief` pins the "never move belief" half;
//! `recall_deranks_the_shifted_from_source` pins the "re-rank" half.
//!
//! ## Why params are built with `serde_json::from_value`
//!
//! Same reason as `recall_temporal.rs`: this file must COMPILE against HEAD,
//! where no `shifted_to` support exists, so every failure below is a
//! BEHAVIOURAL assertion failure rather than a compile error. A compile error
//! would prove nothing about behaviour.
//!
//! Uses the lexical (embedder-down) leg like `recall_dispute_awareness.rs` —
//! no embedding API key is available in CI, and temporal re-ranking is
//! orthogonal to which retrieval leg produced the page.

use epigraph_mcp::tools::link_epistemic::do_link_epistemic;
use epigraph_mcp::tools::memory::recall;
use epigraph_mcp::types::LinkEpistemicParams;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

fn build_test_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[7u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None); // mock → lexical leg
    EpiGraphMcpFull::new(pool, signer, embedder, /*read_only=*/ false)
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-shift-mcp', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// A live claim carrying a populated DS interval, so a belief MOVE would be
/// observable if `shifted_to` were (wrongly) wired as an epistemic relation.
async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, truth: f64) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims
             (content, content_hash, truth_value, agent_id, is_current, labels,
              belief, plausibility, pignistic_prob)
         VALUES ($1, sha256($1::bytea), $2, $3, true, ARRAY['shiftfixture'],
              0.9, 0.9, 0.9)
         RETURNING id",
    )
    .bind(content)
    .bind(truth)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// Raw edge insert, deliberately bypassing every application-level allow-list.
/// `recall_deranks_the_shifted_from_source` uses this so it isolates the
/// RE-RANKING defect from the "the tool refuses the relationship" defect that
/// `link_epistemic_accepts_shifted_to` already pins on its own.
async fn seed_edge_raw(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
         VALUES ($1, $2, 'claim', 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
}

fn recall_params() -> epigraph_mcp::types::RecallParams {
    serde_json::from_value(json!({
        "query": "quorbulator throughput ceiling",
        "min_truth": 0.0,
        "limit": 10,
        "tags": ["shiftfixture"],
    }))
    .expect("RecallParams")
}

/// Ordered claim ids of a recall page, best-ranked first.
fn ranked_ids(result: &rmcp::model::CallToolResult) -> Vec<String> {
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    let v: serde_json::Value = serde_json::from_str(&text).expect("recall envelope");
    v["results"]
        .as_array()
        .expect("results array")
        .iter()
        .map(|r| r["claim_id"].as_str().expect("claim_id").to_string())
        .collect()
}

fn position(ids: &[String], id: Uuid) -> usize {
    ids.iter()
        .position(|s| *s == id.to_string())
        .unwrap_or_else(|| panic!("claim {id} missing from recall page {ids:?}"))
}

/// Seed the pair. Both contents carry EVERY query term, so both clear
/// `websearch_to_tsquery`'s implicit AND and land on the same page; `prior`
/// carries them twice and in a tighter cover, so it deliberately out-ranks
/// `successor` under `ts_rank_cd`. A page that puts `successor` first can
/// therefore ONLY be the result of temporal re-ranking, never of the base
/// lexical score.
async fn seed_pair(pool: &PgPool, agent: Uuid) -> (Uuid, Uuid) {
    let prior = seed_claim(
        pool,
        agent,
        "quorbulator throughput ceiling: the quorbulator throughput ceiling is 400 units per second",
        0.8,
    )
    .await;
    let successor = seed_claim(
        pool,
        agent,
        "after the redesign the quorbulator sustained a remeasured throughput ceiling of 900 units per second",
        0.8,
    )
    .await;
    (prior, successor)
}

/// PART 1 of the reproduction: no write path admits the relationship at all.
///
/// FAILS on HEAD: `EPISTEMIC_RELATIONSHIPS` / `STRUCTURAL_RELATIONSHIPS` in
/// `tools/link_epistemic.rs` do not contain `shifted_to`, so the allow-list
/// gate rejects it with `invalid_params` before any row is written.
#[sqlx::test(migrations = "../../migrations")]
async fn link_epistemic_accepts_shifted_to(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let (prior, successor) = seed_pair(&pool, agent).await;
    let server = build_test_server(pool.clone());

    let out = do_link_epistemic(
        &server,
        LinkEpistemicParams {
            source_claim_id: prior.to_string(),
            target_claim_id: successor.to_string(),
            relationship: "shifted_to".to_string(),
            properties: None,
        },
    )
    .await;

    assert!(
        out.is_ok(),
        "link_epistemic must admit `shifted_to` (temporal succession, \
         source=prior value, target=successor value); got {:?}",
        out.err()
    );

    let n = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND target_id = $2 \
           AND relationship = 'shifted_to'",
    )
    .bind(prior)
    .bind(successor)
    .fetch_one(&pool)
    .await
    .expect("count shifted_to edges");
    assert_eq!(n, 1, "exactly one durable shifted_to edge must be written");
}

/// PART 2 of the reproduction — the substantive half. With a `shifted_to`
/// edge present, the SOURCE end (the superseded-in-time value) must fall
/// BELOW its successor in the recall page even though it out-ranks it
/// lexically.
///
/// The pre-edge assertion is the fixture's own control: it proves the base
/// ranking really does put `prior` first, so the post-edge assertion cannot
/// pass by accident.
///
/// FAILS on HEAD: `recall_post_embed` (tools/memory.rs) orders solely by the
/// RRF score and applies no edge-derived re-rank. Its dispute post-pass is
/// explicitly annotate-only ("Ranking is deliberately untouched"), and no
/// other pass reads `shifted_to`.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_deranks_the_shifted_from_source(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let (prior, successor) = seed_pair(&pool, agent).await;
    let server = build_test_server(pool.clone());

    // Control: without the edge, `prior` out-ranks `successor` lexically.
    let before = ranked_ids(&recall(&server, recall_params()).await.expect("recall ok"));
    assert!(
        position(&before, prior) < position(&before, successor),
        "fixture precondition: prior must out-rank successor before the \
         shifted_to edge exists, else the post-edge assertion is vacuous. \
         Got {before:?}"
    );

    seed_edge_raw(&pool, prior, successor, "shifted_to").await;

    let after = ranked_ids(&recall(&server, recall_params()).await.expect("recall ok"));
    assert!(
        position(&after, successor) < position(&after, prior),
        "recall must de-rank the SOURCE end of a shifted_to edge below its \
         successor: {prior} shifted_to {successor}, so the successor is the \
         answer the caller wants first. Got order {after:?}"
    );
    assert!(
        after.contains(&prior.to_string()),
        "de-ranked, NOT dropped: the prior value is still true of its own \
         era and must remain retrievable. Got {after:?}"
    );
}

/// The fork, pinned: `shifted_to` moves NO belief. A temporal succession is
/// not counter-evidence, so neither endpoint's DS columns may change and
/// `belief_wired` must be `false`.
///
/// FAILS on HEAD for the same allow-list reason as
/// `link_epistemic_accepts_shifted_to`; it exists so that an implementer who
/// fixes the allow-list by adding `shifted_to` to `EPISTEMIC_RELATIONSHIPS`
/// (which would map it through `restriction_kind_with_profile` and wire a
/// mass function) fails here instead of silently falsifying history.
#[sqlx::test(migrations = "../../migrations")]
async fn shifted_to_moves_no_belief(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let (prior, successor) = seed_pair(&pool, agent).await;
    let server = build_test_server(pool.clone());

    let read_betp = |id: Uuid, p: PgPool| async move {
        sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
            .bind(id)
            .fetch_one(&p)
            .await
            .expect("read pignistic_prob")
    };
    let before_prior = read_betp(prior, pool.clone()).await;
    let before_successor = read_betp(successor, pool.clone()).await;

    let out = do_link_epistemic(
        &server,
        LinkEpistemicParams {
            source_claim_id: prior.to_string(),
            target_claim_id: successor.to_string(),
            relationship: "shifted_to".to_string(),
            properties: None,
        },
    )
    .await
    .expect("link_epistemic must admit shifted_to");

    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    let body: serde_json::Value = serde_json::from_str(&text).expect("LinkEpistemicResponse");
    assert_eq!(
        body["belief_wired"],
        json!(false),
        "shifted_to is a retrieval-ordering relation, not evidence — it must \
         never materialize a mass function. Got {body}"
    );

    assert_eq!(
        read_betp(prior, pool.clone()).await,
        before_prior,
        "the PRIOR value must keep its belief: it was true of an earlier \
         world, and a later measurement is not a refutation of it"
    );
    assert_eq!(
        read_betp(successor, pool.clone()).await,
        before_successor,
        "the SUCCESSOR must not be strengthened either — succession is not \
         corroboration"
    );

    // The auto_create_factor_from_edge trigger (migration 001) must not have
    // minted a BP factor for this edge either; `edge_to_factor_type` returning
    // NULL for an unmapped relationship is what keeps `shifted_to` inert.
    let factors = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM factors WHERE properties->>'relationship' = 'shifted_to'",
    )
    .fetch_one(&pool)
    .await
    .expect("count factors");
    assert_eq!(factors, 0, "shifted_to must mint no BP factor");
}

/// Integrity, the directional analogue of migration 042's symmetric index:
/// the `shifted_to` PAIR is unique and ANTI-SYMMETRIC. "A shifted_to B" plus
/// "B shifted_to A" is a temporal contradiction, not two facts, and the same
/// `(LEAST, GREATEST) WHERE relationship = 'shifted_to'` partial unique index
/// rejects both that and an exact duplicate. Migration 053 dropped the
/// `(source_id, target_id, relationship)` unique index workspace-wide, so
/// nothing in the schema stops either shape today.
///
/// Deliberately does NOT assert one-successor-per-source: 400 -> 900 -> 1500
/// is a legitimate chain, and `UNIQUE(source_id)` is a stronger claim than
/// this item needs.
///
/// COST THE IMPLEMENTER MUST PAY WITH THIS INDEX: `mark_duplicate`
/// (`claim.rs` ~L3234) and `consolidate` (`claim.rs` ~L4891) both hard-code
/// `alternative_of` as the ONLY direction-agnostic-unique relationship. Ship
/// this index without extending both sites and a merge that re-points a
/// `shifted_to` edge trips the unique index and rolls the whole transaction
/// back — backlog 2905150e / issue #286, verbatim, for a second relationship.
///
/// FAILS on HEAD: both the exact-duplicate and the reversed insert succeed.
#[sqlx::test(migrations = "../../migrations")]
async fn shifted_to_pair_is_unique_and_antisymmetric(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let (prior, successor) = seed_pair(&pool, agent).await;
    seed_edge_raw(&pool, prior, successor, "shifted_to").await;

    let dup = sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
         VALUES ($1, $2, 'claim', 'claim', 'shifted_to')",
    )
    .bind(prior)
    .bind(successor)
    .execute(&pool)
    .await;
    assert!(
        dup.is_err(),
        "a duplicate shifted_to(A,B) must be rejected by a partial unique index"
    );

    let reversed = sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
         VALUES ($1, $2, 'claim', 'claim', 'shifted_to')",
    )
    .bind(successor)
    .bind(prior)
    .execute(&pool)
    .await;
    assert!(
        reversed.is_err(),
        "shifted_to(B,A) contradicts shifted_to(A,B) in time — the pair must \
         be anti-symmetric, so a LEAST/GREATEST partial unique index (the \
         directional analogue of migration 042) must reject it"
    );
}
