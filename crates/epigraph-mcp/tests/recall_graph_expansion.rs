//! Regression test for Task 6.1 (claim `29e789fd-92fb-497f-b9bf-5dff1d96408b`):
//! `recall_with_context`'s optional `graph_expansion_depth` param.
//!
//! Bypasses the MCP wrapper's OpenAI embedder the same way
//! `recall_with_context.rs` does — via `__test_only::recall_with_context_with_pgvec`,
//! which lets the test pre-format a known pgvector literal and dispatch
//! directly into the post-embed pipeline (the same code path
//! `recall_with_context` runs after `embedder.generate_at_dim`).
//!
//! ## Fixture shape
//!
//! - Paragraph A: ANN seed. Embedded in the SAME cluster bucket as the query
//!   (cosine-similar), so flat ANN surfaces it directly.
//! - Paragraph MID: a level=2 paragraph reachable from A via a `supports`
//!   edge (1 hop). Embedded ORTHOGONAL to the query (a different bucket) so
//!   it is not itself an ANN hit — present purely to make the reachability
//!   to B genuinely 2-hop, not 1-hop-that-happens-to-also-look-2-hop.
//! - Paragraph B: reachable from MID via a second `supports` edge (2 hops
//!   from A). Embedded ORTHOGONAL to the query in a DIFFERENT bucket than
//!   MID, so B is not ANN-close to the query either — the only way B can
//!   surface in `recall_with_context`'s results is the graph-expansion path.
//!
//! `graph_expansion_depth` unset (or `Some(1)`) must NOT surface B (it's 2
//! hops away). `graph_expansion_depth=2` must surface B. This is the
//! load-bearing assertion: it proves the expansion path actually reaches and
//! returns a claim ANN alone would never find, not just that the param is
//! accepted without crashing.

#[path = "viewer_fixture.rs"]
mod viewerfx;

#[rustfmt::skip]
use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;
use epigraph_mcp::tools::link_epistemic::do_link_epistemic;
use epigraph_mcp::tools::recall::RecallWithContextParams;
use epigraph_mcp::types::LinkEpistemicParams;
use sqlx::PgPool;
use uuid::Uuid;

mod fixture {
    use super::*;

    const DIM: usize = 1536;
    const N_BUCKETS: usize = 8;
    const STRIDE: usize = DIM / N_BUCKETS;

    fn vec_to_pgvec(v: &[f32]) -> String {
        let inner: Vec<String> = v.iter().map(|x| x.to_string()).collect();
        format!("[{}]", inner.join(","))
    }

    /// Pgvector literal concentrated in `bucket * STRIDE .. (bucket+1) * STRIDE`.
    /// Same-bucket vectors are highly cosine-similar; different-bucket
    /// vectors are orthogonal (cosine similarity ~0). Mirrors
    /// `diverse_fixture::cluster_pgvec` in `recall_with_context.rs`.
    pub fn cluster_pgvec(bucket: usize, value: f32) -> String {
        let mut v = vec![0.0f32; DIM];
        let start = bucket * STRIDE;
        let end = start + STRIDE;
        for slot in v.iter_mut().take(end).skip(start) {
            *slot = value;
        }
        vec_to_pgvec(&v)
    }

    /// A "decoy" vector: mostly concentrated in an orthogonal bucket (7) like
    /// MID/B, but with a small deliberate sliver of overlap in bucket 0 (the
    /// query's bucket). This gives decoys a small POSITIVE cosine similarity
    /// to the query, strictly greater than MID/B's exact-zero similarity —
    /// so flat ANN deterministically ranks decoys above MID/B on ties,
    /// rather than relying on row-order luck. `search_by_embedding` has no
    /// similarity cutoff (pure top-K by distance), so this is what makes a
    /// small `limit` reliably exclude MID/B from the ANN seed set.
    pub fn decoy_pgvec(sliver: f32) -> String {
        let mut v = vec![0.0f32; DIM];
        for slot in v.iter_mut().take(STRIDE) {
            *slot = sliver;
        }
        let start = 7 * STRIDE;
        let end = start + STRIDE;
        for slot in v.iter_mut().take(end).skip(start) {
            *slot = 1.0;
        }
        vec_to_pgvec(&v)
    }

    fn hash_for(id: Uuid) -> Vec<u8> {
        let mut h = vec![0u8; 32];
        h[..16].copy_from_slice(id.as_bytes());
        h
    }

    pub async fn seed_agent(pool: &PgPool) -> Uuid {
        let agent_id = Uuid::new_v4();
        sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
            .bind(agent_id)
            .bind("cc".repeat(32))
            .execute(pool)
            .await
            .expect("seed agent");
        agent_id
    }

    pub async fn seed_paper(pool: &PgPool, doi: &str, title: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(doi)
            .bind(title)
            .execute(pool)
            .await
            .expect("seed paper");
        id
    }

    /// Seed a level=2 paragraph claim with an embedding and a paper
    /// attribution edge (`recall_with_context` drops any hit missing paper
    /// attribution, so every fixture paragraph needs one regardless of
    /// whether it's expected to surface as an ANN seed).
    pub async fn seed_paragraph(
        pool: &PgPool,
        agent_id: Uuid,
        paper_id: Uuid,
        content: &str,
        embedding_pgvec: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding) \
             VALUES ($1, $2, $3, $4, 0.7, jsonb_build_object('level', 2::int), $5::vector)",
        )
        .bind(id)
        .bind(content)
        .bind(hash_for(id))
        .bind(agent_id)
        .bind(embedding_pgvec)
        .execute(pool)
        .await
        .expect("seed paragraph");

        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
             VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
        )
        .bind(paper_id)
        .bind(id)
        .execute(pool)
        .await
        .expect("seed paper-attribution edge");

        id
    }
}

/// `limit` does double duty in `recall_with_context`: it bounds BOTH the
/// flat-ANN seed fetch AND the final post-expansion truncation (when
/// `rerank` is off, both equal `limit` exactly). The fixture seeds A + 2
/// decoys (similarity ~0.05) + MID/B (similarity 0.0), so:
///   - `limit=2` admits exactly `{A, decoy}` as ANN seeds — MID/B never
///     enter the seed pool, which is what the negative
///     (unset / depth=1) tests need.
///   - `limit=3` admits `{A, decoy, decoy}` as ANN seeds (still excluding
///     MID/B), leaving exactly the room graph expansion needs to place B
///     (and MID) into the final result on its own merit — what the positive
///     (depth=2) test needs.
fn base_params(depth: Option<u32>, limit: u32) -> RecallWithContextParams {
    RecallWithContextParams {
        query: "ignored — pgvec is passed directly".to_string(),
        limit: Some(limit),
        min_truth: Some(0.0),
        centroid_dim: Some(1536),
        paper_doi_filter: None,
        siblings_limit: None,
        corroborates_limit: None,
        epistemic_limit: None,
        neighbor_paragraphs_limit: None,
        diverse: None,
        max_themes: None,
        diversity_weight: None,
        candidate_pool: None,
        rerank: None,
        rerank_pool_factor: None,
        groundedness_gate: None,
        frame_id: None,
        perspective_id: None,
        graph_expansion_depth: depth,
        exclude_contested: false,
        since: None,
        epistemic_partition: false,
        diversity_radius: None,
    }
}

fn build_test_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None); // mock — tests use pre-computed pgvec
    EpiGraphMcpFull::new(pool, signer, embedder, /*read_only=*/ false)
}

#[derive(serde::Deserialize, Debug)]
struct RecallResponseStruct {
    results: Vec<RecallResultStruct>,
    #[allow(dead_code)]
    corpus_scope: serde_json::Value,
    #[allow(dead_code)]
    centroid_dim_used: u32,
}

#[derive(serde::Deserialize, Debug)]
struct RecallResultStruct {
    paragraph_id: Uuid,
    #[allow(dead_code)]
    paragraph_content: String,
    #[allow(dead_code)]
    similarity: f64,
}

fn parse_response(result: rmcp::model::CallToolResult) -> RecallResponseStruct {
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    serde_json::from_str(&text).expect("parse RecallWithContextResponse JSON")
}

/// Build the A --supports--> MID --supports--> B fixture described in the
/// module doc comment. Returns (server, query_pgvec, A, MID, B).
async fn build_two_hop_fixture(
    pool: PgPool,
) -> (epigraph_mcp::EpiGraphMcpFull, String, Uuid, Uuid, Uuid) {
    let viewer = viewerfx::public_viewer(&pool).await;
    let agent = fixture::seed_agent(&pool).await;
    let paper = fixture::seed_paper(&pool, "10.1/graph-expansion", "Graph expansion test").await;

    let query_pgvec = fixture::cluster_pgvec(0, 1.0);

    // A: ANN seed, same bucket as the query.
    let a =
        fixture::seed_paragraph(&pool, agent, paper, "paragraph A: ANN seed", &query_pgvec).await;
    // MID: orthogonal bucket 3 — not ANN-close to the query.
    let mid_pgvec = fixture::cluster_pgvec(3, 1.0);
    let mid = fixture::seed_paragraph(
        &pool,
        agent,
        paper,
        "paragraph MID: 1-hop bridge, ANN-invisible",
        &mid_pgvec,
    )
    .await;
    // B: a DIFFERENT orthogonal bucket (6) — not ANN-close to the query, and
    // not accidentally similar to MID either.
    let b_pgvec = fixture::cluster_pgvec(6, 1.0);
    let b = fixture::seed_paragraph(
        &pool,
        agent,
        paper,
        "paragraph B: 2-hop target, ANN-invisible",
        &b_pgvec,
    )
    .await;

    // Decoys: `search_by_embedding` (flat ANN) has no similarity cutoff —
    // it's pure top-K-by-distance — so with `limit` bigger than the corpus
    // size, EVERY seeded paragraph (however orthogonal) comes back as an ANN
    // "seed", masking the graph-expansion path entirely. Seed exactly 2
    // decoys (bucket 7, small deliberate similarity ~0.05 to the query —
    // well below A's 1.0 but strictly above MID/B's exact 0.0), so at
    // limit=3 the ANN seed pool is deterministically `{A, decoy, decoy}` —
    // MID (similarity 0.0, 1-hop score 0.7*1.1=0.77 post-expansion) and B
    // (similarity 0.0, 2-hop score 0.49*1.1=0.539 post-expansion) can ONLY
    // enter the result set via graph expansion, never as raw ANN seeds. 2
    // decoys is load-bearing here: 1 decoy leaves a 3rd ANN slot that MID/B
    // (tied at similarity 0.0) would nondeterministically win, corrupting
    // the "not ANN-close" premise the whole test rests on.
    for i in 0..2 {
        fixture::seed_paragraph(
            &pool,
            agent,
            paper,
            &format!("decoy paragraph {i}"),
            &fixture::decoy_pgvec(0.05),
        )
        .await;
    }

    let server = build_test_server(pool.clone());

    do_link_epistemic(
        &server,
        &viewer,
        LinkEpistemicParams {
            source_claim_id: a.to_string(),
            target_claim_id: mid.to_string(),
            relationship: "supports".to_string(),
            properties: None,
        },
    )
    .await
    .expect("A supports MID");

    do_link_epistemic(
        &server,
        &viewer,
        LinkEpistemicParams {
            source_claim_id: mid.to_string(),
            target_claim_id: b.to_string(),
            relationship: "supports".to_string(),
            properties: None,
        },
    )
    .await
    .expect("MID supports B");

    (server, query_pgvec, a, mid, b)
}

/// The load-bearing assertion: a claim reachable ONLY via a 2-hop `supports`
/// chain from an ANN seed, and NOT itself ANN-close to the query, is
/// returned when `graph_expansion_depth=2` — proving the expansion path
/// surfaces something flat ANN would miss entirely.
#[sqlx::test(migrations = "../../migrations")]
async fn graph_expansion_depth_2_surfaces_two_hop_claim(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    let (server, query_pgvec, a, _mid, b) = build_two_hop_fixture(pool).await;

    // limit=3: ANN seed pool is deterministically {A, decoy, decoy} (see
    // base_params doc comment) — MID/B are graph-expansion-only. B's
    // expansion-assigned score (`seed_similarity * 0.7^hops`, positive)
    // gives it a real shot at the 3rd result slot on its own merit.
    let params = base_params(Some(2), 3);
    let result = recall_with_context_with_pgvec(&server, &viewer, params, 1536, &query_pgvec)
        .await
        .expect("recall with graph_expansion_depth=2 succeeds");
    let resp = parse_response(result);

    let returned: std::collections::HashSet<Uuid> =
        resp.results.iter().map(|r| r.paragraph_id).collect();

    assert!(
        returned.contains(&a),
        "ANN seed A must still be present with expansion on; got {returned:?}"
    );
    assert!(
        returned.contains(&b),
        "paragraph B (2-hop supports target, ANN-invisible) must be surfaced \
         when graph_expansion_depth=2; got {returned:?}"
    );
}

/// Default-off / backward-compatible: with `graph_expansion_depth` unset,
/// the 2-hop claim B must NOT appear — proving expansion is opt-in and the
/// unset case reproduces today's flat-ANN-only behaviour.
#[sqlx::test(migrations = "../../migrations")]
async fn graph_expansion_unset_does_not_surface_two_hop_claim(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    let (server, query_pgvec, a, mid, b) = build_two_hop_fixture(pool).await;

    let params = base_params(None, 2);
    let result = recall_with_context_with_pgvec(&server, &viewer, params, 1536, &query_pgvec)
        .await
        .expect("recall with graph_expansion_depth unset succeeds");
    let resp = parse_response(result);

    let returned: std::collections::HashSet<Uuid> =
        resp.results.iter().map(|r| r.paragraph_id).collect();

    assert!(
        returned.contains(&a),
        "ANN seed A must be present; got {returned:?}"
    );
    assert!(
        !returned.contains(&mid),
        "MID (orthogonal embedding, no expansion) must NOT be ANN-surfaced; got {returned:?}"
    );
    assert!(
        !returned.contains(&b),
        "paragraph B must NOT be surfaced when graph_expansion_depth is unset \
         (default-off, backward-compatible); got {returned:?}"
    );
}

/// `graph_expansion_depth=1` must NOT surface B: B is 2 hops from A, and a
/// 1-hop expansion only reaches MID (which is not asserted here since it is
/// paper-attributed and would pass the assembly filters, but is not the
/// point of this test — the point is that depth is a real bound, not just
/// "on vs off").
#[sqlx::test(migrations = "../../migrations")]
async fn graph_expansion_depth_1_does_not_reach_two_hop_claim(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    let (server, query_pgvec, a, _mid, b) = build_two_hop_fixture(pool).await;

    let params = base_params(Some(1), 2);
    let result = recall_with_context_with_pgvec(&server, &viewer, params, 1536, &query_pgvec)
        .await
        .expect("recall with graph_expansion_depth=1 succeeds");
    let resp = parse_response(result);

    let returned: std::collections::HashSet<Uuid> =
        resp.results.iter().map(|r| r.paragraph_id).collect();

    assert!(
        returned.contains(&a),
        "ANN seed A must be present; got {returned:?}"
    );
    assert!(
        !returned.contains(&b),
        "paragraph B is 2 hops from A; depth=1 must not reach it; got {returned:?}"
    );
}

// ---------------------------------------------------------------------------
// Backlog 4e856a99: the expansion pool must not promote a non-paragraph.
// ---------------------------------------------------------------------------

/// Seed a level=**3** atom with an embedding and a paper attribution edge.
///
/// Both halves are load-bearing and neither is incidental:
///
/// * **`asserts` from a paper.** `ingest_document` writes one for EVERY
///   planned claim, atoms included, so this reproduces production. Without it
///   the atom would be dropped by `recall_with_context`'s paper-attribution
///   filter instead of by the level predicate under test — and the assertion
///   would pass over unmodified code, which is the tautology this fixture
///   exists to avoid.
/// * **An embedding in the QUERY's own bucket.** Maximally cosine-similar, so
///   the atom's absence cannot be explained by distance. The flat kNN
///   (`search_by_embedding_since`) is level=2-only, so a maximally-similar
///   atom is *still* not an ANN seed — which leaves graph expansion as the one
///   and only route by which it could reach `results`.
async fn seed_atom(
    pool: &PgPool,
    agent_id: Uuid,
    paper_id: Uuid,
    content: &str,
    embedding_pgvec: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[..16].copy_from_slice(id.as_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, \
                             embedding) \
         VALUES ($1, $2, $3, $4, 0.7, jsonb_build_object('level', 3::int), $5::vector)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent_id)
    .bind(embedding_pgvec)
    .execute(pool)
    .await
    .expect("seed atom");

    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(paper_id)
    .bind(id)
    .execute(pool)
    .await
    .expect("seed atom paper-attribution edge");

    id
}

/// A level-3 atom one `supports` hop from an ANN seed must NOT be promoted
/// into the top-level hit list, while a level-2 paragraph at the same hop
/// distance must be.
///
/// The paragraph is the calibration: without it, "the atom is absent" is
/// equally satisfied by an expansion path that surfaces nothing at all, and
/// the test would stay green with `graph_expansion_depth` broken outright.
///
/// Pre-fix both are promoted — `graph_expand_seeds_since` walks
/// `EXPANSION_RELATIONSHIPS` with no level predicate, and
/// `apply_graph_expansion` folds everything it returns straight into
/// `raw_hits`. The atom then comes back as a top-level hit with an empty
/// `atoms` list and no `section`, beside paragraphs that have both.
#[sqlx::test(migrations = "../../migrations")]
async fn graph_expansion_does_not_promote_a_level_3_atom(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    let agent = fixture::seed_agent(&pool).await;
    let paper = fixture::seed_paper(&pool, "10.1/atom-promotion", "Atom promotion test").await;

    let query_pgvec = fixture::cluster_pgvec(0, 1.0);

    // A: the ANN seed, same bucket as the query.
    let a =
        fixture::seed_paragraph(&pool, agent, paper, "paragraph A: ANN seed", &query_pgvec).await;
    // PARA: a level=2 paragraph 1 hop from A, orthogonal to the query so it
    // cannot enter the seed pool on similarity. This is the positive control.
    let para = fixture::seed_paragraph(
        &pool,
        agent,
        paper,
        "paragraph PARA: 1-hop expansion target",
        &fixture::cluster_pgvec(3, 1.0),
    )
    .await;
    // ATOM: a level=3 atom 1 hop from A, embedded in the query's OWN bucket.
    let atom = seed_atom(
        &pool,
        agent,
        paper,
        "atom ATOM: 1-hop expansion target, level 3",
        &query_pgvec,
    )
    .await;

    // Two decoys, for the same reason `build_two_hop_fixture` needs them: flat
    // ANN is pure top-K with no similarity cutoff, so at limit=3 they pin the
    // seed pool to {A, decoy, decoy} and keep PARA out of it.
    for i in 0..2 {
        fixture::seed_paragraph(
            &pool,
            agent,
            paper,
            &format!("decoy paragraph {i}"),
            &fixture::decoy_pgvec(0.05),
        )
        .await;
    }

    let server = build_test_server(pool.clone());
    for target in [para, atom] {
        do_link_epistemic(
            &server,
            &viewer,
            LinkEpistemicParams {
                source_claim_id: a.to_string(),
                target_claim_id: target.to_string(),
                relationship: "supports".to_string(),
                properties: None,
            },
        )
        .await
        .expect("A supports target");
    }

    let params = base_params(Some(1), 3);
    let result = recall_with_context_with_pgvec(&server, &viewer, params, 1536, &query_pgvec)
        .await
        .expect("recall with graph_expansion_depth=1 succeeds");
    let resp = parse_response(result);

    let returned: std::collections::HashSet<Uuid> =
        resp.results.iter().map(|r| r.paragraph_id).collect();

    assert!(
        returned.contains(&a),
        "ANN seed A must be present; got {returned:?}"
    );
    assert!(
        returned.contains(&para),
        "the level=2 paragraph one hop from A must be promoted by expansion — \
         without it this test's negative assertion would be satisfied by an \
         expansion path that surfaces nothing at all; got {returned:?}"
    );
    assert!(
        !returned.contains(&atom),
        "a level=3 atom was promoted into the top-level hit list by graph \
         expansion (backlog 4e856a99). Both ANN seed surfaces are level=2-only, \
         and this atom carries a paper `asserts` edge exactly as ingest_document \
         writes one, so the paper-attribution filter does not catch it. It comes \
         back with empty atoms and no section beside paragraphs that have both. \
         Got {returned:?}"
    );
}
