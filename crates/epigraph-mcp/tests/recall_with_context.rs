//! Integration tests for `recall_with_context` batched-context fetch.
//!
//! These tests bypass the MCP wrapper (which would require an OpenAI API
//! key for query embedding) and exercise `fetch_batched_context` directly
//! via the `__test_only` module re-export.
//!
//! Schema notes (verified against `epigraph_db_repo_test`, migrations
//! through 029, mirroring `epigraph-db/tests/claim_search_by_embedding.rs`):
//!   * `claims.agent_id` is NOT NULL — fixtures seed an `agents` row first.
//!   * `agents.public_key` is `bytea NOT NULL` with `octet_length = 32`
//!     enforced by check constraint, so we use a 32-byte literal.
//!   * `claims.content_hash bytea NOT NULL` and `(content_hash, agent_id)`
//!     is UNIQUE; we generate distinct 32-byte hashes per claim.
//!   * `edges.source_type` / `target_type` are NOT NULL with a CHECK
//!     against the entity-type allowlist; paper-attribution uses
//!     `'paper'` / `'claim'`, all other edges `'claim'` / `'claim'`.

#[path = "viewer_fixture.rs"]
mod viewerfx;

// rustfmt 1.8 sorts `NeighborPath` before `__test_only`; older CI rustfmt sorts
// the reverse. #[rustfmt::skip] keeps both happy by opting out of the sort.
#[rustfmt::skip]
use epigraph_mcp::tools::recall::{
    EdgeDirection,
    __test_only::{assemble_neighbor_paragraphs, embedded_3072_population, fetch_batched_context},
    NeighborPath,
};
use sqlx::PgPool;
use uuid::Uuid;

mod fixture {
    use super::*;

    pub struct Fixture {
        /// The agent every fixture claim is authored by. Exposed so tests that
        /// add their own claims reuse it — `seed_agent` pins a fixed public_key
        /// and `agents_public_key_unique` rejects a second call.
        pub agent_id: Uuid,
        #[allow(dead_code)]
        pub paper_a: Uuid,
        #[allow(dead_code)]
        pub paper_b: Uuid,
        #[allow(dead_code)]
        pub section: Uuid,
        pub paragraphs: Vec<Uuid>, // 6 paragraphs in paper A
        pub shared_atom: Uuid,     // atom under paragraphs[0] AND paragraphs[1]
        #[allow(dead_code)]
        pub atom_solo: Uuid, // atom under paragraphs[0] only
        pub corroborates_target: Uuid, // paragraph in paper B linked via CORROBORATES
        /// Atom (level=3) under `corroborates_target` (paper B) that is linked to
        /// `shared_atom` via an atom-atom edge of relationship "same_as".
        pub paper_b_atom: Uuid,
        /// Paragraph in a SEPARATE section under paper A. Both connected to
        /// paragraphs[0] via `continues_argument` AND containing `shared_atom`,
        /// so the dedup test sees one neighbor with two `via` paths and isn't
        /// shadowed by sibling exclusion.
        pub other_section_paragraph: Uuid,
    }

    fn build_paragraph_embedding() -> String {
        let mut v = vec!["0.0"; 1536];
        v[0] = "0.99";
        format!("[{}]", v.join(","))
    }

    pub async fn seed_agent(pool: &PgPool) -> Uuid {
        let agent_id = Uuid::new_v4();
        sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
            .bind(agent_id)
            .bind("aa".repeat(32))
            .execute(pool)
            .await
            .expect("seed agent");
        agent_id
    }

    /// Build a 32-byte content_hash from the claim UUID so each row gets a
    /// distinct value without pulling in pgcrypto.
    fn hash_from_uuid(id: Uuid) -> Vec<u8> {
        let mut h = vec![0u8; 32];
        h[..16].copy_from_slice(id.as_bytes());
        h
    }

    pub async fn insert_claim(
        pool: &PgPool,
        agent_id: Uuid,
        id: Uuid,
        content: &str,
        level: i32,
        embedding: Option<&str>,
    ) {
        if let Some(emb) = embedding {
            sqlx::query(
                "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding) \
                 VALUES ($1, $2, $3, $4, 0.7, jsonb_build_object('level', $5::int), $6::vector)",
            )
            .bind(id)
            .bind(content)
            .bind(hash_from_uuid(id))
            .bind(agent_id)
            .bind(level)
            .bind(emb)
            .execute(pool)
            .await
            .expect("insert claim with embedding");
        } else {
            sqlx::query(
                "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties) \
                 VALUES ($1, $2, $3, $4, 0.7, jsonb_build_object('level', $5::int))",
            )
            .bind(id)
            .bind(content)
            .bind(hash_from_uuid(id))
            .bind(agent_id)
            .bind(level)
            .execute(pool)
            .await
            .expect("insert claim");
        }
    }

    pub async fn insert_edge(
        pool: &PgPool,
        source_id: Uuid,
        source_type: &str,
        target_id: Uuid,
        target_type: &str,
        relationship: &str,
        properties: Option<&str>,
    ) {
        if let Some(props) = properties {
            sqlx::query(
                "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
                 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6::jsonb)",
            )
            .bind(source_id)
            .bind(source_type)
            .bind(target_id)
            .bind(target_type)
            .bind(relationship)
            .bind(props)
            .execute(pool)
            .await
            .expect("insert edge with properties");
        } else {
            sqlx::query(
                "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
                 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)",
            )
            .bind(source_id)
            .bind(source_type)
            .bind(target_id)
            .bind(target_type)
            .bind(relationship)
            .execute(pool)
            .await
            .expect("insert edge");
        }
    }

    pub async fn build(pool: &PgPool) -> Fixture {
        let agent_id = seed_agent(pool).await;

        let paper_a = Uuid::new_v4();
        let paper_b = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO papers (id, doi, title) \
             VALUES ($1, '10.1/A', 'Paper A'), ($2, '10.2/B', 'Paper B')",
        )
        .bind(paper_a)
        .bind(paper_b)
        .execute(pool)
        .await
        .expect("seed papers");

        let pgvec = build_paragraph_embedding();

        // Section under paper A (level=1).
        let section = Uuid::new_v4();
        insert_claim(pool, agent_id, section, "section content", 1, None).await;
        insert_edge(pool, paper_a, "paper", section, "claim", "asserts", None).await;

        // 6 paragraphs (level=2) under section, attributed to paper A.
        let mut paragraphs = vec![];
        for i in 0..6 {
            let pid = Uuid::new_v4();
            insert_claim(
                pool,
                agent_id,
                pid,
                &format!("para-{i} content"),
                2,
                Some(&pgvec),
            )
            .await;
            insert_edge(pool, section, "claim", pid, "claim", "decomposes_to", None).await;
            insert_edge(pool, paper_a, "paper", pid, "claim", "asserts", None).await;
            paragraphs.push(pid);
        }

        // shared_atom under paragraphs[0] AND paragraphs[1]; atom_solo only under paragraphs[0].
        let shared_atom = Uuid::new_v4();
        let atom_solo = Uuid::new_v4();
        insert_claim(pool, agent_id, shared_atom, "shared atom", 3, None).await;
        insert_claim(pool, agent_id, atom_solo, "solo atom", 3, None).await;
        insert_edge(
            pool,
            paragraphs[0],
            "claim",
            shared_atom,
            "claim",
            "decomposes_to",
            None,
        )
        .await;
        insert_edge(
            pool,
            paragraphs[1],
            "claim",
            shared_atom,
            "claim",
            "decomposes_to",
            None,
        )
        .await;
        insert_edge(
            pool,
            paragraphs[0],
            "claim",
            atom_solo,
            "claim",
            "decomposes_to",
            None,
        )
        .await;

        // CORROBORATES from paragraphs[0] to a paragraph in paper B.
        let corroborates_target = Uuid::new_v4();
        insert_claim(
            pool,
            agent_id,
            corroborates_target,
            "paper-b-paragraph",
            2,
            Some(&pgvec),
        )
        .await;
        insert_edge(
            pool,
            paper_b,
            "paper",
            corroborates_target,
            "claim",
            "asserts",
            None,
        )
        .await;
        insert_edge(
            pool,
            paragraphs[0],
            "claim",
            corroborates_target,
            "claim",
            "CORROBORATES",
            Some(r#"{"strength": 0.92}"#),
        )
        .await;

        // continues_argument: paragraphs[0] -> paragraphs[1].
        insert_edge(
            pool,
            paragraphs[0],
            "claim",
            paragraphs[1],
            "claim",
            "continues_argument",
            None,
        )
        .await;

        // paper_b_atom: level=3 atom in paper B that decomposes from
        // corroborates_target. Linked to shared_atom via "same_as" atom-atom edge.
        let paper_b_atom = Uuid::new_v4();
        insert_claim(pool, agent_id, paper_b_atom, "paper-b atom", 3, None).await;
        insert_edge(
            pool,
            corroborates_target,
            "claim",
            paper_b_atom,
            "claim",
            "decomposes_to",
            None,
        )
        .await;
        insert_edge(
            pool,
            shared_atom,
            "claim",
            paper_b_atom,
            "claim",
            "same_as",
            None,
        )
        .await;

        // Separate section under paper A so the dedup test doesn't get
        // filtered out by the sibling exclusion. The `other_section_paragraph`
        // is reachable from paragraphs[0] via TWO paths:
        //   (a) continues_argument paragraphs[0] -> other_section_paragraph
        //   (b) atom-bridge through shared_atom (also a child of other_section_paragraph)
        let other_section = Uuid::new_v4();
        insert_claim(pool, agent_id, other_section, "other section", 1, None).await;
        insert_edge(
            pool,
            paper_a,
            "paper",
            other_section,
            "claim",
            "asserts",
            None,
        )
        .await;
        let other_section_paragraph = Uuid::new_v4();
        insert_claim(
            pool,
            agent_id,
            other_section_paragraph,
            "other-section paragraph",
            2,
            Some(&pgvec),
        )
        .await;
        insert_edge(
            pool,
            other_section,
            "claim",
            other_section_paragraph,
            "claim",
            "decomposes_to",
            None,
        )
        .await;
        insert_edge(
            pool,
            paper_a,
            "paper",
            other_section_paragraph,
            "claim",
            "asserts",
            None,
        )
        .await;
        insert_edge(
            pool,
            paragraphs[0],
            "claim",
            other_section_paragraph,
            "claim",
            "continues_argument",
            None,
        )
        .await;
        // Also share `shared_atom` with the other-section paragraph so
        // atom-bridge surfaces it too.
        insert_edge(
            pool,
            other_section_paragraph,
            "claim",
            shared_atom,
            "claim",
            "decomposes_to",
            None,
        )
        .await;

        Fixture {
            agent_id,
            paper_a,
            paper_b,
            section,
            paragraphs,
            shared_atom,
            atom_solo,
            corroborates_target,
            paper_b_atom,
            other_section_paragraph,
        }
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn truncation_flags_when_siblings_limit_below_total(pool: PgPool) {
    let fx = fixture::build(&pool).await;
    let ctx = fetch_batched_context(
        &pool,
        &viewerfx::public_viewer(&pool).await,
        &[fx.paragraphs[0]],
        /*siblings_limit=*/ 2,
        /*corroborates_limit=*/ 4,
        /*epistemic_limit=*/ 4,
    )
    .await
    .expect("fetch_batched_context");

    let total = ctx
        .siblings_total_by_paragraph
        .get(&fx.paragraphs[0])
        .copied()
        .unwrap_or(0);
    let returned = ctx
        .siblings_by_paragraph
        .get(&fx.paragraphs[0])
        .map(|v| v.len())
        .unwrap_or(0);
    assert_eq!(
        total, 5,
        "5 sibling paragraphs under same section (paragraphs[1..6])"
    );
    assert_eq!(returned, 2, "siblings_limit=2 → 2 returned");
}

#[sqlx::test(migrations = "../../migrations")]
async fn bridge_to_paragraphs_populated(pool: PgPool) {
    let fx = fixture::build(&pool).await;
    let ctx = fetch_batched_context(
        &pool,
        &viewerfx::public_viewer(&pool).await,
        &[fx.paragraphs[0]],
        8,
        4,
        4,
    )
    .await
    .expect("fetch_batched_context");

    let atoms = ctx
        .atoms_by_paragraph
        .get(&fx.paragraphs[0])
        .expect("atoms missing for paragraphs[0]");
    let shared = atoms
        .iter()
        .find(|a| a.atom_id == fx.shared_atom)
        .expect("shared_atom missing");
    assert!(
        shared.bridge_to_paragraphs.contains(&fx.paragraphs[1]),
        "shared_atom must list paragraphs[1] as a bridge"
    );
    assert!(
        !shared.bridge_to_paragraphs.contains(&fx.paragraphs[0]),
        "bridge_to_paragraphs must EXCLUDE the result paragraph itself"
    );
    let solo = atoms
        .iter()
        .find(|a| a.atom_id == fx.atom_solo)
        .expect("atom_solo missing");
    assert!(
        solo.bridge_to_paragraphs.is_empty(),
        "solo atom must have no bridges"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn corroborates_includes_paper_doi(pool: PgPool) {
    let fx = fixture::build(&pool).await;
    let ctx = fetch_batched_context(
        &pool,
        &viewerfx::public_viewer(&pool).await,
        &[fx.paragraphs[0]],
        8,
        4,
        4,
    )
    .await
    .expect("fetch_batched_context");

    let corr = ctx
        .corroborates_by_paragraph
        .get(&fx.paragraphs[0])
        .expect("corroborates missing");
    let edge = corr
        .iter()
        .find(|e| e.claim_id == fx.corroborates_target)
        .expect("CORROBORATES target missing");
    assert_eq!(edge.paper_doi.as_deref(), Some("10.2/B"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn corroborates_appears_on_both_endpoints_when_both_in_result_set(pool: PgPool) {
    let fx = fixture::build(&pool).await;
    // paragraphs[0] -[CORROBORATES]-> corroborates_target.
    // Pass BOTH as paragraph_ids so each should see the other in its list.
    let ctx = fetch_batched_context(
        &pool,
        &viewerfx::public_viewer(&pool).await,
        &[fx.paragraphs[0], fx.corroborates_target],
        8,
        4,
        4,
    )
    .await
    .unwrap();

    // paragraphs[0] sees corroborates_target as a neighbor.
    let p0_corr = ctx
        .corroborates_by_paragraph
        .get(&fx.paragraphs[0])
        .expect("paragraphs[0] missing CORROBORATES entry");
    assert!(
        p0_corr.iter().any(|e| e.claim_id == fx.corroborates_target),
        "paragraphs[0]'s CORROBORATES list must include corroborates_target",
    );

    // corroborates_target ALSO sees paragraphs[0] as a neighbor (the symmetric case).
    let target_corr = ctx
        .corroborates_by_paragraph
        .get(&fx.corroborates_target)
        .expect("corroborates_target missing CORROBORATES entry — bidirectional bug");
    assert!(
        target_corr.iter().any(|e| e.claim_id == fx.paragraphs[0]),
        "corroborates_target's CORROBORATES list must include paragraphs[0]",
    );

    // Per-direction-per-paragraph total accounting.
    let p0_total = ctx
        .corroborates_total_by_paragraph
        .get(&fx.paragraphs[0])
        .copied()
        .unwrap_or(0);
    let target_total = ctx
        .corroborates_total_by_paragraph
        .get(&fx.corroborates_target)
        .copied()
        .unwrap_or(0);
    assert_eq!(
        p0_total, 1,
        "paragraphs[0] should have total=1 corroborates neighbor"
    );
    assert_eq!(
        target_total, 1,
        "corroborates_target should have total=1 corroborates neighbor"
    );
}

/// U014 PR-1 (backlog 3ce5e00c): the batched CORROBORATES context matched only
/// the upper-case spelling the cross-source matcher writes. MCP
/// `link_epistemic` writes `corroborates`, and a later normalise-on-write or
/// data fold makes every row lower case, so a lower-case edge must be read as
/// the same corroboration. The fixture's `CORROBORATES` edge from
/// `paragraphs[0]` is the control.
///
/// The read is a UNION ALL of two arms, one keyed on `source_id` and one on
/// `target_id`, and each arm names the relationship separately. So a
/// lower-case edge is seeded in each direction: `paragraphs[1]` is the SOURCE
/// of one and `paragraphs[2]` is the TARGET of the other. Neither paragraph
/// has any other corroboration in the fixture, so each total is exactly 1.
#[sqlx::test(migrations = "../../migrations")]
async fn fetch_batched_context_counts_lowercase_corroborates(pool: PgPool) {
    let fx = fixture::build(&pool).await;
    let lower_target = Uuid::new_v4();
    fixture::insert_claim(
        &pool,
        fx.agent_id,
        lower_target,
        "lower-case corroboration partner",
        2,
        None,
    )
    .await;
    fixture::insert_edge(
        &pool,
        fx.paragraphs[1],
        "claim",
        lower_target,
        "claim",
        "corroborates",
        Some(r#"{"strength": 0.8}"#),
    )
    .await;
    // Target arm: the requested paragraph is the edge's TARGET.
    let lower_source = Uuid::new_v4();
    fixture::insert_claim(
        &pool,
        fx.agent_id,
        lower_source,
        "lower-case corroboration pointing at a paragraph",
        2,
        None,
    )
    .await;
    fixture::insert_edge(
        &pool,
        lower_source,
        "claim",
        fx.paragraphs[2],
        "claim",
        "corroborates",
        Some(r#"{"strength": 0.6}"#),
    )
    .await;

    let ctx = fetch_batched_context(
        &pool,
        &viewerfx::public_viewer(&pool).await,
        &[fx.paragraphs[0], fx.paragraphs[1], fx.paragraphs[2]],
        8,
        4,
        4,
    )
    .await
    .expect("fetch_batched_context");

    let control = ctx
        .corroborates_by_paragraph
        .get(&fx.paragraphs[0])
        .expect("control: the CORROBORATES edge is read");
    assert!(control.iter().any(|e| e.claim_id == fx.corroborates_target));

    let lower = ctx
        .corroborates_by_paragraph
        .get(&fx.paragraphs[1])
        .expect("a lower-case `corroborates` edge must appear in the batched context");
    assert!(
        lower.iter().any(|e| e.claim_id == lower_target),
        "paragraphs[1]'s corroborates list must include the lower-case partner",
    );
    assert_eq!(
        ctx.corroborates_total_by_paragraph
            .get(&fx.paragraphs[1])
            .copied(),
        Some(1),
        "and it is counted once in the per-paragraph total"
    );

    let incoming = ctx
        .corroborates_by_paragraph
        .get(&fx.paragraphs[2])
        .expect("a lower-case `corroborates` edge INTO a paragraph must be read by the target arm");
    assert!(
        incoming.iter().any(|e| e.claim_id == lower_source),
        "paragraphs[2]'s corroborates list must include the lower-case source; got {incoming:?}",
    );
    assert_eq!(
        ctx.corroborates_total_by_paragraph
            .get(&fx.paragraphs[2])
            .copied(),
        Some(1),
        "the incoming lower-case edge is counted once in paragraphs[2]'s total"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn explicit_3072_with_no_population_returns_invalid_params(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::tools::recall::{recall_with_context, RecallWithContextParams};
    use epigraph_mcp::EpiGraphMcpFull;

    // Seed: paragraphs with 1536d embeddings only — embedding_3072 untouched.
    let _fx = fixture::build(&pool).await;

    // Sanity: helper reports 0.0 for the unpopulated 3072 column.
    let frac = embedded_3072_population(&pool, &viewerfx::public_viewer(&pool).await)
        .await
        .expect("embedded_3072_population helper");
    assert_eq!(
        frac, 0.0,
        "fixture should leave embedding_3072 unpopulated on every embedded claim"
    );

    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None); // mock — no API key
    let server = EpiGraphMcpFull::new(pool.clone(), signer, embedder, /*read_only=*/ false);

    let params = RecallWithContextParams {
        query: "anything".to_string(),
        limit: Some(10),
        min_truth: None,
        centroid_dim: Some(3072),
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
        graph_expansion_depth: None,
        exclude_contested: false,
        since: None,
        epistemic_partition: false,
        diversity_radius: None,
    };

    let result = recall_with_context(&server, &viewer, params).await;
    let err = result.expect_err("expected an error for centroid_dim=3072 with no population");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("3072") && msg.contains("populated"),
        "error message should mention 3072 and population; got: {msg}",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighbor_paragraphs_include_continues_argument(pool: PgPool) {
    let fx = fixture::build(&pool).await;
    let ctx = fetch_batched_context(
        &pool,
        &viewerfx::public_viewer(&pool).await,
        &[fx.paragraphs[0]],
        8,
        4,
        4,
    )
    .await
    .unwrap();
    let neighbors = ctx
        .continues_argument_by_paragraph
        .get(&fx.paragraphs[0])
        .cloned()
        .unwrap_or_default();
    assert!(
        neighbors.contains(&fx.paragraphs[1]),
        "continues_argument from paragraphs[0] to paragraphs[1] must be reported"
    );
    assert!(
        neighbors.contains(&fx.other_section_paragraph),
        "continues_argument from paragraphs[0] to other_section_paragraph must be reported"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighbor_paragraphs_include_atom_atom_bridge(pool: PgPool) {
    let fx = fixture::build(&pool).await;
    let ctx = fetch_batched_context(
        &pool,
        &viewerfx::public_viewer(&pool).await,
        &[fx.paragraphs[0]],
        8,
        4,
        4,
    )
    .await
    .unwrap();
    // shared_atom (paper A) -[same_as]-> paper_b_atom (paper B);
    // paper_b_atom is a child of corroborates_target.
    let links = ctx
        .atom_atom_links_by_atom
        .get(&fx.shared_atom)
        .cloned()
        .unwrap_or_default();
    assert!(
        links
            .iter()
            .any(|(atom_b, rel)| atom_b == &fx.paper_b_atom && rel == "same_as"),
        "atom_atom_links must surface shared_atom -> paper_b_atom via same_as; got {links:?}"
    );
    let parents = ctx
        .paragraphs_by_atom
        .get(&fx.paper_b_atom)
        .cloned()
        .unwrap_or_default();
    assert!(
        parents.contains(&fx.corroborates_target),
        "paragraphs_by_atom for paper_b_atom must include corroborates_target; got {parents:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighbor_paragraphs_dedupe_and_via_aggregation(pool: PgPool) {
    let fx = fixture::build(&pool).await;
    let ctx = fetch_batched_context(
        &pool,
        &viewerfx::public_viewer(&pool).await,
        &[fx.paragraphs[0]],
        8,
        4,
        4,
    )
    .await
    .unwrap();

    let atoms = ctx
        .atoms_by_paragraph
        .get(&fx.paragraphs[0])
        .cloned()
        .unwrap_or_default();
    let siblings = ctx
        .siblings_by_paragraph
        .get(&fx.paragraphs[0])
        .cloned()
        .unwrap_or_default();

    let (neighbors, total, truncated) =
        assemble_neighbor_paragraphs(fx.paragraphs[0], &atoms, &siblings, &ctx, 16);

    assert!(!truncated, "16 cap should not truncate");

    // other_section_paragraph is reachable via BOTH continues_argument AND
    // atom-bridge (shared_atom). Should appear ONCE in neighbors with both
    // paths in `via`.
    let other = neighbors
        .iter()
        .find(|n| n.paragraph_id == fx.other_section_paragraph)
        .expect("other_section_paragraph must appear in neighbor_paragraphs");

    let has_continues = other
        .via
        .iter()
        .any(|p| matches!(p, NeighborPath::ContinuesArgument));
    let has_atom_bridge = other.via.iter().any(|p| {
        matches!(
            p,
            NeighborPath::AtomBridge { atom_id } if *atom_id == fx.shared_atom
        )
    });
    assert!(
        has_continues && has_atom_bridge,
        "other_section_paragraph must aggregate continues_argument + atom-bridge; got via={:?}",
        other.via
    );

    // Dedup: exactly one entry for other_section_paragraph.
    let count = neighbors
        .iter()
        .filter(|n| n.paragraph_id == fx.other_section_paragraph)
        .count();
    assert_eq!(count, 1, "other_section_paragraph must be deduped");

    // paragraphs[1] is a sibling of paragraphs[0] — must be EXCLUDED from
    // neighbor_paragraphs even though it's reachable via continues_argument
    // and atom-bridge.
    assert!(
        !neighbors.iter().any(|n| n.paragraph_id == fx.paragraphs[1]),
        "sibling paragraphs[1] must NOT appear in neighbor_paragraphs"
    );

    // The result paragraph itself must never appear.
    assert!(
        !neighbors.iter().any(|n| n.paragraph_id == fx.paragraphs[0]),
        "result paragraph must not appear in its own neighbor_paragraphs"
    );

    // total reflects pre-truncation count.
    assert_eq!(
        total,
        neighbors.len(),
        "total must equal materialized count when not truncated"
    );

    // corroborates_target is reachable via atom-atom-bridge
    // (shared_atom -[same_as]-> paper_b_atom, paper_b_atom decomposes_from
    // corroborates_target).
    let corr = neighbors
        .iter()
        .find(|n| n.paragraph_id == fx.corroborates_target)
        .expect("corroborates_target must appear via atom-atom-bridge");
    assert!(
        corr.via.iter().any(|p| matches!(
            p,
            NeighborPath::AtomAtomBridge { atom_a, atom_b, relationship }
            if *atom_a == fx.shared_atom
                && *atom_b == fx.paper_b_atom
                && relationship == "same_as"
        )),
        "corroborates_target's via must include AtomAtomBridge(shared_atom,paper_b_atom,same_as); got {:?}",
        corr.via
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighbor_paragraphs_truncation_flag_when_over_limit(pool: PgPool) {
    let fx = fixture::build(&pool).await;
    let ctx = fetch_batched_context(
        &pool,
        &viewerfx::public_viewer(&pool).await,
        &[fx.paragraphs[0]],
        8,
        4,
        4,
    )
    .await
    .unwrap();

    let atoms = ctx
        .atoms_by_paragraph
        .get(&fx.paragraphs[0])
        .cloned()
        .unwrap_or_default();
    let siblings = ctx
        .siblings_by_paragraph
        .get(&fx.paragraphs[0])
        .cloned()
        .unwrap_or_default();

    // Cap at 1 — both other_section_paragraph and corroborates_target are
    // reachable, so we should be truncated.
    let (materialized, total, truncated) =
        assemble_neighbor_paragraphs(fx.paragraphs[0], &atoms, &siblings, &ctx, 1);

    assert_eq!(materialized.len(), 1, "limit=1 should yield 1 result");
    assert!(total >= 2, "total before truncation should be >= 2");
    assert!(truncated, "truncated flag must be true");

    // Priority sort: continues_argument (priority=0) wins over
    // atom-atom-bridge (priority=2). other_section_paragraph has
    // continues_argument in its `via`, so it must come first.
    assert_eq!(
        materialized[0].paragraph_id, fx.other_section_paragraph,
        "highest-priority (continues_argument) neighbor must be first"
    );
}

// ============================================================================
// Diverse-mode tests
// ============================================================================
//
// These tests use the `__test_only::recall_with_context_with_pgvec`
// entry point to bypass the OpenAI embedder (tests run without an API
// key). They exercise the diverse-vs-flat branch in `recall_with_context`
// directly, with deterministic pgvector literals.

mod diverse_fixture {
    use super::*;

    const DIM: usize = 1536;
    const N_BUCKETS: usize = 8;
    pub const STRIDE: usize = DIM / N_BUCKETS;

    fn vec_to_pgvec(v: &[f32]) -> String {
        let inner: Vec<String> = v.iter().map(|x| x.to_string()).collect();
        format!("[{}]", inner.join(","))
    }

    /// Pgvector literal at dim=1536 that's heavily concentrated in
    /// `bucket * STRIDE .. (bucket+1) * STRIDE`. Same-bucket vectors are
    /// highly cosine-similar; different-bucket vectors are orthogonal.
    pub fn cluster_pgvec(bucket: usize, value: f32) -> String {
        let mut v = vec![0.0f32; DIM];
        let start = bucket * STRIDE;
        let end = start + STRIDE;
        for slot in v.iter_mut().take(end).skip(start) {
            *slot = value;
        }
        vec_to_pgvec(&v)
    }

    /// Pgvector with `value` in `bucket` AND `drift` in `drift_bucket`.
    /// Used by candidate_pool tests where we need *monotonically
    /// decreasing cosine similarity* across seeded rows: scaling
    /// magnitude alone (as `cluster_pgvec(0, 1.0 - i*0.01)` does) yields
    /// IDENTICAL cosine sim because direction is unchanged — direction
    /// must drift instead. `cos = value / sqrt(value² + drift²)`,
    /// monotonically decreasing in `drift > 0`.
    pub fn cluster_pgvec_with_drift(
        bucket: usize,
        value: f32,
        drift_bucket: usize,
        drift: f32,
    ) -> String {
        vec_to_pgvec(&drift_vec(bucket, value, drift_bucket, drift))
    }

    /// The raw vector behind `cluster_pgvec_with_drift`, shared with
    /// `cluster_pgvec_with_drift_and_query_share` so the drift layout lives
    /// in one place.
    fn drift_vec(bucket: usize, value: f32, drift_bucket: usize, drift: f32) -> Vec<f32> {
        let mut v = vec![0.0f32; DIM];
        let start = bucket * STRIDE;
        let end = start + STRIDE;
        for slot in v.iter_mut().take(end).skip(start) {
            *slot = value;
        }
        let dstart = drift_bucket * STRIDE;
        let dend = dstart + STRIDE;
        for slot in v.iter_mut().take(dend).skip(dstart) {
            *slot = drift;
        }
        v
    }

    /// `cluster_pgvec_with_drift(bucket, value, drift_bucket, drift)` plus a
    /// constant `query_share` in bucket 0 (the query bucket in these tests).
    ///
    /// For a "far" cluster that must stay further from the query than the
    /// near rows, yet NOT be exactly orthogonal to them. When two clusters are
    /// exactly orthogonal, every cross-cluster distance ties at cosine
    /// distance 1.0 (similarity 0), and the HNSW index built on insert can
    /// leave the near cluster unreachable from the graph's entry point. An
    /// index scan then returns only far rows, even at `hnsw.ef_search = 1000`
    /// with iterative scan. The shared bucket-0 component removes that exact
    /// tie. This is a measured result, not a guarantee: the unreachable-graph
    /// failure went from about 3% of fresh builds to 0 in 2750 (a 95% upper
    /// bound of about 0.11% per build).
    ///
    /// Precondition: `bucket` and `drift_bucket` are not 0. Bucket 0 is the
    /// query-share slot and is written last, so it would silently overwrite
    /// either of them.
    pub fn cluster_pgvec_with_drift_and_query_share(
        bucket: usize,
        value: f32,
        drift_bucket: usize,
        drift: f32,
        query_share: f32,
    ) -> String {
        debug_assert!(
            bucket != 0 && drift_bucket != 0,
            "bucket 0 is the query-share slot; got bucket={bucket}, drift_bucket={drift_bucket}"
        );
        let mut v = drift_vec(bucket, value, drift_bucket, drift);
        for slot in v.iter_mut().take(STRIDE) {
            *slot = query_share;
        }
        vec_to_pgvec(&v)
    }

    /// Pgvector that overlays mass in bucket 0 (the query bucket in
    /// these tests) AND in `far_bucket`. Used so theme_b candidates
    /// have meaningful similarity to the query (~0.7) — enough that
    /// the calibrated alpha=0.4 default exercises diversity rather
    /// than being overwhelmed by orthogonal sim=0 scores.
    pub fn mixed_bucket_pgvec(far_bucket: usize, query_share: f32) -> String {
        let mut v = vec![0.0f32; DIM];
        for slot in v.iter_mut().take(STRIDE) {
            *slot = query_share;
        }
        let start = far_bucket * STRIDE;
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
            .bind("bb".repeat(32))
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

    pub async fn seed_paragraph(
        pool: &PgPool,
        agent_id: Uuid,
        paper_id: Uuid,
        content: &str,
        embedding_pgvec: &str,
        theme_id: Option<Uuid>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding, theme_id) \
             VALUES ($1, $2, $3, $4, 0.7, jsonb_build_object('level', 2::int), $5::vector, $6)",
        )
        .bind(id)
        .bind(content)
        .bind(hash_for(id))
        .bind(agent_id)
        .bind(embedding_pgvec)
        .bind(theme_id)
        .execute(pool)
        .await
        .expect("seed paragraph");

        // Paper-attribution edge so the recall pipeline keeps the hit.
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

    pub async fn seed_theme_with_centroid(pool: &PgPool, label: &str, pgvec: &str) -> Uuid {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO claim_themes (label, description) VALUES ($1, 'diverse-test theme') \
             RETURNING id",
        )
        .bind(label)
        .fetch_one(pool)
        .await
        .expect("create theme");
        sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
            .bind(id)
            .bind(pgvec)
            .execute(pool)
            .await
            .expect("set centroid");
        id
    }
}

fn diverse_params(
    diverse: bool,
    max_themes: Option<u32>,
    alpha: Option<f32>,
    limit: u32,
) -> epigraph_mcp::tools::recall::RecallWithContextParams {
    diverse_params_with_pool(diverse, max_themes, alpha, limit, None)
}

fn diverse_params_with_pool(
    diverse: bool,
    max_themes: Option<u32>,
    alpha: Option<f32>,
    limit: u32,
    candidate_pool: Option<u32>,
) -> epigraph_mcp::tools::recall::RecallWithContextParams {
    use epigraph_mcp::tools::recall::RecallWithContextParams;
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
        diverse: Some(diverse),
        max_themes,
        diversity_weight: alpha,
        candidate_pool,
        rerank: None,
        rerank_pool_factor: None,
        groundedness_gate: None,
        frame_id: None,
        perspective_id: None,
        graph_expansion_depth: None,
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

/// Test: diverse=true with NO themes seeded must silently degrade to
/// flat ANN and still return results. Mirrors the REST fallback.
#[sqlx::test(migrations = "../../migrations")]
async fn diverse_mode_falls_back_to_flat_when_themes_empty(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;

    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/fb", "Fallback test").await;

    // 3 paragraphs, no themes seeded at all.
    let pgvec = diverse_fixture::cluster_pgvec(0, 1.0);
    let mut paragraph_ids = Vec::new();
    for i in 0..3 {
        let id = diverse_fixture::seed_paragraph(
            &pool,
            agent,
            paper,
            &format!("paragraph-{i}"),
            &pgvec,
            /*theme_id=*/ None,
        )
        .await;
        paragraph_ids.push(id);
    }

    let server = build_test_server(pool.clone());
    let params = diverse_params(/*diverse=*/ true, Some(5), Some(0.4), 10);
    let result = recall_with_context_with_pgvec(&server, &viewer, params, 1536, &pgvec)
        .await
        .expect("diverse-on-empty-themes must succeed");
    let resp = parse_response(result);

    assert_eq!(resp.centroid_dim_used, 1536);
    assert_eq!(
        resp.results.len(),
        3,
        "diverse=true with no themes must fall back to flat ANN and surface all 3 paragraphs"
    );
    let returned: std::collections::HashSet<Uuid> =
        resp.results.iter().map(|r| r.paragraph_id).collect();
    let expected: std::collections::HashSet<Uuid> = paragraph_ids.into_iter().collect();
    assert_eq!(
        returned, expected,
        "fallback should surface every seeded paragraph"
    );
}

/// Test: diverse=false leaves the existing flat-ANN ordering unchanged.
/// Compares against `ClaimRepository::search_by_embedding_since` in the
/// whole-corpus scope (drain U082) — the exact call the flat path makes.
#[sqlx::test(migrations = "../../migrations")]
async fn diverse_false_matches_existing_flat_ordering(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;

    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/reg", "Regression test").await;

    // Seed paragraphs at staggered similarity to the query.
    let query_pgvec = diverse_fixture::cluster_pgvec(0, 1.0);
    let mut paragraph_ids = Vec::new();
    for i in 0..5 {
        // Direction drift, not magnitude, so every paragraph has its own
        // cosine and the order is fully determined (scaling `cluster_pgvec`
        // leaves the cosine unchanged, and an all-tie page's order is just
        // the plan's).
        let para_vec = diverse_fixture::cluster_pgvec_with_drift(0, 1.0, 1, 0.1 * i as f32);
        let id = diverse_fixture::seed_paragraph(
            &pool,
            agent,
            paper,
            &format!("paragraph-{i}"),
            &para_vec,
            None,
        )
        .await;
        paragraph_ids.push(id);
    }

    // Reference: direct call to the same repo function recall_with_context
    // uses in diverse=false mode. If diverse=false matches this ordering
    // verbatim, the diverse-routing change preserves the flat path.
    let direct_hits = epigraph_db::ClaimRepository::search_by_embedding_since(
        &pool,
        &viewer,
        &query_pgvec,
        1536,
        10,
        None,
        None,
        epigraph_db::EmbeddingSeedScope::AllClaims,
    )
    .await
    .expect("direct flat ANN");
    let direct_order: Vec<Uuid> = direct_hits.iter().map(|h| h.claim_id).collect();
    assert_eq!(
        direct_order, paragraph_ids,
        "calibration: the drifted fixture ranks the paragraphs in seed order"
    );

    let server = build_test_server(pool.clone());
    let params = diverse_params(/*diverse=*/ false, None, None, 10);
    let result = recall_with_context_with_pgvec(&server, &viewer, params, 1536, &query_pgvec)
        .await
        .expect("diverse=false");
    let resp = parse_response(result);

    let recall_order: Vec<Uuid> = resp.results.iter().map(|r| r.paragraph_id).collect();
    assert_eq!(
        recall_order, direct_order,
        "diverse=false ordering must match direct ClaimRepository::search_by_embedding_since \
         (AllClaims) ordering"
    );
}

/// `candidate_pool` plumbing — small value should restrict the SQL pool
/// so submodular `diverse_select` cannot see low-relevance rows.
///
/// Seeds 30 paragraphs in ONE theme, similarity monotonically decreasing.
/// Runs `recall_with_context` with `diverse=true, candidate_pool=20`,
/// `budget=5`, `diversity_weight=0.0` (pure relevance). Asserts the result
/// is the top-5 by similarity AND none of seeded rows 20..30 (those are
/// strictly excluded by SQL `LIMIT 20`) appear.
#[sqlx::test(migrations = "../../migrations")]
async fn candidate_pool_20_restricts_mcp_diverse_pool(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;

    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/pool20", "candidate_pool=20").await;
    let theme = diverse_fixture::seed_theme_with_centroid(
        &pool,
        "single-theme",
        &diverse_fixture::cluster_pgvec(0, 1.0),
    )
    .await;

    // 30 paragraphs in this theme, monotonically decreasing similarity.
    let mut seeded: Vec<Uuid> = Vec::with_capacity(30);
    for i in 0..30 {
        let v = diverse_fixture::cluster_pgvec_with_drift(0, 1.0, 1, (i as f32) * 0.05);
        let id = diverse_fixture::seed_paragraph(
            &pool,
            agent,
            paper,
            &format!("pool20-claim-{i}"),
            &v,
            Some(theme),
        )
        .await;
        seeded.push(id);
    }

    let server = build_test_server(pool.clone());
    let query_pgvec = diverse_fixture::cluster_pgvec(0, 1.0);
    let params = diverse_params_with_pool(
        /*diverse=*/ true,
        Some(5),
        /*alpha=*/ Some(0.0), // pure relevance
        /*limit=*/ 5,
        /*candidate_pool=*/ Some(20),
    );

    let result = recall_with_context_with_pgvec(&server, &viewer, params, 1536, &query_pgvec)
        .await
        .expect("recall_with_context with candidate_pool=20");
    let resp = parse_response(result);

    let returned: std::collections::HashSet<Uuid> =
        resp.results.iter().map(|r| r.paragraph_id).collect();
    assert_eq!(returned.len(), 5, "budget=5 → 5 results");

    // Top-5 of 30 by similarity are seeded[0..5].
    let top_5: std::collections::HashSet<Uuid> = seeded[..5].iter().copied().collect();
    assert_eq!(
        returned, top_5,
        "candidate_pool=20 + pure-relevance MUST yield exactly the top-5 by similarity"
    );

    // Rows 20..30 are strictly excluded by SQL `LIMIT 20` in candidates_in_themes_at_dim.
    // Their exclusion is the proof that 20 reached the SQL — a leak to the default 100
    // would still pure-relevance pick the same top-5, so we also assert the result is
    // EXACTLY the top-5 above.
    let excluded_tail: std::collections::HashSet<Uuid> = seeded[20..30].iter().copied().collect();
    assert!(
        returned.is_disjoint(&excluded_tail),
        "rows 20..30 must not appear (SQL LIMIT 20 excludes them); returned={returned:?}"
    );
}

/// `candidate_pool` plumbing — large value widens the SQL pool so
/// submodular `diverse_select` under pure-coverage selects ≥1 claim
/// outside the top-5 by similarity. With pool=5 (or 20) that claim
/// could never enter the candidate matrix.
#[sqlx::test(migrations = "../../migrations")]
async fn candidate_pool_200_widens_mcp_diverse_pool(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;

    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/pool200", "candidate_pool=200").await;
    let theme = diverse_fixture::seed_theme_with_centroid(
        &pool,
        "single-theme-large",
        &diverse_fixture::cluster_pgvec(0, 1.0),
    )
    .await;

    let mut seeded: Vec<Uuid> = Vec::with_capacity(30);
    for i in 0..30 {
        let v = diverse_fixture::cluster_pgvec_with_drift(0, 1.0, 1, (i as f32) * 0.05);
        let id = diverse_fixture::seed_paragraph(
            &pool,
            agent,
            paper,
            &format!("pool200-claim-{i}"),
            &v,
            Some(theme),
        )
        .await;
        seeded.push(id);
    }

    let server = build_test_server(pool.clone());
    let query_pgvec = diverse_fixture::cluster_pgvec(0, 1.0);
    let params = diverse_params_with_pool(
        /*diverse=*/ true,
        Some(5),
        /*alpha=*/ Some(1.0), // pure coverage
        /*limit=*/ 5,
        /*candidate_pool=*/ Some(200),
    );

    let result = recall_with_context_with_pgvec(&server, &viewer, params, 1536, &query_pgvec)
        .await
        .expect("recall_with_context with candidate_pool=200");
    let resp = parse_response(result);

    let returned: std::collections::HashSet<Uuid> =
        resp.results.iter().map(|r| r.paragraph_id).collect();
    assert_eq!(returned.len(), 5, "budget=5 → 5 results");

    // With pure coverage on a 30-row pool, submodular spread should reach
    // claims outside the top-5 by relevance.
    let top_5: std::collections::HashSet<Uuid> = seeded[..5].iter().copied().collect();
    let outside_top_5: usize = returned.iter().filter(|id| !top_5.contains(id)).count();
    assert!(
        outside_top_5 >= 1,
        "candidate_pool=200 + pure coverage must surface ≥1 claim outside the top-5 by relevance; \
         returned={returned:?}, top_5={top_5:?}"
    );
}

/// Diversity proof: diverse=true selects across ≥2 themes when flat ANN
/// would have landed entirely in 1. Fixture has theme_a near the query
/// and theme_b far; flat takes 5 from theme_a, diverse with alpha=0.4
/// pulls in ≥1 from theme_b for graph coverage.
#[sqlx::test(migrations = "../../migrations")]
async fn diverse_true_spreads_across_themes_versus_flat(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;

    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/div", "Diversity test").await;

    // theme_a near bucket 0 (query lives here); theme_b shares some
    // mass with bucket 0 (sim_b ≈ 0.7) so it isn't orthogonally
    // dismissed by the relevance term. See the engine integration test
    // for the exact arithmetic — alpha=0.4 default needs sim_b > 0.33
    // for the coverage term to win pick #2.
    let theme_a = diverse_fixture::seed_theme_with_centroid(
        &pool,
        "near-theme",
        &diverse_fixture::cluster_pgvec(0, 1.0),
    )
    .await;
    let theme_b = diverse_fixture::seed_theme_with_centroid(
        &pool,
        "far-theme",
        &diverse_fixture::mixed_bucket_pgvec(3, 1.0),
    )
    .await;

    // 6 paragraphs near (theme_a) — slight stagger so they're top-5 by
    // flat ANN. 6 paragraphs at the mixed (bucket 0 + bucket 3) region
    // (theme_b) — lower flat score but coverage gain.
    let query_pgvec = diverse_fixture::cluster_pgvec(0, 1.0);
    for i in 0..6 {
        let v = diverse_fixture::cluster_pgvec(0, 1.0 - (i as f32) * 0.001);
        diverse_fixture::seed_paragraph(
            &pool,
            agent,
            paper,
            &format!("near-{i}"),
            &v,
            Some(theme_a),
        )
        .await;
    }
    for i in 0..6 {
        let v = diverse_fixture::mixed_bucket_pgvec(3, 1.0 - (i as f32) * 0.01);
        diverse_fixture::seed_paragraph(
            &pool,
            agent,
            paper,
            &format!("far-{i}"),
            &v,
            Some(theme_b),
        )
        .await;
    }

    let server = build_test_server(pool.clone());

    // Flat baseline: hit count by theme.
    let flat_params = diverse_params(/*diverse=*/ false, None, None, 5);
    let flat_result =
        recall_with_context_with_pgvec(&server, &viewer, flat_params, 1536, &query_pgvec)
            .await
            .expect("flat baseline");
    let flat_resp = parse_response(flat_result);
    assert_eq!(
        flat_resp.results.len(),
        5,
        "fixture must give flat ANN 5 results to fill the budget"
    );
    let flat_ids: Vec<Uuid> = flat_resp.results.iter().map(|r| r.paragraph_id).collect();
    let flat_themes: std::collections::HashSet<Uuid> = sqlx::query_scalar(
        "SELECT theme_id FROM claims WHERE id = ANY($1) AND theme_id IS NOT NULL",
    )
    .bind(&flat_ids)
    .fetch_all(&pool)
    .await
    .expect("flat theme_ids")
    .into_iter()
    .collect();
    assert_eq!(
        flat_themes.len(),
        1,
        "fixture invariant: flat ANN must hit exactly one theme; got {flat_themes:?}"
    );
    assert!(
        flat_themes.contains(&theme_a),
        "flat ANN should pick from theme_a (closest to query)"
    );

    // Diverse path: budget 5, alpha 0.4 (MCP default).
    let diverse_params_v = diverse_params(/*diverse=*/ true, Some(5), Some(0.4), 5);
    let diverse_result =
        recall_with_context_with_pgvec(&server, &viewer, diverse_params_v, 1536, &query_pgvec)
            .await
            .expect("diverse path");
    let diverse_resp = parse_response(diverse_result);
    assert_eq!(
        diverse_resp.results.len(),
        5,
        "diverse=true should fill the budget (5) when ≥5 paragraph candidates exist across the themes — partial fill would mean the post-selection enrichment is dropping rows unexpectedly"
    );
    let diverse_ids: Vec<Uuid> = diverse_resp
        .results
        .iter()
        .map(|r| r.paragraph_id)
        .collect();
    let diverse_themes: std::collections::HashSet<Uuid> = sqlx::query_scalar(
        "SELECT theme_id FROM claims WHERE id = ANY($1) AND theme_id IS NOT NULL",
    )
    .bind(&diverse_ids)
    .fetch_all(&pool)
    .await
    .expect("diverse theme_ids")
    .into_iter()
    .collect();
    assert!(
        diverse_themes.len() >= 2,
        "diverse_select must spread across ≥2 themes; got {diverse_themes:?}, diverse_ids={diverse_ids:?}"
    );
    assert!(
        diverse_themes.contains(&theme_a) && diverse_themes.contains(&theme_b),
        "diverse selection should contain both theme_a (relevance) and theme_b (coverage); got {diverse_themes:?}"
    );
}

/// F3 (backlog 34d3400d): a contested paragraph hit carries the dispute
/// annotation through `recall_with_context`, and an uncontested hit on the
/// same page omits the fields entirely.
///
/// This surface keys its post-passes on `paragraph_id` rather than a
/// `claim_id` field, so it is the one most likely to silently annotate
/// nothing if the post-pass collects the wrong id — hence a dedicated test
/// rather than relying on the plain-`recall` coverage.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_annotates_contested_paragraph(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;

    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/dispute", "Dispute test").await;
    let pgvec = diverse_fixture::cluster_pgvec(0, 1.0);

    let contested =
        diverse_fixture::seed_paragraph(&pool, agent, paper, "contested para", &pgvec, None).await;
    let clean =
        diverse_fixture::seed_paragraph(&pool, agent, paper, "clean para", &pgvec, None).await;

    // Two live contesters (differing truth) plus one retracted contester that
    // must NOT count — the is_current filter is the easiest thing to lose in a
    // refactor of the post-pass.
    let strong: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ('strong rebuttal', sha256('strong rebuttal'::bytea), 0.9, $1, true) RETURNING id",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("seed strong contester");
    let weak: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ('weak rebuttal', sha256('weak rebuttal'::bytea), 0.4, $1, true) RETURNING id",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("seed weak contester");
    let retracted: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ('retracted rebuttal', sha256('retracted rebuttal'::bytea), 0.9, $1, false)
         RETURNING id",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("seed retracted contester");

    for (src, rel) in [
        (strong, "contradicts"),
        (weak, "refutes"),
        (retracted, "contradicts"),
    ] {
        sqlx::query(
            "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
             VALUES ($1, $2, 'claim', 'claim', $3)",
        )
        .bind(src)
        .bind(contested)
        .bind(rel)
        .execute(&pool)
        .await
        .expect("seed dispute edge");
    }

    let server = build_test_server(pool.clone());
    let result = recall_with_context_with_pgvec(
        &server,
        &viewer,
        diverse_params(false, None, None, 10),
        1536,
        &pgvec,
    )
    .await
    .expect("recall_with_context ok");

    // Parse as raw JSON, not the typed struct: field ABSENCE is the assertion,
    // and a typed struct with defaults would mask it.
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    let json: serde_json::Value = serde_json::from_str(&text).expect("parse JSON");
    let results = json["results"].as_array().expect("results array");

    let contested_row = results
        .iter()
        .find(|r| r["paragraph_id"] == contested.to_string())
        .expect("contested paragraph returned");
    assert_eq!(
        contested_row["dispute_count"],
        serde_json::json!(2),
        "two live contesters; the retracted one must not count"
    );
    assert_eq!(contested_row["is_contested"], serde_json::json!(true));
    let ids = contested_row["contesting_claim_ids"]
        .as_array()
        .expect("contesting ids present");
    assert_eq!(
        ids[0],
        serde_json::json!(strong.to_string()),
        "strongest contester ranks first"
    );
    assert!(
        !ids.iter()
            .any(|v| *v == serde_json::json!(retracted.to_string())),
        "retracted contester must not be surfaced"
    );

    let clean_row = results
        .iter()
        .find(|r| r["paragraph_id"] == clean.to_string())
        .expect("uncontested paragraph returned");
    assert!(
        clean_row.get("dispute_count").is_none(),
        "uncontested hit omits dispute_count entirely (byte-identical to pre-F3)"
    );
    assert!(
        clean_row.get("is_contested").is_none(),
        "uncontested hit omits is_contested"
    );
}

// ============================================================================
// Epistemic-edge neighbours at the TOOL-RESPONSE boundary (backlog 922a1e54)
// ============================================================================
//
// `fetch_batched_context` has filled `epistemic_edges_by_paragraph` since #462,
// and the ctx-level tests further down pin that. But the hit-assembly loop never
// read the map, so no caller ever saw a single supports / refutes / specializes
// neighbour — and the ctx tests stayed green throughout. These assert on the
// serialized response a caller actually receives.

/// A claim inserted for its role as an epistemic-edge endpoint: public (the
/// insert trigger stamps tenancy from the default visibility), current, no
/// embedding — so it is never itself a recall hit.
async fn seed_neighbour_claim(pool: &PgPool, agent: Uuid, content: &str, truth: f64) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), $2, $3, true) RETURNING id",
    )
    .bind(content)
    .bind(truth)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed epistemic neighbour claim")
}

async fn seed_claim_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
         VALUES ($1, $2, 'claim', 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed epistemic edge");
}

/// Run `recall_with_context` end to end and return the raw JSON row for
/// `paragraph`. Raw `serde_json::Value`, not a typed struct: the defect is a
/// MISSING key, and a typed struct with `#[serde(default)]` would mask it.
async fn recall_row_for(
    pool: &PgPool,
    params: epigraph_mcp::tools::recall::RecallWithContextParams,
    pgvec: &str,
    paragraph: Uuid,
) -> serde_json::Value {
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;
    let viewer = viewerfx::public_viewer(pool).await;
    let server = build_test_server(pool.clone());
    let result = recall_with_context_with_pgvec(&server, &viewer, params, 1536, pgvec)
        .await
        .expect("recall_with_context ok");
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    let json: serde_json::Value = serde_json::from_str(&text).expect("parse JSON");
    json["results"]
        .as_array()
        .expect("results array")
        .iter()
        .find(|r| r["paragraph_id"] == paragraph.to_string())
        .cloned()
        .unwrap_or_else(|| panic!("paragraph {paragraph} not returned by recall_with_context"))
}

fn epistemic_edges_of(row: &serde_json::Value) -> Vec<serde_json::Value> {
    let edges = row.get("epistemic_edges");
    assert!(
        edges.is_some(),
        "recall_with_context fetched epistemic edges but dropped them before RecallHit \
         (backlog 922a1e54); hit keys were: {:?}",
        row.as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>())
    );
    edges
        .and_then(|v| v.as_array())
        .cloned()
        .expect("epistemic_edges must be a JSON array")
}

fn has_edge(edges: &[serde_json::Value], claim: Uuid, relationship: &str, direction: &str) -> bool {
    edges.iter().any(|e| {
        e["claim_id"] == claim.to_string()
            && e["relationship"] == relationship
            && e["direction"] == direction
    })
}

/// The hit itself must carry its epistemic neighbours, with direction: an
/// INCOMING `refutes` is "is refuted by", the opposite credibility signal from
/// an outgoing one.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_hit_carries_epistemic_edges(pool: PgPool) {
    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/epi-edges", "Epistemic edges").await;
    let pgvec = diverse_fixture::cluster_pgvec(0, 1.0);
    let para = diverse_fixture::seed_paragraph(&pool, agent, paper, "epi para", &pgvec, None).await;

    let refuter = seed_neighbour_claim(&pool, agent, "a refutation of epi para", 0.9).await;
    let supported = seed_neighbour_claim(&pool, agent, "a claim epi para supports", 0.6).await;
    seed_claim_edge(&pool, refuter, para, "refutes").await; // incoming, from para's view
    seed_claim_edge(&pool, para, supported, "supports").await; // outgoing
                                                               // A second hit in the same cluster with NO epistemic edges at all.
    let bare =
        diverse_fixture::seed_paragraph(&pool, agent, paper, "bare para", &pgvec, None).await;

    let row = recall_row_for(&pool, diverse_params(false, None, None, 10), &pgvec, para).await;
    let edges = epistemic_edges_of(&row);

    assert!(
        has_edge(&edges, refuter, "refutes", "incoming"),
        "the refuter is the edge SOURCE, so the hit must report it as an incoming \
         `refutes` (\"is refuted by\"); got {edges:?}"
    );
    assert!(
        has_edge(&edges, supported, "supports", "outgoing"),
        "the hit is the edge SOURCE of `supports`, so it must be reported outgoing; got {edges:?}"
    );
    let refuter_entry = edges
        .iter()
        .find(|e| e["claim_id"] == refuter.to_string())
        .expect("refuter entry");
    assert_eq!(refuter_entry["content"], "a refutation of epi para");
    assert_eq!(refuter_entry["truth_value"], serde_json::json!(0.9));
    assert_eq!(
        edges.len(),
        2,
        "exactly the two seeded epistemic neighbours"
    );
    assert_eq!(row["epistemic_edges_total"], serde_json::json!(2));
    assert_eq!(row["epistemic_edges_truncated"], serde_json::json!(false));

    // Stable shape (scope OQ2): a hit with no visible epistemic neighbours still
    // CARRIES the three keys, so an empty list reads "none visible" rather than
    // "not computed". `skip_serializing_if = "Vec::is_empty"` would drop them.
    let bare_row = recall_row_for(&pool, diverse_params(false, None, None, 10), &pgvec, bare).await;
    let bare_obj = bare_row.as_object().expect("hit is a JSON object");
    for key in [
        "epistemic_edges",
        "epistemic_edges_total",
        "epistemic_edges_truncated",
    ] {
        assert!(
            bare_obj.contains_key(key),
            "a hit with no epistemic neighbours must still carry `{key}` (always \
             serialized, like `corroborates`); hit keys were: {:?}",
            bare_obj.keys().collect::<Vec<_>>()
        );
    }
    assert_eq!(bare_row["epistemic_edges"], serde_json::json!([]));
    assert_eq!(bare_row["epistemic_edges_total"], serde_json::json!(0));
    assert_eq!(
        bare_row["epistemic_edges_truncated"],
        serde_json::json!(false)
    );
}

/// A claim's scope caveats travel with it (backlog 99582af7, design note 3): a
/// `qualifies` edge ("A bounds the conditions under which B applies") is
/// returned among the hit's epistemic neighbours, with direction, so a caller
/// reading the hit also reads where it does NOT hold. Both directions are
/// seeded: incoming = "is qualified by", outgoing = "qualifies".
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_hit_carries_its_qualifies_caveats(pool: PgPool) {
    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/epi-qualifies", "Scope caveats").await;
    let pgvec = diverse_fixture::cluster_pgvec(0, 1.0);
    let para =
        diverse_fixture::seed_paragraph(&pool, agent, paper, "anchor hub para", &pgvec, None).await;

    let caveat = seed_neighbour_claim(&pool, agent, "holds only in 1 M monovalent NaCl", 0.9).await;
    let bounded = seed_neighbour_claim(&pool, agent, "a claim the hub para bounds", 0.7).await;
    seed_claim_edge(&pool, caveat, para, "qualifies").await; // incoming
    seed_claim_edge(&pool, para, bounded, "qualifies").await; // outgoing

    let row = recall_row_for(&pool, diverse_params(false, None, None, 10), &pgvec, para).await;
    let edges = epistemic_edges_of(&row);

    assert!(
        has_edge(&edges, caveat, "qualifies", "incoming"),
        "the caveat is the edge SOURCE, so the hit must carry it as an incoming \
         `qualifies` (\"is qualified by\"); got {edges:?}"
    );
    assert!(
        has_edge(&edges, bounded, "qualifies", "outgoing"),
        "the hit is the SOURCE of the second `qualifies`, so it must be reported \
         outgoing; got {edges:?}"
    );
    assert_eq!(row["epistemic_edges_total"], serde_json::json!(2));

    // The contract a caller reads names the relation too.
    let tools = epigraph_mcp::EpiGraphMcpFull::all_tools_json();
    let limit_doc = tools
        .as_array()
        .expect("all_tools_json returns an array")
        .iter()
        .find(|t| t["name"] == "recall_with_context")
        .expect("recall_with_context is registered")["inputSchema"]["properties"]
        ["epistemic_limit"]["description"]
        .as_str()
        .expect("epistemic_limit has a description")
        .to_string();
    assert!(
        limit_doc.contains("elaborates / cites / qualifies"),
        "recall_with_context's epistemic_limit must list qualifies among the carried \
         relationships; got: {limit_doc}"
    );
}

/// `epistemic_limit` caps PER RELATIONSHIP, keeps the strongest neighbour of
/// each, and `epistemic_edges_total` / `_truncated` report what the cap hid.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_epistemic_edges_cap_per_relationship(pool: PgPool) {
    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/epi-cap", "Epistemic cap").await;
    let pgvec = diverse_fixture::cluster_pgvec(0, 1.0);
    let para =
        diverse_fixture::seed_paragraph(&pool, agent, paper, "capped para", &pgvec, None).await;

    let strong = seed_neighbour_claim(&pool, agent, "strong support", 0.9).await;
    let middling = seed_neighbour_claim(&pool, agent, "middling support", 0.5).await;
    let weak = seed_neighbour_claim(&pool, agent, "weak support", 0.3).await;
    let refuter = seed_neighbour_claim(&pool, agent, "lone refutation", 0.4).await;
    for s in [middling, weak, strong] {
        seed_claim_edge(&pool, s, para, "supports").await;
    }
    seed_claim_edge(&pool, refuter, para, "refutes").await;

    let mut params = diverse_params(false, None, None, 10);
    params.epistemic_limit = Some(1);
    let row = recall_row_for(&pool, params, &pgvec, para).await;
    let edges = epistemic_edges_of(&row);

    let supports: Vec<_> = edges
        .iter()
        .filter(|e| e["relationship"] == "supports")
        .collect();
    assert_eq!(
        supports.len(),
        1,
        "epistemic_limit=1 caps EACH relationship at one; got {edges:?}"
    );
    assert_eq!(
        supports[0]["claim_id"],
        serde_json::json!(strong.to_string()),
        "the cap must keep the highest-truth neighbour of the relationship"
    );
    assert!(
        has_edge(&edges, refuter, "refutes", "incoming"),
        "a cap on `supports` must not starve `refutes` — the limit is per relationship; \
         got {edges:?}"
    );
    assert_eq!(edges.len(), 2);
    assert_eq!(
        row["epistemic_edges_total"],
        serde_json::json!(4),
        "total counts every visible epistemic neighbour, not the returned page"
    );
    assert_eq!(row["epistemic_edges_truncated"], serde_json::json!(true));

    // epistemic_limit=0 is raised to 1. The total is carried on the returned
    // rows, so a literal cap of 0 returned no rows and reported `total: 0,
    // truncated: false` for a hit with four visible neighbours.
    let mut params = diverse_params(false, None, None, 10);
    params.epistemic_limit = Some(0);
    let row = recall_row_for(&pool, params, &pgvec, para).await;
    let edges = epistemic_edges_of(&row);
    assert_eq!(
        row["epistemic_edges_total"],
        serde_json::json!(4),
        "epistemic_limit=0 must not hide the total; got row {row}"
    );
    assert_eq!(row["epistemic_edges_truncated"], serde_json::json!(true));
    assert_eq!(
        edges.len(),
        2,
        "epistemic_limit=0 is floored to 1 per relationship; got {edges:?}"
    );
}

/// The tool description is the only place a caller learns the field exists.
/// No DB: the description is static router metadata.
#[test]
fn recall_with_context_description_advertises_epistemic_edges() {
    let tools = epigraph_mcp::EpiGraphMcpFull::all_tools_json();
    let description = tools
        .as_array()
        .expect("tools array")
        .iter()
        .find(|t| t["name"] == "recall_with_context")
        .and_then(|t| t["description"].as_str())
        .expect("recall_with_context is registered with a description")
        .to_string();
    for needle in [
        "epistemic-edge neighbours",
        "supports / refutes / contradicts / specializes / elaborates / cites",
        "direction incoming|outgoing",
        "epistemic_limit",
        "epistemic_edges_total",
    ] {
        assert!(
            description.contains(needle),
            "recall_with_context description must advertise the epistemic-edge payload \
             ({needle:?} missing); got: {description}"
        );
    }
}

/// F5 (backlog 8cbffa0e): `recall_with_context` must write its OWN audit row,
/// tagged with its own tool name. The plain `recall` path logging is not
/// evidence that this surface does — they are separate handlers.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_writes_its_own_audit_row(pool: PgPool) {
    // A viewer for a REAL principal, not the nil one: the audit row is owned by
    // the request principal's personal group, and a principal that is not an
    // agent has none — so the write correctly drops rather than widening. See
    // `recall_audit_wiring.rs::principal_viewer`.
    let (audit_principal, _audit_group) = viewerfx::seed_agent_with_group(&pool, "rwc-audit").await;
    let viewer = epigraph_db::Viewer::resolve(&pool, audit_principal)
        .await
        .expect("resolve the request principal");
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;

    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/audit", "Audit test").await;
    let pgvec = diverse_fixture::cluster_pgvec(0, 1.0);
    let para =
        diverse_fixture::seed_paragraph(&pool, agent, paper, "audited para", &pgvec, None).await;

    // WITH a `ScopedPool`: the audit owner is read on a transaction stamped from
    // the principal's own viewer and never minted (#493); without one the row
    // is dropped. See `recall_audit_wiring.rs::build_test_server`.
    let server =
        build_test_server(pool.clone()).with_scoped_pool(viewerfx::scoped_pool(&pool).await);
    let result = recall_with_context_with_pgvec(
        &server,
        &viewer,
        diverse_params(false, None, None, 10),
        1536,
        &pgvec,
    )
    .await
    .expect("recall_with_context ok");

    // The response cites the audit row it wrote.
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text");
    let json: serde_json::Value = serde_json::from_str(&text).expect("parse");
    let event_id = json["recall_event_id"]
        .as_str()
        .expect("recall_event_id must be returned so a caller can cite the retrieval");

    // The write is spawned; poll for it.
    let mut row: Option<(String, Vec<Uuid>)> = None;
    for _ in 0..50 {
        if let Some(r) = sqlx::query!(
            "SELECT tool, returned_claim_ids FROM recall_events WHERE id = $1::uuid",
            Uuid::parse_str(event_id).unwrap()
        )
        .fetch_optional(&pool)
        .await
        .unwrap()
        {
            row = Some((r.tool, r.returned_claim_ids));
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let (tool, ids) = row.expect("the cited audit row must actually exist");
    assert_eq!(
        tool, "recall_with_context",
        "the row must be attributed to THIS surface, not to plain recall"
    );
    assert!(
        ids.contains(&para),
        "the audit row records the paragraph ids actually returned"
    );
}

/// Regression guard for backlog claim 922a1e54.
///
/// `recall_with_context`'s structural context advertised epistemic-edge
/// neighbours (the `EpistemicEdgeNeighbor` type and the
/// `epistemic_edges_by_paragraph` field both shipped), but the field was bound
/// with `let` rather than `let mut` and initialised to an empty map, so it was
/// structurally incapable of ever being populated. A hit therefore arrived
/// without the relationships that determine whether it should be believed.
///
/// Asserts BOTH directions, because direction carries the meaning: `refutes`
/// read backwards is "is refuted by".
#[sqlx::test(migrations = "../../migrations")]
async fn epistemic_edges_populated_in_both_directions(pool: PgPool) {
    let fx = fixture::build(&pool).await;
    let agent_id = fx.agent_id;

    // Incoming: refuter --refutes--> paragraphs[0]
    let refuter = Uuid::new_v4();
    fixture::insert_claim(&pool, agent_id, refuter, "a refuting claim", 2, None).await;
    fixture::insert_edge(
        &pool,
        refuter,
        "claim",
        fx.paragraphs[0],
        "claim",
        "refutes",
        None,
    )
    .await;

    // Outgoing: paragraphs[0] --supports--> supported
    let supported = Uuid::new_v4();
    fixture::insert_claim(&pool, agent_id, supported, "a supported claim", 2, None).await;
    fixture::insert_edge(
        &pool,
        fx.paragraphs[0],
        "claim",
        supported,
        "claim",
        "supports",
        None,
    )
    .await;

    let ctx = fetch_batched_context(
        &pool,
        &viewerfx::public_viewer(&pool).await,
        &[fx.paragraphs[0]],
        8,
        4,
        4,
    )
    .await
    .expect("fetch_batched_context");

    let edges = ctx
        .epistemic_edges_by_paragraph
        .get(&fx.paragraphs[0])
        .unwrap_or_else(|| {
            panic!(
                "no epistemic edges for paragraph {} — the context payload never traverses \
                 supports/refutes/contradicts/specializes/elaborates/cites (claim 922a1e54)",
                fx.paragraphs[0]
            )
        });

    let incoming = edges
        .iter()
        .find(|e| e.claim_id == refuter)
        .expect("incoming refutes neighbour missing");
    assert_eq!(incoming.relationship, "refutes");
    assert!(
        matches!(incoming.direction, EdgeDirection::Incoming),
        "refuter is the edge SOURCE, so from the paragraph's view it is Incoming"
    );

    let outgoing = edges
        .iter()
        .find(|e| e.claim_id == supported)
        .expect("outgoing supports neighbour missing");
    assert_eq!(outgoing.relationship, "supports");
    assert!(
        matches!(outgoing.direction, EdgeDirection::Outgoing),
        "paragraph is the edge SOURCE, so from the paragraph's view it is Outgoing"
    );

    assert_eq!(
        ctx.epistemic_edges_total_by_paragraph
            .get(&fx.paragraphs[0])
            .copied(),
        Some(2),
        "total must count every epistemic neighbour, not just the returned page"
    );
}

/// `decomposes_to` and `continues_argument` are structural, not epistemic, and
/// are already carried by their own fields. Including them here would double-count
/// the document skeleton as argument.
#[sqlx::test(migrations = "../../migrations")]
async fn epistemic_edges_exclude_structural_relationships(pool: PgPool) {
    let fx = fixture::build(&pool).await;

    // The fixture already wires decomposes_to and continues_argument on paragraphs[0].
    let edges = ctx_edges(&pool, fx.paragraphs[0]).await;
    for e in &edges {
        assert!(
            !matches!(
                e.relationship.as_str(),
                "decomposes_to" | "continues_argument"
            ),
            "structural relationship {} leaked into the epistemic-edge payload",
            e.relationship
        );
    }
}

async fn ctx_edges(
    pool: &PgPool,
    paragraph: Uuid,
) -> Vec<epigraph_mcp::tools::recall::EpistemicEdgeNeighbor> {
    let ctx = fetch_batched_context(
        pool,
        &viewerfx::public_viewer(pool).await,
        &[paragraph],
        8,
        4,
        4,
    )
    .await
    .expect("fetch_batched_context");
    ctx.epistemic_edges_by_paragraph
        .get(&paragraph)
        .cloned()
        .unwrap_or_default()
}

/// Tenancy guard for the epistemic-edge query.
///
/// The query in `7b. Epistemic-edge neighbours` was authored on a branch where
/// `Viewer` did not exist, so it arrived carrying no visibility predicate while the
/// other ten queries in `fetch_batched_context` all carry the static three-bind form.
///
/// Both branches merely ADDED a parameter to `fetch_batched_context`, so git
/// conflicted only on the test call sites in this file. Resolving those the obvious
/// way — passing both arguments — produces a tree that compiles, passes, and returns
/// epistemic-edge neighbours across tenancy boundaries. Nothing in the merge surfaces
/// that. This test is what surfaces it.
#[sqlx::test(migrations = "../../migrations")]
async fn epistemic_edges_respect_the_viewer_boundary(pool: PgPool) {
    let fx = fixture::build(&pool).await;

    // A claim owned by a REAL group the public viewer is not a member of.
    // `seed_group` returns the migration-062 seed sentinel, which the
    // `claims_group_needs_real_group` CHECK rejects as an owner — the group has to
    // be one an agent actually belongs to.
    let (other_agent, other_group) =
        viewerfx::seed_agent_with_group(&pool, "epistemic-edge-tenancy-guard").await;
    let hidden = viewerfx::seed_group_claim(
        &pool,
        other_agent,
        other_group,
        "out-of-group refutation that must not leak through the context payload",
    )
    .await;

    // It refutes a paragraph the viewer CAN see. The edge is legitimate; the
    // question is only whether its far endpoint is disclosed.
    fixture::insert_edge(
        &pool,
        hidden,
        "claim",
        fx.paragraphs[0],
        "claim",
        "refutes",
        None,
    )
    .await;

    let ctx = fetch_batched_context(
        &pool,
        &viewerfx::public_viewer(&pool).await,
        &[fx.paragraphs[0]],
        8,
        4,
        4,
    )
    .await
    .expect("fetch_batched_context");

    let leaked: Vec<_> = ctx
        .epistemic_edges_by_paragraph
        .get(&fx.paragraphs[0])
        .map(|v| v.iter().filter(|e| e.claim_id == hidden).collect())
        .unwrap_or_default();

    assert!(
        leaked.is_empty(),
        "a public viewer received an epistemic-edge neighbour owned by another group: \
         {leaked:?}. The query in `7b. Epistemic-edge neighbours` is missing the \
         visibility predicate its ten sibling queries carry."
    );
}

/// Run `fetch_batched_context` for one paragraph under `viewer` and return
/// `(neighbours, total)`. The total is asserted alongside the neighbours: a
/// hidden row that still counts toward `epistemic_edges_total` discloses its
/// existence through the count and the truncation flag.
async fn ctx_edges_for(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    paragraph: Uuid,
) -> (
    Vec<epigraph_mcp::tools::recall::EpistemicEdgeNeighbor>,
    Option<usize>,
) {
    let ctx = fetch_batched_context(pool, viewer, &[paragraph], 8, 4, 4)
        .await
        .expect("fetch_batched_context");
    (
        ctx.epistemic_edges_by_paragraph
            .get(&paragraph)
            .cloned()
            .unwrap_or_default(),
        ctx.epistemic_edges_total_by_paragraph
            .get(&paragraph)
            .copied(),
    )
}

/// Edge tenancy, distinct from `epistemic_edges_respect_the_viewer_boundary`
/// (which covers a private NEIGHBOUR CLAIM): here both endpoints are public and
/// only the EDGE is group-private. Migration 070's trigger honours exactly that
/// declaration, so such edges exist; `ClaimRepository::dispute_batch` filters on
/// the edge's own tenancy columns and query 7b must too, or wiring 7b onto the
/// hit discloses another group's private assertion that two public claims are
/// related.
///
/// Query 7b repeats the edge predicate in BOTH arms of its `UNION ALL`
/// (outgoing and incoming), so the test seeds one private edge in each
/// direction: dropping the predicate from a single arm must red this test.
#[sqlx::test(migrations = "../../migrations")]
async fn epistemic_edges_omit_a_group_private_edge_between_public_claims(pool: PgPool) {
    let fx = fixture::build(&pool).await;
    let para = fx.paragraphs[0];
    let (member, other_group) =
        viewerfx::seed_agent_with_group(&pool, "epistemic-private-edge").await;

    // Positive control: a public claim on an ordinary (trigger-stamped public) edge.
    let control = Uuid::new_v4();
    fixture::insert_claim(&pool, fx.agent_id, control, "public refutation", 2, None).await;
    fixture::insert_edge(&pool, control, "claim", para, "claim", "refutes", None).await;

    // A public claim reached ONLY through a group-private `supports` edge.
    let behind_private_edge = Uuid::new_v4();
    fixture::insert_claim(
        &pool,
        fx.agent_id,
        behind_private_edge,
        "public claim linked by a private edge",
        2,
        None,
    )
    .await;
    // OUTGOING from para's view (para --supports--> behind_private_edge).
    viewerfx::seed_edge_owned_by(&pool, para, behind_private_edge, "group", other_group).await;

    // The mirror: a public claim reaching para ONLY through a group-private
    // INCOMING `supports` edge (behind_private_incoming --supports--> para).
    let behind_private_incoming = Uuid::new_v4();
    fixture::insert_claim(
        &pool,
        fx.agent_id,
        behind_private_incoming,
        "public claim linked to the paragraph by a private incoming edge",
        2,
        None,
    )
    .await;
    viewerfx::seed_edge_owned_by(&pool, behind_private_incoming, para, "group", other_group).await;

    let public = viewerfx::public_viewer(&pool).await;
    let (edges, total) = ctx_edges_for(&pool, &public, para).await;
    assert!(
        edges.iter().any(|e| e.claim_id == control),
        "positive control: the public-edge neighbour must be returned; got {edges:?}"
    );
    assert!(
        !edges.iter().any(|e| e.claim_id == behind_private_edge),
        "a public viewer received a neighbour reachable only through another group's \
         private OUTGOING edge: {edges:?}. Query 7b's outgoing arm checks the neighbour \
         claim's visibility but not the edge's own tenancy columns."
    );
    assert!(
        !edges.iter().any(|e| e.claim_id == behind_private_incoming),
        "a public viewer received a neighbour reachable only through another group's \
         private INCOMING edge: {edges:?}. Query 7b's incoming arm checks the neighbour \
         claim's visibility but not the edge's own tenancy columns."
    );
    assert_eq!(
        total,
        Some(1),
        "neither private edge may count toward the public viewer's total"
    );

    // Calibration: a member of the edge's group DOES see it, so the predicate
    // filters on tenancy rather than dropping group edges outright.
    let insider = epigraph_db::visibility::Viewer::resolve(&pool, member)
        .await
        .expect("resolve group member");
    let (edges, total) = ctx_edges_for(&pool, &insider, para).await;
    assert!(
        edges.iter().any(|e| e.claim_id == behind_private_edge
            && e.relationship == "supports"
            && matches!(e.direction, EdgeDirection::Outgoing)),
        "a member of the edge's owning group must see the private outgoing edge; got {edges:?}"
    );
    assert!(
        edges.iter().any(|e| e.claim_id == behind_private_incoming
            && e.relationship == "supports"
            && matches!(e.direction, EdgeDirection::Incoming)),
        "a member of the edge's owning group must see the private incoming edge; got {edges:?}"
    );
    assert_eq!(total, Some(3));

    // Calibration: a BYPASS (system / maintenance) viewer is in no group, yet the
    // `$4::bool OR` disjunct must still admit both private edges, as it does in
    // `dispute_batch` and 7b's sibling queries.
    let (_scoped, system) = viewerfx::bypass(&pool).await;
    let (edges, total) = ctx_edges_for(&pool, &system, para).await;
    assert!(
        edges
            .iter()
            .any(|e| e.claim_id == behind_private_edge
                && matches!(e.direction, EdgeDirection::Outgoing)),
        "a bypass viewer must see the group-private OUTGOING edge (query 7b's outgoing \
         arm lost its `$4::bool OR` bypass disjunct); got {edges:?}"
    );
    assert!(
        edges.iter().any(|e| e.claim_id == behind_private_incoming
            && matches!(e.direction, EdgeDirection::Incoming)),
        "a bypass viewer must see the group-private INCOMING edge (query 7b's incoming \
         arm lost its `$4::bool OR` bypass disjunct); got {edges:?}"
    );
    assert_eq!(total, Some(3));
}

/// The co-owner half of the edge-tenancy predicate. A CO-OWNED edge (owner
/// `GA`, co-owner `GB`, migration 072) is visible only to a viewer in BOTH
/// groups — `dispute_batch`'s `(e.co_owner_group_id IS NULL OR
/// e.co_owner_group_id = ANY(groups))`. A viewer in the owner group alone must
/// not see it. One co-owned edge per `UNION ALL` arm, so the clause cannot be
/// dropped from either arm unnoticed.
#[sqlx::test(migrations = "../../migrations")]
async fn epistemic_edges_require_both_groups_for_a_co_owned_edge(pool: PgPool) {
    let fx = fixture::build(&pool).await;
    let para = fx.paragraphs[0];
    let (owner_only, group_a) = viewerfx::seed_agent_with_group(&pool, "epi-co-owner-a").await;
    let (in_both, group_b) = viewerfx::seed_agent_with_group(&pool, "epi-co-owner-b").await;
    // `in_both` already belongs to group_b; add it to group_a as well.
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(group_a)
    .bind(in_both)
    .execute(&pool)
    .await
    .expect("add in_both to group_a");

    let control = Uuid::new_v4();
    fixture::insert_claim(&pool, fx.agent_id, control, "public refutation", 2, None).await;
    fixture::insert_edge(&pool, control, "claim", para, "claim", "refutes", None).await;

    let co_out = Uuid::new_v4();
    fixture::insert_claim(
        &pool,
        fx.agent_id,
        co_out,
        "co-owned outgoing target",
        2,
        None,
    )
    .await;
    let co_in = Uuid::new_v4();
    fixture::insert_claim(
        &pool,
        fx.agent_id,
        co_in,
        "co-owned incoming source",
        2,
        None,
    )
    .await;
    for (source, target) in [(para, co_out), (co_in, para)] {
        let edge = viewerfx::seed_edge_owned_by(&pool, source, target, "group", group_a).await;
        sqlx::query("UPDATE edges SET co_owner_group_id = $2 WHERE id = $1")
            .bind(edge)
            .bind(group_b)
            .execute(&pool)
            .await
            .expect("co-own edge with group_b");
    }

    let owner_viewer = epigraph_db::visibility::Viewer::resolve(&pool, owner_only)
        .await
        .expect("resolve owner-group-only viewer");
    let (edges, total) = ctx_edges_for(&pool, &owner_viewer, para).await;
    assert!(
        edges.iter().any(|e| e.claim_id == control),
        "positive control: the public-edge neighbour must be returned; got {edges:?}"
    );
    assert!(
        !edges.iter().any(|e| e.claim_id == co_out),
        "a viewer in the owner group ONLY received a co-owned OUTGOING edge: {edges:?}. \
         Query 7b's outgoing arm is missing the co_owner_group_id clause."
    );
    assert!(
        !edges.iter().any(|e| e.claim_id == co_in),
        "a viewer in the owner group ONLY received a co-owned INCOMING edge: {edges:?}. \
         Query 7b's incoming arm is missing the co_owner_group_id clause."
    );
    assert_eq!(
        total,
        Some(1),
        "co-owned edges the viewer cannot see must not count toward its total"
    );

    // Calibration: a viewer in BOTH groups sees both co-owned edges.
    let both_viewer = epigraph_db::visibility::Viewer::resolve(&pool, in_both)
        .await
        .expect("resolve two-group viewer");
    let (edges, total) = ctx_edges_for(&pool, &both_viewer, para).await;
    assert!(
        edges
            .iter()
            .any(|e| e.claim_id == co_out && matches!(e.direction, EdgeDirection::Outgoing)),
        "a viewer in both owner and co-owner groups must see the co-owned outgoing edge; \
         got {edges:?}"
    );
    assert!(
        edges
            .iter()
            .any(|e| e.claim_id == co_in && matches!(e.direction, EdgeDirection::Incoming)),
        "a viewer in both owner and co-owner groups must see the co-owned incoming edge; \
         got {edges:?}"
    );
    assert_eq!(total, Some(3));
}

/// Set `valid_to` on the single `source --relationship--> target` edge to
/// `now() + offset` (a Postgres interval literal, e.g. `'-1 second'`).
async fn set_edge_valid_to(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    relationship: &str,
    offset: &str,
) {
    let updated = sqlx::query(
        "UPDATE edges SET valid_to = now() + $4::interval
         WHERE source_id = $1 AND target_id = $2 AND relationship = $3",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .bind(offset)
    .execute(pool)
    .await
    .expect("set edge valid_to");
    assert_eq!(
        updated.rows_affected(),
        1,
        "fixture: exactly one {source} --{relationship}--> {target} edge"
    );
}

/// An edge retracted by `delete_edge` (`valid_to` set) is no longer in force
/// (`EdgeRepository`'s `EDGE_IN_FORCE`); presenting it as a live `supports` would
/// report an argument its author withdrew.
///
/// Query 7b repeats the in-force predicate in BOTH arms of its `UNION ALL`, so
/// a retracted edge is seeded in each direction. And because the predicate is
/// `EDGE_IN_FORCE` (`valid_to IS NULL OR valid_to > now()`), not a bare
/// `valid_to IS NULL`, an edge whose retraction is only SCHEDULED (future
/// `valid_to`) is still live and must be returned and counted — again in each
/// direction.
#[sqlx::test(migrations = "../../migrations")]
async fn epistemic_edges_omit_retracted_edges(pool: PgPool) {
    let fx = fixture::build(&pool).await;
    let para = fx.paragraphs[0];

    let control = Uuid::new_v4();
    fixture::insert_claim(&pool, fx.agent_id, control, "live refutation", 2, None).await;
    fixture::insert_edge(&pool, control, "claim", para, "claim", "refutes", None).await;

    // Retracted, INCOMING (withdrawn_in --supports--> para). Retracted the way
    // `EdgeRepository::retract_by_id` does, backdated a second so
    // `valid_to > now()` cannot hold at read time.
    let withdrawn_in = Uuid::new_v4();
    fixture::insert_claim(
        &pool,
        fx.agent_id,
        withdrawn_in,
        "withdrawn support",
        2,
        None,
    )
    .await;
    fixture::insert_edge(
        &pool,
        withdrawn_in,
        "claim",
        para,
        "claim",
        "supports",
        None,
    )
    .await;
    set_edge_valid_to(&pool, withdrawn_in, para, "supports", "-1 second").await;

    // Retracted, OUTGOING (para --supports--> withdrawn_out).
    let withdrawn_out = Uuid::new_v4();
    fixture::insert_claim(
        &pool,
        fx.agent_id,
        withdrawn_out,
        "withdrawn supported",
        2,
        None,
    )
    .await;
    fixture::insert_edge(
        &pool,
        para,
        "claim",
        withdrawn_out,
        "claim",
        "supports",
        None,
    )
    .await;
    set_edge_valid_to(&pool, para, withdrawn_out, "supports", "-1 second").await;

    // Retraction SCHEDULED an hour out, one edge in each direction: still in force.
    let scheduled_in = Uuid::new_v4();
    fixture::insert_claim(
        &pool,
        fx.agent_id,
        scheduled_in,
        "expiring support",
        2,
        None,
    )
    .await;
    fixture::insert_edge(
        &pool,
        scheduled_in,
        "claim",
        para,
        "claim",
        "supports",
        None,
    )
    .await;
    set_edge_valid_to(&pool, scheduled_in, para, "supports", "1 hour").await;

    let scheduled_out = Uuid::new_v4();
    fixture::insert_claim(
        &pool,
        fx.agent_id,
        scheduled_out,
        "expiring supported",
        2,
        None,
    )
    .await;
    fixture::insert_edge(
        &pool,
        para,
        "claim",
        scheduled_out,
        "claim",
        "supports",
        None,
    )
    .await;
    set_edge_valid_to(&pool, para, scheduled_out, "supports", "1 hour").await;

    let (edges, total) = ctx_edges_for(&pool, &viewerfx::public_viewer(&pool).await, para).await;
    assert!(
        edges.iter().any(|e| e.claim_id == control),
        "positive control: the in-force edge must be returned; got {edges:?}"
    );
    assert!(
        !edges.iter().any(|e| e.claim_id == withdrawn_in),
        "a retracted (valid_to in the past) INCOMING edge was reported as a live \
         epistemic neighbour: {edges:?}"
    );
    assert!(
        !edges.iter().any(|e| e.claim_id == withdrawn_out),
        "a retracted (valid_to in the past) OUTGOING edge was reported as a live \
         epistemic neighbour: {edges:?}"
    );
    assert!(
        edges
            .iter()
            .any(|e| e.claim_id == scheduled_in && matches!(e.direction, EdgeDirection::Incoming)),
        "an INCOMING edge whose retraction is scheduled in the future (valid_to > now()) \
         is still in force and must be returned; got {edges:?}"
    );
    assert!(
        edges
            .iter()
            .any(|e| e.claim_id == scheduled_out && matches!(e.direction, EdgeDirection::Outgoing)),
        "an OUTGOING edge whose retraction is scheduled in the future (valid_to > now()) \
         is still in force and must be returned; got {edges:?}"
    );
    assert_eq!(
        total,
        Some(3),
        "the total counts the live edge and the two scheduled-retraction edges, and \
         neither retracted edge"
    );
}

/// A superseded neighbour (`is_current = false`) is not live argument;
/// `dispute_batch` already joins `src.is_current` for the same page.
#[sqlx::test(migrations = "../../migrations")]
async fn epistemic_edges_omit_superseded_neighbours(pool: PgPool) {
    let fx = fixture::build(&pool).await;
    let para = fx.paragraphs[0];

    let control = Uuid::new_v4();
    fixture::insert_claim(&pool, fx.agent_id, control, "current refutation", 2, None).await;
    fixture::insert_edge(&pool, control, "claim", para, "claim", "refutes", None).await;

    let superseded: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ('superseded refutation', sha256('superseded refutation'::bytea), 0.9, $1, false)
         RETURNING id",
    )
    .bind(fx.agent_id)
    .fetch_one(&pool)
    .await
    .expect("seed superseded neighbour");
    fixture::insert_edge(&pool, superseded, "claim", para, "claim", "refutes", None).await;

    let (edges, total) = ctx_edges_for(&pool, &viewerfx::public_viewer(&pool).await, para).await;
    assert!(
        edges.iter().any(|e| e.claim_id == control),
        "positive control: the current neighbour must be returned; got {edges:?}"
    );
    assert!(
        !edges.iter().any(|e| e.claim_id == superseded),
        "a superseded (is_current = false) neighbour was reported as live argument: {edges:?}"
    );
    assert_eq!(
        total,
        Some(1),
        "a superseded neighbour must not count toward the total"
    );
}

// ============================================================================
// Theme-coverage guard (diverse mode must not route a query through a theme
// set that does not cover the query's neighbourhood)
// ============================================================================
//
// Diverse mode draws its candidates ONLY from claims assigned to a theme. When
// the theme set is small and stale — built once over a narrow slice of a
// corpus that has since grown — every diverse query is funnelled through that
// slice, and the nearest themes win the shortlist however far away they are,
// because the theme lookup is `ORDER BY distance LIMIT n` with no relevance
// floor.

/// Seed `n` UNTHEMED paragraphs in the query's bucket (0) with strictly
/// decreasing similarity to `cluster_pgvec(0, 1.0)`. Returned in similarity
/// order, so `ids[..k]` is the flat top-k.
async fn seed_unthemed_relevant(
    pool: &PgPool,
    agent: Uuid,
    paper: Uuid,
    tag: &str,
    n: usize,
) -> Vec<Uuid> {
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let v = diverse_fixture::cluster_pgvec_with_drift(0, 1.0, 1, (i as f32) * 0.01);
        ids.push(
            diverse_fixture::seed_paragraph(pool, agent, paper, &format!("{tag}-{i}"), &v, None)
                .await,
        );
    }
    ids
}

/// Make every vector read in this test's private database EXACT by dropping
/// the approximate (HNSW) indexes on `claims` and `claim_themes`.
///
/// Why the reproduction needs it: an approximate read on the way to the
/// theme candidates can come back empty, and an empty theme lookup or
/// candidate pull falls back to flat retrieval BY ACCIDENT — letting the
/// unfixed code pass. Measured: with the indexes in place the unfixed arm
/// passed in a small fraction of parallel runs. Observed mechanism: with no
/// table statistics the candidate query plans as an HNSW scan whose
/// `theme_id = ANY(..)` post-filter finds none of the far-away themed rows.
/// Exact reads remove every approximate step, so the arm is deterministic in
/// both directions. The guard is still exercised under index-backed plans by
/// the covered/boundary arms below.
async fn drop_ann_indexes(pool: &PgPool) {
    sqlx::query(
        "DO $$ DECLARE r record; BEGIN \
           FOR r IN SELECT i.relname FROM pg_index x \
                      JOIN pg_class i ON i.oid = x.indexrelid \
                      JOIN pg_am a ON a.oid = i.relam \
                     WHERE x.indrelid IN ('claims'::regclass, 'claim_themes'::regclass) \
                       AND a.amname = 'hnsw' LOOP \
             EXECUTE format('DROP INDEX %I', r.relname); \
           END LOOP; \
         END $$",
    )
    .execute(pool)
    .await
    .expect("drop claims and claim_themes ANN indexes");
}

/// The bug: a large corpus of relevant, UNTHEMED paragraphs plus a tiny theme
/// set that sits in an orthogonal (off-topic) region. Before the guard,
/// `diverse=true` selected the off-topic theme (it is the nearest theme there
/// is) and returned only its members — every relevant paragraph was invisible.
/// After the guard, the query's nearest neighbourhood is measured as uncovered
/// and the request falls back to flat retrieval, returning the relevant hits.
#[sqlx::test(migrations = "../../migrations")]
async fn diverse_mode_falls_back_when_tiny_theme_set_does_not_cover_query(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;

    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/cov-bug", "coverage bug").await;

    // Tiny, off-topic theme set: one theme, three members, all in bucket 5
    // (orthogonal to the query in bucket 0).
    let off_topic_theme = diverse_fixture::seed_theme_with_centroid(
        &pool,
        "stale-probe-theme",
        &diverse_fixture::cluster_pgvec(5, 1.0),
    )
    .await;
    let mut off_topic = std::collections::HashSet::new();
    for i in 0..3 {
        off_topic.insert(
            diverse_fixture::seed_paragraph(
                &pool,
                agent,
                paper,
                &format!("off-topic-{i}"),
                &diverse_fixture::cluster_pgvec(5, 1.0),
                Some(off_topic_theme),
            )
            .await,
        );
    }

    // Large relevant corpus that was never themed.
    let relevant = seed_unthemed_relevant(&pool, agent, paper, "relevant", 120).await;

    drop_ann_indexes(&pool).await;

    let server = build_test_server(pool.clone());
    let query = diverse_fixture::cluster_pgvec(0, 1.0);
    let params = diverse_params(/*diverse=*/ true, Some(5), Some(0.4), 5);
    let resp = parse_response(
        recall_with_context_with_pgvec(&server, &viewer, params, 1536, &query)
            .await
            .expect("diverse recall"),
    );

    let returned: std::collections::HashSet<Uuid> =
        resp.results.iter().map(|r| r.paragraph_id).collect();
    let leaked: Vec<&Uuid> = returned.intersection(&off_topic).collect();
    assert!(
        leaked.is_empty(),
        "diverse=true returned off-topic members of a theme set that covers none of the \
         query's neighbourhood: {leaked:?}"
    );
    let flat_top_5: std::collections::HashSet<Uuid> = relevant[..5].iter().copied().collect();
    assert_eq!(
        returned, flat_top_5,
        "with the theme set not covering the query, diverse=true must fall back to flat \
         retrieval and return the 5 most relevant (unthemed) paragraphs"
    );
}

/// The guard must be PER-QUERY, not corpus-wide: here most of the corpus is
/// unthemed (a large cluster far from the query), but the query's own neighbourhood is
/// almost entirely themed. Diverse selection must still run — observable
/// because diverse candidates come only from themes, so the single UNTHEMED
/// paragraph that is the query's nearest neighbour must NOT be returned (flat
/// retrieval would rank it first).
#[sqlx::test(migrations = "../../migrations")]
async fn diverse_mode_still_selects_from_themes_when_query_neighbourhood_is_covered(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;

    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/cov-ok", "coverage ok").await;

    let near_theme = diverse_fixture::seed_theme_with_centroid(
        &pool,
        "near-theme",
        &diverse_fixture::cluster_pgvec(0, 1.0),
    )
    .await;

    // The query's nearest neighbour, deliberately left unthemed.
    let unthemed_nearest = diverse_fixture::seed_paragraph(
        &pool,
        agent,
        paper,
        "unthemed-nearest",
        &diverse_fixture::cluster_pgvec(0, 1.0),
        None,
    )
    .await;

    // 60 themed paragraphs in the query's region, all slightly further away.
    let mut themed = std::collections::HashSet::new();
    for i in 0..60 {
        let v = diverse_fixture::cluster_pgvec_with_drift(0, 1.0, 1, 0.05 + (i as f32) * 0.01);
        themed.insert(
            diverse_fixture::seed_paragraph(
                &pool,
                agent,
                paper,
                &format!("themed-{i}"),
                &v,
                Some(near_theme),
            )
            .await,
        );
    }

    // A large unthemed cluster far from the query, so corpus-wide coverage is
    // well under half (60/211). A corpus-ratio guard would (wrongly) disable
    // diverse mode here; a per-query guard must not.
    //
    // The far cluster is deliberately NOT orthogonal to the query region: each
    // far row carries a 0.5 share in the query's bucket 0. Its cosine to the
    // query is at most 0.5/sqrt(1.25) ≈ 0.447, below the least similar themed
    // row's 1/sqrt(1 + 0.64²) ≈ 0.842, so the themed rows stay the nearest
    // ones. With exactly orthogonal clusters, about 3% of freshly built HNSW
    // graphs left the near cluster unreachable from the entry point. The
    // guard's probe then saw 40 far rows (0 covered), the request fell back
    // to flat retrieval, and that index scan also returned far rows.
    let mut far = std::collections::HashSet::new();
    for i in 0..150 {
        let v = diverse_fixture::cluster_pgvec_with_drift_and_query_share(
            6,
            1.0,
            7,
            (i as f32) * 0.01,
            0.5,
        );
        far.insert(
            diverse_fixture::seed_paragraph(&pool, agent, paper, &format!("far-{i}"), &v, None)
                .await,
        );
    }
    // Keep the ANN indexes here (unlike the coverage-bug arm) and give the
    // planner statistics, so the guard's probe and the candidate query run
    // under the plans a populated database would choose. An index scan is
    // approximate, so the result does not depend on the plan only as far as
    // the HNSW graph reaches the query region. With the shared bucket-0
    // component above, that failed in 0 of 2750 fresh builds (about 3% before).
    sqlx::query("VACUUM ANALYZE claims")
        .execute(&pool)
        .await
        .expect("analyze claims");

    let server = build_test_server(pool.clone());
    let query = diverse_fixture::cluster_pgvec(0, 1.0);
    let params = diverse_params(/*diverse=*/ true, Some(5), Some(0.4), 5);
    let resp = parse_response(
        recall_with_context_with_pgvec(&server, &viewer, params, 1536, &query)
            .await
            .expect("diverse recall"),
    );

    let returned: std::collections::HashSet<Uuid> =
        resp.results.iter().map(|r| r.paragraph_id).collect();
    assert_eq!(returned.len(), 5, "budget=5 → 5 results");
    assert!(
        !returned.contains(&unthemed_nearest),
        "a covered neighbourhood must still go through diverse selection, whose candidates \
         are themed only — the unthemed nearest neighbour appearing means the request fell \
         back to flat retrieval"
    );
    let far_returned = returned.intersection(&far).count();
    assert!(
        returned.is_subset(&themed),
        "every diverse pick must come from the covering theme; got {returned:?}. \
         {far_returned} of them are far-cluster rows: a non-zero count means the HNSW \
         index scan never reached the query region (a fixture-geometry problem, see the \
         far-cluster comment above), not a per-query guard regression"
    );
}

/// Seed a corpus of exactly `THEME_COVERAGE_PROBE_K` paragraphs in the query's
/// region, laid out nearest-first as `(themed?, count)` runs, so the guard's
/// probe sees the whole corpus in a known order. Returns `(themed, unthemed)`
/// ids, each in nearest-first order.
async fn seed_coverage_layout(
    pool: &PgPool,
    agent: Uuid,
    paper: Uuid,
    theme: Uuid,
    layout: &[(bool, usize)],
) -> (Vec<Uuid>, Vec<Uuid>) {
    let total: usize = layout.iter().map(|(_, n)| n).sum();
    assert_eq!(
        total,
        epigraph_engine::diverse_retrieval::THEME_COVERAGE_PROBE_K as usize,
        "the boundary layout must be exactly one probe wide"
    );
    let (mut themed, mut unthemed) = (Vec::new(), Vec::new());
    let mut rank = 0usize;
    for &(is_themed, n) in layout {
        for _ in 0..n {
            let v = diverse_fixture::cluster_pgvec_with_drift(0, 1.0, 1, rank as f32 * 0.01);
            let id = diverse_fixture::seed_paragraph(
                pool,
                agent,
                paper,
                &format!("layout-{rank}"),
                &v,
                is_themed.then_some(theme),
            )
            .await;
            if is_themed {
                themed.push(id);
            } else {
                unthemed.push(id);
            }
            rank += 1;
        }
    }
    sqlx::query("VACUUM ANALYZE claims")
        .execute(pool)
        .await
        .expect("analyze claims");
    (themed, unthemed)
}

/// Themed count needed to sit exactly AT the threshold within one probe.
fn themed_at_threshold() -> usize {
    use epigraph_engine::diverse_retrieval::{MIN_THEME_COVERAGE_FRACTION, THEME_COVERAGE_PROBE_K};
    (MIN_THEME_COVERAGE_FRACTION * f64::from(THEME_COVERAGE_PROBE_K)).ceil() as usize
}

/// Boundary, inclusive side: exactly the threshold share of the probe is
/// themed, so diverse selection runs. Observable because the single nearest
/// paragraph is UNTHEMED — flat retrieval would rank it first, diverse cannot
/// see it.
///
/// Layout is nearest-first: 1 unthemed, then the threshold count themed, then
/// the rest unthemed. Placing the extra unthemed rows FURTHEST means that if an
/// approximate index scan ever truncated the probe, it would drop unthemed rows
/// and only raise the measured share — the arm cannot flip for that reason.
#[sqlx::test(migrations = "../../migrations")]
async fn diverse_mode_runs_when_coverage_is_exactly_at_threshold(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;

    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/cov-at", "coverage at").await;
    let theme = diverse_fixture::seed_theme_with_centroid(
        &pool,
        "boundary-theme",
        &diverse_fixture::cluster_pgvec(0, 1.0),
    )
    .await;

    let k = epigraph_engine::diverse_retrieval::THEME_COVERAGE_PROBE_K as usize;
    let at = themed_at_threshold();
    assert!(
        at >= 5 && k - at >= 1,
        "layout needs ≥5 themed and ≥1 unthemed"
    );
    let (themed, unthemed) = seed_coverage_layout(
        &pool,
        agent,
        paper,
        theme,
        &[(false, 1), (true, at), (false, k - at - 1)],
    )
    .await;

    let server = build_test_server(pool.clone());
    let query = diverse_fixture::cluster_pgvec(0, 1.0);
    let params = diverse_params(/*diverse=*/ true, Some(5), Some(0.4), 5);
    let resp = parse_response(
        recall_with_context_with_pgvec(&server, &viewer, params, 1536, &query)
            .await
            .expect("diverse recall"),
    );
    let returned: std::collections::HashSet<Uuid> =
        resp.results.iter().map(|r| r.paragraph_id).collect();
    let themed: std::collections::HashSet<Uuid> = themed.into_iter().collect();

    assert_eq!(returned.len(), 5);
    assert!(
        !returned.contains(&unthemed[0]),
        "{at}/{k} themed is AT the threshold: diverse mode must run, so the unthemed \
         nearest paragraph must not appear (it did — the guard fell back)"
    );
    assert!(returned.is_subset(&themed), "diverse picks are themed only");
}

/// Boundary, exclusive side: one themed paragraph fewer than the threshold,
/// so the request must fall back to flat retrieval — observable as the flat
/// top-5, which here are all unthemed.
///
/// Layout is nearest-first: unthemed first, themed furthest, so a truncated
/// probe could only LOWER the measured share — the arm cannot flip for that
/// reason either.
#[sqlx::test(migrations = "../../migrations")]
async fn diverse_mode_falls_back_one_below_threshold(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;

    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/cov-below", "coverage below").await;
    let theme = diverse_fixture::seed_theme_with_centroid(
        &pool,
        "boundary-theme",
        &diverse_fixture::cluster_pgvec(0, 1.0),
    )
    .await;

    let k = epigraph_engine::diverse_retrieval::THEME_COVERAGE_PROBE_K as usize;
    let below = themed_at_threshold() - 1;
    assert!(k - below >= 5, "layout needs ≥5 unthemed nearest");
    let (_themed, unthemed) = seed_coverage_layout(
        &pool,
        agent,
        paper,
        theme,
        &[(false, k - below), (true, below)],
    )
    .await;

    let server = build_test_server(pool.clone());
    let query = diverse_fixture::cluster_pgvec(0, 1.0);
    let params = diverse_params(/*diverse=*/ true, Some(5), Some(0.4), 5);
    let resp = parse_response(
        recall_with_context_with_pgvec(&server, &viewer, params, 1536, &query)
            .await
            .expect("diverse recall"),
    );
    let returned: std::collections::HashSet<Uuid> =
        resp.results.iter().map(|r| r.paragraph_id).collect();
    let flat_top_5: std::collections::HashSet<Uuid> = unthemed[..5].iter().copied().collect();
    assert_eq!(
        returned, flat_top_5,
        "{below}/{k} themed is BELOW the threshold: the request must fall back to flat \
         retrieval and return the 5 nearest (unthemed) paragraphs"
    );
}

/// Coverage is measured against the theme SHORTLIST, not against "any theme".
///
/// Theme N holds the query's whole neighbourhood (60 relevant paragraphs), but
/// its centroid sits off-axis, so it loses the `max_themes = 1` shortlist to
/// theme S, whose centroid equals the query and whose three members are
/// off-topic. Diverse mode draws only from the shortlist, so it can see none
/// of N's members. A guard that counted membership in any theme would read the
/// neighbourhood as fully covered and return S's off-topic members; the guard
/// must instead fall back to flat retrieval.
///
/// Exact reads (indexes dropped) for the same reason as the coverage-bug arm.
#[sqlx::test(migrations = "../../migrations")]
async fn diverse_mode_falls_back_when_neighbourhood_sits_outside_the_theme_shortlist(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;

    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/cov-shortlist", "shortlist").await;

    let neighbourhood_theme = diverse_fixture::seed_theme_with_centroid(
        &pool,
        "holds-the-neighbourhood",
        &diverse_fixture::cluster_pgvec(3, 1.0),
    )
    .await;
    let shortlisted_theme = diverse_fixture::seed_theme_with_centroid(
        &pool,
        "wins-the-shortlist",
        &diverse_fixture::cluster_pgvec(0, 1.0),
    )
    .await;

    let mut off_topic = std::collections::HashSet::new();
    for i in 0..3 {
        off_topic.insert(
            diverse_fixture::seed_paragraph(
                &pool,
                agent,
                paper,
                &format!("shortlisted-off-topic-{i}"),
                &diverse_fixture::cluster_pgvec(5, 1.0),
                Some(shortlisted_theme),
            )
            .await,
        );
    }
    let mut relevant = Vec::new();
    for i in 0..60 {
        let v = diverse_fixture::cluster_pgvec_with_drift(0, 1.0, 1, (i as f32) * 0.01);
        relevant.push(
            diverse_fixture::seed_paragraph(
                &pool,
                agent,
                paper,
                &format!("neighbourhood-{i}"),
                &v,
                Some(neighbourhood_theme),
            )
            .await,
        );
    }
    drop_ann_indexes(&pool).await;

    let server = build_test_server(pool.clone());
    let query = diverse_fixture::cluster_pgvec(0, 1.0);
    let params = diverse_params(/*diverse=*/ true, Some(1), Some(0.4), 5);
    let resp = parse_response(
        recall_with_context_with_pgvec(&server, &viewer, params, 1536, &query)
            .await
            .expect("diverse recall"),
    );

    let returned: std::collections::HashSet<Uuid> =
        resp.results.iter().map(|r| r.paragraph_id).collect();
    let leaked: Vec<&Uuid> = returned.intersection(&off_topic).collect();
    assert!(
        leaked.is_empty(),
        "the shortlist holds none of the query's neighbourhood, yet diverse=true returned its \
         off-topic members: {leaked:?}"
    );
    let flat_top_5: std::collections::HashSet<Uuid> = relevant[..5].iter().copied().collect();
    assert_eq!(
        returned, flat_top_5,
        "the request must fall back to flat retrieval and return the 5 nearest paragraphs"
    );
}

/// The coverage-bug layout again, but with the ANN indexes KEPT and planner
/// statistics present — the plan shape a populated database runs. The guard
/// must fall back here too (no off-topic member, flat top-5); the exact-read
/// arm above is the deterministic reproduction, this one pins that nothing in
/// the index-backed plan turns the fallback into an error or a wrong answer.
#[sqlx::test(migrations = "../../migrations")]
async fn diverse_mode_falls_back_under_index_backed_plans(pool: PgPool) {
    let viewer = viewerfx::public_viewer(&pool).await;
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;

    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/cov-indexed", "coverage indexed").await;
    let off_topic_theme = diverse_fixture::seed_theme_with_centroid(
        &pool,
        "stale-probe-theme",
        &diverse_fixture::cluster_pgvec(5, 1.0),
    )
    .await;
    let mut off_topic = std::collections::HashSet::new();
    for i in 0..3 {
        off_topic.insert(
            diverse_fixture::seed_paragraph(
                &pool,
                agent,
                paper,
                &format!("off-topic-{i}"),
                &diverse_fixture::cluster_pgvec(5, 1.0),
                Some(off_topic_theme),
            )
            .await,
        );
    }
    let relevant = seed_unthemed_relevant(&pool, agent, paper, "relevant", 120).await;
    sqlx::query("VACUUM ANALYZE claims")
        .execute(&pool)
        .await
        .expect("analyze claims");
    sqlx::query("VACUUM ANALYZE claim_themes")
        .execute(&pool)
        .await
        .expect("analyze claim_themes");

    let server = build_test_server(pool.clone());
    let query = diverse_fixture::cluster_pgvec(0, 1.0);
    let params = diverse_params(/*diverse=*/ true, Some(5), Some(0.4), 5);
    let resp = parse_response(
        recall_with_context_with_pgvec(&server, &viewer, params, 1536, &query)
            .await
            .expect("diverse recall"),
    );

    let returned: std::collections::HashSet<Uuid> =
        resp.results.iter().map(|r| r.paragraph_id).collect();
    assert!(
        returned.is_disjoint(&off_topic),
        "off-topic members of the uncovering theme set must not be returned"
    );
    let flat_top_5: std::collections::HashSet<Uuid> = relevant[..5].iter().copied().collect();
    assert_eq!(returned, flat_top_5, "the fallback returns the flat top-5");
}

// ============================================================================
// Whole-corpus seeding (drain U082, backlog a1d89aab; operator ruling
// 2026-10-14). `recall_with_context` seeds on EVERY embedded claim the viewer
// can see, not only on level-2 paragraphs with a paper attribution. Paper and
// section parentage are enrichment attributes: a parentless hit omits `paper`
// (and carries `section: null`, as any section-less hit always did) instead of
// being dropped.
// ============================================================================

/// An embedded claim that is NOT an `ingest_document` paragraph: no paper
/// `asserts` edge, and `properties` as given (`{}` for a `submit_claim` /
/// `memorize` claim, `{"level": 2, "kind": "workflow_step"}` for a workflow
/// step). Public, current.
async fn seed_parentless_claim(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    properties: &str,
    embedding_pgvec: &str,
    theme_id: Option<Uuid>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             properties, embedding, theme_id) \
         VALUES ($1, sha256($1::bytea), 0.7, $2, true, $3::jsonb, $4::vector, $5) \
         RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(properties)
    .bind(embedding_pgvec)
    .bind(theme_id)
    .fetch_one(pool)
    .await
    .expect("seed parentless claim")
}

/// The full `results` array as raw JSON. Raw `serde_json::Value`, not a typed
/// struct: one assertion is about a key being ABSENT, which a typed struct
/// with `Option` + `#[serde(default)]` cannot distinguish from `null`.
async fn recall_results_json(
    pool: &PgPool,
    params: epigraph_mcp::tools::recall::RecallWithContextParams,
    pgvec: &str,
) -> Vec<serde_json::Value> {
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;
    let viewer = viewerfx::public_viewer(pool).await;
    let server = build_test_server(pool.clone());
    let result = recall_with_context_with_pgvec(&server, &viewer, params, 1536, pgvec)
        .await
        .expect("recall_with_context ok");
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    let json: serde_json::Value = serde_json::from_str(&text).expect("parse JSON");
    json["results"].as_array().expect("results array").clone()
}

fn result_ids(results: &[serde_json::Value]) -> Vec<String> {
    results
        .iter()
        .map(|r| r["paragraph_id"].as_str().unwrap_or("<no id>").to_string())
        .collect()
}

/// The backlog's own regression test (a1d89aab): a parentless claim that is
/// the BEST semantic match is returned AHEAD of a weaker, paper-attributed
/// paragraph — and it is returned without a `paper` key rather than with a
/// fabricated one.
///
/// Pre-fix the parentless claim is never a candidate (the flat kNN is
/// `level = 2` only, and the assembly loop drops any hit without paper meta),
/// so the page is `[paragraph]` and the first assertion fails on the ids.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_returns_a_parentless_best_match_ahead_of_a_weaker_paragraph(
    pool: PgPool,
) {
    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/parentless", "Parentless test").await;
    let query = diverse_fixture::cluster_pgvec(0, 1.0);

    // Exact match (cosine 1.0), no level, no paper: a submit_claim claim.
    let parentless = seed_parentless_claim(
        &pool,
        agent,
        "EpiGraph is installed correctly.",
        "{}",
        &query,
        None,
    )
    .await;
    // Weaker match (cosine ~0.894). Direction drift, not magnitude: scaling
    // `cluster_pgvec` leaves the cosine unchanged.
    let para = diverse_fixture::seed_paragraph(
        &pool,
        agent,
        paper,
        "a real paper paragraph",
        &diverse_fixture::cluster_pgvec_with_drift(0, 1.0, 1, 0.5),
        None,
    )
    .await;

    let results = recall_results_json(
        &pool,
        diverse_params(false, None, None, /*limit=*/ 2),
        &query,
    )
    .await;

    assert_eq!(
        result_ids(&results),
        vec![parentless.to_string(), para.to_string()],
        "the parentless exact match must be a candidate and rank first; a level-2/paper-only \
         seed never considers it"
    );
    assert!(
        results[0].get("paper").is_none(),
        "a parentless hit omits `paper` (never null, never fabricated); got {}",
        results[0]
    );
    assert!(
        results[0]["section"].is_null() && results[0].get("section").is_some(),
        "a parentless hit carries `section: null` (the key set of a section-less hit is \
         unchanged); got {}",
        results[0]
    );
    assert_eq!(
        results[1]["paper"]["doi"], "10.1/parentless",
        "a paper paragraph still carries its paper attribution"
    );
}

/// A level-2 claim with NO paper attribution — a workflow step, which
/// `crates/epigraph-ingest/src/workflow/builder.rs` writes as
/// `{"level": 2, "kind": "workflow_step"}` with only author `asserts` edges —
/// is a hit in its own right.
///
/// The fixture carries that author edge in the shape `ingest_workflow`
/// persists it (`crates/epigraph-mcp/src/tools/ingestion.rs` resolves the
/// planner's `author_placeholder` source to the author's agent: `source_type =
/// 'agent'`, `relationship = 'asserts'`), so the "omits `paper`" assertion
/// covers the production edge shape: an `asserts` edge that is not from a
/// paper must not produce paper meta.
///
/// Pre-fix it is the worst case of the old filter pair: the level-2 kNN
/// spends the page's only slot (`limit = 1`) on it, and the assembly loop then
/// drops it for having no paper, so the page comes back EMPTY.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_returns_a_level_2_claim_without_paper_attribution(pool: PgPool) {
    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/wfstep", "Workflow step test").await;
    let query = diverse_fixture::cluster_pgvec(0, 1.0);

    let step = seed_parentless_claim(
        &pool,
        agent,
        "workflow step: install the toolchain",
        r#"{"level": 2, "kind": "workflow_step"}"#,
        &query,
        None,
    )
    .await;
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES (gen_random_uuid(), $1, 'agent', $2, 'claim', 'asserts', \
                 '{\"role\": \"author\", \"source\": \"workflow_attribution\"}'::jsonb)",
    )
    .bind(agent)
    .bind(step)
    .execute(&pool)
    .await
    .expect("seed the workflow step's author asserts edge");
    diverse_fixture::seed_paragraph(
        &pool,
        agent,
        paper,
        "a weaker paper paragraph",
        &diverse_fixture::cluster_pgvec_with_drift(0, 1.0, 1, 0.5),
        None,
    )
    .await;

    let results = recall_results_json(
        &pool,
        diverse_params(false, None, None, /*limit=*/ 1),
        &query,
    )
    .await;

    assert_eq!(
        result_ids(&results),
        vec![step.to_string()],
        "limit=1 must return the best match, the unattributed workflow step"
    );
    assert!(
        results[0].get("paper").is_none(),
        "an unattributed hit omits `paper`; got {}",
        results[0]
    );
}

/// The diverse surface seeds on the whole corpus too: a parentless claim
/// inside the selected theme is a candidate for `diverse_select`.
///
/// Four of the five rows sit in the one theme, so the theme-coverage guard
/// passes (4/5 probed rows reachable; 3/4 if the probe were paragraph-only)
/// and the DIVERSE path serves the page. The fifth row is an UNTHEMED
/// paragraph nearer the query than any themed paragraph: the flat fallback
/// would put it second, the diverse path cannot return it. Its absence is
/// what proves the diverse path served the page, so a regression that always
/// falls back cannot pass here. That is also what makes this test independent
/// of the flat-path tests above: with the diverse candidate query still
/// restricted to paragraphs, the parentless claim is absent here even when
/// the flat path is fixed.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_diverse_returns_a_parentless_claim_in_a_theme(pool: PgPool) {
    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/div-parentless", "Diverse").await;
    let query = diverse_fixture::cluster_pgvec(0, 1.0);
    let theme = diverse_fixture::seed_theme_with_centroid(&pool, "only-theme", &query).await;

    let parentless = seed_parentless_claim(
        &pool,
        agent,
        "a memorized note that matches exactly",
        "{}",
        &query,
        Some(theme),
    )
    .await;
    let mut paragraphs = Vec::new();
    for i in 0..3 {
        paragraphs.push(
            diverse_fixture::seed_paragraph(
                &pool,
                agent,
                paper,
                &format!("themed paragraph {i}"),
                &diverse_fixture::cluster_pgvec_with_drift(0, 1.0, 1, 0.3 + 0.1 * i as f32),
                Some(theme),
            )
            .await,
        );
    }
    let unthemed = diverse_fixture::seed_paragraph(
        &pool,
        agent,
        paper,
        "an unthemed paragraph nearer than every themed one",
        &diverse_fixture::cluster_pgvec_with_drift(0, 1.0, 1, 0.05),
        None,
    )
    .await;

    // alpha = 0.0: pure relevance, so the exact match must be selected.
    let results = recall_results_json(
        &pool,
        diverse_params(true, Some(5), Some(0.0), /*limit=*/ 3),
        &query,
    )
    .await;

    let ids = result_ids(&results);
    assert_eq!(
        ids.len(),
        3,
        "the diverse page must fill its budget; got {ids:?}"
    );
    assert_eq!(
        ids[0],
        parentless.to_string(),
        "the parentless exact match must be a diverse candidate and rank first; got {ids:?}"
    );
    assert!(
        results[0].get("paper").is_none(),
        "a parentless diverse hit omits `paper`; got {}",
        results[0]
    );
    assert!(
        !ids.contains(&unthemed.to_string()),
        "the unthemed paragraph is the flat path's second hit; its presence means the \
         page came from the flat fallback, not the diverse path. Got {ids:?}"
    );
}

/// The diverse path's flat FALLBACK seeds on the whole corpus too. With no
/// themes at all the diverse pipeline selects nothing and
/// `recall_with_context_post_embed` falls back to
/// `search_by_embedding_since` (the `kNN fallback` call site), a separate
/// call from the `diverse=false` path, with its own scope argument.
///
/// Pre-fix (or with that one argument at `EmbeddingSeedScope::Paragraphs`)
/// the parentless exact match is never a candidate and the page is
/// `[paragraph]`.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_diverse_fallback_returns_a_parentless_best_match(pool: PgPool) {
    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/fallback-parentless", "Fallback").await;
    let query = diverse_fixture::cluster_pgvec(0, 1.0);

    let parentless = seed_parentless_claim(
        &pool,
        agent,
        "a memorized note, no themes anywhere",
        "{}",
        &query,
        None,
    )
    .await;
    let para = diverse_fixture::seed_paragraph(
        &pool,
        agent,
        paper,
        "a weaker paper paragraph",
        &diverse_fixture::cluster_pgvec_with_drift(0, 1.0, 1, 0.5),
        None,
    )
    .await;
    let themes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claim_themes")
        .fetch_one(&pool)
        .await
        .expect("count themes");
    assert_eq!(
        themes, 0,
        "calibration: no themes, so diverse must fall back"
    );

    let results = recall_results_json(
        &pool,
        diverse_params(true, Some(5), Some(0.0), /*limit=*/ 2),
        &query,
    )
    .await;

    assert_eq!(
        result_ids(&results),
        vec![parentless.to_string(), para.to_string()],
        "the diverse fallback must seed on every embedded claim: the parentless exact \
         match first, then the weaker paragraph"
    );
    assert!(
        results[0].get("paper").is_none(),
        "a parentless fallback hit omits `paper`; got {}",
        results[0]
    );
}

/// `centroid_dim` auto-detect measures the population the seed searches: every
/// embedded claim, not only level-2 paragraphs.
///
/// One paragraph re-embedded at 3072 (both columns) beside two `submit_claim`
/// style claims that, like every MCP write path, carry only the 1536-d vector.
/// Paragraph-only, the fraction is 1/1 and auto-detect would pick 3072 — where
/// the two parentless claims have no vector, so they could never be returned.
/// Whole-corpus, it is 1/3 and auto-detect stays on 1536, where all three are
/// candidates.
#[sqlx::test(migrations = "../../migrations")]
async fn centroid_auto_detect_counts_every_embedded_claim_not_just_paragraphs(pool: PgPool) {
    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/detect", "Detect test").await;
    let v1536 = diverse_fixture::cluster_pgvec(0, 1.0);
    let para =
        diverse_fixture::seed_paragraph(&pool, agent, paper, "re-embedded para", &v1536, None)
            .await;
    let v3072 = format!("[{}]", vec!["0.5"; 3072].join(","));
    sqlx::query("UPDATE claims SET embedding_3072 = $2::vector WHERE id = $1")
        .bind(para)
        .bind(&v3072)
        .execute(&pool)
        .await
        .expect("set embedding_3072 on the paragraph");
    for content in ["memorized note one", "memorized note two"] {
        seed_parentless_claim(&pool, agent, content, "{}", &v1536, None).await;
    }

    let frac = embedded_3072_population(&pool, &viewerfx::public_viewer(&pool).await)
        .await
        .expect("embedded_3072_population");
    assert!(
        (frac - 1.0 / 3.0).abs() < 1e-9,
        "1 of the 3 embedded claims carries a 3072-d vector; a paragraph-only \
         denominator reports 1.0 and auto-selects 3072, hiding both parentless claims. \
         Got {frac}"
    );

    // The decision the caller sees (`centroid_dim_used`), not just its input:
    // a threshold change or a call site reading the wrong helper flips this.
    use epigraph_mcp::tools::recall::__test_only::detect_centroid_dim;
    let dim = detect_centroid_dim(&pool, &viewerfx::public_viewer(&pool).await)
        .await
        .expect("detect_centroid_dim");
    assert_eq!(
        dim, 1536,
        "auto-detect must stay on 1536, where the two parentless claims have vectors"
    );
}
