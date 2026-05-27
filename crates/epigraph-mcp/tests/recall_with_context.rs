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

// rustfmt 1.8 sorts `NeighborPath` before `__test_only`; older CI rustfmt sorts
// the reverse. #[rustfmt::skip] keeps both happy by opting out of the sort.
#[rustfmt::skip]
use epigraph_mcp::tools::recall::{
    __test_only::{assemble_neighbor_paragraphs, fetch_batched_context, paragraph_3072_population},
    NeighborPath,
};
use sqlx::PgPool;
use uuid::Uuid;

mod fixture {
    use super::*;

    pub struct Fixture {
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

    async fn seed_agent(pool: &PgPool) -> Uuid {
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

    async fn insert_claim(
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

    async fn insert_edge(
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
        &[fx.paragraphs[0]],
        /*siblings_limit=*/ 2,
        /*corroborates_limit=*/ 4,
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
    let ctx = fetch_batched_context(&pool, &[fx.paragraphs[0]], 8, 4)
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
    let ctx = fetch_batched_context(&pool, &[fx.paragraphs[0]], 8, 4)
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
    let ctx = fetch_batched_context(&pool, &[fx.paragraphs[0], fx.corroborates_target], 8, 4)
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

#[sqlx::test(migrations = "../../migrations")]
async fn explicit_3072_with_no_population_returns_invalid_params(pool: PgPool) {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::tools::recall::{recall_with_context, RecallWithContextParams};
    use epigraph_mcp::EpiGraphMcpFull;

    // Seed: paragraphs with 1536d embeddings only — embedding_3072 untouched.
    let _fx = fixture::build(&pool).await;

    // Sanity: helper reports 0.0 for the unpopulated 3072 column.
    let frac = paragraph_3072_population(&pool)
        .await
        .expect("paragraph_3072_population helper");
    assert_eq!(
        frac, 0.0,
        "fixture should leave embedding_3072 unpopulated on level=2 paragraphs"
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
        neighbor_paragraphs_limit: None,
        diverse: None,
        max_themes: None,
        diversity_weight: None,
        candidate_pool: None,
    };

    let result = recall_with_context(&server, params).await;
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
    let ctx = fetch_batched_context(&pool, &[fx.paragraphs[0]], 8, 4)
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
    let ctx = fetch_batched_context(&pool, &[fx.paragraphs[0]], 8, 4)
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
    let ctx = fetch_batched_context(&pool, &[fx.paragraphs[0]], 8, 4)
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
    let ctx = fetch_batched_context(&pool, &[fx.paragraphs[0]], 8, 4)
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

fn diverse_params(diverse: bool, max_themes: Option<u32>, alpha: Option<f32>, limit: u32)
    -> epigraph_mcp::tools::recall::RecallWithContextParams
{
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
        neighbor_paragraphs_limit: None,
        diverse: Some(diverse),
        max_themes,
        diversity_weight: alpha,
        candidate_pool,
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
    let result = recall_with_context_with_pgvec(&server, params, 1536, &pgvec)
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
/// Compares against `ClaimRepository::search_by_embedding` directly.
#[sqlx::test(migrations = "../../migrations")]
async fn diverse_false_matches_existing_flat_ordering(pool: PgPool) {
    use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;

    let agent = diverse_fixture::seed_agent(&pool).await;
    let paper = diverse_fixture::seed_paper(&pool, "10.1/reg", "Regression test").await;

    // Seed paragraphs at staggered similarity to the query.
    let query_pgvec = diverse_fixture::cluster_pgvec(0, 1.0);
    let mut paragraph_ids = Vec::new();
    for i in 0..5 {
        // Slight reduction in value moves the cosine score down monotonically.
        let para_vec = diverse_fixture::cluster_pgvec(0, 1.0 - (i as f32) * 0.05);
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
    let direct_hits = epigraph_db::ClaimRepository::search_by_embedding(
        &pool, &query_pgvec, 1536, 10, None,
    )
    .await
    .expect("direct flat ANN");
    let direct_order: Vec<Uuid> = direct_hits.iter().map(|h| h.claim_id).collect();

    let server = build_test_server(pool.clone());
    let params = diverse_params(/*diverse=*/ false, None, None, 10);
    let result = recall_with_context_with_pgvec(&server, params, 1536, &query_pgvec)
        .await
        .expect("diverse=false");
    let resp = parse_response(result);

    let recall_order: Vec<Uuid> = resp.results.iter().map(|r| r.paragraph_id).collect();
    assert_eq!(
        recall_order, direct_order,
        "diverse=false ordering must match direct ClaimRepository::search_by_embedding ordering"
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

    let result = recall_with_context_with_pgvec(&server, params, 1536, &query_pgvec)
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

    let result = recall_with_context_with_pgvec(&server, params, 1536, &query_pgvec)
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
    let flat_result = recall_with_context_with_pgvec(&server, flat_params, 1536, &query_pgvec)
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
        recall_with_context_with_pgvec(&server, diverse_params_v, 1536, &query_pgvec)
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
