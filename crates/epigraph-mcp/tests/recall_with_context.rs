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
