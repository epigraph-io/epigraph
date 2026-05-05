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

use epigraph_mcp::tools::recall::__test_only::fetch_batched_context;
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
        pub paragraphs: Vec<Uuid>,     // 6 paragraphs in paper A
        pub shared_atom: Uuid,         // atom under paragraphs[0] AND paragraphs[1]
        pub atom_solo: Uuid,           // atom under paragraphs[0] only
        pub corroborates_target: Uuid, // paragraph in paper B linked via CORROBORATES
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

        Fixture {
            paper_a,
            paper_b,
            section,
            paragraphs,
            shared_atom,
            atom_solo,
            corroborates_target,
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
