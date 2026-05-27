//! Truth-table coverage for migration 041's `same_source_papers` function.
//!
//! Setup: two papers, each asserting two claims. Intra-paper pairs return
//! true (regardless of which traversal path), cross-paper pairs return
//! false, self-pair returns true (short-circuit).
//!
//! Schema notes (mirrors `claim_search_by_embedding.rs`):
//!   * `claims.agent_id` is NOT NULL, so we seed an `agents` row first.
//!   * `(content_hash, agent_id)` is UNIQUE, so we hand-build distinct
//!     32-byte hashes for each claim.
//!   * `edges.source_type` / `target_type` are NOT NULL and validated
//!     against the entity-type allowlist; we use `'paper'`/`'claim'` for
//!     `asserts`, `'claim'`/`'claim'` for `decomposes_to`.
//!   * `relationship` is a free-form `varchar(100)` — `'asserts'` and
//!     `'decomposes_to'` insert without enum constraints.
//!
//! Fixtures are kept inline (no `tests/common/` module) to match the
//! pattern in `claim_search_by_embedding.rs` and `paper_repo_tests.rs`.

use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Insert an `agents` row whose UUID we control so that downstream claims
/// can reference it. `public_key` is a deterministic 32-byte tag.
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

/// Build a 32-byte hash with the high byte set to `tag` so each claim gets
/// a distinct `content_hash` without depending on pgcrypto.
fn distinct_hash(tag: u8) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[0] = tag;
    h
}

async fn seed_paper(pool: &PgPool, doi: &str, title: &str) -> Uuid {
    let paper_id = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, $3)")
        .bind(paper_id)
        .bind(doi)
        .bind(title)
        .execute(pool)
        .await
        .expect("seed paper");
    paper_id
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid, content: &str, tag: u8) -> Uuid {
    let claim_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value) \
         VALUES ($1, $2, $3, $4, 0.5)",
    )
    .bind(claim_id)
    .bind(content)
    .bind(distinct_hash(tag))
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    claim_id
}

async fn insert_edge(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    source_type: &str,
    target_type: &str,
    relationship: &str,
) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)",
    )
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(target_type)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("insert edge");
}

async fn same_source(pool: &PgPool, a: Uuid, b: Uuid) -> bool {
    sqlx::query("SELECT same_source_papers($1, $2) AS r")
        .bind(a)
        .bind(b)
        .fetch_one(pool)
        .await
        .expect("call same_source_papers")
        .get::<bool, _>("r")
}

#[sqlx::test(migrations = "../../migrations")]
async fn same_source_papers_truth_table(pool: PgPool) {
    let agent = seed_agent(&pool).await;

    let p1 = seed_paper(&pool, "10.1/paper-one", "Paper One").await;
    let p2 = seed_paper(&pool, "10.2/paper-two", "Paper Two").await;

    let a1 = seed_claim(&pool, agent, "p1::claim1", 1).await;
    let a2 = seed_claim(&pool, agent, "p1::claim2", 2).await;
    let b1 = seed_claim(&pool, agent, "p2::claim1", 3).await;
    let b2 = seed_claim(&pool, agent, "p2::claim2", 4).await;

    // p1 asserts a1, a2
    insert_edge(&pool, p1, a1, "paper", "claim", "asserts").await;
    insert_edge(&pool, p1, a2, "paper", "claim", "asserts").await;

    // p2 asserts b1, b2
    insert_edge(&pool, p2, b1, "paper", "claim", "asserts").await;
    insert_edge(&pool, p2, b2, "paper", "claim", "asserts").await;

    // a1 decomposes_to a2 (intra-paper sibling-via-decomposes)
    insert_edge(&pool, a1, a2, "claim", "claim", "decomposes_to").await;

    // ── Truth table ────────────────────────────────────────────────────
    assert!(same_source(&pool, a1, a1).await, "self-pair must be true");
    assert!(
        same_source(&pool, a1, a2).await,
        "intra-paper via asserts+asserts (sibling) must be true"
    );
    assert!(
        same_source(&pool, a2, a1).await,
        "intra-paper symmetric (a2,a1) must be true"
    );
    assert!(
        !same_source(&pool, a1, b1).await,
        "cross-paper must be false"
    );
    assert!(
        !same_source(&pool, b1, a2).await,
        "cross-paper must be false (reversed)"
    );
    assert!(
        same_source(&pool, b1, b2).await,
        "intra-paper for paper 2 must be true"
    );
}
