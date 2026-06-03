//! Integration tests for `ClaimRepository::search_hybrid_scoped` (RRF fusion of
//! the dense `claims.embedding` leg and the lexical `content_tsv` leg).
//!
//! Schema notes (mirrors claim_search_by_embedding.rs): seed an `agents` row
//! first (FK + edge-validation trigger); `content_hash bytea NOT NULL` and
//! `(content_hash, agent_id)` UNIQUE → use distinct hashes. `content_tsv` is a
//! GENERATED column (migration 050), so inserting `content` auto-populates it.

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// 1536-d unit-ish vector with the "hot" dimension at `idx` set to 0.99.
fn vec_hot(idx: usize) -> String {
    let mut v = vec!["0.0"; 1536];
    v[idx] = "0.99";
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

fn distinct_hash(tag: u8) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[0] = tag;
    h
}

#[allow(clippy::too_many_arguments)]
async fn insert_claim(
    pool: &PgPool,
    id: Uuid,
    agent: Uuid,
    tag: u8,
    content: &str,
    embedding_pgvec: &str,
    is_current: bool,
    labels: &[&str],
) {
    let labels_arr: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, labels, embedding) \
         VALUES ($1, $2, $3, $4, 0.8, $5, $6, $7::vector)",
    )
    .bind(id)
    .bind(content)
    .bind(distinct_hash(tag))
    .bind(agent)
    .bind(is_current)
    .bind(&labels_arr)
    .bind(embedding_pgvec)
    .execute(pool)
    .await
    .expect("insert claim");
}

#[sqlx::test(migrations = "../../migrations")]
async fn hybrid_fuses_both_legs_ranking_the_overlap_first(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let query = vec_hot(0); // dense query points at dim 0

    // DENSE: closest vector, no lexical overlap with the query text.
    let dense = Uuid::new_v4();
    insert_claim(
        &pool,
        dense,
        agent,
        1,
        "orthogonal filler prose about weather",
        &vec_hot(0),
        true,
        &[],
    )
    .await;
    // BOTH: 2nd-closest vector AND contains the rare lexical term.
    let both = Uuid::new_v4();
    insert_claim(
        &pool,
        both,
        agent,
        2,
        "discussion of quasinormal mechanosynthesis tooling",
        &vec_hot(1),
        true,
        &[],
    )
    .await;
    // LEX: far vector, contains the rare lexical term.
    let lex = Uuid::new_v4();
    insert_claim(
        &pool,
        lex,
        agent,
        3,
        "quasinormal mechanosynthesis appears here too",
        &vec_hot(900),
        true,
        &[],
    )
    .await;

    let hits = ClaimRepository::search_hybrid_scoped(
        &pool,
        &query,
        "quasinormal mechanosynthesis",
        50,
        60,
        10,
        None,
        None,
    )
    .await
    .expect("hybrid search");

    let order: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();
    assert!(order.contains(&both) && order.contains(&dense) && order.contains(&lex));
    // `both` is in BOTH legs → its RRF sum beats any single-leg claim.
    assert_eq!(
        order[0], both,
        "overlap claim must rank first; got {order:?}"
    );

    let both_hit = hits.iter().find(|h| h.claim_id == both).unwrap();
    assert!(
        both_hit.dense_similarity.is_some() && both_hit.in_lexical,
        "both legs"
    );
    let dense_hit = hits.iter().find(|h| h.claim_id == dense).unwrap();
    assert!(
        dense_hit.dense_similarity.is_some() && !dense_hit.in_lexical,
        "dense only"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn hybrid_surfaces_lexical_only_hit_outside_dense_pool(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let query = vec_hot(0);

    let dense = Uuid::new_v4();
    insert_claim(
        &pool,
        dense,
        agent,
        1,
        "no overlap filler",
        &vec_hot(0),
        true,
        &[],
    )
    .await;
    let lex = Uuid::new_v4();
    insert_claim(
        &pool,
        lex,
        agent,
        2,
        "rare token zubuzonium present",
        &vec_hot(900),
        true,
        &[],
    )
    .await;

    // candidate_pool=1 → dense leg yields only `dense`; `lex` can only enter via
    // the lexical leg, so dense_similarity must be NULL there.
    let hits =
        ClaimRepository::search_hybrid_scoped(&pool, &query, "zubuzonium", 1, 60, 10, None, None)
            .await
            .expect("hybrid search");

    let lex_hit = hits
        .iter()
        .find(|h| h.claim_id == lex)
        .expect("lexical-only hit present");
    assert!(
        lex_hit.dense_similarity.is_none(),
        "lexical-only ⇒ no dense similarity"
    );
    assert!(lex_hit.in_lexical);
}

#[sqlx::test(migrations = "../../migrations")]
async fn hybrid_excludes_non_current_and_honors_tag_scope(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let query = vec_hot(0);

    // Non-current claim that would otherwise match both legs.
    let stale = Uuid::new_v4();
    insert_claim(
        &pool,
        stale,
        agent,
        1,
        "zubuzonium stale",
        &vec_hot(0),
        false,
        &["keep"],
    )
    .await;
    // Current, in-scope (label "keep").
    let keep = Uuid::new_v4();
    insert_claim(
        &pool,
        keep,
        agent,
        2,
        "zubuzonium keep",
        &vec_hot(0),
        true,
        &["keep"],
    )
    .await;
    // Current, out-of-scope (no "keep" label).
    let drop = Uuid::new_v4();
    insert_claim(
        &pool,
        drop,
        agent,
        3,
        "zubuzonium drop",
        &vec_hot(0),
        true,
        &["other"],
    )
    .await;

    let tags = vec!["keep".to_string()];
    let hits = ClaimRepository::search_hybrid_scoped(
        &pool,
        &query,
        "zubuzonium",
        50,
        60,
        10,
        Some(&tags),
        None,
    )
    .await
    .expect("hybrid search");

    let ids: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();
    assert!(ids.contains(&keep), "in-scope current claim present");
    assert!(!ids.contains(&stale), "non-current excluded");
    assert!(
        !ids.contains(&drop),
        "out-of-scope (tag) excluded on both legs"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn lexical_scoped_ranks_matches_and_honors_scope(pool: PgPool) {
    let agent = seed_agent(&pool).await;

    let hit = Uuid::new_v4();
    insert_claim(
        &pool,
        hit,
        agent,
        1,
        "zubuzonium reactor design",
        &vec_hot(0),
        true,
        &["keep"],
    )
    .await;
    let miss = Uuid::new_v4();
    insert_claim(
        &pool,
        miss,
        agent,
        2,
        "unrelated weather prose",
        &vec_hot(0),
        true,
        &["keep"],
    )
    .await;
    let stale = Uuid::new_v4();
    insert_claim(
        &pool,
        stale,
        agent,
        3,
        "zubuzonium stale",
        &vec_hot(0),
        false,
        &["keep"],
    )
    .await;
    let oos = Uuid::new_v4();
    insert_claim(
        &pool,
        oos,
        agent,
        4,
        "zubuzonium other",
        &vec_hot(0),
        true,
        &["other"],
    )
    .await;

    let tags = vec!["keep".to_string()];
    let hits =
        ClaimRepository::search_lexical_scoped(&pool, "zubuzonium", 60, 10, Some(&tags), None)
            .await
            .expect("lexical search");

    let ids: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();
    assert!(ids.contains(&hit), "lexical match in scope present");
    assert!(!ids.contains(&miss), "non-matching content excluded");
    assert!(!ids.contains(&stale), "non-current excluded");
    assert!(!ids.contains(&oos), "out-of-scope tag excluded");

    let h = hits.iter().find(|h| h.claim_id == hit).unwrap();
    assert!(
        h.dense_similarity.is_none() && h.in_lexical,
        "lexical-only shape"
    );
    assert!(h.rrf_score > 0.0);
}
