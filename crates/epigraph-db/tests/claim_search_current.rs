//! Integration tests for `ClaimRepository::search_by_embedding_current` and
//! `search_by_embedding_scoped`.
//!
//! Context: the simple `recall` MCP tool used to search `evidence.embedding`,
//! which is NULL for every memorized claim (memorize embeds `claims.embedding`).
//! The existing `ClaimRepository::search_by_embedding` can't serve recall
//! either — it restricts to `(properties->>'level')::int = 2` (paper
//! paragraphs), excluding the level-`<none>` memorized claims. These tests pin
//! the behavior of the new recall-facing search: current claims, ANY level,
//! with optional tag/agent scope.
//!
//! Schema notes (mirrors `claim_search_by_embedding.rs`): `agents` row must
//! exist before claims (FK); `content_hash` is NOT NULL and unique per agent.

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

fn build_query_vec() -> String {
    let mut v = vec!["0.0"; 1536];
    v[0] = "0.99";
    format!("[{}]", v.join(","))
}

async fn seed_agent(pool: &PgPool, tag: &str) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent_id)
        .bind(
            format!("{:0>2}", tag)
                .repeat(32)
                .chars()
                .take(64)
                .collect::<String>(),
        )
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

/// Insert a claim with control over level, is_current, labels and agent.
/// `level = None` inserts an empty properties object (level `<none>`), the
/// shape of a memorized claim.
#[allow(clippy::too_many_arguments)]
async fn seed_claim(
    pool: &PgPool,
    agent: Uuid,
    hash_tag: u8,
    level: Option<i32>,
    is_current: bool,
    labels: &[&str],
    pgvec: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let props = match level {
        Some(l) => format!(r#"{{"level": {l}}}"#),
        None => "{}".to_string(),
    };
    let labels_vec: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    // Invariant chk_deprecated_no_embedding (migration 052): is_current=false rows
    // MUST have embedding=NULL. A non-current claim can no longer carry an embedding,
    // so search_by_embedding_current excludes the retired row on both counts. Mirror
    // the production invariant in the fixture rather than inserting an illegal row.
    let emb = if is_current { Some(pgvec) } else { None };
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding, is_current, labels) \
         VALUES ($1, $2, $3, $4, 0.6, $5::jsonb, $6::vector, $7, $8)",
    )
    .bind(id)
    .bind(format!("c-{id}"))
    .bind(distinct_hash(hash_tag))
    .bind(agent)
    .bind(props)
    .bind(emb)
    .bind(is_current)
    .bind(&labels_vec)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

/// The recall-facing search must return CURRENT claims of ANY level (including
/// level-`<none>` memories) that have an embedding, and must EXCLUDE
/// non-current claims — unlike the level-2-only `search_by_embedding`.
#[sqlx::test(migrations = "../../migrations")]
async fn search_current_returns_all_levels_excludes_non_current(pool: PgPool) {
    let agent = seed_agent(&pool, "a1").await;
    let pgvec = build_query_vec();

    let mem = seed_claim(&pool, agent, 1, None, true, &[], &pgvec).await; // level <none>, current
    let para = seed_claim(&pool, agent, 2, Some(2), true, &[], &pgvec).await; // level 2, current
    let retired = seed_claim(&pool, agent, 3, None, false, &[], &pgvec).await; // current=false

    let hits = ClaimRepository::search_by_embedding_current(&pool, &pgvec, 10)
        .await
        .expect("search_by_embedding_current");
    let ids: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();

    assert!(
        ids.contains(&mem),
        "memorized (level <none>) current claim must be returned"
    );
    assert!(
        ids.contains(&para),
        "level-2 current claim must be returned"
    );
    assert!(
        !ids.contains(&retired),
        "non-current claim must be excluded"
    );

    // Contrast: the existing level-2-only method would MISS the memory and the
    // level<none> retired claim, returning only the level-2 paragraph. This is
    // exactly why recall needs the new method.
    let level2_only = ClaimRepository::search_by_embedding(&pool, &pgvec, 1536, 10, None)
        .await
        .expect("legacy search_by_embedding");
    let l2_ids: Vec<Uuid> = level2_only.iter().map(|h| h.claim_id).collect();
    assert!(
        !l2_ids.contains(&mem),
        "legacy method excludes the level <none> memory (the bug)"
    );
    assert!(
        l2_ids.contains(&para),
        "legacy method returns the level-2 paragraph"
    );
}

/// `search_by_embedding_scoped` pushes optional tag (label containment) and
/// agent predicates into the query. A None filter must not restrict; a Some
/// filter must restrict, and the two combine (AND).
#[sqlx::test(migrations = "../../migrations")]
async fn search_scoped_filters_by_tag_and_agent(pool: PgPool) {
    let agent_a = seed_agent(&pool, "a1").await;
    let agent_b = seed_agent(&pool, "b2").await;
    let pgvec = build_query_vec();

    let a_x = seed_claim(&pool, agent_a, 1, None, true, &["topic-x"], &pgvec).await;
    let a_plain = seed_claim(&pool, agent_a, 2, None, true, &[], &pgvec).await;
    let b_x = seed_claim(&pool, agent_b, 3, None, true, &["topic-x"], &pgvec).await;

    let ids = |hits: &[epigraph_db::ClaimEmbeddingHit]| -> Vec<Uuid> {
        hits.iter().map(|h| h.claim_id).collect()
    };

    // No scope → all three.
    let all = ClaimRepository::search_by_embedding_scoped(&pool, &pgvec, 10, None, None)
        .await
        .expect("scoped none");
    let all_ids = ids(&all);
    assert!(
        [a_x, a_plain, b_x].iter().all(|c| all_ids.contains(c)),
        "no scope returns all"
    );

    // Tag scope → only the two carrying topic-x, across agents.
    let tagged = ClaimRepository::search_by_embedding_scoped(
        &pool,
        &pgvec,
        10,
        Some(&["topic-x".to_string()]),
        None,
    )
    .await
    .expect("scoped tag");
    let tagged_ids = ids(&tagged);
    assert!(
        tagged_ids.contains(&a_x) && tagged_ids.contains(&b_x),
        "tag scope keeps topic-x claims"
    );
    assert!(
        !tagged_ids.contains(&a_plain),
        "tag scope drops the untagged claim"
    );

    // Agent scope → only agent_a's claims, regardless of tag.
    let by_agent =
        ClaimRepository::search_by_embedding_scoped(&pool, &pgvec, 10, None, Some(agent_a))
            .await
            .expect("scoped agent");
    let agent_ids = ids(&by_agent);
    assert!(
        agent_ids.contains(&a_x) && agent_ids.contains(&a_plain),
        "agent scope keeps agent_a claims"
    );
    assert!(!agent_ids.contains(&b_x), "agent scope drops agent_b claim");

    // Both → intersection: agent_a AND topic-x = only a_x.
    let both = ClaimRepository::search_by_embedding_scoped(
        &pool,
        &pgvec,
        10,
        Some(&["topic-x".to_string()]),
        Some(agent_a),
    )
    .await
    .expect("scoped both");
    assert_eq!(
        ids(&both),
        vec![a_x],
        "tag AND agent intersect to a single claim"
    );
}
