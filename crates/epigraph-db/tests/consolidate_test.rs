//! `ClaimRepository::consolidate` — N→1 merge (backlog 44b19521 / design F1).
//!
//! The edge-collision cases below are taken from
//! `docs/architecture/audit-edge-collision-mark-duplicate.md`, adapted to the
//! cross-source class that only N→1 can produce:
//!
//! - `alternative_of` collisions are a HARD constraint violation
//!   (`edges_alternative_of_symmetric_uniq`, migration 042) that rolls the
//!   whole merge back — and the index is symmetric, so direction does not
//!   save you.
//! - Every other relationship collides SILENTLY (migration 018 dropped triple
//!   uniqueness), double-feeding Dempster-Shafer mass. Belief corruption that
//!   no error surfaces.

use epigraph_db::{ClaimRepository, ConsolidateMode};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-consolidate', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool).await.expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, labels: &[&str]) -> Uuid {
    let labels: Vec<String> = labels.iter().map(ToString::to_string).collect();
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, labels, embedding)
         VALUES ($1, sha256($1::bytea), 0.7, $2, true, $3, NULL) RETURNING id",
    )
    .bind(content).bind(agent).bind(&labels).fetch_one(pool).await.expect("seed claim")
}

async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid, rel: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
         VALUES ($1, $2, 'claim', 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(rel)
    .execute(pool)
    .await
    .expect("seed edge");
}

async fn count_edges(pool: &PgPool, source: Uuid, target: Uuid, rel: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM edges WHERE source_id=$1 AND target_id=$2 AND relationship=$3",
    )
    .bind(source)
    .bind(target)
    .bind(rel)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Baseline: sources retired with a forwarding pointer, merged owned by the
/// ACTING agent (not inherited — ill-defined for N>1), labels unioned,
/// properties.merge populated, and N supersedes edges fanned out.
#[sqlx::test(migrations = "../../migrations")]
async fn merge_retires_sources_and_records_lineage(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let actor = seed_agent(&pool).await;
    let s1 = seed_claim(&pool, author, "source one", &["alpha"]).await;
    let s2 = seed_claim(&pool, author, "source two", &["beta"]).await;

    let res = ClaimRepository::consolidate(
        &pool,
        &[s1, s2],
        "merged restatement",
        0.8,
        ConsolidateMode::Merge,
        "near-identical",
        actor,
    )
    .await
    .expect("consolidate");

    assert!(!res.already_existed);
    assert_eq!(res.superseded.len(), 2);

    // Sources: retired, forwarding at the merged claim, embedding nulled.
    for s in [s1, s2] {
        let r = sqlx::query!(
            "SELECT is_current, supersedes, embedding IS NULL AS \"emb_null!\" FROM claims WHERE id=$1", s)
            .fetch_one(&pool).await.unwrap();
        assert!(!r.is_current, "source retired");
        assert_eq!(
            r.supersedes,
            Some(res.merged_id),
            "forwarding pointer at merged"
        );
        assert!(
            r.emb_null,
            "chk_deprecated_no_embedding: embedding nulled with is_current"
        );
    }

    let m = sqlx::query!(
        "SELECT agent_id, is_current, supersedes, labels, properties FROM claims WHERE id=$1",
        res.merged_id
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        m.agent_id, actor,
        "merged belongs to the ACTING agent, not a source author"
    );
    assert!(m.is_current);
    assert!(
        m.supersedes.is_none(),
        "merged's own supersedes column stays NULL for N>1"
    );
    let labels = m.labels;
    assert!(
        labels.contains(&"alpha".to_string()) && labels.contains(&"beta".to_string()),
        "labels unioned across sources: {labels:?}"
    );
    let merge = &m.properties["merge"];
    assert_eq!(merge["mode"], "merge");
    assert_eq!(merge["merged_from"].as_array().unwrap().len(), 2);
    assert!(
        merge["merged_at"].as_str().is_some(),
        "merge date is queryable"
    );

    for s in [s1, s2] {
        assert_eq!(
            count_edges(&pool, res.merged_id, s, "supersedes").await,
            1,
            "reverse fan-out edge merged->source"
        );
    }
}

/// THE CROSS-SOURCE CLASS, silent variant. `T supports s1` AND `T supports s2`
/// both migrate onto the merged claim. Without dedup this leaves TWO identical
/// `T supports merged` rows, feeding the same DS mass twice through
/// auto_create_factor_from_edge — corruption no error would reveal.
#[sqlx::test(migrations = "../../migrations")]
async fn cross_source_duplicate_supports_edges_collapse_to_one(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s1 = seed_claim(&pool, agent, "src a", &[]).await;
    let s2 = seed_claim(&pool, agent, "src b", &[]).await;
    let t = seed_claim(&pool, agent, "third party", &[]).await;

    seed_edge(&pool, t, s1, "supports").await;
    seed_edge(&pool, t, s2, "supports").await;

    let res = ClaimRepository::consolidate(
        &pool,
        &[s1, s2],
        "merged c",
        0.8,
        ConsolidateMode::Merge,
        "dedup",
        agent,
    )
    .await
    .expect("consolidate");

    assert_eq!(
        count_edges(&pool, t, res.merged_id, "supports").await,
        1,
        "exactly ONE supports edge survives; a second would double-count DS mass"
    );
    assert_eq!(
        res.edges_deduped, 1,
        "the redundant edge is reported, not silently dropped"
    );
}

/// THE CROSS-SOURCE CLASS, hard variant. `alternative_of` carries a symmetric
/// partial unique index, so an un-deduped merge raises a constraint violation
/// and rolls the ENTIRE merge back. Direction is deliberately opposed here:
/// the index is keyed on (LEAST, GREATEST), so a direction-aware dedup would
/// still collide.
#[sqlx::test(migrations = "../../migrations")]
async fn opposed_direction_alternative_of_does_not_violate_symmetric_index(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s1 = seed_claim(&pool, agent, "alt a", &[]).await;
    let s2 = seed_claim(&pool, agent, "alt b", &[]).await;
    let c = seed_claim(&pool, agent, "shared alternative", &[]).await;

    seed_edge(&pool, s1, c, "alternative_of").await; // s1 -> C
    seed_edge(&pool, c, s2, "alternative_of").await; // C  -> s2  (opposite direction)

    let res = ClaimRepository::consolidate(
        &pool,
        &[s1, s2],
        "merged alt",
        0.8,
        ConsolidateMode::Merge,
        "alt merge",
        agent,
    )
    .await
    .expect("merge must not trip edges_alternative_of_symmetric_uniq");

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE relationship='alternative_of'
           AND (source_id=$1 OR target_id=$1)",
    )
    .bind(res.merged_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        total, 1,
        "one alternative_of edge survives the symmetric collapse"
    );

    // The merge actually committed — a rollback would leave sources current.
    let still_current: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE id = ANY($1) AND is_current")
            .bind(vec![s1, s2])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(still_current, 0, "transaction committed; sources retired");
}

/// The same HARD class for the SECOND pair-unique relationship, `shifted_to`
/// (migration 060, backlog 52eff3ab). Ships with the index, because the index
/// is what creates the hazard: `edges_shifted_to_pair_uniq` is keyed on
/// `(LEAST, GREATEST)` exactly like `alternative_of`'s, so a merge that
/// re-points a `shifted_to` edge into an already-occupied pair slot trips it
/// and rolls the entire merge back before `is_current` flips — backlog
/// 2905150e / issue #286 reproduced verbatim for a second relationship.
///
/// Direction is deliberately opposed, for a sharper reason than in the
/// `alternative_of` case above. `shifted_to` is genuinely DIRECTIONAL — it is
/// pair-unique without being symmetric — so a direction-aware dedup looks
/// correct here right up until the index rejects it. The dedup must key on the
/// PAIR (`epigraph_db::PAIR_UNIQUE_RELATIONSHIPS` drives that), not on what
/// the relationship means.
#[sqlx::test(migrations = "../../migrations")]
async fn opposed_direction_shifted_to_does_not_violate_pair_index(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s1 = seed_claim(&pool, agent, "ceiling 400/s", &[]).await;
    let s2 = seed_claim(&pool, agent, "ceiling 400 per second", &[]).await;
    let c = seed_claim(&pool, agent, "ceiling 900/s", &[]).await;

    seed_edge(&pool, s1, c, "shifted_to").await; // s1 -> C
    seed_edge(&pool, c, s2, "shifted_to").await; // C  -> s2  (opposite direction)

    let res = ClaimRepository::consolidate(
        &pool,
        &[s1, s2],
        "merged ceiling",
        0.8,
        ConsolidateMode::Merge,
        "shift merge",
        agent,
    )
    .await
    .expect("merge must not trip edges_shifted_to_pair_uniq");

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE relationship='shifted_to'
           AND (source_id=$1 OR target_id=$1)",
    )
    .bind(res.merged_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(total, 1, "one shifted_to edge survives the pair collapse");

    // The merge actually committed — a rollback would leave sources current.
    let still_current: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE id = ANY($1) AND is_current")
            .bind(vec![s1, s2])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(still_current, 0, "transaction committed; sources retired");
}

/// The two pair-unique relationships must not delete EACH OTHER. Their indexes
/// are per-relationship PARTIAL indexes, so an `alternative_of` edge and a
/// `shifted_to` edge over the same pair do not collide — a dedup that keyed on
/// the pair alone (dropping the relationship from the key) would silently
/// destroy one of two legitimate, non-colliding facts.
#[sqlx::test(migrations = "../../migrations")]
async fn pair_unique_relationships_do_not_collapse_into_each_other(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s1 = seed_claim(&pool, agent, "mixed a", &[]).await;
    let s2 = seed_claim(&pool, agent, "mixed b", &[]).await;
    let c = seed_claim(&pool, agent, "mixed third", &[]).await;

    seed_edge(&pool, s1, c, "alternative_of").await;
    seed_edge(&pool, c, s2, "shifted_to").await;

    let res = ClaimRepository::consolidate(
        &pool,
        &[s1, s2],
        "merged mixed",
        0.8,
        ConsolidateMode::Merge,
        "mixed merge",
        agent,
    )
    .await
    .expect("consolidate");

    for rel in ["alternative_of", "shifted_to"] {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM edges WHERE relationship=$2
               AND (source_id=$1 OR target_id=$1)",
        )
        .bind(res.merged_id)
        .bind(rel)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            n, 1,
            "'{rel}' must survive the merge: the two pair-unique relationships have SEPARATE \
             partial indexes and do not collide with one another"
        );
    }
}

/// Edges interior to the merge would become merged→merged self-loops.
#[sqlx::test(migrations = "../../migrations")]
async fn interior_edges_do_not_become_self_loops(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s1 = seed_claim(&pool, agent, "inner a", &[]).await;
    let s2 = seed_claim(&pool, agent, "inner b", &[]).await;
    seed_edge(&pool, s1, s2, "supports").await;

    let res = ClaimRepository::consolidate(
        &pool,
        &[s1, s2],
        "merged inner",
        0.8,
        ConsolidateMode::Merge,
        "interior",
        agent,
    )
    .await
    .expect("consolidate");

    assert_eq!(
        count_edges(&pool, res.merged_id, res.merged_id, "supports").await,
        0,
        "no merged->merged self-loop"
    );
}

/// AUTHORED is exempt from dedup (migration 017 lets it accumulate): both
/// authorship records must survive onto the merged claim.
#[sqlx::test(migrations = "../../migrations")]
async fn authored_edges_are_migrated_not_deduped(pool: PgPool) {
    let a1 = seed_agent(&pool).await;
    let a2 = seed_agent(&pool).await;
    let s1 = seed_claim(&pool, a1, "auth a", &[]).await;
    let s2 = seed_claim(&pool, a2, "auth b", &[]).await;
    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
                 VALUES ($1,$2,'agent','claim','AUTHORED'), ($3,$4,'agent','claim','AUTHORED')",
    )
    .bind(a1)
    .bind(s1)
    .bind(a2)
    .bind(s2)
    .execute(&pool)
    .await
    .unwrap();

    let res = ClaimRepository::consolidate(
        &pool,
        &[s1, s2],
        "merged auth",
        0.8,
        ConsolidateMode::Merge,
        "auth",
        a1,
    )
    .await
    .expect("consolidate");

    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE target_id=$1 AND relationship='AUTHORED'",
    )
    .bind(res.merged_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        n, 2,
        "both AUTHORED edges survive; they are meant to accumulate"
    );
}

/// An already-merged source must not be re-merged — that would rewrite its
/// forwarding pointer and orphan the first merge's lineage.
#[sqlx::test(migrations = "../../migrations")]
async fn already_superseded_source_is_refused(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s1 = seed_claim(&pool, agent, "once a", &[]).await;
    let s2 = seed_claim(&pool, agent, "once b", &[]).await;
    let s3 = seed_claim(&pool, agent, "once c", &[]).await;

    ClaimRepository::consolidate(
        &pool,
        &[s1, s2],
        "first merge",
        0.8,
        ConsolidateMode::Merge,
        "one",
        agent,
    )
    .await
    .expect("first");

    let err = ClaimRepository::consolidate(
        &pool,
        &[s1, s3],
        "second merge",
        0.8,
        ConsolidateMode::Merge,
        "two",
        agent,
    )
    .await
    .expect_err("re-merging an already-superseded source must be refused");
    let msg = format!("{err}");
    assert!(
        msg.contains("superseded") || msg.contains("not current"),
        "{msg}"
    );
}

/// A repeated identical merge returns the existing claim instead of tripping
/// uq_claims_content_hash_agent — a retried merge is idempotent, not fatal.
#[sqlx::test(migrations = "../../migrations")]
async fn identical_repeat_merge_returns_existing(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s1 = seed_claim(&pool, agent, "idem a", &[]).await;
    let s2 = seed_claim(&pool, agent, "idem b", &[]).await;
    let s3 = seed_claim(&pool, agent, "idem c", &[]).await;
    let s4 = seed_claim(&pool, agent, "idem d", &[]).await;

    let first = ClaimRepository::consolidate(
        &pool,
        &[s1, s2],
        "same text",
        0.8,
        ConsolidateMode::Merge,
        "r",
        agent,
    )
    .await
    .expect("first");
    let second = ClaimRepository::consolidate(
        &pool,
        &[s3, s4],
        "same text",
        0.8,
        ConsolidateMode::Merge,
        "r",
        agent,
    )
    .await
    .expect("second must not error");

    assert!(second.already_existed);
    assert_eq!(second.merged_id, first.merged_id);
    // The rollback must leave the second pair untouched.
    let current: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE id = ANY($1) AND is_current")
            .bind(vec![s3, s4])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        current, 2,
        "no partial merge left behind by the idempotent return"
    );
}

/// Source-set validation.
#[sqlx::test(migrations = "../../migrations")]
async fn invalid_source_sets_are_rejected(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s1 = seed_claim(&pool, agent, "v a", &[]).await;

    assert!(
        ClaimRepository::consolidate(&pool, &[s1], "x", 0.8, ConsolidateMode::Merge, "r", agent)
            .await
            .is_err(),
        "fewer than 2 sources"
    );
    assert!(
        ClaimRepository::consolidate(
            &pool,
            &[s1, s1],
            "x",
            0.8,
            ConsolidateMode::Merge,
            "r",
            agent
        )
        .await
        .is_err(),
        "duplicate ids"
    );

    let many: Vec<Uuid> = (0..21).map(|_| Uuid::new_v4()).collect();
    assert!(
        ClaimRepository::consolidate(&pool, &many, "x", 0.8, ConsolidateMode::Merge, "r", agent)
            .await
            .is_err(),
        "more than 20 sources"
    );

    let missing = vec![s1, Uuid::new_v4()];
    assert!(
        ClaimRepository::consolidate(
            &pool,
            &missing,
            "x",
            0.8,
            ConsolidateMode::Merge,
            "r",
            agent
        )
        .await
        .is_err(),
        "nonexistent source"
    );
}
