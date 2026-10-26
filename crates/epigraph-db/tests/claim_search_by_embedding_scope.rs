//! `ClaimRepository::search_by_embedding_since`'s [`EmbeddingSeedScope`] and
//! its iterative HNSW scan (drain U082, backlog a1d89aab).
//!
//! `recall_with_context` seeds on the whole corpus
//! ([`EmbeddingSeedScope::AllClaims`]); the original-arity
//! `search_by_embedding` wrapper keeps the level-2 contract
//! ([`EmbeddingSeedScope::Paragraphs`]). In the whole-corpus scope the 1536d
//! statement is served by `idx_claims_embedding_hnsw`, whose scan yields at
//! most `hnsw.ef_search` (default 40) rows before the predicates it does not
//! encode are applied, so the call widens it with an iterative scan.
//!
//! The index tests pin the plan prod runs, as `semantic_search_flat_hnsw.rs`
//! does: ONE connection, seq scans / bitmap scans / explicit sorts disabled,
//! `hnsw.ef_search` left at its default (the test must not set the knob the
//! implementation sets).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{ClaimRepository, EmbeddingSeedScope};
use sqlx::PgPool;
use uuid::Uuid;

/// Rows seeded by the index tests: twice the default `hnsw.ef_search` window.
const ROWS: usize = 80;

/// A unit vector at `deg` degrees in the dim-0/dim-1 plane. Rows on one arc
/// give a well-connected HNSW graph (see `semantic_search_flat_hnsw.rs`).
fn vec_angle(deg: f64) -> String {
    let (s, c) = deg.to_radians().sin_cos();
    let mut v: Vec<String> = vec!["0.0".to_string(); 1536];
    v[0] = format!("{c:.6}");
    v[1] = format!("{s:.6}");
    format!("[{}]", v.join(","))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent_id)
        .bind("ab".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    agent_id
}

/// Insert one public, current claim with the given `properties` and 1536d
/// vector (`None` = no embedding).
async fn seed_claim(
    pool: &PgPool,
    agent: Uuid,
    tag: u16,
    properties: &str,
    embedding: Option<&str>,
) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[..2].copy_from_slice(&tag.to_be_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             properties, embedding) \
         VALUES ($1, $2, $3, $4, 0.8, true, $5::jsonb, $6::vector)",
    )
    .bind(id)
    .bind(format!("scope test claim {tag}"))
    .bind(hash)
    .bind(agent)
    .bind(properties)
    .bind(embedding)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

/// The two scopes over one mixed population: `AllClaims` returns every
/// embedded claim whatever its level (or none), `Paragraphs` only level 2,
/// and neither returns a claim with no vector.
#[sqlx::test(migrations = "../../migrations")]
async fn all_claims_scope_seeds_every_level_and_paragraphs_scope_keeps_level_2(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let q = vec_angle(0.0);

    let paragraph = seed_claim(&pool, agent, 1, r#"{"level": 2}"#, Some(&vec_angle(3.0))).await;
    let atom = seed_claim(&pool, agent, 2, r#"{"level": 3}"#, Some(&vec_angle(2.0))).await;
    let memorized = seed_claim(&pool, agent, 3, "{}", Some(&vec_angle(1.0))).await;
    let _unembedded = seed_claim(&pool, agent, 4, "{}", None).await;

    let search = |scope| {
        let (pool, viewer, q) = (&pool, &viewer, &q);
        async move {
            ClaimRepository::search_by_embedding_since(pool, viewer, q, 1536, 10, None, None, scope)
                .await
                .expect("search_by_embedding_since")
                .into_iter()
                .map(|h| h.claim_id)
                .collect::<Vec<_>>()
        }
    };

    assert_eq!(
        search(EmbeddingSeedScope::AllClaims).await,
        vec![memorized, atom, paragraph],
        "the whole-corpus scope returns every embedded claim, nearest first"
    );
    assert_eq!(
        search(EmbeddingSeedScope::Paragraphs).await,
        vec![paragraph],
        "the paragraph scope keeps the level = 2 contract"
    );
    let wrapper: Vec<Uuid> =
        ClaimRepository::search_by_embedding(&pool, &viewer, &q, 1536, 10, None)
            .await
            .expect("search_by_embedding")
            .into_iter()
            .map(|h| h.claim_id)
            .collect();
    assert_eq!(
        wrapper,
        vec![paragraph],
        "the original-arity wrapper stays paragraph-only"
    );
}

/// Seed `ROWS` level-less embedded claims on the arc and return their ids in
/// ascending distance from `vec_angle(0.0)`.
async fn seed_arc(pool: &PgPool) -> Vec<Uuid> {
    let agent = seed_agent(pool).await;
    let mut ids = Vec::with_capacity(ROWS);
    for i in 0..ROWS {
        ids.push(
            seed_claim(
                pool,
                agent,
                100 + i as u16,
                "{}",
                Some(&vec_angle(0.5 * i as f64)),
            )
            .await,
        );
    }
    ids
}

async fn force_index_plans(conn: &mut sqlx::PgConnection) {
    for s in [
        "SET enable_seqscan = off",
        "SET enable_bitmapscan = off",
        "SET enable_sort = off",
    ] {
        sqlx::query(s).execute(&mut *conn).await.expect(s);
    }
}

/// Calibration: with `ef_search` above the table size the HNSW plan reaches
/// every row, so a short page below can only be `ef_search` truncation.
async fn hnsw_graph_reaches_every_row(conn: &mut sqlx::PgConnection) {
    let q = vec_angle(0.0);
    sqlx::query("BEGIN")
        .execute(&mut *conn)
        .await
        .expect("BEGIN");
    sqlx::query("SET LOCAL hnsw.ef_search = 1000")
        .execute(&mut *conn)
        .await
        .expect("SET LOCAL ef_search");
    let reached: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM (SELECT c.id FROM claims c \
         WHERE c.embedding IS NOT NULL \
         ORDER BY c.embedding <=> '{q}'::vector LIMIT 1000) s"
    ))
    .fetch_one(&mut *conn)
    .await
    .expect("graph reach probe");
    sqlx::query("ROLLBACK")
        .execute(&mut *conn)
        .await
        .expect("ROLLBACK");
    assert_eq!(
        reached, ROWS as i64,
        "calibration: HNSW graph reaches only {reached} of {ROWS} rows"
    );
}

/// Index scans this transaction has made on `idx_claims_embedding_hnsw`.
async fn hnsw_scans(conn: &mut sqlx::PgConnection) -> i64 {
    sqlx::query_scalar(
        "SELECT COALESCE(sum(pg_stat_get_xact_numscans(i.indexrelid)), 0)::bigint \
         FROM pg_index i JOIN pg_class ix ON ix.oid = i.indexrelid \
         WHERE i.indrelid = 'claims'::regclass \
           AND ix.relname LIKE 'idx_claims_embedding_hnsw%'",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("pg_stat_get_xact_numscans")
}

/// The whole-corpus statement is served by migration 001's full HNSW index
/// (not a seq scan + sort over every embedded claim), AND it fills a `limit`
/// beyond the default `ef_search` of 40. With NEITHER of the call's settings
/// the page stops at 40 rows; either one alone fills it here (`ef_search` is
/// widened to `clamp(60, 40, 1000) = 60`), so this test does not isolate the
/// iterative scan — `all_claims_scope_fills_its_limit_past_rows_a_post_filter_rejects`
/// below does.
///
/// Its distinct job is the LEAK check: the call runs inside the caller's
/// transaction, where `begin()` opens a savepoint; it must roll that back so
/// the `SET LOCAL` values do not survive into the caller's later HNSW reads.
#[sqlx::test(migrations = "../../migrations")]
async fn all_claims_scope_on_the_index_fills_a_limit_beyond_ef_search(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let ids = seed_arc(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    force_index_plans(&mut conn).await;
    hnsw_graph_reaches_every_row(&mut conn).await;

    let limit = 60_usize; // above pgvector's default ef_search of 40
    use sqlx::Connection;
    let mut outer = conn.begin().await.expect("BEGIN");
    let before = hnsw_scans(&mut outer).await;
    let hits = ClaimRepository::search_by_embedding_since(
        &mut *outer,
        &viewer,
        &vec_angle(0.0),
        1536,
        limit as i64,
        None,
        None,
        EmbeddingSeedScope::AllClaims,
    )
    .await
    .expect("search_by_embedding_since inside the caller's transaction");
    let after = hnsw_scans(&mut outer).await;

    // The widened settings are SET LOCAL inside a savepoint the call rolls
    // back; releasing it instead would leak them into the caller's later reads.
    let ef: String = sqlx::query_scalar("SHOW hnsw.ef_search")
        .fetch_one(&mut *outer)
        .await
        .expect("SHOW hnsw.ef_search");
    let iterative: String = sqlx::query_scalar("SHOW hnsw.iterative_scan")
        .fetch_one(&mut *outer)
        .await
        .expect("SHOW hnsw.iterative_scan");
    outer.rollback().await.expect("ROLLBACK");

    assert!(
        after > before,
        "the whole-corpus kNN must be served by idx_claims_embedding_hnsw"
    );
    let got: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();
    assert_eq!(
        got.len(),
        limit,
        "an index scan at the default hnsw.ef_search returns 40 rows; the call's widened \
         ef_search / iterative scan must fill LIMIT {limit}"
    );
    assert_eq!(
        got,
        ids[..limit].to_vec(),
        "hits must be the {limit} nearest rows, nearest first"
    );
    assert_eq!(
        (ef.as_str(), iterative.as_str()),
        ("40", "off"),
        "search_by_embedding_since leaked its HNSW settings into the caller's transaction"
    );
}

/// The iterative scan proper. Widening `ef_search` to `limit` (above) does
/// not help when the predicates the index does not encode reject the nearest
/// rows: here the 60 nearest claims fall outside the `since` window, so a
/// non-iterative scan's first batch (`ef_search = clamp(10, 40, 1000) = 40`)
/// is rejected wholesale and the page comes back EMPTY. With
/// `hnsw.iterative_scan = strict_order` the scan continues until `LIMIT`
/// in-window rows are found, nearest first. In the whole-corpus scope this is
/// the common case, not an edge case: the visibility splice rejects every
/// claim the viewer cannot see out of the entire corpus the same way.
#[sqlx::test(migrations = "../../migrations")]
async fn all_claims_scope_fills_its_limit_past_rows_a_post_filter_rejects(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let ids = seed_arc(&pool).await;
    let old: Vec<Uuid> = ids[..60].to_vec();
    sqlx::query("UPDATE claims SET created_at = now() - interval '2 days' WHERE id = ANY($1)")
        .bind(&old)
        .execute(&pool)
        .await
        .expect("age the nearest 60 rows");
    let since = chrono::Utc::now() - chrono::Duration::hours(1);

    let mut conn = pool.acquire().await.expect("acquire");
    force_index_plans(&mut conn).await;
    hnsw_graph_reaches_every_row(&mut conn).await;

    let hits = ClaimRepository::search_by_embedding_since(
        &mut *conn,
        &viewer,
        &vec_angle(0.0),
        1536,
        10,
        None,
        Some(since),
        EmbeddingSeedScope::AllClaims,
    )
    .await
    .expect("search_by_embedding_since");

    let got: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();
    assert_eq!(
        got,
        ids[60..70].to_vec(),
        "the 10 nearest IN-WINDOW rows, nearest first; a scan that stops at its first \
         ef_search batch returns none of them"
    );
}

/// `paper_doi_filter` composes with the scope. In `AllClaims` the DOI shape
/// returns EVERY embedded claim the named paper `asserts` (a paragraph and an
/// atom here) and nothing of another paper; in `Paragraphs` it keeps the
/// level-2 contract and returns that paper's paragraph only. A deliberate
/// change in drain U082: a DOI-filtered `recall_with_context` page now carries
/// that paper's atoms and sections too, not only its paragraphs.
#[sqlx::test(migrations = "../../migrations")]
async fn doi_filter_returns_every_claim_the_paper_asserts_in_all_claims_scope(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let q = vec_angle(0.0);

    async fn seed_paper(pool: &PgPool, doi: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(doi)
            .bind(format!("paper {doi}"))
            .execute(pool)
            .await
            .expect("seed paper");
        id
    }
    async fn asserts(pool: &PgPool, paper: Uuid, claim: Uuid) {
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
             VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
        )
        .bind(paper)
        .bind(claim)
        .execute(pool)
        .await
        .expect("seed paper asserts edge");
    }

    let ours = seed_paper(&pool, "10.1/doi-scope-ours").await;
    let theirs = seed_paper(&pool, "10.1/doi-scope-theirs").await;

    let paragraph = seed_claim(&pool, agent, 1, r#"{"level": 2}"#, Some(&vec_angle(3.0))).await;
    let atom = seed_claim(&pool, agent, 2, r#"{"level": 3}"#, Some(&vec_angle(2.0))).await;
    // Nearest of all, but asserted by the OTHER paper.
    let other = seed_claim(&pool, agent, 3, r#"{"level": 2}"#, Some(&vec_angle(1.0))).await;
    // Nearest-but-one, asserted by no paper at all.
    let _memorized = seed_claim(&pool, agent, 4, "{}", Some(&vec_angle(1.5))).await;
    asserts(&pool, ours, paragraph).await;
    asserts(&pool, ours, atom).await;
    asserts(&pool, theirs, other).await;

    let search = |scope| {
        let (pool, viewer, q) = (&pool, &viewer, &q);
        async move {
            ClaimRepository::search_by_embedding_since(
                pool,
                viewer,
                q,
                1536,
                10,
                Some("10.1/doi-scope-ours"),
                None,
                scope,
            )
            .await
            .expect("search_by_embedding_since with a DOI")
            .into_iter()
            .map(|h| h.claim_id)
            .collect::<Vec<_>>()
        }
    };

    assert_eq!(
        search(EmbeddingSeedScope::AllClaims).await,
        vec![atom, paragraph],
        "DOI + AllClaims: every claim the paper asserts (its atom too), nearest first, and \
         nothing asserted by another paper or by none"
    );
    assert_eq!(
        search(EmbeddingSeedScope::Paragraphs).await,
        vec![paragraph],
        "DOI + Paragraphs: the paper's level-2 paragraph only"
    );
}

/// The DOI filter matches every spelling of the paper's document key (backlog
/// 90756d26), through the same normalizer the paper writers use: a bare
/// filter finds a paper an older writer keyed on the resolver URL, and a
/// `doi:` / URL filter finds a bare-keyed paper. Before, `p.doi = $4` matched
/// the filter's spelling only, so both returned nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn doi_filter_matches_every_spelling_of_the_document_key(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let q = vec_angle(0.0);

    async fn seed_paper_asserting(pool: &PgPool, doi: &str, claim: Uuid) {
        let paper = Uuid::new_v4();
        sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, 'spelling test')")
            .bind(paper)
            .bind(doi)
            .execute(pool)
            .await
            .expect("seed paper");
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
             VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
        )
        .bind(paper)
        .bind(claim)
        .execute(pool)
        .await
        .expect("seed paper asserts edge");
    }

    let legacy_claim = seed_claim(&pool, agent, 1, "{}", Some(&vec_angle(1.0))).await;
    let bare_claim = seed_claim(&pool, agent, 2, "{}", Some(&vec_angle(2.0))).await;
    seed_paper_asserting(
        &pool,
        "https://doi.org/10.5555/doi-scope-legacy",
        legacy_claim,
    )
    .await;
    seed_paper_asserting(&pool, "10.5555/doi-scope-bare", bare_claim).await;

    for (filter, expected) in [
        ("10.5555/doi-scope-legacy", legacy_claim),
        ("doi:10.5555/doi-scope-legacy", legacy_claim),
        ("doi:10.5555/doi-scope-bare", bare_claim),
        ("https://dx.doi.org/10.5555/doi-scope-bare", bare_claim),
    ] {
        let hits: Vec<Uuid> = ClaimRepository::search_by_embedding_since(
            &pool,
            &viewer,
            &q,
            1536,
            10,
            Some(filter),
            None,
            EmbeddingSeedScope::AllClaims,
        )
        .await
        .expect("search_by_embedding_since with a DOI")
        .into_iter()
        .map(|h| h.claim_id)
        .collect();
        assert_eq!(hits, vec![expected], "filter {filter:?}");
    }
}
