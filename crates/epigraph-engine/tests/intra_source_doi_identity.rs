//! The edge-factor intra-source test compares documents by their shared key,
//! not by exact string (backlog e34fd66e).
//!
//! # What was wrong, measured at origin/main before this file
//!
//! `edge_factor::edge_source_is_intra` joined `papers.doi = e.properties->>'doi'`
//! exactly. `papers.doi` holds the canonical stored key (the bare DOI), while
//! an evidence row's `doi` holds whatever its writer passed: a doi.org link,
//! a `doi:` label, another case. Each of those spellings named the target's
//! own paper and was read as a CROSS-source edge, so its BBA escaped the
//! intra-source discount.
//!
//! # The oracle
//!
//! Spellings of one DOI are intra; a different DOI is not; a document keyed on
//! its URI still matches itself (the exact join's one working case).

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_engine::edge_factor::edge_source_is_intra;

async fn agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("agent")
}

async fn claim(pool: &PgPool, author: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
         VALUES ('intra doi identity', sha256(gen_random_uuid()::text::bytea), $1, 0.5) \
         RETURNING id",
    )
    .bind(author)
    .fetch_one(pool)
    .await
    .expect("claim")
}

/// A target claim asserted by a paper whose stored key is `paper_doi`.
async fn asserted_target(pool: &PgPool, author: Uuid, paper_doi: &str) -> Uuid {
    let target = claim(pool, author).await;
    let paper: Uuid =
        sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, 'paper') RETURNING id")
            .bind(paper_doi)
            .fetch_one(pool)
            .await
            .expect("paper");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(paper)
    .bind(target)
    .execute(pool)
    .await
    .expect("asserts edge");
    target
}

/// A source claim citing evidence whose `properties.doi` is `doi`.
async fn citing_source(pool: &PgPool, author: Uuid, doi: &str) -> Uuid {
    let source = claim(pool, author).await;
    sqlx::query(
        "INSERT INTO evidence (content_hash, evidence_type, claim_id, properties) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'reference', $1, \
                 jsonb_build_object('doi', $2::text))",
    )
    .bind(source)
    .bind(doi)
    .execute(pool)
    .await
    .expect("evidence");
    source
}

async fn is_intra(pool: &PgPool, source: Uuid, target: Uuid) -> bool {
    let mut conn = pool.acquire().await.expect("acquire");
    edge_source_is_intra(&mut conn, source, target)
        .await
        .expect("intra lookup")
}

#[sqlx::test(migrations = "../../migrations")]
async fn every_spelling_of_the_targets_paper_is_intra_source(pool: PgPool) {
    let author = agent(&pool).await;
    let target = asserted_target(&pool, author, "10.5555/Intra.Case").await;

    for spelling in [
        "10.5555/Intra.Case",
        "https://doi.org/10.5555/intra.case",
        "doi:10.5555/INTRA.CASE",
        "dx.doi.org/10.5555/Intra.Case",
        "10.5555/intra.case",
    ] {
        let source = citing_source(&pool, author, spelling).await;
        assert!(
            is_intra(&pool, source, target).await,
            "evidence DOI {spelling:?} names the target's paper 10.5555/Intra.Case"
        );
    }

    // Negative control: another paper is a cross-source edge.
    let other = citing_source(&pool, author, "https://doi.org/10.5555/other.paper").await;
    assert!(!is_intra(&pool, other, target).await);
    // A placeholder names no document.
    let unknown = citing_source(&pool, author, "unknown").await;
    assert!(!is_intra(&pool, unknown, target).await);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_document_keyed_on_its_uri_still_matches_itself(pool: PgPool) {
    let author = agent(&pool).await;
    let uri = "https://example.org/reports/annual.pdf";
    let target = asserted_target(&pool, author, uri).await;
    let source = citing_source(&pool, author, uri).await;
    assert!(
        is_intra(&pool, source, target).await,
        "the exact match the old join found is kept"
    );
    let elsewhere = citing_source(&pool, author, "https://example.org/reports/other.pdf").await;
    assert!(!is_intra(&pool, elsewhere, target).await);
}
