//! Ruling R-49: an edge's `signer_id` is the agent whose key ATTESTED it (the
//! MCP server's or the API's signer agent signs every edge that server writes),
//! not its author. Since migration 120 the author record of an edge is its
//! writer group, and the author of what an edge asserts is its SOURCE claim's
//! author. Every CLI reader that took `signer_id` for the author must read the
//! source claim's author instead:
//!
//! * `backfill_factors::EDGE_QUERY` (the agent an edge factor is wired under);
//! * the operator's edge writer (`tables::fetch_attached`, read by
//!   `reown-claims --derived keep-writer` and its spill report, and by
//!   `restrict-claims`).
//!
//! The fixture's edge is signed by a third agent that authored neither
//! endpoint, so the old reading returns the signer and the new one the author.
#![cfg(feature = "db")]

mod viewer_fixture;

use epigraph_cli::backfill_factors::EDGE_QUERY;
use epigraph_cli::operator::tables::{fetch_attached, propagated_tables};
use sqlx::PgPool;
use uuid::Uuid;

async fn agent(pool: &PgPool) -> Uuid {
    viewer_fixture::seed_agent_with_group(pool, "r49").await.0
}

async fn claim(pool: &PgPool, author: Uuid, text: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             owner_group_id, visibility) \
         VALUES ($1, $2, $3, 0.7, $4, true, '00000000-0000-0000-0000-000000000000', 'public')",
    )
    .bind(id)
    .bind(text)
    .bind(epigraph_crypto::ContentHasher::hash(text.as_bytes()).as_slice())
    .bind(author)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// `source -supports-> target`, attested by `signer` (a placeholder signature:
/// the readers under test never verify it).
async fn signed_edge(pool: &PgPool, source: Uuid, target: Uuid, signer: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            signer_id, signature) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'supports', $4, decode(repeat('cd', 64), 'hex'))",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .bind(signer)
    .execute(pool)
    .await
    .expect("seed signed edge");
    id
}

struct Fx {
    author: Uuid,
    signer: Uuid,
    source: Uuid,
    edge: Uuid,
}

async fn seed(pool: &PgPool) -> Fx {
    let author = agent(pool).await;
    let target_author = agent(pool).await;
    let signer = agent(pool).await;
    let source = claim(
        pool,
        author,
        "R-49: the source claim's author asserts the edge",
    )
    .await;
    let target = claim(pool, target_author, "R-49: the target claim, factorless").await;
    let edge = signed_edge(pool, source, target, signer).await;
    Fx {
        author,
        signer,
        source,
        edge,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_edge_phase_wires_an_edge_factor_under_the_source_author(pool: PgPool) {
    let fx = seed(&pool).await;
    let rows: Vec<(Uuid, Uuid, Uuid, Uuid, String)> = sqlx::query_as(EDGE_QUERY)
        .bind(100_i64)
        .bind(0_i64)
        .fetch_all(&pool)
        .await
        .expect("EDGE_QUERY");
    let row = rows
        .iter()
        .find(|r| r.0 == fx.edge)
        .unwrap_or_else(|| panic!("calibration: EDGE_QUERY selects the edge: {rows:?}"));
    assert_ne!(fx.author, fx.signer, "calibration");
    assert_eq!(
        row.1, fx.author,
        "EDGE_QUERY read the edge's signer {} as its author",
        fx.signer
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_operator_reads_an_edges_writer_as_its_source_author(pool: PgPool) {
    let fx = seed(&pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    let specs = propagated_tables(&mut conn).await.expect("specs");
    let attached = fetch_attached(&mut conn, &specs, &[fx.source])
        .await
        .expect("fetch_attached");
    let edge = attached
        .get(&("edges".to_string(), fx.edge.to_string()))
        .unwrap_or_else(|| panic!("calibration: the edge is attached to its source claim"));
    assert_eq!(
        edge.writer,
        Some(fx.author),
        "the operator read the edge's signer {} as its writer",
        fx.signer
    );
}
