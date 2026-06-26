//! Per-herb, per-perspective belief dump — for comparing two independently-built
//! graphs (the hand-curated demo graph vs the deep-research ingest graph) through
//! the SAME engine (`get_perspective_belief`). Computes BetP(positive pole) for each
//! herb's efficacy and safety claims under each perspective, averaged across the
//! herb's claims, and prints tab-separated `ROW` lines for downstream diffing.
//!
//! MODE selects the graph's claim layout:
//!   demo   — directional frames treatment_efficacy {efficacious,no_effect} /
//!            treatment_safety {safe,harmful}; claims "<herb> ... is efficacious/safe for <symptom>"
//!   ingest — native binary_truth {TRUE,FALSE}; propositions "<herb> is efficacious/safe for chronic ..."
//!
//! Run:
//!   MODE=demo   DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_anxiety_dev \
//!   MODE=ingest DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_anxiety_ingest_dev \
//!     SQLX_OFFLINE=true cargo test -p epigraph-engine --test herb_belief_dump -- --ignored --nocapture

use std::collections::BTreeMap;

use epigraph_db::PgPool;
use epigraph_engine::belief_query::get_perspective_belief;
use uuid::Uuid;

#[tokio::test]
#[ignore = "operator-driven: needs DATABASE_URL + MODE"]
async fn herb_belief_dump() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let mode = std::env::var("MODE").expect("MODE=demo|ingest");
    let pool = PgPool::connect(&url).await.expect("connect");

    let perspectives: Vec<(String, Uuid)> =
        sqlx::query_as("SELECT name, id FROM perspectives ORDER BY name")
            .fetch_all(&pool)
            .await
            .expect("perspectives");

    // (aspect, frame_name, content LIKE filter)
    let specs: Vec<(&str, &str, &str)> = if mode == "demo" {
        vec![
            ("efficacy", "treatment_efficacy", "% is efficacious for %"),
            ("safety", "treatment_safety", "% is safe%"),
        ]
    } else {
        vec![
            ("efficacy", "binary_truth", "% is efficacious for chronic%"),
            ("safety", "binary_truth", "% is safe for chronic%"),
        ]
    };

    for (aspect, frame_name, like) in specs {
        let frame_id: Uuid = sqlx::query_scalar("SELECT id FROM frames WHERE name = $1")
            .bind(frame_name)
            .fetch_one(&pool)
            .await
            .expect("frame");
        let claims: Vec<(Uuid, String)> = sqlx::query_as(
            r#"SELECT DISTINCT c.id, c.content
                 FROM claims c
                 JOIN claim_frames cf ON cf.claim_id = c.id
                WHERE cf.frame_id = $1 AND c.content LIKE $2"#,
        )
        .bind(frame_id)
        .bind(like)
        .fetch_all(&pool)
        .await
        .expect("claims");

        // (herb, perspective) -> (sum BetP, n)
        let mut acc: BTreeMap<(String, String), (f64, i64)> = BTreeMap::new();
        for (cid, content) in &claims {
            let herb = content.split_whitespace().next().unwrap_or("?").to_string();
            for (pname, pid) in &perspectives {
                let bi = get_perspective_belief(&pool, *cid, frame_id, *pid)
                    .await
                    .expect("belief");
                let e = acc.entry((herb.clone(), pname.clone())).or_insert((0.0, 0));
                e.0 += bi.pignistic_prob;
                e.1 += 1;
            }
            // NOTE: redirect stdout to a file (`> out 2>&1`) rather than piping
            // through `grep` under --nocapture; the test-harness pipe can drop a
            // line when stdout/stderr interleave.
        }
        for ((herb, persp), (sum, n)) in &acc {
            println!(
                "ROW\t{mode}\t{aspect}\t{herb}\t{persp}\t{:.3}\t{n}",
                sum / (*n as f64)
            );
        }
    }
}
