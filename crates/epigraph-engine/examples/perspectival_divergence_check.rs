//! Operator-driven proof that per-perspective discounting actually diverges on
//! a tagged ingest graph. Picks treatment_efficacy claims of differing source
//! types and runs the REAL `belief_query::get_perspective_belief` (compute-on-read:
//! source-reliability discounting -> combination -> pignistic) under each of the
//! four observer perspectives, printing BetP so divergence is visible.
//!
//! Run:
//!   DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_anxiety_ingest_dev \
//!   SQLX_OFFLINE=true \
//!     cargo run -p epigraph-engine --example perspectival_divergence_check
//!
//! An operator tool, run as a cargo example. It lived in `tests/` as an
//! `#[ignore]`d test that no gate ran (backlog 4ae8f96c); it asserts nothing, so
//! it is not a test. `cargo test` and `clippy --all-targets` still compile it.

#[path = "../tests/viewer_fixture.rs"]
mod fixture;

use epigraph_db::PgPool;
use epigraph_engine::belief_query::get_perspective_belief;
use uuid::Uuid;

/// An operator tool, not a test: a missing input is a usage error.
fn require_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        eprintln!("error: {name} is not set (see the run line at the top of this file)");
        std::process::exit(2);
    })
}

#[tokio::main]
async fn main() {
    let url = require_env("DATABASE_URL");
    let pool = PgPool::connect(&url).await.expect("connect");
    let viewer = fixture::public_viewer(&pool).await;

    let perspectives: Vec<(String, Uuid)> =
        sqlx::query_as("SELECT name, id FROM perspectives ORDER BY name")
            .fetch_all(&pool)
            .await
            .expect("perspectives");
    if perspectives.is_empty() {
        eprintln!(
            "error: no perspectives in this graph — run tag_ingest first. This tool \
             reports on a specific tagged ingest; point DATABASE_URL at one."
        );
        std::process::exit(1);
    }

    // The native binary frame; BetP(TRUE) = P(the proposition holds).
    let frame_id: Uuid = sqlx::query_scalar("SELECT id FROM frames WHERE name = 'binary_truth'")
        .fetch_one(&pool)
        .await
        .expect("binary_truth frame");

    // The per-herb efficacy/safety propositions built by build_axis, with their
    // TRUE/FALSE supporting-BBA counts (conflicted ones show within-claim divergence).
    let props: Vec<(Uuid, String)> = sqlx::query_as(
        r#"SELECT id, content FROM claims
            WHERE content LIKE '% for chronic generalized anxiety (Chittodvega)'
            ORDER BY content"#,
    )
    .fetch_all(&pool)
    .await
    .expect("propositions");
    if props.is_empty() {
        eprintln!(
            "error: no build_axis propositions in this graph — run build_axis first. \
             Absence here means the database is not the tagged ingest."
        );
        std::process::exit(1);
    }

    println!("\n=========== BetP(holds) per perspective — binary propositions ===========");
    for (cid, content) in &props {
        let counts: (i64, i64) = sqlx::query_as(
            r#"SELECT
                 count(*) FILTER (WHERE masses ? '0') AS t,
                 count(*) FILTER (WHERE masses ? '1') AS f
               FROM mass_functions WHERE claim_id = $1 AND frame_id = $2"#,
        )
        .bind(cid)
        .bind(frame_id)
        .fetch_one(&pool)
        .await
        .expect("bba counts");
        println!("\n{content}   [{}T / {}F evidence]", counts.0, counts.1);
        let mut betps = vec![];
        for (pname, pid) in &perspectives {
            let bi = get_perspective_belief(&pool, &viewer, *cid, frame_id, *pid)
                .await
                .expect("belief");
            println!(
                "   {:<24} BetP(holds)={:.3}  bel={:.3}  pl={:.3}",
                pname, bi.pignistic_prob, bi.belief, bi.plausibility
            );
            betps.push(bi.pignistic_prob);
        }
        let (min, max) = (
            betps.iter().cloned().fold(f64::INFINITY, f64::min),
            betps.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        );
        println!("   -> spread: {:.3}", max - min);
    }
}
