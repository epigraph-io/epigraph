#![cfg(feature = "db")]
//! The **HTTP** surface runs the retraction cascade too — PREREGISTRATION.md
//! C1(b)/C2/C5 for `crates/epigraph-api/src/routes/versioning.rs`.
//!
//! Both routes gained an awaited cascade and a `belief_cascade` response field
//! in the same change, and `supersede_claim` now runs the new cascade
//! immediately before the pre-existing fire-and-forget
//! `propagate_to_dependents` at step 10. Nothing exercised any of that: the
//! MCP tests cover the same engine entry points, but "the HTTP handler calls
//! the same function" is an assumption, not an observation — and the field is
//! serialized by a different `Serialize` impl on a different struct.
//!
//! These fixtures share the `DATABASE_URL` database with the rest of
//! `epigraph-api`'s integration tests (they are not `#[sqlx::test]`), so every
//! claim's content is tagged with a per-run UUID and every assertion is scoped
//! to the ids this test created.

// `common` is a shared helper module compiled into every test binary in this
// directory; each binary uses a different slice of it.
#[allow(dead_code)]
mod common;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// Wire `source --supports--> target` through the real edge-factor path so the
/// target actually carries a `perspective_id = edge_id` BBA — the derived
/// record the cascade exists to repair.
async fn wire_supports(pool: &sqlx::PgPool, agent: Uuid, source: Uuid, target: Uuid) {
    let edge_id = epigraph_db::EdgeRepository::create(
        pool, source, "claim", target, "claim", "supports", None, None, None,
    )
    .await
    .expect("create edge");
    let outcome = epigraph_engine::edge_factor::auto_wire_ds_for_edge(
        pool, edge_id, agent, source, target, "supports",
    )
    .await
    .expect("auto-wire edge factor");
    assert!(
        matches!(
            outcome,
            epigraph_engine::edge_factor::EdgeFactorOutcome::Wired
        ),
        "fixture precondition: the edge must materialize a BBA, else the \
         cascade has nothing to repair; got {outcome:?}"
    );
}

async fn betp(pool: &sqlx::PgPool, claim_id: Uuid) -> Option<f64> {
    sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("read pignistic_prob")
}

async fn plant_interval(pool: &sqlx::PgPool, claim_id: Uuid) {
    sqlx::query("UPDATE claims SET belief = 0.8, plausibility = 0.9 WHERE id = $1")
        .bind(claim_id)
        .execute(pool)
        .await
        .expect("plant interval");
}

fn uuids(cascade: &serde_json::Value, key: &str) -> Vec<String> {
    cascade[key]
        .as_array()
        .unwrap_or_else(|| panic!("belief_cascade.{key} must be an array; got {cascade}"))
        .iter()
        .map(|v| v.as_str().expect("uuid string").to_string())
        .collect()
}

/// `POST /api/v1/claims/:id/supersede` must repair the downstream claim AND
/// report what it repaired, exactly like the MCP tool.
#[tokio::test(flavor = "multi_thread")]
async fn supersede_route_reports_and_applies_the_belief_cascade() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;

    let tag = Uuid::new_v4();
    let a =
        common::seed_claim_with_agent(&pool, &format!("http cascade supporter {tag}"), client_id)
            .await;
    plant_interval(&pool, a).await;
    let b = common::seed_claim(&pool, &format!("http cascade downstream {tag}")).await;
    wire_supports(&pool, client_id, a, b).await;

    assert!(
        betp(&pool, b).await.is_some(),
        "fixture: B carries a cached BetP derived from A"
    );

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{a}/supersede"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "content": format!("replacement for {a}"),
            "truth_value": 0.5,
            "reason": "http cascade fixture",
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert!(
        status == 200 || status == 201,
        "supersede must succeed; got {status} — body={text}"
    );
    let json: serde_json::Value = serde_json::from_str(&text).expect("response json");

    // C1(a): the pre-existing keys are still there.
    assert!(json["new_claim_id"].as_str().is_some(), "body={text}");
    assert_eq!(
        json["superseded_claim_id"].as_str(),
        Some(a.to_string()).as_deref()
    );

    // C1(b) + C4: the cascade is reported over HTTP, and it found B.
    let cascade = &json["belief_cascade"];
    assert_eq!(
        uuids(cascade, "targets"),
        vec![b.to_string()],
        "the HTTP response must report the downstream claim it repaired; \
         got {cascade}"
    );
    assert_eq!(
        uuids(cascade, "unbacked"),
        vec![b.to_string()],
        "A was B's only supporter, so B is unbacked, not recomputed; \
         got {cascade}"
    );
    assert!(
        uuids(cascade, "errors").is_empty(),
        "healthy cascade must report no errors; got {cascade}"
    );

    // ...and the repair really landed, not just the report. (Nothing in this
    // test body calls `recompute_beliefs`.)
    assert_eq!(
        betp(&pool, b).await,
        None,
        "B's sole supporter was retracted; its cached BetP must not survive"
    );
}

/// `POST /api/v1/claims/:id/dedup` must do the same on the dedup path.
#[tokio::test(flavor = "multi_thread")]
async fn dedup_route_reports_and_applies_the_belief_cascade() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:admin"]).await;

    let tag = Uuid::new_v4();
    let canonical = common::seed_claim(&pool, &format!("http dedup canonical {tag}")).await;
    let dup =
        common::seed_claim_with_agent(&pool, &format!("http dedup duplicate {tag}"), client_id)
            .await;
    let supporter = common::seed_claim(&pool, &format!("http dedup supporter {tag}")).await;
    plant_interval(&pool, supporter).await;
    wire_supports(&pool, client_id, supporter, dup).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{dup}/dedup"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "canonical_id": canonical,
            "reason": "http cascade fixture",
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(status, 200, "dedup must succeed; body={text}");
    let json: serde_json::Value = serde_json::from_str(&text).expect("response json");

    assert_eq!(
        json["duplicate_id"].as_str(),
        Some(dup.to_string()).as_deref()
    );
    assert_eq!(
        json["canonical_id"].as_str(),
        Some(canonical.to_string()).as_deref()
    );
    assert_eq!(json["mode"].as_str(), Some("mark_duplicate"));

    let cascade = &json["belief_cascade"];
    assert!(
        uuids(cascade, "recomputed").contains(&canonical.to_string()),
        "canonical inherited the duplicate's supporter, so its belief was \
         rebuilt; got {cascade}"
    );
    assert!(
        uuids(cascade, "errors").is_empty(),
        "healthy cascade must report no errors; got {cascade}"
    );

    // The inherited supporter is visible in the survivor's cache, and the
    // retired duplicate no longer claims a belief it lost the evidence for.
    let frame_id = epigraph_engine::edge_factor::ensure_binary_frame(&pool)
        .await
        .expect("binary frame");
    let coherent =
        epigraph_engine::edge_factor::preview_claim_belief_on_frame(&pool, canonical, frame_id)
            .await
            .expect("preview")
            .expect("canonical inherited the supporter's BBA");
    let cached = betp(&pool, canonical)
        .await
        .expect("canonical must have a cached BetP");
    assert!(
        (cached - coherent.pignistic_prob).abs() < 1e-12,
        "canonical's cached BetP ({cached}) must equal the canonical combine of \
         its post-dedup mass_functions set ({})",
        coherent.pignistic_prob
    );
    assert_eq!(
        betp(&pool, dup).await,
        None,
        "the duplicate's supporter moved to canonical; its cached BetP is a \
         derived record with nothing behind it"
    );
}
